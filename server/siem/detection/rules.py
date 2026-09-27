"""Rule engine — phân tích DỰA TRÊN LUẬT.

Luật viết bằng YAML (thư mục rules/), cú pháp tương tự Sigma nhưng gọn hơn.
Hỗ trợ 3 kiểu:

  type: match      -> 1 event khớp điều kiện là sinh alert
  type: threshold  -> >= N event khớp trong cửa sổ T giây, gom nhóm theo trường
                      (tùy chọn distinct: đếm số GIÁ TRỊ KHÁC NHAU của 1 trường,
                      vd: số port đích khác nhau -> phát hiện port scan)
  type: sequence   -> chuỗi bước theo thứ tự trong khoảng `within` giây, cùng
                      group_by (vd: brute-force xong đăng nhập thành công)

Ngoại lệ (exceptions): điều kiện LOẠI TRỪ gắn vào một rule — event khớp ngoại lệ
thì rule bỏ qua. Dùng để giảm báo nhầm mà KHÔNG sửa điều kiện gốc của rule.
Khai báo trong file riêng rules/exceptions/*.yml (mỗi mục có rule_id) hoặc
trực tiếp trong rule bằng khóa `exceptions:`.

Điều kiện (condition) là cây:
  {all: [...]}, {any: [...]}, {not: {...}},
  lá: {field: <đường.dẫn>, op: <toán tử>, value: <giá trị>}
Toán tử: eq, neq, in, contains, not_contains, startswith, endswith, regex,
         gt, gte, lt, lte, exists, cidr
So khớp chuỗi mặc định KHÔNG phân biệt hoa/thường.
"""
from __future__ import annotations

import ipaddress
import logging
import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from ..pipeline.normalize import Doc, get

log = logging.getLogger(__name__)

SEVERITY_SCORE = {"low": 1, "medium": 2, "high": 3, "critical": 4}


# ---------------------------------------------------------------------------
# Biên dịch điều kiện
# ---------------------------------------------------------------------------

class Condition:
    def __init__(self, spec: Any):
        self.spec = self._compile(spec)

    def _compile(self, spec: Any) -> Any:
        if isinstance(spec, list):
            return ("all", [self._compile(s) for s in spec])
        if not isinstance(spec, dict):
            raise ValueError(f"điều kiện không hợp lệ: {spec!r}")
        if "all" in spec:
            return ("all", [self._compile(s) for s in spec["all"]])
        if "any" in spec:
            return ("any", [self._compile(s) for s in spec["any"]])
        if "not" in spec:
            return ("not", self._compile(spec["not"]))
        if "field" in spec:
            op = spec.get("op", "eq")
            value = spec.get("value")
            if op == "regex":
                flags = 0 if spec.get("case_sensitive") else re.IGNORECASE
                pats = value if isinstance(value, list) else [value]
                value = [re.compile(p, flags) for p in pats]
            elif op == "cidr":
                nets = value if isinstance(value, list) else [value]
                value = [ipaddress.ip_network(n, strict=False) for n in nets]
            elif op in ("in", "contains", "not_contains", "startswith", "endswith", "eq", "neq"):
                vals = value if isinstance(value, list) else [value]
                value = [_lower(v) for v in vals]
            return ("leaf", spec["field"], op, value)
        raise ValueError(f"điều kiện không hợp lệ: {spec!r}")

    def match(self, doc: Doc) -> bool:
        return _eval(self.spec, doc)


def _lower(v: Any) -> Any:
    return v.lower() if isinstance(v, str) else v


def _eval(node: Any, doc: Doc) -> bool:
    kind = node[0]
    if kind == "all":
        return all(_eval(n, doc) for n in node[1])
    if kind == "any":
        return any(_eval(n, doc) for n in node[1])
    if kind == "not":
        return not _eval(node[1], doc)
    _, path, op, value = node
    actual = get(doc, path)
    if op == "exists":
        return (actual is not None) == bool(value if value is not None else True)
    if actual is None:
        return op in ("neq", "not_contains")
    values = actual if isinstance(actual, list) else [actual]
    return any(_leaf(op, v, value) for v in values)


def _leaf(op: str, actual: Any, value: Any) -> bool:
    a = _lower(actual)
    if op in ("eq", "in"):
        return a in value or str(a) in [str(v) for v in value]
    if op == "neq":
        return a not in value and str(a) not in [str(v) for v in value]
    s = str(a)
    if op == "contains":
        return any(str(v) in s for v in value)
    if op == "not_contains":
        return not any(str(v) in s for v in value)
    if op == "startswith":
        return any(s.startswith(str(v)) for v in value)
    if op == "endswith":
        return any(s.endswith(str(v)) for v in value)
    if op == "regex":
        return any(p.search(str(actual)) for p in value)
    if op == "cidr":
        try:
            ip = ipaddress.ip_address(str(actual))
        except ValueError:
            return False
        return any(ip in n for n in value)
    try:
        x, y = float(actual), float(value)
    except (TypeError, ValueError):
        return False
    return {"gt": x > y, "gte": x >= y, "lt": x < y, "lte": x <= y}.get(op, False)


# ---------------------------------------------------------------------------
# Rule
# ---------------------------------------------------------------------------

@dataclass
class Rule:
    id: str
    title: str
    severity: str
    type: str
    condition: Condition | None
    description: str = ""
    mitre: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    group_by: list[str] = field(default_factory=list)
    count: int = 1
    window: int = 60
    distinct: str | None = None
    steps: list[tuple[Condition, int]] = field(default_factory=list)
    within: int = 300
    suppress: int = 0
    exceptions: list["RuleException"] = field(default_factory=list)
    source_file: str = ""

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Rule":
        rtype = d.get("type", "match")
        thr = d.get("threshold") or {}
        seq = d.get("sequence") or {}
        r = cls(
            id=str(d["id"]), title=d["title"], severity=d.get("severity", "medium").lower(),
            type=rtype, description=d.get("description", ""), mitre=d.get("mitre") or {},
            tags=d.get("tags") or [],
            condition=Condition(d["condition"]) if "condition" in d else None,
            group_by=thr.get("group_by") or seq.get("group_by") or d.get("group_by") or [],
            count=int(thr.get("count", 1)), window=int(thr.get("window", 60)),
            distinct=thr.get("distinct"), within=int(seq.get("within", 300)),
            suppress=int(d.get("suppress", 0 if rtype == "match" else 300)),
        )
        for st in seq.get("steps") or []:
            r.steps.append((Condition(st["condition"]), int(st.get("count", 1))))
        for i, ex in enumerate(d.get("exceptions") or []):
            r.exceptions.append(RuleException.from_dict({"id": f"{r.id}-inline-{i}", **ex, "rule_id": r.id}))
        if r.severity not in SEVERITY_SCORE:
            raise ValueError(f"severity không hợp lệ: {r.severity}")
        if rtype in ("match", "threshold") and r.condition is None:
            raise ValueError("thiếu condition")
        if rtype == "sequence" and len(r.steps) < 2:
            raise ValueError("sequence cần >= 2 bước")
        return r


@dataclass
class RuleException:
    """Điều kiện loại trừ gắn vào 1 rule (vd: bỏ qua máy quét lỗ hổng được phép)."""
    id: str
    rule_id: str
    condition: Condition
    description: str = ""
    source: str = "manual"          # manual | ai
    meta: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "RuleException":
        if not d.get("rule_id") or "condition" not in d:
            raise ValueError("exception cần rule_id và condition")
        meta = {k: v for k, v in d.items() if k not in ("id", "rule_id", "condition", "description", "source")}
        return cls(id=str(d.get("id") or f"{d['rule_id']}-exc"), rule_id=str(d["rule_id"]),
                   condition=Condition(d["condition"]), description=d.get("description", ""),
                   source=d.get("source", "manual"), meta=meta)

    def match(self, doc: Doc) -> bool:
        return self.condition.match(doc)


EXCEPTIONS_DIR = "exceptions"


def _yaml_docs(path: Path) -> list[dict[str, Any]]:
    docs = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    return [d for d in (docs if isinstance(docs, list) else [docs]) if d]


def load_rules(rules_dir: Path) -> list[Rule]:
    """Nạp rule từ mọi file *.yml trong rules_dir (kể cả thư mục con, vd rules/ai/),
    rồi gắn các ngoại lệ trong rules/exceptions/*.yml vào rule tương ứng."""
    rules: list[Rule] = []
    for path in sorted(rules_dir.glob("**/*.y*ml")):
        if EXCEPTIONS_DIR in path.relative_to(rules_dir).parts:
            continue
        for d in _yaml_docs(path):
            if d.get("enabled", True) is False:
                continue
            try:
                r = Rule.from_dict(d)
                r.source_file = str(path.relative_to(rules_dir)).replace("\\", "/")
                rules.append(r)
            except Exception as e:  # noqa: BLE001
                log.error("rule lỗi trong %s (%s): %s", path.name, d.get("id"), e)
    ids = [r.id for r in rules]
    dup = {i for i in ids if ids.count(i) > 1}
    if dup:
        raise ValueError(f"trùng rule id: {dup}")

    by_id = {r.id: r for r in rules}
    n_exc = 0
    for path in sorted((rules_dir / EXCEPTIONS_DIR).glob("*.y*ml")):
        for d in _yaml_docs(path):
            if d.get("enabled", True) is False:
                continue
            try:
                ex = RuleException.from_dict(d)
            except Exception as e:  # noqa: BLE001
                log.error("exception lỗi trong %s: %s", path.name, e)
                continue
            if ex.rule_id not in by_id:
                log.warning("exception %s trỏ tới rule không tồn tại %s — bỏ qua", ex.id, ex.rule_id)
                continue
            by_id[ex.rule_id].exceptions.append(ex)
            n_exc += 1
    log.info("đã nạp %d rule, %d ngoại lệ từ %s", len(rules), n_exc, rules_dir)
    return rules


def rules_fingerprint(rules_dir: Path) -> tuple:
    """Dấu vân tay thư mục rule (tên + mtime + kích thước) để phát hiện thay đổi -> nạp lại."""
    out = []
    for p in sorted(rules_dir.glob("**/*.y*ml")):
        try:
            st = p.stat()
            out.append((str(p), st.st_mtime_ns, st.st_size))
        except OSError:
            pass
    return tuple(out)


_NESTED_QUANTIFIER = re.compile(r"\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)\s*[+*{]")


def regex_risk(pattern: str) -> str | None:
    """Kiểm tra nhanh regex có nguy cơ backtracking thảm họa (ReDoS) hoặc quá dài.
    Trả về lý do nếu KHÔNG an toàn, None nếu chấp nhận được."""
    if len(pattern) > 300:
        return "regex dài quá 300 ký tự"
    if _NESTED_QUANTIFIER.search(pattern):
        return "regex có lượng từ lồng nhau (vd (a+)+), nguy cơ ReDoS"
    try:
        re.compile(pattern)
    except re.error as e:
        return f"regex không hợp lệ: {e}"
    return None


def event_time(doc: Doc) -> float:
    ts = doc.get("@timestamp")
    if isinstance(ts, str):
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
        except ValueError:
            pass
    return time.time()


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

@dataclass
class Detection:
    rule: Rule
    event: Doc
    group: dict[str, Any]
    count: int
    related: list[str]


class RuleEngine:
    def __init__(self, rules: list[Rule]):
        self.rules = rules
        # (rule_id, group_key) -> deque[(ts, distinct_value, event_id)]
        self._windows: dict[tuple[str, tuple], deque] = defaultdict(deque)
        # (rule_id, group_key) -> {"stage", "start", "hits": deque, "related": []}
        self._seq: dict[tuple[str, tuple], dict[str, Any]] = {}
        self._suppressed: dict[tuple[str, tuple], float] = {}
        self._last_gc = time.time()

    def _group(self, rule: Rule, doc: Doc) -> tuple | None:
        vals = tuple(get(doc, f) for f in rule.group_by)
        if rule.group_by and any(v is None for v in vals):
            return None  # thiếu trường nhóm -> không thể tương quan
        return vals

    def _is_suppressed(self, key: tuple, now: float, rule: Rule) -> bool:
        until = self._suppressed.get(key)
        if until and now < until:
            return True
        if rule.suppress:
            self._suppressed[key] = now + rule.suppress
        return False

    def process(self, doc: Doc) -> list[Detection]:
        out: list[Detection] = []
        ts = event_time(doc)
        eid = get(doc, "event.id", "")
        for rule in self.rules:
            try:
                det = self._process_rule(rule, doc, ts, eid)
            except Exception as e:  # noqa: BLE001
                log.exception("rule %s lỗi: %s", rule.id, e)
                continue
            if det:
                out.append(det)
        if time.time() - self._last_gc > 60:
            self._gc(ts)
        return out

    @staticmethod
    def _excepted(rule: Rule, doc: Doc) -> bool:
        return bool(rule.exceptions) and any(ex.match(doc) for ex in rule.exceptions)

    def _process_rule(self, rule: Rule, doc: Doc, ts: float, eid: str) -> Detection | None:
        if rule.type == "sequence":
            if self._excepted(rule, doc):
                return None
            return self._sequence(rule, doc, ts, eid)
        if not rule.condition.match(doc) or self._excepted(rule, doc):
            return None
        grp = self._group(rule, doc)
        if grp is None:
            return None
        key = (rule.id, grp)
        group = dict(zip(rule.group_by, grp))

        if rule.type == "match":
            if rule.suppress and self._is_suppressed(key, ts, rule):
                return None
            return Detection(rule, doc, group, 1, [eid])

        # threshold
        win = self._windows[key]
        win.append((ts, get(doc, rule.distinct) if rule.distinct else None, eid))
        while win and win[0][0] < ts - rule.window:
            win.popleft()
        n = len({d for _, d, _ in win if d is not None}) if rule.distinct else len(win)
        if n < rule.count:
            return None
        related = [e for _, _, e in win][-50:]
        win.clear()
        if self._is_suppressed(key, ts, rule):
            return None
        return Detection(rule, doc, group, n, related)

    def _sequence(self, rule: Rule, doc: Doc, ts: float, eid: str) -> Detection | None:
        grp = self._group(rule, doc)
        if grp is None:
            return None
        key = (rule.id, grp)
        st = self._seq.get(key)
        if st and ts - st["start"] > rule.within:
            st = None
            self._seq.pop(key, None)

        stage = st["stage"] if st else 0
        cond, need = rule.steps[stage]
        if not cond.match(doc):
            # event khớp bước 0 khi đang ở bước sau -> vẫn tiếp tục tích lũy bước sau, bỏ qua
            return None
        if st is None:
            st = {"stage": 0, "start": ts, "hits": deque(), "related": []}
            self._seq[key] = st
        st["hits"].append(ts)
        st["related"].append(eid)
        if len(st["hits"]) < need:
            return None
        st["stage"] += 1
        st["hits"] = deque()
        if st["stage"] < len(rule.steps):
            return None
        self._seq.pop(key, None)
        if self._is_suppressed(key, ts, rule):
            return None
        return Detection(rule, doc, dict(zip(rule.group_by, grp)), len(st["related"]), st["related"][-50:])

    def _gc(self, now: float) -> None:
        """Dọn state cũ để bộ nhớ không phình vô hạn."""
        self._last_gc = time.time()
        max_window = max([r.window for r in self.rules] + [r.within for r in self.rules] + [60])
        for k in [k for k, w in self._windows.items() if not w or w[-1][0] < now - max_window]:
            del self._windows[k]
        for k in [k for k, s in self._seq.items() if now - s["start"] > max_window]:
            del self._seq[k]
        for k in [k for k, t in self._suppressed.items() if t < now]:
            del self._suppressed[k]
