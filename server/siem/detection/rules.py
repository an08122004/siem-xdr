"""Rule engine — phân tích DỰA TRÊN LUẬT.

Luật viết bằng YAML (thư mục rules/), cú pháp tương tự Sigma nhưng gọn hơn.
Hỗ trợ 3 kiểu:

  type: match      -> 1 event khớp điều kiện là sinh alert
  type: threshold  -> >= N event khớp trong cửa sổ T giây, gom nhóm theo trường
                      (tùy chọn distinct: đếm số GIÁ TRỊ KHÁC NHAU của 1 trường,
                      vd: số port đích khác nhau -> phát hiện port scan)
  type: sequence   -> chuỗi bước theo thứ tự trong khoảng `within` giây, cùng
                      group_by (vd: brute-force xong đăng nhập thành công)

Chế độ (`mode`): `active` (mặc định) hoặc `shadow` — rule CHẠY BÓNG: vẫn sinh alert (gắn alert.shadow) để đo số alert
và tỉ lệ báo nhầm, nhưng SOAR bỏ qua (không thông báo, không mở case, không phản ứng), console ẩn khỏi danh sách mặc
định. Rule mới (kể cả rule AI vừa duyệt) chạy bóng tối thiểu 7 ngày rồi Detection Engineer mới bật chính thức
(SOC-OPERATIONS.md mục 4).

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

import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ..ai.condition import RULE_MODES, Condition, Rule, RuleException, regex_risk  # noqa: F401
from ..pipeline.normalize import Doc, get
from .alerts import SEVERITY_SCORE, event_time  # noqa: F401

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Biên dịch điều kiện
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Rule
# ---------------------------------------------------------------------------

EXCEPTIONS_DIR = "exceptions"
CASES_DIR = "cases"            # ca test dương / âm của rule (detection/ruletest.py), không phải rule
SKIP_DIRS = (EXCEPTIONS_DIR, CASES_DIR)


def _yaml_docs(path: Path) -> list[dict[str, Any]]:
    docs = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    return [d for d in (docs if isinstance(docs, list) else [docs]) if d]


def load_rules(rules_dir: Path) -> list[Rule]:
    """Nạp rule từ mọi file *.yml trong rules_dir (kể cả thư mục con, vd rules/ai/),
    rồi gắn các ngoại lệ trong rules/exceptions/*.yml vào rule tương ứng."""
    rules: list[Rule] = []
    for path in sorted(rules_dir.glob("**/*.y*ml")):
        if set(SKIP_DIRS) & set(path.relative_to(rules_dir).parts):
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
    first_time: float | None = None     # thời điểm event ĐẦU TIÊN của chuỗi (threshold / sequence) -> MTTD


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
            return Detection(rule, doc, group, 1, [eid], ts)

        # threshold
        win = self._windows[key]
        win.append((ts, get(doc, rule.distinct) if rule.distinct else None, eid))
        while win and win[0][0] < ts - rule.window:
            win.popleft()
        n = len({d for _, d, _ in win if d is not None}) if rule.distinct else len(win)
        if n < rule.count:
            return None
        related = [e for _, _, e in win][-50:]
        first = win[0][0]
        win.clear()
        if self._is_suppressed(key, ts, rule):
            return None
        return Detection(rule, doc, group, n, related, first)

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
        return Detection(rule, doc, dict(zip(rule.group_by, grp)), len(st["related"]), st["related"][-50:], st["start"])

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
