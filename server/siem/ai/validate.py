"""Kiểm định tự động đề xuất của AI — hoàn toàn độc lập với LLM (không tin output của model).

Ngoại lệ (giảm cảnh báo) — rủi ro cao nhất vì có thể "làm mù" SIEM:
  cấu trúc, trường có thật, toán tử, regex an toàn, đủ hẹp (neo vào thực thể cụ thể),
  khớp phần lớn báo nhầm, KHÔNG khớp event nào của sự cố thật (case) và của BỘ MẪU VÀNG (dataset),
  replay dữ liệu thật để ước lượng số alert bị tắt, hiệu năng.
Rule mới:
  cấu trúc, trường có thật, regex an toàn, ID không trùng, bắt được mẫu nghi vấn ở TẬP KIỂM TRA
  (tách riêng với mẫu đưa cho LLM -> tránh học vẹt), báo nhầm trên tập bình thường, số alert/ngày khi
  replay dữ liệu thật, hiệu năng.
"""
from __future__ import annotations

import re
import time
from dataclasses import asdict, dataclass, replace
from datetime import datetime
from typing import Any
from urllib.parse import unquote_plus

from ..detection.rules import Rule, RuleEngine, RuleException, _eval, regex_risk
from ..pipeline.normalize import Doc, get
from .golden import PublicDatasets
from .prompts import EXC_OPS, RULE_OPS

FIELD_RE = re.compile(r"^[a-z_@][a-z0-9_.@]*$")
SPECIFIC_OPS = {"eq", "in", "cidr", "startswith"}
GENERIC_PREFIXES = ("event.", "message", "log.", "tags")
_SEGMENT = re.compile(r"[^a-z0-9_.\-~]+")
SCOPE_FIELDS = {"event.category", "event.module", "event.action", "event.code", "event.dataset", "event.type"}

# URL bình thường của một website bất kỳ. Tập bình thường CSIC chỉ có một ứng dụng (/tienda1/...), không có
# URL thư mục, trang tĩnh, API... nên rule kiểu `url endswith "/"` vẫn đạt 0 báo nhầm trên CSIC. Rule web
# khớp bất kỳ URL nào dưới đây là quá chung chung.
ORDINARY_URLS = [
    "/", "/index.html", "/images/", "/images/logo.png", "/css/site.css", "/js/app.min.js", "/favicon.ico",
    "/robots.txt", "/about-us", "/news/", "/blog/2024/05/hello-world/", "/login", "/account/settings",
    "/products?category=shoes&sort=price-asc&page=2", "/search?q=summer+sale", "/search?q=O%27Brien+%26+Sons",
    "/api/v1/users/42", "/api/v1/orders?status=open&limit=20", "/docs/guide.html", "/download?file=report-2024.pdf",
    "/cart/add?id=17&qty=1", "/?lang=en", "/contact?name=Anna&email=anna%40example.com&msg=Hi%2C+see+you+at+5",
]


def _ordinary_doc(u: str) -> Doc:
    path, _, query = u.partition("?")
    return {"event": {"category": "web", "module": "apache", "type": "access"},
            "http": {"request": {"method": "GET"}, "response": {"status_code": 200}},
            "url": {"original": u, "path": path, "query": query, "decoded": unquote_plus(u)}}


ORDINARY_DOCS = [_ordinary_doc(u) for u in ORDINARY_URLS]


def ordinary_hits(cond) -> list[str]:
    """URL bình thường mà điều kiện khớp (chỉ xét nếu điều kiện dùng trường url.*)."""
    return [get(d, "url.original") for d in ORDINARY_DOCS if cond.match(d)]


@dataclass
class Check:
    name: str
    ok: bool
    detail: str
    blocking: bool = True


@dataclass
class Validation:
    passed: bool
    risk: str
    checks: list[Check]
    metrics: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {"passed": self.passed, "risk": self.risk, "checks": [asdict(c) for c in self.checks],
                "metrics": self.metrics}


# ---------------------------------------------------------------- tiện ích
def build_condition(match: str, clauses: list[dict[str, Any]]) -> dict[str, Any]:
    leaves = []
    for c in clauses:
        op, val = str(c.get("op", "eq")), c.get("value")
        if op in ("in", "cidr") and not isinstance(val, list):
            val = [val]
        if op == "eq" and isinstance(val, list):
            op = "in"
        if isinstance(val, str):
            val = val.strip()
        leaves.append({"field": str(c.get("field", "")).strip(), "op": op, "value": val})
    return {"any" if match == "any" else "all": leaves}


def leaves_of(cond: dict[str, Any]) -> list[dict[str, Any]]:
    return next(iter(cond.values()))


def span_days(events: list[Doc]) -> float:
    ts = [e.get("@timestamp") for e in events if isinstance(e.get("@timestamp"), str)]
    if len(ts) < 2:
        return 1.0
    try:
        a = datetime.fromisoformat(min(ts).replace("Z", "+00:00"))
        b = datetime.fromisoformat(max(ts).replace("Z", "+00:00"))
    except ValueError:
        return 1.0
    return max((b - a).total_seconds() / 86400, 1 / 24)


def replay(rule: Rule, events: list[Doc]) -> tuple[int, float]:
    eng = RuleEngine([rule])
    t0 = time.perf_counter()
    n = sum(len(eng.process(e)) for e in events)
    return n, time.perf_counter() - t0


def scope_match(rule: Rule, doc: Doc) -> bool:
    """Rule có 'xem xét' loại event này không: chỉ đánh giá các mệnh đề phạm vi
    (event.category/module/action/code...), bỏ qua mệnh đề chi tiết."""
    def ev(node) -> bool:
        kind = node[0]
        if kind == "all":
            return all(ev(n) for n in node[1])
        if kind == "any":
            return any(ev(n) for n in node[1])
        if kind == "not":
            return True
        if node[1] not in SCOPE_FIELDS:
            return True
        return _eval(node, doc)
    conds = [rule.condition] if rule.condition else [c for c, _ in rule.steps]
    return any(ev(c.spec) for c in conds if c is not None)


def _fields_present(clauses: list[dict[str, Any]], docs: list[Doc]) -> list[str]:
    return [c["field"] for c in clauses if not any(get(d, c["field"]) is not None for d in docs)]


def _regex_problems(clauses: list[dict[str, Any]]) -> list[str]:
    out = []
    for c in clauses:
        if c["op"] == "regex":
            for p in c["value"] if isinstance(c["value"], list) else [c["value"]]:
                if (why := regex_risk(str(p))):
                    out.append(f"{c['field']}: {why}")
    return out


def _app_specific(clauses: list[dict[str, Any]], app_tokens: set[str]) -> set[str]:
    """Giá trị trong rule chứa nguyên một đoạn đường dẫn / tên file của ứng dụng mẫu (vd tienda1, anadir.jsp).
    So theo từng đoạn, không theo chuỗi con: `global.asa` không bị coi là gắn với thư mục `/global/`."""
    found = set()
    for c in clauses:
        for v in c["value"] if isinstance(c["value"], list) else [c["value"]]:
            found |= app_tokens & set(_SEGMENT.split(str(v).lower().replace("\\.", ".")))
    return found


# ---------------------------------------------------------------- ngoại lệ
def validate_exception(rule: Rule, exc: dict[str, Any], fp: list[Doc], tp: list[Doc],
                       golden: PublicDatasets | None, replay_events: list[Doc]) -> Validation:
    checks: list[Check] = []
    metrics: dict[str, Any] = {}
    clauses = leaves_of(exc["condition"])

    bad_fields = [c["field"] for c in clauses if not FIELD_RE.match(c["field"])]
    bad_ops = [c["op"] for c in clauses if c["op"] not in EXC_OPS]
    try:
        ex = RuleException.from_dict(exc)
        ok = not bad_fields and not bad_ops
        checks.append(Check("cấu trúc", ok, "hợp lệ" if ok else f"trường sai: {bad_fields} / toán tử không cho phép: {bad_ops}"))
    except Exception as e:  # noqa: BLE001
        checks.append(Check("cấu trúc", False, f"không compile được: {e}"))
        return Validation(False, "cao", checks, metrics)

    missing = _fields_present(clauses, fp)
    checks.append(Check("trường có thật", not missing, "mọi trường đều có trong mẫu báo nhầm" if not missing
                        else f"trường không có trong dữ liệu: {missing}"))
    rx = _regex_problems(clauses)
    checks.append(Check("regex an toàn", not rx, "ok" if not rx else "; ".join(rx)))

    specific = [c for c in clauses if c["op"] in SPECIFIC_OPS and not c["field"].startswith(GENERIC_PREFIXES)
                and c["value"] not in ("", "*", [], None)]
    narrow = bool(specific) and (next(iter(exc["condition"])) == "all" or len(specific) == len(clauses))
    checks.append(Check("đủ hẹp", narrow, "neo vào thực thể cụ thể: " + ", ".join(c["field"] for c in specific)
                        if narrow else "ngoại lệ quá rộng: cần ít nhất 1 mệnh đề eq/in/cidr/startswith trên trường "
                        "thực thể (IP, user, host, process, url...), không chỉ event.*"))

    fp_hit = sum(ex.match(d) for d in fp)
    metrics["fp_total"], metrics["fp_matched"] = len(fp), fp_hit
    cover = fp_hit / len(fp) if fp else 0
    checks.append(Check("khớp báo nhầm", cover >= 0.5, f"khớp {fp_hit}/{len(fp)} alert báo nhầm ({cover:.0%}, cần ≥ 50%)"))

    tp_hit = sum(ex.match(d) for d in tp)
    metrics["tp_total"], metrics["tp_matched"] = len(tp), tp_hit
    if tp:
        checks.append(Check("không tắt sự cố thật", tp_hit == 0,
                            f"khớp {tp_hit}/{len(tp)} event của case đã xác nhận thật" + (" — LOẠI" if tp_hit else "")))
    else:
        checks.append(Check("không tắt sự cố thật", True, "chưa có case thật nào của rule này để đối chứng", blocking=False))

    golden_pos = golden.positives_for(rule) if golden else []
    g_hit = sum(ex.match(x.doc) for x in golden_pos)
    metrics["golden_total"], metrics["golden_matched"] = len(golden_pos), g_hit
    if golden_pos:
        checks.append(Check("giữ bộ mẫu vàng", g_hit == 0,
                            f"rule đang bắt {len(golden_pos)} mẫu tấn công của dataset; ngoại lệ làm mất {g_hit}"))
    else:
        checks.append(Check("giữ bộ mẫu vàng", True, "dataset không có mẫu tấn công cho rule này", blocking=False))

    before, t_before = replay(rule, replay_events)
    after, t_after = replay(replace(rule, exceptions=rule.exceptions + [ex]), replay_events)
    ratio = (before - after) / before if before else 0.0
    metrics.update(replay_events=len(replay_events), replay_days=round(span_days(replay_events), 2),
                   alerts_before=before, alerts_after=after, suppressed_ratio=round(ratio, 3))
    checks.append(Check("replay dữ liệu thật", True,
                        f"{len(replay_events)} event: {before} alert -> {after} alert (tắt {ratio:.0%})", blocking=False))
    slow = t_after > 2 * t_before + 0.5
    checks.append(Check("hiệu năng", not slow, f"{t_before:.2f}s -> {t_after:.2f}s"))

    passed = all(c.ok for c in checks if c.blocking)
    risk = "cao" if (not tp and not golden_pos) or ratio > 0.8 else "thấp"
    return Validation(passed, risk, checks, metrics)


# ---------------------------------------------------------------- rule mới
def validate_new_rule(rule_dict: dict[str, Any], existing: list[Rule], suspicious_train: list[Doc],
                      suspicious_test: list[Doc], normal: list[Doc], replay_events: list[Doc],
                      max_alerts_per_day: float, app_tokens: set[str] | None = None) -> Validation:
    checks: list[Check] = []
    metrics: dict[str, Any] = {}
    clauses = leaves_of(rule_dict["condition"])
    bad_fields = [c["field"] for c in clauses if not FIELD_RE.match(c["field"])]
    bad_ops = [c["op"] for c in clauses if c["op"] not in RULE_OPS]
    try:
        rule = Rule.from_dict(rule_dict)
        ok = not bad_fields and not bad_ops
        checks.append(Check("cấu trúc", ok, "hợp lệ" if ok else f"trường sai: {bad_fields} / toán tử sai: {bad_ops}"))
    except Exception as e:  # noqa: BLE001
        checks.append(Check("cấu trúc", False, f"không compile được: {e}"))
        return Validation(False, "cao", checks, metrics)

    dup = rule.id in {r.id for r in existing}
    checks.append(Check("ID không trùng", not dup, rule.id + (" đã tồn tại" if dup else "")))
    missing = _fields_present(clauses, suspicious_train + suspicious_test)
    checks.append(Check("trường có thật", not missing, "ok" if not missing else f"trường không có trong dữ liệu: {missing}"))
    rx = _regex_problems(clauses)
    checks.append(Check("regex an toàn", not rx, "ok" if not rx else "; ".join(rx)))
    if app_tokens:
        tied = sorted(_app_specific(clauses, app_tokens))
        checks.append(Check("dùng chung được", not tied, "không gắn với ứng dụng mẫu của dataset" if not tied
                            else f"rule chỉ khớp ứng dụng mẫu của dataset (chứa {', '.join(tied[:5])})"))

    test = suspicious_test or suspicious_train
    hit = sum(rule.condition.match(d) for d in test)
    recall = hit / len(test) if test else 0
    metrics.update(test_total=len(test), test_detected=hit, test_recall=round(recall, 3),
                   test_is_holdout=bool(suspicious_test))
    checks.append(Check("bắt mẫu nghi vấn", recall >= 0.3,
                        f"{hit}/{len(test)} mẫu {'ở tập kiểm tra (không đưa cho LLM)' if suspicious_test else ''} ({recall:.0%}, cần ≥ 30%)"))

    if normal:
        nh = sum(rule.condition.match(d) for d in normal)
        fpr = nh / len(normal)
        metrics.update(normal_total=len(normal), normal_hits=nh, fp_rate=round(fpr, 5))
        checks.append(Check("báo nhầm trên dữ liệu bình thường", fpr <= 0.001,
                            f"{nh}/{len(normal)} event bình thường bị bắt ({fpr:.2%}, tối đa 0,1%)"))
    else:
        nh = 0
    if any(c["field"].startswith("url.") for c in clauses):
        oh = ordinary_hits(rule.condition)
        metrics["ordinary_url_hits"] = len(oh)
        checks.append(Check("không khớp URL thông thường", not oh,
                            f"không khớp {len(ORDINARY_URLS)} URL mẫu của website bình thường" if not oh
                            else f"khớp URL bình thường: {', '.join(oh[:3])} — quá chung chung"))

    n, t = replay(rule, replay_events)
    per_day = n / span_days(replay_events) if replay_events else 0
    metrics.update(replay_events=len(replay_events), replay_alerts=n, alerts_per_day=round(per_day, 2))
    checks.append(Check("số alert khi replay", per_day <= max_alerts_per_day,
                        f"{n} alert trên {len(replay_events)} event thật (~{per_day:.1f}/ngày, tối đa {max_alerts_per_day:g})"))
    ref = Rule.from_dict({"id": "_ref", "title": "ref", "condition": {"field": "event.category", "op": "eq", "value": "web"}})
    _, t_ref = replay(ref, replay_events)
    slow = t > 5 * t_ref + 0.5
    checks.append(Check("hiệu năng", not slow, f"{t:.2f}s (tham chiếu {t_ref:.2f}s)"))

    covered_by = [r.id for r in existing if r.type == "match" and test and
                  sum(r.condition.match(d) for d in test) >= 0.8 * len(test)]
    checks.append(Check("trùng rule sẵn có", not covered_by, "không trùng" if not covered_by
                        else f"rule {covered_by} đã bắt phần lớn các mẫu này", blocking=False))

    passed = all(c.ok for c in checks if c.blocking)
    risk = "cao" if nh > 0 or per_day > max_alerts_per_day / 2 else "thấp"
    return Validation(passed, risk, checks, metrics)
