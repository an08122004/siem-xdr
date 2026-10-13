"""Danh mục rule cho tra cứu và so sánh (index siem-rules, Grafana dashboard "Thư viện rule").

Mỗi bản ghi có cùng bộ trường (mã, tên, mức độ, MITRE, tag, trường log dùng trong điều kiện, điều kiện tóm tắt, YAML), nên
rule đang chạy và đề xuất AI đặt cạnh nhau so sánh được trực tiếp. Bốn loại bản ghi (trường `origin`):

  rule          rule đang chạy (server/rules/**, kể cả rule AI đã duyệt trong rules/ai), kèm số alert 24 giờ / 7 ngày
  exception     ngoại lệ đang áp dụng (rules/exceptions)
  ai_proposal   đề xuất của AI (ai-rule-proposals) mọi trạng thái, kèm số liệu kiểm định
  comparison    cặp (đề xuất AI, rule hiện có liên quan) kèm lý do và điểm: cùng kỹ thuật MITRE, cùng tag tấn công, cùng
                trường log, cùng tactic, hoặc chính rule mà ngoại lệ nhắm tới — để người duyệt thấy đề xuất có trùng / bổ sung
                cho rule nào, đặt điều kiện hai bên cạnh nhau

Manager đồng bộ định kỳ (RULES_CATALOG_SECONDS) và ngay sau khi duyệt / từ chối / gỡ đề xuất. Danh mục chỉ để đọc;
nguồn sự thật vẫn là file YAML và index ai-rule-proposals.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import yaml

from . import settings
from .detection.rules import EXCEPTIONS_DIR, SEVERITY_SCORE, SKIP_DIRS

log = logging.getLogger("rules_catalog")

NONE_TACTIC, NONE_LIST = "(chưa gắn)", "(không có)"      # giá trị thay chỗ trống: bộ lọc "Tất cả" (*) vẫn khớp
OP_LABEL = {"eq": "=", "neq": "≠", "in": "thuộc", "contains": "chứa", "not_contains": "không chứa",
            "startswith": "bắt đầu bằng", "endswith": "kết thúc bằng", "regex": "khớp regex", "cidr": "thuộc dải",
            "exists": "có trường", "gt": ">", "gte": "≥", "lt": "<", "lte": "≤"}
STATUS_LABEL = {"pending": "chờ duyệt", "approved": "đã triển khai", "invalid": "không đạt kiểm định",
                "rejected": "đã từ chối", "rolled_back": "đã gỡ", "no_action": "không cần làm gì"}
KIND_LABEL = {"new_rule": "Rule mới", "exception": "Ngoại lệ"}
GENERIC_TAGS = {"ai-generated", "dataset-gap"}                       # không nói gì về loại tấn công
BROAD_TAGS = {"web", "linux", "windows", "network", "auth", "authentication", "wazuh"}
DOMAIN_TAGS = {"web", "linux", "windows", "network"}
MAX_RELATED = 8
# loại tấn công AI phân loại (ai/attack_types.py) -> tag tương ứng của rule viết tay (từ vựng hai bên khác nhau)
ATTACK_TAGS = {"sqli": {"sqli"}, "xss": {"xss"}, "path-traversal": {"lfi", "traversal"},
               "cmd-injection": {"rce", "cmdi"}, "sensitive-path": {"dirbusting", "scanner", "recon"},
               "backup-file": {"dirbusting", "scanner"}, "encoding-evasion": {"evasion"}, "crlf": {"crlf"},
               "ssi": {"ssi", "rce"}, "oversized": {"dos", "overflow"}}
# so khớp nội dung mẫu: bỏ trường mô tả loại event (giống nhau ở mọi rule cùng nhóm) và từ quá chung
GENERIC_FIELDS = {"event.category", "event.outcome", "event.action", "event.module", "event.type", "event.dataset"}
STOP_TOKENS = {"and", "or", "not", "the", "all", "http", "https", "www", "com", "html", "htm", "php", "asp", "aspx", "jsp",
               "index", "get", "post", "null", "true", "false", "select_"}


# ------------------------------------------------------------------ tóm tắt điều kiện
def _short(v: Any, n: int = 40) -> str:
    s = str(v)
    return s if len(s) <= n else s[:n - 1] + "…"


def _values(v: Any) -> str:
    vals = v if isinstance(v, list) else [v]
    shown = ", ".join(_short(x) for x in vals[:4])
    return f"[{shown}{f', +{len(vals) - 4}' if len(vals) > 4 else ''}]" if len(vals) > 1 else shown


def summarize(spec: Any) -> str:
    """Điều kiện YAML -> 1 dòng dễ đọc, vd: url.decoded chứa [union select, ' or 1=1] VÀ http.response.status_code < 500"""
    if isinstance(spec, list):
        spec = {"all": spec}
    if not isinstance(spec, dict):
        return _short(spec)
    for key, joiner in (("all", " VÀ "), ("any", " HOẶC ")):
        if key in spec:
            parts = [summarize(s) for s in spec[key]]
            inner = joiner.join(f"({p})" if (" VÀ " in p or " HOẶC " in p) else p for p in parts)
            return inner
    if "not" in spec:
        return f"KHÔNG ({summarize(spec['not'])})"
    if "field" in spec:
        op = spec.get("op", "eq")
        if op == "exists":
            return f"có trường {spec['field']}"
        return f"{spec['field']} {OP_LABEL.get(op, op)} {_values(spec.get('value'))}"
    return _short(spec)


def condition_fields(spec: Any, out: set[str] | None = None) -> set[str]:
    out = set() if out is None else out
    if isinstance(spec, list):
        for s in spec:
            condition_fields(s, out)
    elif isinstance(spec, dict):
        if "field" in spec:
            out.add(str(spec["field"]))
        for key in ("all", "any"):
            if key in spec:
                condition_fields(spec[key], out)
        if "not" in spec:
            condition_fields(spec["not"], out)
    return out


def pattern_tokens(spec: Any, out: set[str] | None = None) -> set[str]:
    """Từ khóa trong giá trị điều kiện (vd union, select, _vti_bin): hai rule cùng bắt các chuỗi này là dấu hiệu trùng."""
    out = set() if out is None else out
    if isinstance(spec, list):
        for s in spec:
            pattern_tokens(s, out)
    elif isinstance(spec, dict):
        for key in ("all", "any"):
            if key in spec:
                pattern_tokens(spec[key], out)
        if "not" in spec:
            pattern_tokens(spec["not"], out)
        if "field" in spec and spec["field"] not in GENERIC_FIELDS:
            for v in spec.get("value") if isinstance(spec.get("value"), list) else [spec.get("value")]:
                for tok in re.split(r"[^a-z0-9_]+", str(v).lower()):
                    if len(tok) >= 3 and not tok.isdigit() and tok not in STOP_TOKENS:
                        out.add(tok)
    return out


def rule_text(d: dict[str, Any]) -> tuple[str, set[str]]:
    """Điều kiện tóm tắt + mọi trường log rule dùng (cả group_by / distinct / các bước sequence)."""
    rtype = d.get("type", "match")
    fields = condition_fields(d.get("condition"))
    if rtype == "sequence":
        seq = d.get("sequence") or {}
        steps = seq.get("steps") or []
        for st in steps:
            condition_fields(st.get("condition"), fields)
        text = "; ".join(f"bước {i + 1}: {summarize(st.get('condition'))}" + (f" (≥{st['count']} lần)" if st.get("count", 1) > 1 else "")
                         for i, st in enumerate(steps)) + f" — trong {seq.get('within', 300)} giây"
        group = seq.get("group_by") or d.get("group_by") or []
    else:
        text = summarize(d.get("condition"))
        thr = d.get("threshold") or {}
        group = thr.get("group_by") or d.get("group_by") or []
        if rtype == "threshold":
            text += f" — đếm ≥{thr.get('count', 1)} trong {thr.get('window', 60)} giây"
            if thr.get("distinct"):
                text += f", {thr['distinct']} khác nhau"
                fields.add(str(thr["distinct"]))
    if group:
        text += f", theo {', '.join(group)}"
        fields.update(str(g) for g in group)
    return text, fields


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat()


def _yaml_docs(path: Path) -> list[dict[str, Any]]:
    docs = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    return [d for d in (docs if isinstance(docs, list) else [docs]) if isinstance(d, dict)]


def _dump(d: dict[str, Any]) -> str:
    if d.get("sigma"):                     # rule AI: rule Sigma nhiều dòng hiển thị dạng khối, không phải chuỗi thoát \n
        from .ai.sigma import dump
        return dump([d])
    return yaml.safe_dump([d], allow_unicode=True, sort_keys=False, width=110)


def _common(*, tactic: Any, techniques: Any, tags: Iterable[str], fields: Iterable[str]) -> dict[str, Any]:
    tech = [str(t) for t in (techniques if isinstance(techniques, list) else [techniques] if techniques else [])]
    return {"mitre": {"tactic": str(tactic) if tactic else NONE_TACTIC, "technique": tech or [NONE_LIST]},
            "tags": sorted({str(t) for t in tags}) or [NONE_LIST], "fields": sorted(set(fields)) or [NONE_LIST]}


# ------------------------------------------------------------------ dựng bản ghi
def rule_docs(rules_dir: Path, alert_stats: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    docs = []
    for path in sorted(rules_dir.glob("**/*.y*ml")):
        rel = path.relative_to(rules_dir)
        if set(SKIP_DIRS) & set(rel.parts):
            continue
        try:
            items = _yaml_docs(path)
        except Exception as e:  # noqa: BLE001 - file lỗi: analyzer cũng bỏ qua, danh mục ghi rõ
            log.warning("không đọc được %s: %s", path, e)
            continue
        ai = rel.parts[0] == "ai"
        for d in items:
            if d.get("enabled", True) is False or "id" not in d:
                continue
            text, fields = rule_text(d)
            mitre = d.get("mitre") or {}
            st = alert_stats.get(str(d["id"]), {})
            sev = str(d.get("severity", "medium")).lower()
            docs.append({
                "_id": f"rule:{d['id']}", "origin": "rule", "origin_label": "Rule AI (đã duyệt)" if ai else "Rule sẵn có",
                "source": "ai" if ai else "builtin", "updated_at": _iso(path.stat().st_mtime),
                "rule": {"id": str(d["id"]), "name": d.get("title", "")}, "description": d.get("description", ""),
                "severity": sev, "severity_score": SEVERITY_SCORE.get(sev, 0), "type": d.get("type", "match"),
                **_common(tactic=mitre.get("tactic"), techniques=mitre.get("technique"), tags=d.get("tags") or [], fields=fields),
                "condition_text": text, "patterns": sorted(_rule_tokens(d)), "yaml": _dump(d),
                "file": str(rel).replace("\\", "/"),
                "ai_proposal_id": d.get("ai_proposal_id"),
                "alerts": {"h24": st.get("h24", 0), "d7": st.get("d7", 0), "last": st.get("last")},
            })
    return docs


def exception_docs(rules_dir: Path, rules: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    docs = []
    for path in sorted((rules_dir / EXCEPTIONS_DIR).glob("*.y*ml")):
        try:
            items = _yaml_docs(path)
        except Exception as e:  # noqa: BLE001
            log.warning("không đọc được %s: %s", path, e)
            continue
        for d in items:
            if d.get("enabled", True) is False or not d.get("rule_id"):
                continue
            target = rules.get(str(d["rule_id"]), {})
            docs.append({
                "_id": f"exception:{d.get('id') or path.stem}", "origin": "exception", "origin_label": "Ngoại lệ",
                "source": d.get("source", "manual"), "updated_at": _iso(path.stat().st_mtime),
                "rule": {"id": str(d["rule_id"]), "name": (target.get("rule") or {}).get("name", "")},
                "description": d.get("description", ""), "severity": target.get("severity", "low"),
                "severity_score": target.get("severity_score", 0), "type": "exception",
                **_common(tactic=(target.get("mitre") or {}).get("tactic"), techniques=None, tags=[],
                          fields=condition_fields(d.get("condition"))),
                "condition_text": "bỏ qua khi " + summarize(d.get("condition")), "yaml": _dump(d),
                "file": f"{EXCEPTIONS_DIR}/{path.name}", "ai_proposal_id": d.get("proposal_id"),
            })
    return docs


def pick(p: dict[str, Any]) -> str:
    """Nhãn chọn đề xuất trong ô "Đề xuất cần so sánh" của Grafana (console dùng để mở thẳng phần so sánh)."""
    status = p.get("status")
    return f"{p.get('title') or p.get('id')} ({STATUS_LABEL.get(status, status)}, {p.get('id')})"


def proposal_docs(proposals: list[dict[str, Any]], rules: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    docs = []
    for p in proposals:
        body = p.get("proposal") or {}
        kind, status = p.get("kind"), p.get("status")
        v = p.get("validation") or {}
        m = v.get("metrics") or {}
        target = rules.get(str(p.get("target_rule_id")), {})
        if kind == "exception":
            text, fields = "bỏ qua khi " + summarize(body.get("condition")), condition_fields(body.get("condition"))
            common = _common(tactic=(target.get("mitre") or {}).get("tactic"), techniques=None, tags=[], fields=fields)
            sev, rtype = target.get("severity", "low"), "exception"
        else:
            text, fields = rule_text(body)
            mitre = body.get("mitre") or {}
            attack = str(p.get("target") or "").rsplit(":", 1)[-1]
            common = _common(tactic=mitre.get("tactic"), techniques=mitre.get("technique"),
                             tags=[*(body.get("tags") or []), *([attack] if attack else [])], fields=fields)
            common["attack"] = {"key": attack, "tags": sorted(ATTACK_TAGS.get(attack, {attack} if attack else set()))}
            sev, rtype = str(body.get("severity", "medium")).lower(), body.get("type", "match")
        test = f"{m['test_detected']}/{m['test_total']}" if "test_total" in m else None
        fp = f"{m['normal_hits']}/{m['normal_total']}" if "normal_total" in m else \
            (f"{m['fp_matched']}/{m['fp_total']} báo nhầm khớp" if "fp_total" in m else None)
        title = p.get("title") or body.get("title") or p.get("id")
        docs.append({
            "_id": f"proposal:{p['id']}", "origin": "ai_proposal", "origin_label": "Đề xuất AI", "source": "ai",
            "updated_at": p.get("updated_at") or p.get("created_at"),
            "rule": {"id": str(p.get("target_rule_id") or ""), "name": title}, "description": body.get("description", ""),
            "severity": sev, "severity_score": SEVERITY_SCORE.get(sev, 0), "type": rtype, **common,
            "condition_text": text, "patterns": sorted(_rule_tokens(body)), "yaml": p.get("yaml") or "",
            "proposal": {
                "id": p["id"], "kind": kind, "kind_label": KIND_LABEL.get(kind, kind), "status": status,
                "status_label": STATUS_LABEL.get(status, status), "pick": pick(p | {"title": title}),
                "target": p.get("target"), "passed": v.get("passed"), "risk": v.get("risk") or p.get("risk"),
                "test": test, "recall": m.get("test_recall"), "fp": fp, "alerts_per_day": m.get("alerts_per_day"),
                "approvals": f"{len(p.get('approvals') or [])}/{p.get('required_approvals') or 1}",
                "created_at": p.get("created_at"),
            },
        })
    return docs


def _rule_tokens(d: dict[str, Any]) -> set[str]:
    out = pattern_tokens(d.get("condition"))
    for st in (d.get("sequence") or {}).get("steps") or []:
        pattern_tokens(st.get("condition"), out)
    return out


def _domains(doc: dict[str, Any]) -> set[str]:
    """Lĩnh vực của rule: theo tag, hoặc suy ra từ trường log (đề xuất AI thường không gắn tag web dù xét URL)."""
    out = set(doc["tags"]) & DOMAIN_TAGS
    for f in doc["fields"]:
        if f.startswith(("url.", "http.")):
            out.add("web")
        elif f.startswith(("winlog.", "registry.")):
            out.add("windows")
    return out


def _weight(df: int, rare: float, common: float, limit: int = 2) -> float:
    """Đặc điểm càng ít rule có thì càng nói lên sự liên quan (T1190 có ở gần hết rule web -> gần như không tính)."""
    return rare if df <= limit else common


def related(proposal: dict[str, Any], rule: dict[str, Any], df: dict[tuple[str, str], int]) -> tuple[float, list[str]]:
    """Mức liên quan giữa 1 đề xuất và 1 rule đang chạy, kèm lý do (để người duyệt biết vì sao đặt cạnh nhau).
    df: số rule đang chạy có từng đặc điểm (kỹ thuật, tag, trường, tactic, từ khóa mẫu)."""
    why: list[tuple[float, str]] = []       # (điểm, lý do)

    def add(points: float, reason: str, kind: str = "", value: str = "") -> None:
        why.append((points, reason + (" (nhiều rule cùng có)" if df.get((kind, value), 0) > 2 and points < 1 else "")))
    if proposal["rule"]["id"] and proposal["rule"]["id"] == rule["rule"]["id"]:
        add(10, "ngoại lệ áp dụng cho chính rule này" if proposal["type"] == "exception" else "trùng mã rule")
    attack = set((proposal.get("attack") or {}).get("tags") or []) & set(rule["tags"])
    pd, rd = _domains(proposal), _domains(rule)
    if pd and rd and not pd & rd:
        attack = set()             # "recon" của rule Linux không phải dò quét web: khác lĩnh vực thì không tính loại tấn công
    for t in sorted(attack):
        add(4, f"cùng loại tấn công {t}", "tag", t)
    tokens = sorted(set(proposal.get("patterns") or []) & set(rule.get("patterns") or []),
                    key=lambda t: df.get(("pattern", t), 0))
    if tokens:
        add(sum(_weight(df.get(("pattern", t), 0), 1.5, 0.3) for t in tokens[:6]),
            "cùng bắt chuỗi " + ", ".join(tokens[:6]) + (f" (+{len(tokens) - 6})" if len(tokens) > 6 else ""))
    for t in sorted((set(proposal["mitre"]["technique"]) & set(rule["mitre"]["technique"])) - {NONE_LIST}):
        add(_weight(df.get(("technique", t), 0), 3, 0.5), f"cùng kỹ thuật MITRE {t}", "technique", t)
    for t in sorted((set(proposal["tags"]) & set(rule["tags"])) - {NONE_LIST} - GENERIC_TAGS - attack):
        add(0.25 if t in BROAD_TAGS else _weight(df.get(("tag", t), 0), 2, 0.5), f"cùng tag {t}", "tag", t)
    tactic = rule["mitre"]["tactic"]
    if tactic != NONE_TACTIC and proposal["mitre"]["tactic"] == tactic:
        add(_weight(df.get(("tactic", tactic), 0), 1, 0.3), f"cùng tactic {tactic}", "tactic", tactic)
    for f in sorted((set(proposal["fields"]) & set(rule["fields"])) - {NONE_LIST}):
        add(_weight(df.get(("field", f), 0), 1, 0.3, limit=3), f"cùng xét trường {f}", "field", f)
    why.sort(key=lambda x: -x[0])                # lý do mạnh nhất đứng đầu
    return round(sum(pt for pt, _ in why), 2), why


def reasons_text(why: list[tuple[float, str]]) -> str:
    """Ô "Vì sao liên quan" của Grafana chỉ hiện ~2 dòng: ghi lý do mạnh, gộp lý do yếu (đủ danh sách ở trường reasons)."""
    strong = [t for pt, t in why if pt >= 1] or [t for _, t in why[:1]]
    weak = len(why) - len(strong)
    return "; ".join(strong) + (f"; +{weak} điểm chung yếu" if weak else "")


def comparison_docs(proposals: list[dict[str, Any]], rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    df: dict[tuple[str, str], int] = {}
    for r in rules:
        feats = {("technique", t) for t in r["mitre"]["technique"]} | {("tag", t) for t in r["tags"]} |                 {("field", f) for f in r["fields"]} | {("tactic", r["mitre"]["tactic"])} | {("pattern", t) for t in r.get("patterns") or []}
        for k in feats:
            df[k] = df.get(k, 0) + 1
    docs = []
    for p in proposals:
        scored = sorted(((related(p, r, df), r) for r in rules), key=lambda x: -x[0][0])
        for (score, why), r in [x for x in scored if x[0][0] >= 2][:MAX_RELATED]:
            docs.append({
                "_id": f"cmp:{p['proposal']['id']}:{r['rule']['id']}", "origin": "comparison", "origin_label": "So sánh",
                "updated_at": p["updated_at"], "score": score, "reasons": [t for _, t in why],
                "reasons_text": reasons_text(why),
                "proposal": {k: p["proposal"][k] for k in ("id", "pick", "kind_label", "status_label")}
                | {"name": p["rule"]["name"], "condition_text": p["condition_text"], "severity": p["severity"]},
                "rule": r["rule"], "severity": r["severity"], "source": r["source"], "file": r["file"],
                "condition_text": r["condition_text"], "alerts": r["alerts"],
            })
    return docs


# ------------------------------------------------------------------ đọc nguồn + ghi Elasticsearch
def alert_stats(es) -> dict[str, dict[str, Any]]:
    """Số alert 24 giờ / 7 ngày và lần gần nhất của từng rule (để biết rule nào hay kêu, rule nào im lặng)."""
    try:
        res = es.search(index=settings.IDX_ALERTS, size=0, aggs={"r": {"terms": {"field": "rule.id", "size": 2000}, "aggs": {
            "d7": {"filter": {"range": {"@timestamp": {"gte": "now-7d"}}}},
            "h24": {"filter": {"range": {"@timestamp": {"gte": "now-24h"}}}},
            "last": {"max": {"field": "@timestamp"}}}}})
    except Exception as e:  # noqa: BLE001 - chưa có alert nào
        log.debug("không đếm được alert: %s", e)
        return {}
    return {b["key"]: {"d7": b["d7"]["doc_count"], "h24": b["h24"]["doc_count"], "last": b["last"].get("value_as_string")}
            for b in res["aggregations"]["r"]["buckets"]}


def load_proposals(es) -> list[dict[str, Any]]:
    try:
        res = es.search(index=settings.IDX_AI_PROPOSALS, size=1000, query={"match_all": {}},
                        sort=[{"created_at": {"order": "desc", "unmapped_type": "date"}}])
    except Exception as e:  # noqa: BLE001 - AI chưa chạy lần nào
        log.debug("không đọc được đề xuất AI: %s", e)
        return []
    return [h["_source"] | {"id": h["_source"].get("id") or h["_id"]} for h in res["hits"]["hits"]]


def build(rules_dir: Path, proposals: list[dict[str, Any]], stats: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    rules = rule_docs(rules_dir, stats)
    by_id = {r["rule"]["id"]: r for r in rules}
    props = proposal_docs(proposals, by_id)
    docs = rules + exception_docs(rules_dir, by_id) + props + comparison_docs(props, rules)
    for d in docs:
        d["@timestamp"] = d["updated_at"]
        # bản chuỗi của các trường danh sách để bảng Grafana hiển thị gọn (danh sách vẫn giữ để lọc)
        for key, val in (("technique_text", (d.get("mitre") or {}).get("technique")), ("tags_text", d.get("tags")),
                         ("fields_text", d.get("fields"))):
            if val is not None:
                d[key] = ", ".join(v for v in val if v != NONE_LIST) or "—"
    return docs


_lock = threading.Lock()
_last_sig: str | None = None


def sync(es, rules_dir: Path = settings.RULES_DIR, force: bool = False) -> int:
    """Ghi danh mục vào siem-rules, xóa bản ghi không còn (rule bị xóa / gỡ). Không đổi gì thì không ghi.
    Trả về số bản ghi đã ghi (0 nếu bỏ qua)."""
    global _last_sig
    with _lock:
        docs = build(rules_dir, load_proposals(es), alert_stats(es))
        sig = hashlib.sha1(json.dumps(docs, sort_keys=True, default=str).encode()).hexdigest()
        if sig == _last_sig and not force:
            return 0
        ops: list[dict[str, Any]] = []
        for d in docs:
            ops += [{"index": {"_index": settings.IDX_RULES, "_id": d["_id"]}}, {k: v for k, v in d.items() if k != "_id"}]
        if ops:
            res = es.bulk(operations=ops, refresh="wait_for")
            if res.get("errors"):
                bad = [i for i in res["items"] if i["index"].get("error")]
                log.warning("danh mục rule: %d bản ghi lỗi, ví dụ %s", len(bad), bad[:1])
        # không refresh=True: cần quyền maintenance mà manager không có (lỗi 403 như SOAR đã gặp)
        es.delete_by_query(index=settings.IDX_RULES, conflicts="proceed",
                           query={"bool": {"must_not": [{"ids": {"values": [d["_id"] for d in docs]}}]}})
        _last_sig = sig
        log.info("đã đồng bộ danh mục rule: %d bản ghi", len(docs))
        return len(docs)
