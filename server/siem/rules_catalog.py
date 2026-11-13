"""Danh mục rule cho tra cứu (index siem-rules, Grafana dashboard "Thư viện rule").

Mỗi bản ghi có cùng bộ trường (mã, tên, mức độ, MITRE, tag, trường log, điều kiện tóm tắt), nên rule Wazuh và đề xuất AI
lọc được chung. Các loại bản ghi (trường `origin`):

  wazuh_rule    mỗi rule trong Wazuh (rule gốc + rule dự án, kể cả rules-dynamic/), kèm số alert 24 giờ / 7 ngày / 90 ngày,
                số báo nhầm 30 ngày, chế độ (chính thức / chạy bóng / không tạo alert / đã tắt)
  detector      phát hiện có sẵn của nền tảng, không phải rule Wazuh: RBA-001 (soar/risk.py), HLT-* (soar/health.py)
  coverage      kỹ thuật ATT&CK ưu tiên (config/threat_profile.yml): có / chưa có rule Wazuh đang bật và ra alert (R49)
  ai_proposal   đề xuất của AI (ai-rule-proposals) mọi trạng thái, kèm số liệu kiểm định

Manager đồng bộ định kỳ (RULES_CATALOG_SECONDS) và ngay sau khi duyệt / từ chối / gỡ đề xuất. Danh mục chỉ để đọc;
nguồn sự thật là Wazuh API và index ai-rule-proposals.
"""
from __future__ import annotations

import hashlib
import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import yaml

from . import settings
from .detection.alerts import SEVERITY_SCORE

log = logging.getLogger("rules_catalog")

NONE_TACTIC, NONE_LIST = "(chưa gắn)", "(không có)"      # giá trị thay chỗ trống: bộ lọc "Tất cả" (*) vẫn khớp
OP_LABEL = {"eq": "=", "neq": "≠", "in": "thuộc", "contains": "chứa", "not_contains": "không chứa",
            "startswith": "bắt đầu bằng", "endswith": "kết thúc bằng", "regex": "khớp regex", "cidr": "thuộc dải",
            "exists": "có trường", "gt": ">", "gte": "≥", "lt": "<", "lte": "≤"}
STATUS_LABEL = {"pending": "chờ duyệt", "approved": "đã triển khai", "invalid": "không đạt kiểm định",
                "rejected": "đã từ chối", "rolled_back": "đã gỡ", "no_action": "không cần làm gì"}
KIND_LABEL = {"new_rule": "Rule mới", "exception": "Ngoại lệ"}


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


def _common(*, tactic: Any, techniques: Any, tags: Iterable[str], fields: Iterable[str]) -> dict[str, Any]:
    tech = [str(t) for t in (techniques if isinstance(techniques, list) else [techniques] if techniques else [])]
    return {"mitre": {"tactic": str(tactic) if tactic else NONE_TACTIC, "technique": tech or [NONE_LIST]},
            "tags": sorted({str(t) for t in tags}) or [NONE_LIST], "fields": sorted(set(fields)) or [NONE_LIST]}


# ------------------------------------------------------------------ dựng bản ghi
MODE_LABEL = {"active": "chính thức", "shadow": "chạy bóng", "nobridge": "không tạo alert", "off": "đã tắt"}


# Phát hiện có sẵn của nền tảng (không phải rule Wazuh): để Thư viện rule tra cứu được mã alert RBA / HLT
DETECTORS = [
    ("RBA-001", "Rủi ro tích lũy vượt ngưỡng trên máy / tài khoản", "high", "soar/risk.py",
     "Tổng risk_score các alert của cùng máy / tài khoản trong RBA_WINDOW_HOURS giờ >= RBA_THRESHOLD, từ >= RBA_MIN_RULES rule khác nhau"),
    ("TI-002", "IOC mới khớp log cũ (dò ngược)", "high", "soar/retrohunt.py",
     "IOC mới (config/intel, MISP) khớp event trong RETROHUNT_DAYS ngày qua mà lúc vào chưa được gắn IOC đó"),
    ("HLT-001", "Agent mất kết nối", "medium", "soar/health.py", "Wazuh báo disconnected, keepalive cuối quá AGENT_DOWN_MINUTES phút"),
    ("HLT-002", "Nguồn log im lặng", "medium", "soar/health.py",
     "Không event nào trong SOURCE_SILENT_MINUTES phút dù trung bình 7 ngày phải có >= SOURCE_MIN_EXPECTED event"),
    ("HLT-003", "Lưu lượng log lệch bất thường", "low", "soar/health.py",
     "Lưu lượng 1 giờ qua lệch quá VOLUME_DEVIATION so với trung bình 7 ngày"),
    ("HLT-004", "Mất đồng bộ trạng thái agent với Wazuh manager", "high", "soar/health.py", "SOAR không gọi được Wazuh API"),
    ("HLT-005", "Đường ống Kafka bị nghẽn", "high", "soar/health.py",
     "Consumer analyzer / SOAR tụt sau quá KAFKA_LAG_MAX_MESSAGES message liên tục KAFKA_LAG_MINUTES phút"),
    ("HLT-006", "Elasticsearch lỗi hoặc sắp đầy đĩa", "high", "soar/health.py", "Cluster RED, hoặc đĩa node >= ES_DISK_MAX_PCT%"),
    ("HLT-007", "Sao lưu Elasticsearch không chạy", "high", "soar/health.py",
     "Không có chính sách SLM daily-snapshots, lần chạy gần nhất lỗi, hoặc snapshot thành công cũ hơn SNAPSHOT_MAX_AGE_HOURS giờ"),
]


def detector_docs(alert_stats: dict[str, dict[str, Any]], now: str) -> list[dict[str, Any]]:
    out = []
    for rid, name, sev, src, cond in DETECTORS:
        st = alert_stats.get(rid, {})
        out.append({"_id": f"detector:{rid}", "origin": "detector", "origin_label": "Phát hiện nền tảng", "source": "builtin",
                    "updated_at": now, "rule": {"id": rid, "name": name}, "severity": sev,
                    "severity_score": SEVERITY_SCORE.get(sev, 0), "type": "rba" if rid.startswith("RBA") else "health",
                    **_common(tactic=None, techniques=None, tags=["platform"], fields=[]), "condition_text": cond,
                    "file": src, "mode": "active", "mode_label": MODE_LABEL["active"],
                    "alerts": {"h24": st.get("h24", 0), "d7": st.get("d7", 0), "d90": st.get("d90", 0), "last": st.get("last")}})
    return out


def load_profile(config_dir: Path | None) -> dict[str, Any]:
    """config/threat_profile.yml: kỹ thuật ATT&CK ưu tiên phát hiện; không có file thì rỗng."""
    path = config_dir / "threat_profile.yml" if config_dir else None
    if not path or not path.exists():
        return {}
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def attack_coverage(docs: list[dict[str, Any]], profile: dict[str, Any]) -> list[dict[str, Any]]:
    """Độ phủ kỹ thuật ưu tiên từ bản ghi thư viện (R49): kỹ thuật được phủ khi có ÍT NHẤT MỘT rule Wazuh thật sự bật (ra
    alert qua cầu nối, không chạy bóng, không tắt). Kỹ thuật con (T1110.001) tính cho kỹ thuật gốc (T1110). Danh sách mã
    rule cắt 10; `sources` = "wazuh" khi phủ, rỗng khi chưa."""
    out = []
    for t in profile.get("techniques") or []:
        tid = str(t["id"])
        on: list[str] = []
        shadow: list[str] = []
        for d in docs:
            techs = (d.get("mitre") or {}).get("technique") or []
            if d.get("origin") != "wazuh_rule" or not any(x == tid or x.startswith(tid + ".") for x in techs):
                continue
            rid, mode = d["rule"]["id"], d.get("mode")
            if d.get("bridged") is not True and mode != "off":
                continue                                    # bật nhưng không ra alert (cầu nối loại): không tính phủ
            if d.get("shadow") is True or mode == "shadow":
                shadow.append(rid)
            elif mode != "off" and str(d.get("status", "enabled")).lower() == "enabled":
                on.append(rid)
        out.append({"id": tid, "name": t.get("name", ""), "why": t.get("why", ""), "covered": bool(on), "rules": on[:10],
                    "rules_n": len(on), "shadow": shadow[:10], "sources": "wazuh" if on else ""})
    return out


def coverage_docs(coverage: list[dict[str, Any]], now: str) -> list[dict[str, Any]]:
    return [{"_id": f"coverage:{c['id']}", "origin": "coverage", "origin_label": "Độ phủ ATT&CK ưu tiên", "updated_at": now,
             "technique": c["id"], "name": c["name"], "why": c.get("why", ""), "covered": c["covered"],
             "covered_text": "có" if c["covered"] else "CHƯA CÓ",
             "rules_text": ", ".join(c["rules"]) + (f" (+{c['rules_n'] - len(c['rules'])})" if c["rules_n"] > len(c["rules"]) else "")
             or "—", "shadow_text": ", ".join(c["shadow"]) or "", "sources": c["sources"] or "none"} for c in coverage]


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
            cond = body.get("condition") or body.get("conditions")        # engine YAML cũ / ngoại lệ AI Wazuh (R73)
            text, fields = "bỏ qua khi " + summarize(cond), condition_fields(cond)
            common = _common(tactic=(target.get("mitre") or {}).get("tactic"), techniques=None, tags=[], fields=fields)
            sev, rtype = target.get("severity", "low"), "exception"
        else:
            text, fields = rule_text(body)
            mitre = body.get("mitre") or {}
            attack = str(p.get("target") or "").rsplit(":", 1)[-1]
            common = _common(tactic=mitre.get("tactic"), techniques=mitre.get("technique"),
                             tags=[*(body.get("tags") or []), *([attack] if attack else [])], fields=fields)
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
            "condition_text": text, "yaml": p.get("yaml") or "",
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


# ------------------------------------------------------------------ rule của Wazuh (GET /rules)
WAZUH_PAGE = 500


def wazuh_rule_docs(api, alert_stats: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Mỗi rule trong Wazuh (rule gốc ~4,5 nghìn + rule dự án, kể cả rules-dynamic/) thành một bản ghi của thư viện.
    `shadow` khớp đúng cách cầu nối cấp alert (detection/wazuh.py): nhóm `shadow` hoặc rule gốc is_shadow_stock, để thư viện
    không bao giờ ghi "chính thức" cho rule chỉ ra alert chạy bóng. Lỗi API thì raise (người gọi giữ danh mục cũ)."""
    from .detection.wazuh import _is_local, is_shadow_stock, severity_for, should_bridge
    docs, offset, seen = [], 0, {}
    while True:
        data = (api.rules(offset, WAZUH_PAGE) or {}).get("data") or {}
        items = data.get("affected_items") or []
        for r in items:
            level, groups = int(r.get("level") or 0), [str(g) for g in r.get("groups") or []]
            # Wazuh 4.14 trả `mitre` là list mã kỹ thuật (['T1110']), không có tactic; dạng dict {id, tactic} vẫn đọc được
            m = r.get("mitre") or []
            ids = [str(i) for i in ((m.get("id") or []) if isinstance(m, dict) else m)]
            tactic = (m.get("tactic") or [None])[0] if isinstance(m, dict) else None
            sev, rid = severity_for(level), f"WZH-{r['id']}"
            legacy = [g for g in groups if g.startswith("legacy_")]
            shadow = "shadow" in groups or is_shadow_stock({"id": r["id"], "level": level, "groups": groups})
            off = str(r.get("status", "enabled")).lower() != "enabled"
            # rule không qua cầu nối (stock level thấp, sca) hoặc rule dự án level < 3 (log_alert_level) không bao giờ ra alert
            rule = {"id": r["id"], "level": level, "groups": groups}
            bridged = should_bridge(rule) and (level >= 3 or not _is_local(rule))
            mode = "off" if off else "shadow" if shadow else "active" if bridged else "nobridge"
            st = alert_stats.get(rid, {})
            doc = {
                "_id": f"rule:{rid}", "origin": "wazuh_rule", "origin_label": "Rule Wazuh", "source": "wazuh",
                "rule": {"id": rid, "name": r.get("description", "")}, "description": r.get("description", ""),
                "severity": sev, "severity_score": SEVERITY_SCORE.get(sev, 0), "type": "wazuh", "level": level,
                **_common(tactic=tactic, techniques=ids, tags=["wazuh", *groups], fields=[]),
                "groups": groups, **({"legacy_id": legacy[0][7:]} if legacy else {}),     # như alert: không có thì bỏ khóa
                "condition_text": "", "yaml": "",
                "file": f"{r.get('relative_dirname', '')}/{r.get('filename', '')}".strip("/"),
                "status": r.get("status", "enabled"), "shadow": shadow, "bridged": bridged,
                "alerts": {"h24": st.get("h24", 0), "d7": st.get("d7", 0), "d90": st.get("d90", 0), "last": st.get("last"),
                           "closed30": st.get("closed30", 0), "fp30": st.get("fp30", 0), "fp_rate30": None},
                "mode": mode, "mode_label": "đã tắt" if off else MODE_LABEL[mode],
            }
            # rule gốc bị đè (overwrite trong etc/rules/0999-tuning.xml) có 2 bản trong API: giữ bản đè (bản đang chạy)
            if r["id"] in seen:
                if not str(r.get("relative_dirname", "")).startswith("ruleset"):
                    docs[seen[r["id"]]] = doc
                continue
            seen[r["id"]] = len(docs)
            docs.append(doc)
        offset += len(items)
        if not items or offset >= int(data.get("total_affected_items") or 0):
            return docs


# ------------------------------------------------------------------ đọc nguồn + ghi Elasticsearch
def alert_stats(es) -> dict[str, dict[str, Any]]:
    """Số alert 24 giờ / 7 ngày và lần gần nhất của từng rule (để biết rule nào hay kêu, rule nào im lặng)."""
    try:
        # 10 000: rule Wazuh (WZH-*) cũng kêu, 2000 làm rớt rule; vẫn dưới search.max_buckets (65 536)
        d30 = {"range": {"@timestamp": {"gte": "now-30d"}}}
        res = es.search(index=settings.IDX_ALERTS, size=0, aggs={"r": {"terms": {"field": "rule.id", "size": 10000}, "aggs": {
            "d90": {"filter": {"range": {"@timestamp": {"gte": "now-90d"}}}},
            "d7": {"filter": {"range": {"@timestamp": {"gte": "now-7d"}}}},
            "h24": {"filter": {"range": {"@timestamp": {"gte": "now-24h"}}}},
            # tỉ lệ báo nhầm theo rule: rà soát hằng quý, tiêu chí bật rule chạy bóng (SOC-OPERATIONS.md mục 4)
            "closed30": {"filter": {"bool": {"filter": [d30, {"terms": {"alert.status": ["closed", "false_positive"]}}]}}},
            "fp30": {"filter": {"bool": {"filter": [d30, {"term": {"alert.status": "false_positive"}}]}}},
            "last": {"max": {"field": "@timestamp"}}}}})
    except Exception as e:  # noqa: BLE001 - chưa có alert nào
        log.debug("không đếm được alert: %s", e)
        return {}
    return {b["key"]: {"d90": b["d90"]["doc_count"], "d7": b["d7"]["doc_count"], "h24": b["h24"]["doc_count"],
                       "closed30": b["closed30"]["doc_count"], "fp30": b["fp30"]["doc_count"],
                       "last": b["last"].get("value_as_string")}
            for b in res["aggregations"]["r"]["buckets"]}


def load_proposals(es) -> list[dict[str, Any]]:
    try:
        res = es.search(index=settings.IDX_AI_PROPOSALS, size=1000, query={"match_all": {}},
                        sort=[{"created_at": {"order": "desc", "unmapped_type": "date"}}])
    except Exception as e:  # noqa: BLE001 - AI chưa chạy lần nào
        log.debug("không đọc được đề xuất AI: %s", e)
        return []
    return [h["_source"] | {"id": h["_source"].get("id") or h["_id"]} for h in res["hits"]["hits"]]


def build(proposals: list[dict[str, Any]], stats: dict[str, dict[str, Any]], profile: dict[str, Any] | None = None,
          wazuh: list[dict[str, Any]] | None = None, today: str | None = None) -> list[dict[str, Any]]:
    wazuh = list(wazuh or [])
    props = proposal_docs(proposals, {w["rule"]["id"]: w for w in wazuh})     # ngoại lệ AI nhắm rule WZH-<id>
    # mốc ngày (UTC) thay cho mtime file YAML cũ: ổn định trong ngày để chữ ký không đổi mỗi chu kỳ, và nằm trong khung
    # 20 năm của dashboard (mốc 1970 thì bản ghi biến mất khỏi Grafana); mỗi ngày ghi lại toàn bộ danh mục một lần
    now = today or datetime.now(timezone.utc).strftime("%Y-%m-%dT00:00:00+00:00")
    cov = attack_coverage(wazuh, profile) if profile else []
    docs = props + detector_docs(stats, now) + coverage_docs(cov, now) + [{**w, "updated_at": now} for w in wazuh]
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
_doc_sigs: dict[str, str] = {}      # chữ ký từng bản ghi đã ghi: chỉ gửi bản ghi đổi (~4,5 nghìn rule Wazuh, mỗi chu kỳ ít đổi)


def sync(es, force: bool = False, api=None) -> int:
    """Ghi danh mục vào siem-rules, xóa bản ghi không còn (rule bị xóa / gỡ). Không đổi gì thì không ghi.
    Có `api` (Wazuh) thì thêm rule Wazuh; API lỗi thì ghi log và GIỮ bản ghi Wazuh cũ (không xóa nhầm cả chỉ mục).
    Trả về số bản ghi đã ghi (0 nếu bỏ qua)."""
    global _last_sig
    with _lock:
        stats, wazuh, keep_wazuh = alert_stats(es), None, True      # mặc định giữ rule Wazuh
        if api is not None:
            try:
                wazuh, keep_wazuh = wazuh_rule_docs(api, stats), False
            except Exception as e:  # noqa: BLE001
                log.warning("không đọc được rule từ Wazuh API, giữ danh mục Wazuh cũ: %s", e)
        docs = build(load_proposals(es), stats, load_profile(settings.CONFIG_DIR), wazuh)
        sig = hashlib.sha1(json.dumps(docs, sort_keys=True, default=str).encode()).hexdigest()
        if sig == _last_sig and not force:
            return 0
        ops: list[dict[str, Any]] = []
        sent: list[str] = []
        sigs = {d["_id"]: hashlib.sha1(json.dumps(d, sort_keys=True, default=str).encode()).hexdigest() for d in docs}
        for d in docs:
            if not force and _doc_sigs.get(d["_id"]) == sigs[d["_id"]]:
                continue
            sent.append(d["_id"])
            ops += [{"index": {"_index": settings.IDX_RULES, "_id": d["_id"]}}, {k: v for k, v in d.items() if k != "_id"}]
        if ops:
            res = es.bulk(operations=ops, refresh="wait_for")
            failed = {sent[n] for n, i in enumerate(res.get("items") or []) if i["index"].get("error")} if res.get("errors") else set()
            if failed:
                log.warning("danh mục rule: %d bản ghi lỗi, ví dụ %s", len(failed), sorted(failed)[:1])
            for k in failed:
                sigs.pop(k)          # bản ghi lỗi: không ghi chữ ký để chu kỳ sau gửi lại
        else:
            failed = set()
        # không refresh=True: cần quyền maintenance mà manager không có (lỗi 403 như SOAR đã gặp)
        for k in [k for k in _doc_sigs if k not in sigs and not (keep_wazuh and k.startswith("rule:WZH-"))] + list(failed):
            _doc_sigs.pop(k, None)      # bản ghi đã gỡ / ghi lỗi: lần sau gửi lại dù nội dung y hệt
        _doc_sigs.update(sigs)
        must_not = [{"ids": {"values": [d["_id"] for d in docs]}}]
        if keep_wazuh:      # chỉ xóa bản ghi Wazuh khi lần lấy Wazuh API trong chính lần này thành công
            must_not.append({"term": {"origin": "wazuh_rule"}})
        es.delete_by_query(index=settings.IDX_RULES, conflicts="proceed", query={"bool": {"must_not": must_not}})
        _last_sig = None if failed or (api is not None and keep_wazuh) else sig        # lần sau thử lại Wazuh
        log.info("đã đồng bộ danh mục rule: %d bản ghi", len(docs))
        return len(docs)
