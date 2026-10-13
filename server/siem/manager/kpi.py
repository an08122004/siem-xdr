"""KPI của SOC (SOC-OPERATIONS.md mục 7), tính tự động từ dữ liệu, không nhập tay. Manager tính mỗi KPI_SECONDS giây
trên cửa sổ KPI_WINDOW_DAYS ngày và lưu một bản ghi vào index siem-kpi (chuỗi thời gian): dashboard Grafana "SOC KPI"
hiện giá trị mới nhất (tô màu theo đích) và xu hướng; console đọc qua GET /api/v1/kpi.

  MTTD       từ event đầu tiên của chuỗi tới lúc sinh alert (alert.metrics.ttd_seconds), alert critical
  MTTA       từ lúc mở case tới khi có người nhận (case.metrics.tta_seconds), theo mức ưu tiên
  MTTC       từ lúc mở case tới khi khoanh vùng xong (case.metrics.ttc_seconds), theo mức ưu tiên
  SLA        % case xác nhận / khoanh vùng trong hạn của mức ưu tiên (config/priority.yml)
  Báo nhầm   alert kết luận báo nhầm / alert đã đóng
  Tải        alert mỗi analyst mỗi ca (SOC_SHIFTS_PER_DAY ca / ngày, analyst = người đã xử lý alert / case trong kỳ)
  Làm giàu   % alert có ngữ cảnh tài sản (asset.*) từ danh mục tài sản
  ATT&CK     % kỹ thuật ưu tiên (config/threat_profile.yml) có rule chạy chính thức đã kiểm thử (detection/lint.py)
  Nguồn log  % nguồn đã onboard không im lặng (siem-sources, soar/health.py)
  Hunting    số cuộc hunt hoàn thành trong kỳ (siem-hunts)
Alert của rule chạy bóng không tính vào KPI."""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .. import settings, store

log = logging.getLogger("manager.kpi")

IDX_KPI = "siem-kpi"
IDX_SOURCES = "siem-sources"
IDX_HUNTS = "siem-hunts"
NOT_SHADOW = {"term": {"alert.shadow": True}}
# Đích theo kế hoạch SOC (bảng KPI): (cuối giai đoạn 2, cuối giai đoạn 4, hướng tốt: "low" = càng thấp càng tốt)
TARGETS: dict[str, tuple[float | None, float, str]] = {
    "mttd_critical_s": (30 * 60, 15 * 60, "low"),
    "mtta_p1_s": (30 * 60, 15 * 60, "low"),
    "mttc_p1_s": (4 * 3600, 3600, "low"),
    "sla_pct": (85, 95, "high"),
    "fp_rate_pct": (50, 30, "low"),
    "alerts_per_analyst_shift": (60, 40, "low"),
    "enrichment_pct": (50, 80, "high"),
    "attack_coverage_pct": (50, 70, "high"),
    "source_health_pct": (95, 98, "high"),
    "hunts_month": (None, 2, "high"),
}


def grade(key: str, value: float | None) -> str | None:
    """'gd4' đạt đích cuối giai đoạn 4, 'gd2' đạt đích giai đoạn 2, 'below' chưa đạt, None chưa đo được."""
    if value is None or key not in TARGETS:
        return None
    g2, g4, way = TARGETS[key]
    ok = (lambda t: value <= t) if way == "low" else (lambda t: value >= t)
    if ok(g4):
        return "gd4"
    return "gd2" if g2 is not None and ok(g2) else "below"


def _pct(a: float, b: float) -> float | None:
    return round(100.0 * a / b, 1) if b else None


def _avg(aggs: dict[str, Any], name: str) -> float | None:
    v = (aggs.get(name) or {}).get("value")
    return round(v, 1) if v is not None else None


def compute(es, rules_dir: Path | None = None, config_dir: Path | None = None, days: int | None = None,
            now: datetime | None = None) -> dict[str, Any]:
    days = days or settings.KPI_WINDOW_DAYS
    now = now or datetime.now(timezone.utc)
    since = (now - timedelta(days=days)).isoformat()
    doc: dict[str, Any] = {"@timestamp": now.isoformat(), "window_days": days}

    # ---------------------------------------------------------------- alert
    a = es.search(index=settings.IDX_ALERTS, size=0, query={"bool": {
        "filter": [{"range": {"@timestamp": {"gte": since}}}], "must_not": [NOT_SHADOW]}}, aggs={
        "ttd_crit": {"filter": {"term": {"severity": "critical"}}, "aggs": {"v": {"avg": {"field": "metrics.ttd_seconds"}}}},
        "ttd": {"avg": {"field": "metrics.ttd_seconds"}},
        "closed": {"filter": {"terms": {"alert.status": ["closed", "false_positive"]}}},
        "fp": {"filter": {"term": {"alert.status": "false_positive"}}},
        "verdicts": {"terms": {"field": "alert.verdict", "size": 10}},
        "enriched": {"filter": {"exists": {"field": "asset.id"}}},
        "handlers": {"cardinality": {"field": "alert.acknowledged_by"}},
        "days": {"date_histogram": {"field": "@timestamp", "calendar_interval": "day", "min_doc_count": 1}},
        "priority": {"terms": {"field": "priority", "size": 5}}})
    total = a["hits"]["total"]["value"]
    ag = a["aggregations"]
    closed, fp = ag["closed"]["doc_count"], ag["fp"]["doc_count"]
    doc["alerts"] = {"total": total, "closed": closed, "false_positive": fp,
                     "verdicts": {b["key"]: b["doc_count"] for b in ag["verdicts"]["buckets"]},
                     "by_priority": {b["key"]: b["doc_count"] for b in ag["priority"]["buckets"]}}
    doc["mttd_critical_s"] = _avg(ag["ttd_crit"], "v")
    doc["mttd_all_s"] = _avg(ag, "ttd")
    doc["fp_rate_pct"] = _pct(fp, closed)
    doc["enrichment_pct"] = _pct(ag["enriched"]["doc_count"], total)

    # ---------------------------------------------------------------- case
    c = es.search(index=settings.IDX_CASES, size=0, query={"range": {"created_at": {"gte": since}}}, aggs={
        "prio": {"terms": {"field": "priority", "size": 5}, "aggs": {
            "tta": {"avg": {"field": "metrics.tta_seconds"}}, "ttc": {"avg": {"field": "metrics.ttc_seconds"}}}},
        "tta": {"avg": {"field": "metrics.tta_seconds"}}, "ttc": {"avg": {"field": "metrics.ttc_seconds"}},
        "ack": {"terms": {"field": "sla.ack_met", "size": 2}}, "contain": {"terms": {"field": "sla.contain_met", "size": 2}},
        "handlers": {"cardinality": {"field": "acknowledged_by"}},
        "open": {"filter": {"terms": {"status": ["open", "in_progress", "contained"]}}},
        "overdue": {"filter": {"bool": {"filter": [{"terms": {"status": ["open", "in_progress", "contained"]}},
                                                   {"range": {"sla_due": {"lt": now.isoformat()}}}],
                                        "must_not": [{"exists": {"field": "acknowledged_at"}}]}}},
        "major": {"filter": {"exists": {"field": "incident.declared_at"}}}})
    cg = c["aggregations"]
    by_p = {b["key"]: b for b in cg["prio"]["buckets"]}
    doc["mtta"] = {p: _avg(by_p.get(p, {}), "tta") for p in ("P1", "P2", "P3", "P4")} | {"all": _avg(cg, "tta")}
    doc["mttc"] = {p: _avg(by_p.get(p, {}), "ttc") for p in ("P1", "P2", "P3", "P4")} | {"all": _avg(cg, "ttc")}
    doc["mtta_p1_s"], doc["mttc_p1_s"] = doc["mtta"]["P1"], doc["mttc"]["P1"]

    def met(name: str) -> tuple[int, int]:
        b = {str(x.get("key_as_string", x["key"])).lower(): x["doc_count"] for x in cg[name]["buckets"]}
        return b.get("true", 0) + b.get("1", 0), b.get("false", 0) + b.get("0", 0)
    (ack_ok, ack_bad), (con_ok, con_bad) = met("ack"), met("contain")
    breached_open = cg["overdue"]["doc_count"]                 # quá hạn mà chưa ai nhận: chưa ghi ack_met nhưng đã trễ
    doc["sla"] = {"ack_pct": _pct(ack_ok, ack_ok + ack_bad + breached_open), "contain_pct": _pct(con_ok, con_ok + con_bad),
                  "overdue_open": breached_open}
    doc["sla_pct"] = _pct(ack_ok + con_ok, ack_ok + ack_bad + breached_open + con_ok + con_bad)
    doc["cases"] = {"total": c["hits"]["total"]["value"], "open": cg["open"]["doc_count"],
                    "major_incidents": cg["major"]["doc_count"]}

    # ---------------------------------------------------------------- tải công việc
    handlers = max(ag["handlers"]["value"], cg["handlers"]["value"])
    active_days = len(ag["days"]["buckets"])
    shifts = active_days * settings.SOC_SHIFTS_PER_DAY
    doc["workload"] = {"handlers": handlers, "active_days": active_days, "shifts_per_day": settings.SOC_SHIFTS_PER_DAY}
    doc["alerts_per_analyst_shift"] = round(total / (handlers * shifts), 1) if handlers and shifts else None

    # ---------------------------------------------------------------- nguồn log, hunting
    try:
        s = es.search(index=IDX_SOURCES, size=0, query={"range": {"checked_at": {"gte": (now - timedelta(minutes=15)).isoformat()}}},
                      aggs={"st": {"terms": {"field": "status", "size": 5}}})
        st = {b["key"]: b["doc_count"] for b in s["aggregations"]["st"]["buckets"]}
        n = sum(st.values())
        doc["sources"] = {"total": n, "silent": st.get("silent", 0), "deviation": st.get("deviation", 0)}
        doc["source_health_pct"] = _pct(n - st.get("silent", 0), n)
    except Exception as e:  # noqa: BLE001 - SOAR chưa ghi siem-sources lần nào
        log.debug("chưa có siem-sources: %s", e)
        doc["sources"], doc["source_health_pct"] = {"total": 0}, None
    try:
        doc["hunts_month"] = es.count(index=IDX_HUNTS, query={"bool": {"filter": [
            {"term": {"status": "completed"}}, {"range": {"completed_at": {"gte": (now - timedelta(days=30)).isoformat()}}}]}})["count"]
    except Exception:  # noqa: BLE001 - chưa có cuộc hunt nào
        doc["hunts_month"] = 0

    # ---------------------------------------------------------------- độ phủ ATT&CK
    if rules_dir:
        from ..detection.lint import lint
        rep = lint(rules_dir, config_dir)
        doc["attack_coverage_pct"] = rep.coverage_pct()
        doc["attack_coverage"] = [{k: c[k] for k in ("id", "name", "covered", "rules")} for c in rep.coverage]
        doc["rules"] = {"total": len(rep.rules), "shadow": sum(r.mode == "shadow" for r in rep.rules.values()),
                        "tested": sum(r.tested for r in rep.rules.values()), "lint_errors": len(rep.errors)}
    doc["grade"] = {k: grade(k, doc.get(k)) for k in TARGETS}
    doc["targets"] = {k: {"gd2": g2, "gd4": g4, "better": way} for k, (g2, g4, way) in TARGETS.items()}
    return doc


def save(es, doc: dict[str, Any]) -> None:
    """Một bản ghi mỗi lần tính (id theo phút) -> Grafana vẽ xu hướng; bản mới nhất là trạng thái hiện tại."""
    ts = doc["@timestamp"][:16]
    es.index(index=IDX_KPI, id=f"kpi-{ts}", document=doc)


def latest(es) -> dict[str, Any] | None:
    rows = store.search(es, IDX_KPI, None, size=1, sort=[{"@timestamp": {"order": "desc", "unmapped_type": "date"}}])
    return rows[0] if rows else None
