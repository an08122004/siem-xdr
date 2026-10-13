"""KPI SOC (manager/kpi.py): tính đúng từ aggregation của Elasticsearch, xếp mức đạt theo đích GĐ2 / GĐ4 của kế hoạch."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from siem import settings
from siem.manager import kpi

ROOT = Path(__file__).resolve().parent.parent
NOW = datetime(2026, 10, 13, 12, 0, tzinfo=timezone.utc)


class KES:
    def __init__(self):
        self.queries, self.saved = {}, {}

    def search(self, index, size=0, query=None, aggs=None, **_):
        self.queries[index] = (query, aggs)
        if index == settings.IDX_ALERTS:
            return {"hits": {"total": {"value": 200}}, "aggregations": {
                "ttd_crit": {"doc_count": 10, "v": {"value": 600.0}}, "ttd": {"value": 120.0},
                "closed": {"doc_count": 100}, "fp": {"doc_count": 25},
                "verdicts": {"buckets": [{"key": "true_positive", "doc_count": 60}, {"key": "false_positive", "doc_count": 25}]},
                "enriched": {"doc_count": 170}, "handlers": {"value": 2},
                "days": {"buckets": [{"key": i, "doc_count": 20} for i in range(10)]},
                "priority": {"buckets": [{"key": "P1", "doc_count": 5}]}}}
        if index == settings.IDX_CASES:
            return {"hits": {"total": {"value": 40}}, "aggregations": {
                "prio": {"buckets": [{"key": "P1", "doc_count": 4, "tta": {"value": 700.0}, "ttc": {"value": 7200.0}},
                                     {"key": "P3", "doc_count": 30, "tta": {"value": 5000.0}, "ttc": {"value": None}}]},
                "tta": {"value": 4000.0}, "ttc": {"value": 3000.0},
                "ack": {"buckets": [{"key": 1, "key_as_string": "true", "doc_count": 30},
                                    {"key": 0, "key_as_string": "false", "doc_count": 6}]},
                "contain": {"buckets": [{"key": 1, "key_as_string": "true", "doc_count": 3}]},
                "handlers": {"value": 3}, "open": {"doc_count": 5}, "overdue": {"doc_count": 2},
                "major": {"doc_count": 1}}}
        if index == kpi.IDX_SOURCES:
            return {"aggregations": {"st": {"buckets": [{"key": "ok", "doc_count": 19}, {"key": "silent", "doc_count": 1}]}}}
        raise AssertionError(index)

    def count(self, index, query=None):
        return {"count": 1}

    def index(self, index, id, document, **_):
        self.saved[id] = document


def test_kpi_values_and_grades(monkeypatch):
    monkeypatch.setattr(settings, "SOC_SHIFTS_PER_DAY", 1)
    es = KES()
    d = kpi.compute(es, ROOT / "rules", ROOT / "config", days=30, now=NOW)
    assert d["mttd_critical_s"] == 600.0 and kpi.grade("mttd_critical_s", 600.0) == "gd4"       # <= 15 phút
    assert d["mtta_p1_s"] == 700.0 and d["mtta"]["P3"] == 5000.0 and d["mttc_p1_s"] == 7200.0
    assert d["grade"]["mttc_p1_s"] == "gd2"                                                    # <= 4 giờ, > 1 giờ
    assert d["fp_rate_pct"] == 25.0 and d["grade"]["fp_rate_pct"] == "gd4"
    assert d["enrichment_pct"] == 85.0
    assert d["sla"]["ack_pct"] == round(100 * 30 / 38, 1) and d["sla"]["contain_pct"] == 100.0  # quá hạn chưa nhận tính trễ
    assert d["sla_pct"] == round(100 * 33 / 41, 1) and d["grade"]["sla_pct"] == "below"
    assert d["alerts_per_analyst_shift"] == round(200 / (3 * 10), 1)                          # 3 người, 10 ngày, 1 ca
    assert d["source_health_pct"] == 95.0 and d["hunts_month"] == 1
    assert d["attack_coverage_pct"] == 83.3 and d["rules"]["lint_errors"] == 0
    assert d["grade"]["hunts_month"] == "below" and d["targets"]["hunts_month"]["gd4"] == 2
    q, _ = es.queries[settings.IDX_ALERTS]
    assert q["bool"]["must_not"] == [{"term": {"alert.shadow": True}}]                        # bỏ alert chạy bóng
    kpi.save(es, d)
    assert list(es.saved) == ["kpi-2026-10-13T12:00"]


def test_kpi_grade_directions():
    assert kpi.grade("sla_pct", 96) == "gd4" and kpi.grade("sla_pct", 90) == "gd2" and kpi.grade("sla_pct", 80) == "below"
    assert kpi.grade("mtta_p1_s", 20 * 60) == "gd2" and kpi.grade("mtta_p1_s", 40 * 60) == "below"
    assert kpi.grade("fp_rate_pct", None) is None and kpi.grade("không-có", 1) is None
