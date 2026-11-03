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


def _doc(rid, tech, origin="rule", source="builtin", **kw):
    return {"origin": origin, "source": source, "rule": {"id": rid}, "mitre": {"technique": [tech]}, **kw}


def test_attack_coverage_from_library_docs():
    """R49: phủ khi có ít nhất một rule thật sự bật, từ YAML hoặc Wazuh; rule bóng / tắt không tính; nhãn nguồn đúng."""
    from siem.rules_catalog import attack_coverage
    prof = {"techniques": [{"id": t} for t in ("T1190", "T1486", "T1110", "T1059", "T1003", "T1078")]}
    docs = [
        _doc("WEB-001", "T1190", mode="active"),                                          # chỉ YAML
        _doc("WZH-100", "T1486", origin="wazuh_rule", source="wazuh", mode="shadow", shadow=True, bridged=True),   # bóng
        _doc("WZH-101", "T1110", origin="wazuh_rule", source="wazuh", mode="active", shadow=False, status="enabled", bridged=True),
        _doc("AUTH-001", "T1110.001", mode="active", tests={"tested": True}),            # kỹ thuật con tính cho gốc; cả hai nguồn
        _doc("WZH-102", "T1059", origin="wazuh_rule", source="wazuh", mode="off", status="disabled", bridged=True),   # tắt
        _doc("WZH-5712", "T1003", origin="wazuh_rule", source="wazuh", mode="shadow", shadow=True, bridged=True),     # rule gốc bóng
        _doc("X-001", "T1078", mode="active", tests={"tested": False}),                  # YAML chưa qua kiểm thử
    ]
    cov = {c["id"]: c for c in attack_coverage(docs, prof)}
    assert {t for t, c in cov.items() if c["covered"]} == {"T1190", "T1110"}
    assert cov["T1190"]["sources"] == "yaml" and cov["T1110"]["sources"] == "both"
    assert cov["T1486"]["sources"] == "" and cov["T1486"]["shadow"] == ["WZH-100"]
    only_wazuh = attack_coverage([docs[2]], prof)
    assert next(c for c in only_wazuh if c["id"] == "T1110")["sources"] == "wazuh"


def test_kpi_coverage_reads_rule_library(monkeypatch):
    es = KES()
    orig = es.search

    def search(index, **kw):
        if index == settings.IDX_RULES:
            return {"hits": {"total": {"value": 1}, "hits": [{"_source": _doc("WZH-101", "T1190", origin="wazuh_rule", source="wazuh", mode="active", bridged=True)}]}}
        return orig(index, **kw)
    es.search = search
    d = kpi.compute(es, ROOT / "rules", ROOT / "config", days=30, now=NOW)
    assert d["attack_coverage_source"] == "siem-rules" and d["attack_coverage_pct"] == 8.3 and [c["id"] for c in d["attack_coverage"] if c["covered"]] == ["T1190"]
    assert d["attack_coverage"][0]["sources"] == "wazuh"


def test_kpi_coverage_fallback_is_reported():
    """ES lỗi, hoặc siem-rules chưa có rule Wazuh nào: lùi về lint YAML và nói rõ trong bản ghi KPI."""
    for fake in (lambda: (_ for _ in ()).throw(ConnectionError("ES")), lambda: {"hits": {"total": {"value": 0}, "hits": []}}):
        es = KES()
        orig = es.search

        def search(index, _f=fake, _o=orig, **kw):
            return _f() if index == settings.IDX_RULES else _o(index, **kw)
        es.search = search
        d = kpi.compute(es, ROOT / "rules", ROOT / "config", days=30, now=NOW)
        assert d["attack_coverage_source"] == "lint-yaml" and d["attack_coverage_pct"] == 83.3


def test_attack_coverage_requires_bridged_for_wazuh():
    from siem.rules_catalog import attack_coverage
    w = _doc("WZH-1", "T1190", origin="wazuh_rule", source="wazuh", mode="active", shadow=False, status="enabled")
    assert not attack_coverage([w], {"techniques": [{"id": "T1190"}]})[0]["covered"]
    assert attack_coverage([{**w, "bridged": True}], {"techniques": [{"id": "T1190"}]})[0]["covered"]
