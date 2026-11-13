"""KPI SOC (manager/kpi.py): tính đúng từ aggregation của Elasticsearch, xếp mức đạt theo đích GĐ2 / GĐ4 của kế hoạch."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from siem import settings
from siem.manager import kpi

ROOT = Path(__file__).resolve().parent.parent
NOW = datetime(2026, 10, 13, 12, 0, tzinfo=timezone.utc)


def _doc(rid, tech, origin="wazuh_rule", source="wazuh", **kw):
    return {"origin": origin, "source": source, "rule": {"id": rid}, "mitre": {"technique": [tech]}, **kw}


class KES:
    RULES = [_doc(f"WZH-{i}", t, mode="active", bridged=True) for i, t in enumerate(
        ["T1190", "T1078", "T1110", "T1059", "T1003", "T1021", "T1053", "T1547", "T1105", "T1071"])]

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
        if index == settings.IDX_RULES:     # thư viện rule: 10/12 kỹ thuật ưu tiên có rule Wazuh đang bật
            return {"hits": {"total": {"value": len(self.RULES)}, "hits": [{"_source": d} for d in self.RULES]}}
        raise AssertionError(index)

    def count(self, index, query=None):
        return {"count": 1}

    def index(self, index, id, document, **_):
        self.saved[id] = document


def test_kpi_values_and_grades(monkeypatch):
    monkeypatch.setattr(settings, "SOC_SHIFTS_PER_DAY", 1)
    es = KES()
    d = kpi.compute(es, ROOT / "config", days=30, now=NOW)
    assert d["mttd_critical_s"] == 600.0 and kpi.grade("mttd_critical_s", 600.0) == "gd4"       # <= 15 phút
    assert d["mtta_p1_s"] == 700.0 and d["mtta"]["P3"] == 5000.0 and d["mttc_p1_s"] == 7200.0
    assert d["grade"]["mttc_p1_s"] == "gd2"                                                    # <= 4 giờ, > 1 giờ
    assert d["fp_rate_pct"] == 25.0 and d["grade"]["fp_rate_pct"] == "gd4"
    assert d["enrichment_pct"] == 85.0
    assert d["sla"]["ack_pct"] == round(100 * 30 / 38, 1) and d["sla"]["contain_pct"] == 100.0  # quá hạn chưa nhận tính trễ
    assert d["sla_pct"] == round(100 * 33 / 41, 1) and d["grade"]["sla_pct"] == "below"
    assert d["alerts_per_analyst_shift"] == round(200 / (3 * 10), 1)                          # 3 người, 10 ngày, 1 ca
    assert d["source_health_pct"] == 95.0 and d["hunts_month"] == 1
    assert d["attack_coverage_pct"] == 83.3 and "rules" not in d
    assert d["grade"]["hunts_month"] == "below" and d["targets"]["hunts_month"]["gd4"] == 2
    q, _ = es.queries[settings.IDX_ALERTS]
    assert q["bool"]["must_not"] == [{"term": {"alert.shadow": True}}]                        # bỏ alert chạy bóng
    kpi.save(es, d)
    assert list(es.saved) == ["kpi-2026-10-13T12:00"]


def test_kpi_grade_directions():
    assert kpi.grade("sla_pct", 96) == "gd4" and kpi.grade("sla_pct", 90) == "gd2" and kpi.grade("sla_pct", 80) == "below"
    assert kpi.grade("mtta_p1_s", 20 * 60) == "gd2" and kpi.grade("mtta_p1_s", 40 * 60) == "below"
    assert kpi.grade("fp_rate_pct", None) is None and kpi.grade("không-có", 1) is None


def test_attack_coverage_from_library_docs():
    """R49: phủ khi có ít nhất một rule Wazuh thật sự bật; rule bóng / tắt / không cầu nối không tính; kỹ thuật con tính cho gốc."""
    from siem.rules_catalog import attack_coverage
    prof = {"techniques": [{"id": t} for t in ("T1190", "T1486", "T1110", "T1059", "T1003")]}
    docs = [
        _doc("WZH-100", "T1486", mode="shadow", shadow=True, bridged=True),                       # bóng
        _doc("WZH-101", "T1110.001", mode="active", shadow=False, status="enabled", bridged=True),  # kỹ thuật con
        _doc("WZH-102", "T1059", mode="off", status="disabled", bridged=True),                    # tắt
        _doc("WZH-103", "T1003", mode="nobridge", bridged=False),                                 # không ra alert
        _doc("WEB-001", "T1190", origin="rule", source="builtin", mode="active"),                 # bản ghi YAML cũ: bỏ qua
    ]
    cov = {c["id"]: c for c in attack_coverage(docs, prof)}
    assert {t for t, c in cov.items() if c["covered"]} == {"T1110"}
    assert cov["T1110"]["sources"] == "wazuh" and cov["T1110"]["rules"] == ["WZH-101"]
    assert cov["T1486"]["sources"] == "" and cov["T1486"]["shadow"] == ["WZH-100"]


def test_kpi_coverage_reads_rule_library(monkeypatch):
    es = KES()
    orig = es.search

    def search(index, **kw):
        if index == settings.IDX_RULES:
            assert kw["query"] == {"term": {"origin": "wazuh_rule"}}
            return {"hits": {"total": {"value": 1}, "hits": [{"_source": _doc("WZH-101", "T1190", mode="active", bridged=True)}]}}
        return orig(index, **kw)
    es.search = search
    d = kpi.compute(es, ROOT / "config", days=30, now=NOW)
    assert d["attack_coverage_pct"] == 8.3 and [c["id"] for c in d["attack_coverage"] if c["covered"]] == ["T1190"]
    assert d["attack_coverage"][0]["sources"] == "wazuh"


def test_kpi_coverage_left_empty_when_library_unreadable():
    """ES lỗi: không đoán độ phủ (không còn lint YAML để lùi về), các KPI khác vẫn tính."""
    es = KES()
    orig = es.search
    es.search = lambda index, **kw: (_ for _ in ()).throw(ConnectionError("ES")) if index == settings.IDX_RULES else orig(index, **kw)
    d = kpi.compute(es, ROOT / "config", days=30, now=NOW)
    assert "attack_coverage_pct" not in d and d["grade"]["attack_coverage_pct"] is None and d["fp_rate_pct"] == 25.0
    es = KES()
    es.search = lambda index, **kw: {"hits": {"total": {"value": 0}, "hits": []}} if index == settings.IDX_RULES else orig(index, **kw)
    assert kpi.compute(es, ROOT / "config", days=30, now=NOW)["attack_coverage_pct"] == 0.0     # chưa có rule Wazuh nào


def test_attack_coverage_requires_bridged_for_wazuh():
    from siem.rules_catalog import attack_coverage
    w = _doc("WZH-1", "T1190", mode="active", shadow=False, status="enabled")
    assert not attack_coverage([w], {"techniques": [{"id": "T1190"}]})[0]["covered"]
    assert attack_coverage([{**w, "bridged": True}], {"techniques": [{"id": "T1190"}]})[0]["covered"]


class DetectionKES(KES):
    """ES giả giữ alert thật của audit 05/11: 23 critical rule (~3,6 s), 12 critical rba (~14 751 s), 1 health, 1 retrohunt."""
    DOCS = ([{"source": "rule", "ttd": 3.6, "sev": "critical"}] * 23 + [{"source": "rba", "ttd": 14751.0, "sev": "critical"}] * 12
            + [{"source": "health", "ttd": 0.0, "sev": "critical"}, {"source": "retrohunt", "ttd": 9e6, "sev": "high"},
               {"source": "wazuh", "ttd": 4.0, "sev": "high"}])

    def search(self, index, size=0, query=None, aggs=None, **kw):
        if index != settings.IDX_ALERTS:
            return super().search(index, size, query, aggs, **kw)
        allowed = next(f["terms"]["alert.source"] for f in query["bool"]["filter"] if "terms" in f)
        docs = [d for d in self.DOCS if d["source"] in allowed]
        avg = lambda xs: {"value": sum(xs) / len(xs) if xs else None}  # noqa: E731
        crit = [d["ttd"] for d in docs if d["sev"] == "critical"]
        r = super().search(index, size, query, aggs, **kw)
        r["hits"]["total"]["value"] = len(docs)
        r["aggregations"]["ttd_crit"] = {"doc_count": len(crit), "v": avg(crit)}
        r["aggregations"]["ttd"] = avg([d["ttd"] for d in docs])
        return r


def test_kpi_mttd_only_detection_alerts():
    d = kpi.compute(DetectionKES(), ROOT / "config", days=30, now=NOW)
    assert d["mttd_critical_s"] == 3.6 and d["alerts"]["total"] == 24      # không phải ~5 300 giây khi gộp rba / health
    assert d["grade"]["mttd_critical_s"] == "gd4"


def test_kpi_alert_query_is_detection_only():
    es = KES()
    kpi.compute(es, ROOT / "config", days=30, now=NOW)
    q, _ = es.queries[settings.IDX_ALERTS]
    assert {"terms": {"alert.source": ["rule", "wazuh", "ml"]}} in q["bool"]["filter"]      # R62: loại rba, health, retrohunt
    assert q["bool"]["must_not"] == [{"term": {"alert.shadow": True}}]


def test_dashboard_json_matches_generator(tmp_path):
    """JSON trong grafana/dashboards phải đúng bằng đầu ra của tools/gen_dashboard.py (không sửa tay, không để lệch)."""
    import os
    import subprocess
    import sys
    repo = ROOT.parent
    subprocess.run([sys.executable, str(repo / "tools" / "gen_dashboard.py")], check=True, capture_output=True,
                   env={**os.environ, "GEN_DASHBOARD_OUT": str(tmp_path), "PYTHONIOENCODING": "utf-8"})
    for f in tmp_path.glob("*.json"):
        assert f.read_bytes() == (repo / "grafana" / "dashboards" / f.name).read_bytes(), f"{f.name} lệch generator: chạy lại tools/gen_dashboard.py"
    assert len(list(tmp_path.glob("*.json"))) == 4
