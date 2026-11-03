"""tools/parity_report.py: đối chiếu alert YAML (rule.id = mã cũ) với alert XML (rule.legacy_id) theo event.id (Task 13)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
import parity_report as pr  # noqa: E402

T = "2026-11-02T10:00:00+00:00"


def y(code, events, ts=T):
    return {"@timestamp": ts, "alert": {"source": "rule"}, "rule": {"id": code}, "related_events": events}


def x(code, events, ts=T, shadow=True):
    a = {"@timestamp": ts, "alert": {"source": "wazuh"}, "rule": {"id": "WZH-104001", "legacy_id": code},
         "related_events": events}
    if shadow:
        a["alert"]["shadow"] = True
    return a


def test_matched_yaml_only_xml_only():
    alerts = [y("AUTH-001", ["e1"]), x("AUTH-001", ["e1"]),                    # khớp
              y("AUTH-001", ["e2"]),                                           # chỉ YAML
              x("AUTH-001", ["e3"]),                                           # chỉ XML (cả alert shadow)
              y("NET-004", ["n1"])]
    r = pr.parity(alerts, "2026-11-01T00:00:00+00:00")
    assert r["AUTH-001"] == {"yaml": 2, "xml": 2, "matched": 1, "only_yaml": ["e2"], "only_xml": ["e3"]}
    assert r["NET-004"] == {"yaml": 1, "xml": 0, "matched": 0, "only_yaml": ["n1"], "only_xml": []}


def test_frequency_rule_fires_on_different_event_is_exposed():
    r = pr.parity([y("AUTH-001", ["a", "b", "c"]), x("AUTH-001", ["a", "b"])], "2026-01-01T00:00:00+00:00")
    assert r["AUTH-001"]["only_yaml"] == ["c"] and r["AUTH-001"]["only_xml"] == []


def test_since_filters_old_alerts_and_other_sources():
    old = "2026-10-01T00:00:00+00:00"
    alerts = [y("AUTH-001", ["o1"], old), x("AUTH-001", ["o2"], old), y("AUTH-001", ["n1"]),
              {"@timestamp": T, "alert": {"source": "ml"}, "rule": {"id": "ML-001"}, "related_events": ["m"]},
              {"@timestamp": T, "alert": {"source": "wazuh"}, "rule": {"id": "WZH-5710"}, "related_events": ["w"]}]
    r = pr.parity(alerts, "2026-11-01T00:00:00+00:00")
    assert list(r) == ["AUTH-001"] and r["AUTH-001"]["yaml"] == 1 and r["AUTH-001"]["xml"] == 0


def test_xml_alert_with_several_legacy_ids_counts_for_each():
    a = x("NET-004", ["z"])
    a["rule"]["legacy_ids"] = ["NET-004", "NET-005"]
    r = pr.parity([a, y("NET-005", ["z"])], "2026-01-01T00:00:00+00:00")
    assert r["NET-005"] == {"yaml": 1, "xml": 1, "matched": 1, "only_yaml": [], "only_xml": []} and "NET-004" in r


def test_markdown_row_per_code():
    md = pr.markdown(pr.parity([y("AUTH-001", ["e1"]), x("AUTH-001", ["e1"]), x("AUTH-001", ["e9"])],
                               "2026-01-01T00:00:00+00:00"), "2026-01-01T00:00:00+00:00")
    assert "| AUTH-001 | 1 | 2 | 1 | 0 | 1 |" in md and "e9" in md
