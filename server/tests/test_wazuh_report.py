"""--report của tools/wazuh_rule_test.py: gom ca theo mã rule cũ và quyết định builtin / approx / convert (R29)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
import wazuh_rule_test as wrt  # noqa: E402

INFO = {31103: (7, ["web"]), 31106: (6, ["web"]), 5710: (5, ["syslog"]), 5763: (10, ["syslog"]), 19000: (9, ["sca"]),
        31100: (0, ["web"]), 100101: (12, ["fim"])}


def decide(pos, neg, skipped=""):
    return wrt.decide(pos, neg, INFO, skipped)


def test_builtin_when_every_positive_has_high_stock_and_no_negative_does():
    d, ids, note = decide([{31103}, {31103, 31100}], [{5710}, set()])
    assert d == "builtin" and ids == [31103] and note


def test_union_coverage_across_positives_is_builtin_and_records_all_ids():
    d, ids, _ = decide([{31103}, {5763}], [set()])
    assert d == "builtin" and ids == [5763, 31103]


def test_high_stock_on_a_negative_blocks_builtin():
    d, _, note = decide([{31103}], [{31103}])
    assert d == "approx" and "31103" in note


def test_low_level_only_is_approx_and_noted():
    d, ids, note = decide([{5710}, {5710}], [set()])
    assert d == "approx" and ids == [5710] and "5710" in note


def test_uncovered_positive_is_approx_when_another_is_covered():
    d, _, _ = decide([{31103}, set()], [set()])
    assert d == "approx"


def test_nothing_fired_is_convert():
    assert decide([set(), {31100}], [set()])[0] == "convert"        # level 0 không tính


def test_sca_and_project_rules_do_not_count():
    assert decide([{19000}, {100101}], [set()])[0] == "convert"


def test_generic_31106_is_recorded_with_explanation():
    d, ids, note = decide([{31106}], [set()])
    assert d == "approx" and ids == [31106] and "200" in note


def test_skipped_reason_is_convert_with_reason():
    d, ids, note = wrt.decide([], [], INFO, "phụ thuộc MISP")
    assert d == "convert" and ids == [] and "phụ thuộc MISP" in note


class FakeApi:
    def request(self, method, path, body=None):
        assert method == "GET" and path.startswith("/rules?rule_ids=")
        wanted = [int(x) for x in path.split("rule_ids=")[1].split("&")[0].split(",")]
        return {"data": {"affected_items": [{"id": i, "level": INFO[i][0], "groups": INFO[i][1]} for i in wanted]}}


def leg(code, kind, fmt="syslog", **kw):
    return {"legacy": code, "kind": kind, "log_format": fmt, "location": "x", "events": ["a"], **kw}


def test_report_batches_injection_cases_in_one_call_and_maps_results(monkeypatch):
    inject_calls = []

    def fake_inject(cases):
        inject_calls.append(len(cases))
        return [{5763} if c["legacy"] == "WIN-1" and c["kind"] == "positive" else set() for c in cases]

    monkeypatch.setattr(wrt, "inject", fake_inject)
    monkeypatch.setattr(wrt, "fired", lambda c, api: {31103} if c["legacy"] == "WEB-1" and c["kind"] == "positive" else set())
    cases = [leg("WIN-1", "positive", "eventchannel"), leg("WIN-1", "negative", "eventchannel"),
             leg("FIM-1", "positive", "syscheck"), leg("WEB-1", "positive"), leg("WEB-1", "negative")]
    out = wrt.report(cases, FakeApi(), {"TI-1": "cần MISP"}, codes=["WIN-1", "FIM-1", "WEB-1", "TI-1"])
    assert inject_calls == [3]
    assert out["WIN-1"]["decision"] == "builtin" and out["WIN-1"]["wazuh"] == [5763]
    assert out["WEB-1"]["decision"] == "builtin" and out["WEB-1"]["wazuh"] == [31103]
    assert out["FIM-1"]["decision"] == "convert" and out["FIM-1"]["wazuh"] == []
    assert out["TI-1"]["decision"] == "convert" and "MISP" in out["TI-1"]["note"]
    assert list(out) == ["WIN-1", "FIM-1", "WEB-1", "TI-1"]


def test_report_rejects_missing_codes():
    import pytest
    with pytest.raises(ValueError, match="WEB-2"):
        wrt.report([leg("WEB-1", "positive")], FakeApi(), {}, codes=["WEB-1", "WEB-2"])
