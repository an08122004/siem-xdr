"""Bộ chạy ca test log gốc qua Wazuh logtest (tools/wazuh_rule_test.py), thử bằng API giả."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
import wazuh_rule_test as wrt  # noqa: E402

from siem.soar.wazuh import WazuhError  # noqa: E402


class FakeApi:
    """logtest giả: `answer(line_no, event)` trả id rule báo (hoặc None) cho dòng thứ line_no của session."""

    def __init__(self, answer, fail_429=0):
        self.answer, self.fail_429 = answer, fail_429
        self.sessions: dict[str, int] = {}
        self.deleted: list[str] = []
        self.calls = 0

    def logtest(self, event, log_format, location, token=None):
        self.calls += 1
        if self.fail_429:
            self.fail_429 -= 1
            raise WazuhError("HTTP 429 /logtest: Maximum number of requests per minute")
        if token is None:
            token = f"tok{len(self.sessions)}"
            self.sessions[token] = 0
        assert token in self.sessions, "token lạ"
        self.sessions[token] += 1
        rid = self.answer(self.sessions[token], event)
        return {"token": token, "output": {"rule": {"id": str(rid), "level": 5}} if rid else {}}

    def request(self, method, path, body=None):
        assert method == "DELETE" and path.startswith("/logtest/sessions/")
        self.deleted.append(path.rsplit("/", 1)[1])
        return {}


def case(**kw):
    return {"log_format": "syslog", "location": "x", "events": ["a"], "_file": "f.yml", **kw}


def test_positive_case_missing_id_fails():
    fails = wrt.run([case(rule=104001)], FakeApi(lambda n, e: 5710))
    assert len(fails) == 1 and fails[0].expected == "104001" and fails[0].got_ids == [5710]


def test_positive_case_ok():
    assert wrt.run([case(rule=104001)], FakeApi(lambda n, e: 104001)) == []


def test_negative_case_with_id_fails_and_without_passes():
    assert len(wrt.run([case(none=[104001])], FakeApi(lambda n, e: 104001))) == 1
    assert wrt.run([case(none=[104001])], FakeApi(lambda n, e: 5710)) == []
    assert wrt.run([case(none=[104001])], FakeApi(lambda n, e: None)) == []


def test_five_lines_share_one_session_and_frequency_fires_at_line_5():
    api = FakeApi(lambda n, e: 109041 if n == 5 else 109040)
    c = case(rule=109041, events=["l"] * 5)
    assert wrt.fired(c, api) == {109040, 109041} and len(api.sessions) == 1
    assert 109041 not in wrt.fired(case(events=["l"] * 4), FakeApi(lambda n, e: 109041 if n == 5 else 109040))


def test_session_deleted_after_each_case():
    api = FakeApi(lambda n, e: 1)
    wrt.run([case(rule=1), case(rule=1, events=["a", "b"])], api)
    assert sorted(api.deleted) == sorted(api.sessions) and len(api.deleted) == 2


def test_429_is_retried(monkeypatch):
    monkeypatch.setattr(wrt.time, "sleep", lambda s: None)
    api = FakeApi(lambda n, e: 7, fail_429=2)
    assert wrt.run([case(rule=7)], api) == [] and api.calls == 3


def test_other_http_error_is_not_swallowed():
    class Boom(FakeApi):
        def logtest(self, *a, **k):
            raise WazuhError("HTTP 500 /logtest: boom")
    with pytest.raises(WazuhError):
        wrt.run([case(rule=1)], Boom(lambda n, e: 1))


def test_delay_sleeps_between_lines_only(monkeypatch):
    naps = []
    monkeypatch.setattr(wrt.time, "sleep", naps.append)
    wrt.fired(case(events=["l"] * 4, delay=16), FakeApi(lambda n, e: 1))
    assert naps == [16, 16, 16]                       # 4 dòng -> 3 lần nghỉ, không nghỉ sau dòng cuối
    naps.clear()
    wrt.fired(case(events=["l"] * 4), FakeApi(lambda n, e: 1))
    assert naps == []


@pytest.mark.parametrize("fmt", ["eventchannel", "syscheck"])
def test_delay_ignored_by_injection_formats(monkeypatch, fmt):
    naps = []
    monkeypatch.setattr(wrt.time, "sleep", naps.append)
    monkeypatch.setattr(wrt, "inject", lambda cases: [{1}] * len(cases))
    assert wrt.fired(case(log_format=fmt, events=["a", "b"], delay=16), FakeApi(lambda n, e: None)) == {1}
    assert naps == []


@pytest.mark.parametrize("fmt", ["eventchannel", "syscheck"])
def test_injection_formats_bypass_logtest(monkeypatch, fmt):
    seen = []
    monkeypatch.setattr(wrt, "inject", lambda cases: seen.append(cases) or [{92032}] * len(cases))
    api = FakeApi(lambda n, e: pytest.fail("logtest không được gọi"))
    assert wrt.run([case(rule=92032, log_format=fmt)], api) == []
    assert len(seen) == 1 and api.calls == 0


def test_injection_cases_are_batched_once(monkeypatch):
    calls = []
    monkeypatch.setattr(wrt, "inject", lambda cases: calls.append(len(cases)) or [{1}] * len(cases))
    wrt.run([case(rule=1, log_format="eventchannel"), case(rule=1), case(rule=1, log_format="syscheck")],
            FakeApi(lambda n, e: 1))
    assert calls == [2]


def test_load_cases_tags_file_and_index(tmp_path):
    f = tmp_path / "x.yml"
    f.write_text("- rule: 1\n  log_format: syslog\n  location: l\n  events: [a]\n- none: [2]\n  log_format: syslog\n"
                 "  location: l\n  events: [b]\n", encoding="utf-8")
    cs = wrt.load_cases(tmp_path)
    assert [(c["_file"], c["_index"]) for c in cs] == [("x.yml", 0), ("x.yml", 1)]


# ---------------------------------------------------------------- phần bơm hàng đợi (không docker)
import json  # noqa: E402

EVT = ('{"Message": "m", "Event": "<Event><System><EventRecordID>1</EventRecordID></System></Event>"}')


def test_message_syscheck_added_and_modified():
    m = wrt._message("syscheck", {"path": "/var/www/html/a.php", "type": "added"}, 6_000_007)
    assert m.startswith("8:syscheck:")
    d = json.loads(m[len("8:syscheck:"):])["data"]
    assert d["path"] == "/var/www/html/a.php" and d["type"] == "added" and d["attributes"]["inode"] == 6_000_007
    assert "changed_attributes" not in d
    d = json.loads(wrt._message("syscheck", {"path": "/x", "type": "modified"}, 1)[len("8:syscheck:"):])["data"]
    assert d["changed_attributes"] == ["size", "mtime"] and d["old_attributes"]["size"] == 5


def test_message_eventchannel_rewrites_record_id_or_raises():
    m = wrt._message("eventchannel", EVT, 5_001_002)
    assert m.startswith("f:EventChannel:") and "<EventRecordID>5001002</EventRecordID>" in m
    with pytest.raises(ValueError):
        wrt._message("eventchannel", '{"Event": "<Event/>"}', 1)


def test_alert_ident():
    assert wrt._alert_ident("syscheck", {"syscheck": {"inode_after": 6001000}}) == 6001000
    assert wrt._alert_ident("eventchannel", {"data": {"win": {"system": {"eventRecordID": "5000003"}}}}) == 5000003
    assert wrt._alert_ident("syscheck", {"rule": {}}) is None


def _fake_docker(monkeypatch, alerts_for, sent=None):
    """Thay manager tạm: alerts_for(msgs) -> list alert; sent = số event 'gửi được' (mặc định đủ)."""
    import wazuh_coverage as cov
    import wazuh_noise as noise
    monkeypatch.setattr(noise, "start", lambda tmp: None)
    monkeypatch.setattr(wrt.subprocess, "run", lambda *a, **k: None)

    def run_wazuh(items):
        cov.LAST_SENT = len(items) if sent is None else sent
        return alerts_for([i["msg"] for i in items])
    monkeypatch.setattr(cov, "run_wazuh", run_wazuh)


def _sc_alert(rule, inode):
    return {"rule": {"id": str(rule)}, "syscheck": {"inode_after": inode}}


def _ec_alert(rule, rid):
    return {"rule": {"id": str(rule)}, "data": {"win": {"system": {"eventRecordID": str(rid)}}}}


def test_inject_maps_alerts_back_to_cases(monkeypatch):
    base_s, base_e = wrt._BASE["syscheck"], wrt._BASE["eventchannel"]
    # ca 0 eventchannel (1 dòng), ca 1 syscheck (2 dòng), ca 2 syscheck (1 dòng, không alert)
    alerts = [_ec_alert(92032, base_e + 0), _sc_alert(100100, base_s + 1000), _sc_alert(554, base_s + 1001),
              _sc_alert(554, wrt.CANARY_IDENT), _sc_alert(999, base_e + 1000)]   # inode trùng dải eventchannel: bỏ
    _fake_docker(monkeypatch, lambda msgs: alerts)
    cases = [case(log_format="eventchannel", events=[EVT]),
             case(log_format="syscheck", events=[{"path": "/a", "type": "added"}] * 2),
             case(log_format="syscheck", events=[{"path": "/b", "type": "added"}])]
    assert wrt.inject(cases) == [{92032}, {100100, 554}, set()]


def test_inject_restores_container(monkeypatch):
    import wazuh_coverage as cov
    _fake_docker(monkeypatch, lambda msgs: [_sc_alert(554, wrt.CANARY_IDENT)])
    cov.CONTAINER = "keep-me"
    wrt.inject([case(log_format="syscheck", events=[{"path": "/a", "type": "added"}])])
    assert cov.CONTAINER == "keep-me"


def test_inject_without_canary_alert_raises(monkeypatch):
    _fake_docker(monkeypatch, lambda msgs: [])
    with pytest.raises(wrt.InjectionError, match="canary"):
        wrt.inject([case(log_format="syscheck", events=[{"path": "/a", "type": "added"}])])


def test_inject_short_sent_count_raises(monkeypatch):
    _fake_docker(monkeypatch, lambda msgs: [_sc_alert(554, wrt.CANARY_IDENT)], sent=1)
    with pytest.raises(wrt.InjectionError, match="1/2"):
        wrt.inject([case(log_format="syscheck", events=[{"path": "/a", "type": "added"}])])


def test_negative_only_batch_does_not_pass_when_injection_broken(monkeypatch):
    _fake_docker(monkeypatch, lambda msgs: [])
    with pytest.raises(wrt.InjectionError):
        wrt.run([case(none=[100100], log_format="syscheck", events=[{"path": "/a", "type": "added"}])], FakeApi(None))
