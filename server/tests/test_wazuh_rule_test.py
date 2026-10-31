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
