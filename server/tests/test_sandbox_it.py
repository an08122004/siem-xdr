"""Tích hợp với container wazuh-sandbox thật (Task 20). Chỉ chạy khi có SANDBOX_IT_DIR = thư mục bind vào /sandbox:

    AI_SANDBOX_PATH=<thư mục> docker compose -p p4sbx --profile ai up -d wazuh-sandbox
    SANDBOX_IT_DIR=<thư mục> python -m pytest tests/test_sandbox_it.py -q
Mỗi job có restart manager (~13 giây) và chờ analysisd đứng yên 15 giây.
"""
import os
import re
from pathlib import Path

import pytest
import yaml

from siem.ai import wazuh_events as we
from siem.ai.sandbox import Sandbox

pytestmark = pytest.mark.skipif(not os.getenv("SANDBOX_IT_DIR"), reason="cần container wazuh-sandbox (SANDBOX_IT_DIR)")
ROOT = Path(__file__).resolve().parents[2]
MARK = "sbx-it-marker-7f3a"
CANDIDATE = f"""<group name="sandbox_it,">
  <rule id="119000" level="7">
    <if_sid>102000</if_sid>
    <field name="cmd" type="pcre2">{MARK}</field>
    <description>ứng viên thử sandbox</description>
  </rule>
</group>
"""


@pytest.fixture(scope="module")
def sandbox():
    return Sandbox(Path(os.environ["SANDBOX_IT_DIR"]), timeout=600)


def _events():
    cases = yaml.safe_load((ROOT / "wazuh/manager/tests/cases/0998-stock-real-alerts.yml").read_text(encoding="utf-8"))
    case = next(c for c in cases if c.get("log_format") == "eventchannel")
    win = we.RawEvent(1, "eventchannel", "f:EventChannel:" + re.sub(
        r"<EventRecordID>\d+</EventRecordID>", "<EventRecordID>1</EventRecordID>", case["events"][0]))
    return case["rule"], [win, we.siem_proc_event(2, "/usr/bin/echo", f"echo {MARK}", "echo", "bash"),
                          we.siem_proc_event(3, "/usr/bin/ls", "ls -la", "ls", "bash")]


def ids(res, ident):
    return {h.rule_id for h in res.hits.get(ident, [])}


def test_stock_windows_case_fires_its_rule_without_candidate(sandbox):
    rule, events = _events()
    res = sandbox.run(events)                         # canary sai thì run đã raise SandboxError
    assert res.load_error is None and rule in ids(res, 1) and not ids(res, 2) and not ids(res, 3)


def test_candidate_catches_only_its_own_event(sandbox):
    rule, events = _events()
    res = sandbox.run(events, CANDIDATE)
    assert res.load_error is None and rule in ids(res, 1)
    assert ids(res, 2) == {119000} and not ids(res, 3)


def test_frequency_rule_counts_stock_31101_per_source_ip(sandbox):
    """gap-ml: rule tần suất của emit_frequency đếm thẳng rule gốc 31101 (lỗi 4xx). 16 lần 401 từ 10.10.1.62: job nền
    31151 kích hoạt ở lần 14; có ứng viên (5 lần / 300 giây) thì ứng viên lấy lần 5, 10, 15 nên 31151 hụt đếm, nhưng IP
    vẫn bị phát hiện (so theo IP). 10.10.1.41 hai lần: không kích hoạt."""
    from siem.ai.wazuh_gate import CANDIDATE_BASE, WazuhGate
    from siem.ai.wazuh_xml import emit_frequency
    line = '{ip} - - [19/Nov/2026:12:00:{s:02d} +0700] "GET /portal/ HTTP/1.1" 401 459 "-" "Mozilla/5.0"'

    def raws(ip, idents):
        return [we.log_event(i, we.WEB_LOCATION, line.format(ip=ip, s=i % 60)) for i in idents]

    em = emit_frequency(sid=31101, count=5, timeframe=300, rule_id=CANDIDATE_BASE, level=7, code="AI-CAND", title="t",
                        techniques=["T1110.003"], groups=["siem", "ai"], shadow_since=None)
    checks, m = WazuhGate(sandbox, {}).check_frequency(em.xml, {"10.10.1.62": raws("10.10.1.62", range(1, 17))},
                                                       {"10.10.1.41": raws("10.10.1.41", (17, 18))})
    assert all(c.ok for c in checks), [(c.name, c.detail) for c in checks]
    assert m["wazuh_incidents_detected"] == 1 and m["wazuh_normal_fired"] == 0 and m["wazuh_stolen"] == 0


def test_duplicate_candidate_id_is_load_error(sandbox):
    res = sandbox.run(_events()[1], CANDIDATE.replace("119000", "102001"))
    assert res.load_error and "7612" in res.load_error and res.hits == {}
