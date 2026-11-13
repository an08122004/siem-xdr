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


def test_duplicate_candidate_id_is_load_error(sandbox):
    res = sandbox.run(_events()[1], CANDIDATE.replace("119000", "102001"))
    assert res.load_error and "7612" in res.load_error and res.hits == {}
