"""Client sandbox Wazuh của AI (Task 20, siem/ai/sandbox.py). Runner giả là một thread ghi result.json / alerts.jsonl / done."""
import json
import threading
import time

import pytest

from siem.ai import wazuh_events as we
from siem.ai.sandbox import Hit, Sandbox, SandboxError, alert_ident


@pytest.fixture
def fake_runner():
    threads, seen = [], []

    def start(root, alerts, canary, load_error=None, **extra):
        def loop():
            deadline = time.time() + 5
            while time.time() < deadline:
                for ready in (root / "jobs").glob("*/ready"):
                    job = ready.parent
                    n = sum(1 for _ in (job / "events.jsonl").open(encoding="utf-8"))
                    cand = job / "candidate.xml"
                    seen.append(cand.read_text(encoding="utf-8") if cand.exists() else None)
                    (job / "alerts.jsonl").write_text("".join(json.dumps(a) + "\n" for a in alerts), encoding="utf-8")
                    (job / "result.json").write_text(json.dumps(
                        {"sent": n, "processed": n + 1, "dropped": 0, "canary": canary, "seconds": 0.1,
                         "load_error": load_error, **extra}), encoding="utf-8")
                    (job / "done").touch()
                    return
                time.sleep(0.02)
        t = threading.Thread(target=loop, daemon=True)
        t.start()
        threads.append(t)
    start.seen = seen
    yield start
    for t in threads:
        t.join(5)


def test_run_maps_alerts_to_idents(tmp_path, fake_runner):
    fake_runner(tmp_path, alerts=[{"rule": {"id": "92032", "level": 3}, "agent": {"name": "sbx-5"}},
                                  {"rule": {"id": "502", "level": 3}, "agent": {"name": "wazuh-sandbox"}}], canary=True)
    res = Sandbox(tmp_path, timeout=5).run([we.apache_event(5, "l")])
    assert res.hits == {5: [Hit(92032, 3)]} and res.load_error is None
    assert not any((tmp_path / "jobs").iterdir())                      # đã dọn job


def test_run_passes_candidate_to_runner(tmp_path, fake_runner):
    fake_runner(tmp_path, alerts=[], canary=True)
    Sandbox(tmp_path, timeout=5).run([we.apache_event(1, "l")], "<group/>")
    assert fake_runner.seen == ["<group/>"]


def test_run_raises_when_canary_missing(tmp_path, fake_runner):
    fake_runner(tmp_path, alerts=[], canary=False)
    with pytest.raises(SandboxError, match="canary"):
        Sandbox(tmp_path, timeout=5).run([we.apache_event(1, "l")])


def test_run_raises_when_events_dropped(tmp_path, fake_runner):
    fake_runner(tmp_path, alerts=[], canary=True, dropped=3)
    with pytest.raises(SandboxError, match="bỏ 3"):
        Sandbox(tmp_path, timeout=5).run([we.apache_event(1, "l")])


def test_run_raises_on_runner_error(tmp_path, fake_runner):
    fake_runner(tmp_path, alerts=[], canary=False, error="RuntimeError: wazuh-analysisd không lên")
    with pytest.raises(SandboxError, match="không lên"):
        Sandbox(tmp_path, timeout=5).run([we.apache_event(1, "l")])


def test_run_times_out_and_cleans_job(tmp_path):
    with pytest.raises(SandboxError, match="quá"):
        Sandbox(tmp_path, timeout=0.3).run([we.apache_event(1, "l")])
    assert not any((tmp_path / "jobs").iterdir())


def test_load_error_is_returned_not_raised(tmp_path, fake_runner):
    fake_runner(tmp_path, alerts=[], canary=True, load_error="(7612): Rule ID '119000' is duplicated")
    assert "7612" in Sandbox(tmp_path, timeout=5).run([we.apache_event(1, "l")], "<rule/>").load_error


def test_run_rejects_duplicate_idents(tmp_path):
    with pytest.raises(ValueError):
        Sandbox(tmp_path, timeout=5).run([we.apache_event(1, "a"), we.apache_event(1, "b")])


def test_alert_ident():
    assert alert_ident({"data": {"win": {"system": {"eventRecordID": "17"}}}, "agent": {"name": "wazuh-sandbox"}}) == 17
    assert alert_ident({"agent": {"id": "001", "name": "sbx-42"}, "location": "siem-procs"}) == 42
    assert alert_ident({"agent": {"name": "wazuh-sandbox"}, "location": "syscheck"}) is None
