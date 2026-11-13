"""Runner job của sandbox Wazuh (wazuh/sandbox/runner.py, chạy trong container), nạp bằng importlib theo đường dẫn."""
import importlib.util
from pathlib import Path

import pytest

RUNNER = Path(__file__).resolve().parents[2] / "wazuh" / "sandbox" / "runner.py"


@pytest.fixture(scope="module")
def runner():
    spec = importlib.util.spec_from_file_location("sandbox_runner", RUNNER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_rejects_bad_job_names(runner):
    assert not runner.valid_job("../x") and runner.valid_job("0123456789ab")
    assert not runner.valid_job("0123456789AB") and not runner.valid_job("0123456789abc")


def test_load_problems_catches_warnings(runner):
    assert runner.load_problems(0, "WARNING: (7612): Rule ID '109010' is duplicated") and not runner.load_problems(0, "ok")
    assert runner.load_problems(1, "")


def test_sync_rules_copies_live_then_candidate(runner, tmp_path):
    live, dst = tmp_path / "live", tmp_path / "dst"
    live.mkdir()
    dst.mkdir()
    (live / "ai.xml").write_text("a")
    (live / "x.tmp").write_text("t")
    (dst / "old.xml").write_text("o")
    runner.sync_rules(live, dst, "<rule/>")
    assert sorted(p.name for p in dst.iterdir()) == ["ai.xml", "zz-candidate.xml"]
    runner.sync_rules(live, dst, None)
    assert sorted(p.name for p in dst.iterdir()) == ["ai.xml"]


def test_queue_backlog_reads_state(runner):
    state = "events_processed='12'\nevent_queue_usage='0.31'\nwinevt_queue_usage='0.02'\nevent_queue_size='16384'\n"
    c = runner.parse_state(state)
    assert c["events_processed"] == 12 and runner.backlog(c) == 0.31


def test_step_removes_stale_jobs_and_ignores_foreign_names(runner, tmp_path):
    import os
    old, other = tmp_path / "0123456789ab", tmp_path / "keep-me"
    old.mkdir()
    other.mkdir()
    os.utime(old, (1, 1))
    os.utime(other, (1, 1))
    runner.step(tmp_path)
    assert not old.exists() and other.exists()


def test_handle_reports_runner_error_instead_of_hanging(runner, tmp_path):
    import json
    job = tmp_path / "0123456789ab"
    job.mkdir()
    (job / "ready").touch()                                      # thiếu events.jsonl
    runner.step(tmp_path)
    res = json.loads((job / "result.json").read_text(encoding="utf-8"))
    assert (job / "done").exists() and "FileNotFoundError" in res["error"] and res["canary"] is False


def test_too_many_events_is_runner_error_not_load_error(runner, tmp_path, monkeypatch):
    import json
    monkeypatch.setattr(runner, "MAX_EVENTS", 1)
    job = tmp_path / "0123456789ab"
    job.mkdir()
    (job / "events.jsonl").write_text('{"msg": "a"}\n{"msg": "b"}\n', encoding="utf-8")
    (job / "ready").touch()
    runner.step(tmp_path)
    res = json.loads((job / "result.json").read_text(encoding="utf-8"))
    assert res["load_error"] is None and "quá nhiều event" in res["error"]


def test_wait_idle_has_deadline(runner, monkeypatch):
    n = iter(range(10 ** 9))
    monkeypatch.setattr(runner, "counters", lambda: {"events_processed": float(next(n))})   # luôn còn tiến
    monkeypatch.setattr(runner.time, "sleep", lambda s: None)
    with pytest.raises(RuntimeError, match="vẫn xử lý"):
        runner.wait_idle({}, 0.05)


def test_wait_idle_returns_when_counter_stops(runner, monkeypatch):
    monkeypatch.setattr(runner, "counters", lambda: {"events_processed": 7.0})
    monkeypatch.setattr(runner.time, "sleep", lambda s: None)
    assert runner.wait_idle({}, 60)["events_processed"] == 7.0


def test_copy_alerts_detects_rotation(runner, tmp_path, monkeypatch):
    import os
    alerts = tmp_path / "alerts.json"
    alerts.write_text('{"rule": {"id": "1"}}\n', encoding="utf-8")
    monkeypatch.setattr(runner, "ALERTS", alerts)
    ino = os.stat(alerts).st_ino
    alerts.rename(tmp_path / "ossec-alerts-01.json")   # analysisd qua ngày: file cũ vẫn còn (đổi tên) nên inode không bị tái dùng
    alerts.write_text("", encoding="utf-8")
    assert os.stat(alerts).st_ino != ino
    with pytest.raises(RuntimeError, match="xoay vòng"):
        runner.copy_alerts(tmp_path / "out.jsonl", ino)


def test_copy_alerts_drops_canary(runner, tmp_path, monkeypatch):
    import json
    import os
    alerts = tmp_path / "alerts.json"
    canary = {"rule": {"id": "554"}, "syscheck": {"inode_after": runner.CANARY_IDENT}}
    alerts.write_text(json.dumps({"rule": {"id": "1"}}) + "\n" + json.dumps(canary) + "\n", encoding="utf-8")
    monkeypatch.setattr(runner, "ALERTS", alerts)
    assert runner.copy_alerts(tmp_path / "out.jsonl", os.stat(alerts).st_ino) is True
    assert [json.loads(x)["rule"]["id"] for x in (tmp_path / "out.jsonl").read_text(encoding="utf-8").splitlines()] == ["1"]
