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
