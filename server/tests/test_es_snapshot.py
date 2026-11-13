"""tools/es_snapshot.py: chỉ gửi thân request khi có (ES 8 từ chối thân ở GET và POST _execute — lỗi 05/11/2026)."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
import es_snapshot  # noqa: E402


def _capture(monkeypatch):
    seen = {}

    def run(cmd, input=None, **kw):
        seen["cmd"], seen["input"] = cmd[-1], input
        return subprocess.CompletedProcess(cmd, 0, stdout="{}", stderr="")
    monkeypatch.setattr(es_snapshot.subprocess, "run", run)
    return seen


def test_no_body_sends_no_data(monkeypatch):
    seen = _capture(monkeypatch)
    es_snapshot.es("POST", "/_slm/policy/daily-snapshots/_execute")
    assert "--data-binary" not in seen["cmd"] and seen["input"] == ""


def test_body_is_sent(monkeypatch):
    seen = _capture(monkeypatch)
    es_snapshot.es("POST", "/siem-alerts/_search", {"size": 0})
    assert seen["cmd"].endswith("--data-binary @-") and seen["input"] == '{"size": 0}'
