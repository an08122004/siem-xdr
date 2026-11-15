"""Task 2: alert ML-WEB / ML-AUTH (chạy bóng mặc định), analyzer loại IP có alert thật khỏi tập học, lưu trạng thái."""
from __future__ import annotations

import signal
from pathlib import Path

import pytest

from siem import analyzer as analyzer_mod
from siem import settings
from siem.detection import alerts, ml
from siem.detection import wazuh as bridge
from test_soar_wazuh_groups import run, wazuh_alert

ROOT = Path(__file__).resolve().parents[1]
EV = {"@timestamp": "2026-11-20T10:00:00Z", "source": {"ip": "9.9.9.9"}}


@pytest.fixture(scope="module")
def enricher():
    from siem.pipeline.enrich import Enricher
    return Enricher(ROOT / "config")


def anomaly(**kw):
    return ml.Anomaly("web", "9.9.9.9", -0.31, -0.08, {"n_requests": 400.0, "n_paths": 340.0, "x": 0.123456},
                      [("n_paths", 340.0, 8.0)], EV, ["e1"], 0.0)


def test_from_anomaly_shadow_fields():
    al = alerts.from_anomaly(anomaly(), ml.SPECS["web"], shadow=True)
    assert al["rule"]["id"] == "ML-WEB" and al["alert"]["source"] == "ml" and al["alert"]["shadow"] is True
    assert al["rule"]["mode"] == "shadow" and al["severity"] == "high" and al["source"]["ip"] == "9.9.9.9"
    assert al["ml"]["model"] == "web" and al["ml"]["threshold"] == -0.08
    assert "n_paths=340 (thường 8)" in al["rule"]["description"]
    assert al["rule"]["mitre"]["technique"] == ["T1595"] and al["ml"]["features"]["x"] == 0.123


def test_from_anomaly_active_is_real_alert():
    a = anomaly()
    a.model = "auth"
    al = alerts.from_anomaly(a, ml.SPECS["auth"], shadow=False)
    assert "shadow" not in al["alert"] and al["rule"]["id"] == "ML-AUTH" and "mode" not in al["rule"]


class Det:
    def __init__(self):
        self.excluded = []

    def exclude(self, ip, ts):
        self.excluded.append((ip, ts))

    def add(self, doc, ts):
        pass


def make(enricher, det):
    an = analyzer_mod.Analyzer.__new__(analyzer_mod.Analyzer)
    an.enricher, an.detector, an.buffer, an.stats = enricher, det, [], {"events": 0, "alerts": 0}
    an.emitted = []
    an.emit = an.emitted.append
    an.suppressor = bridge.Suppressor(60)
    return an


def test_analyzer_excludes_alerted_ip(enricher, monkeypatch):
    det = Det()
    an = make(enricher, det)
    a = {"alert": {}, "source": {"ip": "5.5.5.5"}, "event_time": "2026-11-20T10:00:00Z"}
    monkeypatch.setattr(bridge, "to_alert", lambda doc: a)
    an.handle({"event_type": "wazuh_alert"})
    assert det.excluded and det.excluded[0][0] == "5.5.5.5"
    det.excluded.clear()
    a["alert"]["shadow"] = True
    an.handle({"event_type": "wazuh_alert"})
    assert not det.excluded


def test_soar_ignores_shadow_ml_alert(monkeypatch):
    al = alerts.from_anomaly(anomaly(), ml.SPECS["web"], shadow=True)
    res, es = run(al, monkeypatch)
    assert res == [] and not es.docs


def test_tick_emits_shadow_by_mode(enricher, monkeypatch):
    class D(Det):
        def flush(self, now):
            return [anomaly()]
    an = make(enricher, D())
    an.es = an.stream = None
    an.producer = type("P", (), {"flush": lambda self, t: 1})()
    an.last_flush = 0.0
    monkeypatch.setattr(settings, "ML_MODE", "shadow")
    an.tick()
    monkeypatch.setattr(settings, "ML_MODE", "active")
    an.tick()
    assert [bool(a["alert"].get("shadow")) for a in an.emitted] == [True, False]


def test_report_status_and_save(enricher, caplog):
    class D(Det):
        saved = 0

        def save(self):
            self.saved += 1

        def status(self):
            return {"web": {"phase": "active", "windows": 812, "threshold": -0.071, "dropped_late": 3,
                            "dropped_entities": 0}}
    d = D()
    an = make(enricher, d)
    with caplog.at_level("INFO"):
        an.ml_checkpoint()
    assert d.saved == 1
    assert "ML web: active, 812 cửa sổ, ngưỡng -0.071, bỏ muộn 3, bỏ IP 0" in caplog.text


def test_sigterm_handler_saves(enricher):
    d = Det()
    d.save = lambda: setattr(d, "saved", True)
    an = make(enricher, d)
    an.install_signal_handlers()
    try:
        handler = signal.getsignal(signal.SIGTERM)
        try:
            handler(signal.SIGTERM, None)
        except SystemExit:
            pass
        assert d.saved is True
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
