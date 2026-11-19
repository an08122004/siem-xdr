"""tools/ml_eval.py: khớp anomaly với kịch bản, tỉ lệ báo nhầm, loại IP tấn công khỏi tập học."""
from __future__ import annotations

import importlib.util
from datetime import datetime
from pathlib import Path

from siem.detection import ml

_spec = importlib.util.spec_from_file_location("ml_eval", Path(__file__).resolve().parents[2] / "tools" / "ml_eval.py")
ev = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ev)


def epoch(iso):
    return datetime.fromisoformat(iso).timestamp()


def anomaly(model, ip, window_start=0.0):
    return ml.Anomaly(model, ip, -0.2, -0.1, {"n_paths": 340.0}, [("n_paths", 340.0, 8.0)], {}, [], window_start)


def fake_events(ips, windows=6):
    out = []
    for w in range(windows):
        for ip in ips:
            for i in range(8):
                out.append(({"event": {"category": "web", "id": f"{ip}-{w}-{i}"}, "source": {"ip": ip},
                             "url": {"path": f"/p{i}"}, "http": {"response": {"status_code": 200, "bytes": 1024}}},
                            w * 300 + i * 10.0))
    return out



def test_match_anomalies_to_scenarios():
    sc = [{"scenario": "scan_dirs", "ip": "10.10.1.60", "start": "2026-11-17T10:00:00+07:00", "end": "2026-11-17T10:01:00+07:00"},
          {"scenario": "slow_scan", "ip": "10.10.1.61", "start": "2026-11-17T11:00:00+07:00", "end": "2026-11-17T11:30:00+07:00"}]
    a = anomaly("web", "10.10.1.60", window_start=epoch("2026-11-17T10:00:00+07:00"))
    out = ev.match([a], sc)
    assert out["scan_dirs"]["detected"] is True and out["slow_scan"]["detected"] is False


def test_fp_rate_counts_only_normal_ips():
    assert ev.fp_rate([anomaly("web", "10.10.1.41"), anomaly("web", "10.10.1.60")], {"10.10.1.41"}, 200) == 0.005


def test_train_excludes_attack_ips():
    ev_all = fake_events(["10.10.1.41", "10.10.1.60"])
    vecs = ev.training_vectors(ev_all, exclude={"10.10.1.60"})
    both = ev.training_vectors(ev_all, exclude=set())
    assert len(vecs["web"]) == 6 and len(both["web"]) == 12


def test_train_skips_alerted_windows():
    vecs = ev.training_vectors(fake_events(["10.10.1.41"]), exclude=set(), alerted={"10.10.1.41": [10.0]})
    assert len(vecs["web"]) == 5


def test_score_rows_scores_every_window_with_labels():
    from sklearn.ensemble import IsolationForest
    det = ml.AnomalyDetector()
    m = det.models["web"]
    base = ev.training_vectors(fake_events(["10.10.1.41"], windows=20), exclude=set())["web"]
    m.forest = IsolationForest(random_state=0).fit(ml._matrix(m.spec, base))
    m.threshold = -0.05
    attack = [({"event": {"category": "web", "id": f"x{i}"}, "source": {"ip": "10.10.1.60"},
                "url": {"path": f"/scan{i}"}, "http": {"response": {"status_code": 404, "bytes": 0}}}, 600 + i)
              for i in range(60)]
    rows = ev.score_rows(det, fake_events(["10.10.1.41", "10.10.1.99"], windows=2) + attack,
                         attack={"10.10.1.60"}, normal={"10.10.1.41"})
    labels = {(r[1], r[5]) for r in rows}
    assert labels == {("10.10.1.41", "normal"), ("10.10.1.99", "other"), ("10.10.1.60", "attack")}
    assert all(r[0] == "web" for r in rows)                       # model auth chưa học: không có dòng
    assert all(r[6] == int(r[3] < r[4]) for r in rows)
    assert len(rows) == 5                                          # 2 + 2 cửa sổ thường, 1 cửa sổ tấn công


def test_ip_range():
    assert ev.ip_range("10.10.1.60-62") == ["10.10.1.60", "10.10.1.61", "10.10.1.62"]


def test_lab_verdict_for_ml_alerts():
    sc = [{"scenario": "password_spray", "ip": "10.10.1.62", "start": "2026-11-17T21:10:09+07:00",
           "end": "2026-11-17T21:20:09+07:00"}]
    normal = set(ev.ip_range("10.10.1.40-59"))
    t = epoch("2026-11-17T21:15:00+07:00")
    assert ev.lab_verdict("10.10.1.62", "web", t, sc, normal) == "true_positive"
    assert ev.lab_verdict("10.10.1.62", "web", epoch("2026-11-17T21:24:00+07:00"), sc, normal) == "true_positive"  # +1 cửa sổ
    assert ev.lab_verdict("10.10.1.62", "web", epoch("2026-11-17T22:00:00+07:00"), sc, normal) is None
    assert ev.lab_verdict("10.10.1.51", "web", t, sc, normal) == "false_positive"
    assert ev.lab_verdict("203.0.113.9", "auth", t, sc, normal) is None
