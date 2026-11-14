import json, math, random, time
from siem.detection import ml

def web(ip, path="/", status=200, kb=1, ua="UA1", n=0):
    return {"event": {"category": "web", "id": f"e{n}"}, "source": {"ip": ip}, "url": {"path": path},
            "http": {"response": {"status_code": status, "bytes": kb * 1024}}, "user_agent": {"original": ua}}

def auth(ip, user="u", ok=True, n=0):
    return {"event": {"category": "authentication", "outcome": "success" if ok else "failure", "id": f"a{n}"},
            "source": {"ip": ip}, "user": {"name": user}}

def normal_traffic(det, start, hours, ips=50, seed=1):
    """mỗi IP mỗi cửa sổ web 5 phút: 6-30 request, 3-10 path, ít 404; trả về thời điểm cuối"""
    rng = random.Random(seed); t = start
    while t < start + hours * 3600:
        for k in range(ips):
            for i in range(rng.randint(6, 30)):
                det.add(web(f"10.0.0.{k}", f"/p{rng.randint(1, 10)}", 404 if rng.random() < 0.02 else 200,
                            rng.randint(1, 40), f"UA{k % 5}", i), t + rng.uniform(0, 290))
        t += 300; det.flush(t + 31)
    return t

def settle(det, now):
    """flush, rồi flush lần nữa sau IDLE_SECONDS không có event: nguồn im thì cửa sổ đóng theo đồng hồ"""
    return det.flush(now) + det.flush(now + ml.IDLE_SECONDS)

def normal_vectors(n=1000, seed=0):
    """vector web đã cộng dồn, cùng phân bố với normal_traffic. Không seed n bản sao của một vector: dữ liệu học
    giống hệt nhau làm Isolation Forest suy biến (cây không tách được, mọi điểm cùng điểm số, không gì bị gắn cờ).
    1000 vector để tập giữ lại (200) đủ ước lượng phân vị 0,5%; với 300 (giữ lại 60) ngưỡng gần như là điểm thấp
    nhất của 60 cửa sổ, dao động theo seed và có seed làm máy quét lọt ngưỡng"""
    rng = random.Random(seed); out = []
    for _ in range(n):
        k = rng.randint(6, 30); n404 = sum(rng.random() < 0.02 for _ in range(k))
        out.append([k, len({rng.randint(1, 10) for _ in range(k)}), n404 / k, 0, n404,
                    sum(rng.randint(1, 40) for _ in range(k)), 1])
    return out

def test_web_vector_counts():
    w = ml.Window(ml.SPECS["web"])
    for d in [web("1.1.1.1", "/a", 200, 2, "X"), web("1.1.1.1", "/b", 404, 1, "Y"), web("1.1.1.1", "/a", 401, 1, "X")]:
        w.add(d)
    assert w.vector() == [3, 2, 2 / 3, 1, 1, 4.0, 2]

def test_auth_vector():
    w = ml.Window(ml.SPECS["auth"])
    for d in [auth("1.1.1.1", "a", False), auth("1.1.1.1", "b", False), auth("1.1.1.1", "a", True)]:
        w.add(d)
    assert w.vector() == [3, 2, 2 / 3, 2, 1]

def test_learning_phase_emits_nothing():
    det = ml.AnomalyDetector(learn_hours=48, min_windows=200)
    end = normal_traffic(det, 0, 2)
    for i in range(500):
        det.add(web("9.9.9.9", f"/x{i}", 404), end + 1)
    assert settle(det, end + 400) == [] and det.status()["web"]["phase"] == "learning"

def test_active_flags_scan_not_normals():
    det = ml.AnomalyDetector(learn_hours=1, min_windows=200)
    end = normal_traffic(det, 0, 6)                         # 72 cửa sổ x 50 IP
    assert det.status()["web"]["phase"] == "active"
    later = normal_traffic(det, end, 1, seed=2)             # thêm 12 cửa sổ x 50 IP bình thường
    assert det.flagged_ratio("web") <= 0.02                 # cửa sổ bình thường hầu như không bị gắn cờ
    for i in range(400):
        det.add(web("9.9.9.9", f"/x{i}", 404, 0, "scanner", i), later + 5 + i * 0.5)
    hits = [a for a in settle(det, later + 300 + 31) if a.entity == "9.9.9.9"]
    assert len(hits) == 1 and hits[0].model == "web"
    assert {f for f, _, _ in hits[0].top} & {"n_paths", "n_404", "n_requests"}
    assert ml.severity(hits[0]) in ("medium", "high") and "thường" in ml.explain(hits[0])

def test_threshold_calibrated_to_target_fp():
    det = ml.AnomalyDetector(learn_hours=1, min_windows=200, target_fp=0.01, cooldown=0)
    end = normal_traffic(det, 0, 6)
    n_windows, hits = 0, 0
    for s in range(3, 13):                                   # 10 giờ bình thường mới, khác seed
        t0 = end; end = normal_traffic(det, t0, 1, seed=s)
    st = det.status()["web"]
    assert st["threshold"] is not None
    # đếm qua status: tỉ lệ cửa sổ bình thường bị gắn cờ không quá 3 lần mục tiêu
    assert det.flagged_ratio("web") <= 0.03

def test_min_events_gate():
    det = ml.AnomalyDetector(learn_hours=0, min_windows=1)
    det.seed("web", normal_vectors(), first_seen=0)
    det.add(web("8.8.8.8", "/a", 404), 10); det.add(web("8.8.8.8", "/b", 404), 11)
    assert settle(det, 400) == [] and det.status()["web"]["windows"] == 1000   # 2 request < tối thiểu 5

def test_cooldown_suppresses_repeat():
    det = ml.AnomalyDetector(learn_hours=0, min_windows=1, cooldown=1800)
    det.seed("web", normal_vectors(), first_seen=0)
    out = []
    for w in range(3):                                       # 3 cửa sổ liên tiếp đều quét
        for i in range(300):
            det.add(web("9.9.9.9", f"/x{w}-{i}", 404), w * 300 + i * 0.5)
        out += det.flush(w * 300 + 331)
    out += det.flush(2 * 300 + 331 + ml.IDLE_SECONDS)
    assert len([a for a in out if a.entity == "9.9.9.9"]) == 1

def test_excluded_windows_not_learned():
    det = ml.AnomalyDetector(learn_hours=48, min_windows=200)
    for i in range(10):
        det.add(web("7.7.7.7", f"/a{i}"), 5)
    det.exclude("7.7.7.7", 5)
    settle(det, 400)
    assert det.status()["web"]["windows"] == 0

def test_late_events_for_closed_window_dropped():
    det = ml.AnomalyDetector()
    for i in range(6):
        det.add(web("1.2.3.4", f"/a{i}"), 10)
    settle(det, 400)                                         # đóng cửa sổ [0, 300)
    det.add(web("1.2.3.4", "/late"), 20)                     # event muộn của cửa sổ đã đóng
    assert det.flush(800) == [] and det.status()["web"]["dropped_late"] == 1
    assert det.status()["web"]["windows"] == 1

def test_caps_bound_memory():
    w = ml.Window(ml.SPECS["web"])
    for i in range(5000):
        w.add(web("1.1.1.1", f"/p{i}", 404, 0, f"ua{i}", i))
    assert w.vector()[1] == 1000 and w.vector()[6] == 1000 and len(w.event_ids) == 20
    det = ml.AnomalyDetector(max_entities=100)
    for k in range(150):
        det.add(web(f"10.1.{k // 250}.{k % 250}"), 1)
    det.flush(400)
    assert det.status()["web"]["dropped_entities"] == 50

def test_state_roundtrip_and_resume_learning(tmp_path):
    p = tmp_path / "ml-state.json"
    det = ml.AnomalyDetector(state_path=p, learn_hours=48)
    normal_traffic(det, 1000, 1)
    det.save()
    again = ml.AnomalyDetector(state_path=p, learn_hours=48)
    assert again.status()["web"]["windows"] == det.status()["web"]["windows"] > 0
    assert again.status()["web"]["first_seen"] == det.status()["web"]["first_seen"]
    assert json.loads(p.read_text(encoding="utf-8"))["version"] == 2

def test_corrupt_state_starts_fresh(tmp_path, caplog):
    p = tmp_path / "ml-state.json"; p.write_text("{không phải json", encoding="utf-8")
    det = ml.AnomalyDetector(state_path=p)
    assert det.status()["web"]["windows"] == 0 and "ML" in caplog.text

def test_windows_from_events_matches_online():
    docs = [(web("1.1.1.1", f"/a{i % 4}", 200 if i % 5 else 404, 3, "U", i), 10 + i) for i in range(12)]
    off = ml.windows_from_events(docs, ml.SPECS["web"])
    w = ml.Window(ml.SPECS["web"])
    for d, _ in docs:
        w.add(d)
    assert off[0][0] == "1.1.1.1" and off[0][1] == 0 and off[0][2] == w.vector()

def test_fp_does_not_drift_with_retrain():
    # fit lại mỗi giờ trên lưu lượng bình thường ổn định: tỉ lệ gắn cờ từng giờ không được trôi lên theo số lần fit
    det = ml.AnomalyDetector(learn_hours=1, min_windows=200, target_fp=0.01, cooldown=0, retrain_hours=1)
    hits, flush = [], det.flush
    det.flush = lambda now: hits.extend(flush(now)) or []       # cooldown=0: mỗi cửa sổ bị gắn cờ là một Anomaly
    end = normal_traffic(det, 0, 1)                              # học 1 giờ, active ở flush cuối
    for h in range(11):
        hits.clear()
        end = normal_traffic(det, end, 1, seed=100 + h)          # 12 cửa sổ x 50 IP = 600 cửa sổ được chấm
        assert len(hits) / 600 <= 3 * 0.01, f"giờ {h}: {len(hits)}/600"

def test_restart_does_not_reopen_closed_windows(tmp_path):
    p = tmp_path / "ml-state.json"
    det = ml.AnomalyDetector(state_path=p)
    for i in range(6):
        det.add(web("1.2.3.4", f"/a{i}"), 10)
    settle(det, 400); det.save()                                 # đóng cửa sổ [0, 300), watermark 460
    again = ml.AnomalyDetector(state_path=p)
    again.add(web("1.2.3.4", "/late"), 20)                       # backlog của cửa sổ đã đóng trước khi khởi động lại
    again.add(web("5.5.5.5", "/x"), 100)                         # cửa sổ đó cũng đã đóng với IP chưa có event nào
    again.add(web("1.2.3.4", "/new"), 320)                       # cửa sổ [300, 600) chưa đóng: nhận
    assert again.status()["web"]["dropped_late"] == 2 and again.status()["web"]["windows"] == 1

def test_non_finite_inputs_are_safe(tmp_path, caplog):
    w = ml.Window(ml.SPECS["web"])
    for b in (10 ** 400, float("nan"), float("inf"), -5 * 1024, "1e999", 1e300, 1024):
        d = web("1.1.1.1"); d["http"]["response"]["bytes"] = b
        w.add(d)
    v = w.vector()
    assert all(math.isfinite(x) for x in v) and v[5] == 1.0
    p = tmp_path / "ml-state.json"
    for bad in ('[[NaN, 6, 0, 0, 0, 1, 1]], "first_seen": 0', '[[6, 6, 0, 0, 0, 1, 1]], "first_seen": Infinity'):
        p.write_text('{"version": 2, "models": {"web": {"train": %s, "last_fit": null}}}' % bad, encoding="utf-8")
        caplog.clear()
        assert ml.AnomalyDetector(state_path=p).status()["web"]["windows"] == 0 and "ML" in caplog.text

def test_loads_state_without_flags(tmp_path):
    # file trạng thái version 2 cũ (chưa có "flagged", "last_flush"): mọi cửa sổ coi như không bị gắn cờ
    p = tmp_path / "ml-state.json"
    p.write_text(json.dumps({"version": 2, "last_flush": 700, "models": {"web": {"train": [[6, 6, 0, 0, 0, 1, 1]] * 3,
                                                                             "first_seen": 0, "last_fit": None}}}),
                 encoding="utf-8")
    det = ml.AnomalyDetector(state_path=p)
    det.add(web("1.2.3.4"), 20); det.add(auth("1.2.3.4"), 20)    # watermark chung cũ áp cho cả hai model
    assert det.status()["web"]["windows"] == 3
    assert det.status()["web"]["dropped_late"] == 1 and det.status()["auth"]["dropped_late"] == 1

def test_backlog_replay_keeps_windows_complete(tmp_path):
    # analyzer khởi động lại / agent dồn log: 30 phút event của 2 giờ trước tới theo lô 500, sau mỗi lô tick() gọi
    # flush(time.time()). Mọi cửa sổ phải đóng đủ (giống hệt gom offline), không event nào bị coi là muộn
    rng = random.Random(7); t0 = time.time() - 7200
    docs = sorted(((web(f"10.2.0.{k}", f"/p{rng.randint(1, 10)}", 200, 1, "UA", i), t0 + rng.uniform(0, 1800))
                   for k in range(20) for i in range(145)), key=lambda e: e[1])
    p = tmp_path / "ml-state.json"
    det = ml.AnomalyDetector(state_path=p)
    for b in range(0, len(docs), 500):
        for d, ts in docs[b:b + 500]:
            det.add(d, ts)
        det.flush(time.time())
    det.flush(time.time() + ml.IDLE_SECONDS); det.save()
    ref = sorted(v for _, _, v, _ in ml.windows_from_events(docs, ml.SPECS["web"]))
    assert det.status()["web"]["dropped_late"] == 0 and len(ref) >= 120
    assert sorted(json.loads(p.read_text(encoding="utf-8"))["models"]["web"]["train"]) == ref

def test_future_event_cannot_push_watermark_past_clock():
    det = ml.AnomalyDetector()
    for i in range(6):
        det.add(web("6.6.6.6", f"/f{i}"), 10 ** 6)                # đồng hồ máy gửi lệch về tương lai
    det.flush(400)
    det.add(web("1.2.3.4", "/a"), 350)                            # [300, 600) chưa hết theo đồng hồ: vẫn nhận
    det.flush(401)
    assert det.status()["web"]["dropped_late"] == 0 and det.status()["web"]["windows"] == 0

def test_idle_stream_closes_windows_by_clock():
    det = ml.AnomalyDetector()
    for i in range(6):
        det.add(web("1.2.3.4", f"/a{i}"), 10 + i)
    det.flush(400); det.flush(400 + ml.IDLE_SECONDS - 1)          # event vừa tới: watermark theo thời gian event (15)
    assert det.status()["web"]["windows"] == 0
    det.flush(400 + ml.IDLE_SECONDS)                              # im đủ IDLE_SECONDS: đóng theo đồng hồ
    assert det.status()["web"]["windows"] == 1

def test_cross_model_skew_not_dropped(tmp_path):
    # auth từ nguồn khác (sshd trên VM web, đăng nhập console) tới trễ 90 s so với web, tick flush mỗi giây:
    # watermark của model web không được làm rơi event auth, cửa sổ auth phải đủ như gom offline
    rng = random.Random(3); p = tmp_path / "ml-state.json"
    det = ml.AnomalyDetector(state_path=p); auths = []
    for now in range(1000, 4600):
        for k in range(3):
            det.add(web(f"10.4.0.{k}", f"/p{rng.randint(1, 10)}", n=now), now - rng.uniform(0, 1))
        if rng.random() < 0.2:
            auths.append((auth(f"10.5.0.{rng.randint(0, 2)}", f"u{rng.randint(0, 3)}", rng.random() < 0.8, now), now - 90))
            det.add(*auths[-1])
        det.flush(now)
    det.flush(5000); det.save()                                 # nguồn im tới quá cửa sổ auth cuối [4200, 4800)
    st = det.status()
    assert st["auth"]["dropped_late"] == 0 and st["web"]["dropped_late"] == 0
    ref = sorted(v for _, _, v, _ in ml.windows_from_events(auths, ml.SPECS["auth"]))
    assert ref and sorted(json.loads(p.read_text(encoding="utf-8"))["models"]["auth"]["train"]) == ref
