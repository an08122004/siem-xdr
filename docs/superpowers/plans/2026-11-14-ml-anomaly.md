# ML phát hiện bất thường (bật lại, thiết kế lại): kế hoạch triển khai

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** ML phát hiện bất thường chạy được thật trên stack: học "bình thường" từ lưu lượng của lab VM, báo nhầm thấp, có giải thích, chạy bóng trước khi thành alert thật, đo được bằng kịch bản tấn công.

**Architecture:**
- `server/siem/detection/ml.py` viết lại thành **nhiều model theo nguồn**:
  - `web`: theo IP nguồn, cửa sổ 5 phút;
  - `auth`: theo IP nguồn, cửa sổ 10 phút.
- Mỗi model đi qua các bước:
  1. **Học:** chưa báo gì cho tới khi đủ giờ và đủ cửa sổ.
  2. **Fit:** Isolation Forest trên các cửa sổ bình thường.
  3. **Đặt ngưỡng:** hiệu chỉnh trên tập giữ lại theo tỉ lệ báo nhầm mục tiêu (thay ngưỡng cứng −0,05 cũ).
  4. **Giải thích:** đặc trưng lệch nhiều nhất so với trung vị.
  5. **Chống lặp:** im lặng một khoảng sau mỗi lần báo.
  6. **Lưu trạng thái:** các vector cửa sổ ghi ra JSON, fit lại khi nạp, nên không phụ thuộc phiên bản scikit-learn.
- Alert ML là alert bóng (`ML_MODE=shadow`) tới khi đạt tiêu chí bật chính thức.
- `tools/ml_eval.py` dựng model offline từ event đã lưu trong ES và đo trên kịch bản tấn công (`tools/lab/mllab/attacks.py`).

**Tech Stack:** Python 3.12, scikit-learn `IsolationForest`, numpy (đã có trong `server/requirements.txt`), Elasticsearch 8, Wazuh 4.14.8, lab VMware: `Ubuntu_GSANM` = web, `Ubuntu-lab-wazuh` = client mô phỏng.

**Spec:** không có tài liệu thiết kế riêng. Chủ dự án chọn bỏ phần hỏi ("làm đi, vướng thì hỏi"). Mọi quyết định thiết kế dưới đây là **quyết định của controller**, chủ dự án đọc lại khi review.

## Bối cảnh (đo 14/11/2026)

- ML cũ (`ML-001`): Isolation Forest theo (IP, 60 giây), 8 đặc trưng, khởi tạo từ baseline **tổng hợp**, một model chung. Tắt từ 26/09 vì báo nhầm ~32% lưu lượng bình thường, và 100% với IP chỉ có 1 event (README).
- Stack thật cả tháng chỉ có 1.302 event, toàn từ **1 IP** (E2E/demo). CSIC mỗi request một IP giả, nên không dùng được cho model theo IP.
- Lab đã chạy từ 14/11 23:37 (script ở `tools/lab/mllab/`, commit aba4a13):
  - `Ubuntu_GSANM` 10.10.1.132: Apache có `/portal` Basic Auth, SSH, agent `lab-web`.
  - `Ubuntu-lab-wazuh`: dịch vụ `labsim` gồm 20 người dùng, IP 10.10.1.40–59; nhãn bình thường ở `/var/log/labsim/actions.jsonl`; agent `lab-client`.
  - Event về ES đúng IP nguồn (đã kiểm: `source.ip` 10.10.1.40, `host.name` lab-web, `url.path`, `http.response.status_code`).
- Analyzer gọi `detector.add(doc, ts)` cho mọi event và `detector.flush(now)` mỗi tick (`server/siem/analyzer.py`).
- Tài khoản ES của analyzer chỉ **ghi** `siem-events-*` và `siem-alerts`, không đọc lịch sử.
- Volume `mldata:/data` gắn vào analyzer (`settings.DATA_DIR`).

## Quyết định thiết kế

| # | Quyết định | Lý do |
|---|---|---|
| D1 | Hai model: `web` (khóa `source.ip`, cửa sổ 300 s, tối thiểu 5 request) và `auth` (khóa `source.ip`, cửa sổ 600 s, tối thiểu 1 lần đăng nhập). Bỏ đặc trưng cổng / bị chặn (lab chưa có log firewall) | Một model chung cho mọi nguồn là nguyên nhân chính của báo nhầm; cửa sổ 60 giây quá ngắn cho một phiên duyệt web |
| D2 | Bỏ baseline tổng hợp. Model chỉ hoạt động sau giai đoạn học: ≥ `ML_LEARN_HOURS` (48) giờ kể từ cửa sổ đầu tiên **và** ≥ `ML_MIN_WINDOWS` (200) cửa sổ | Baseline tổng hợp lệch dữ liệu thật |
| D3 | Ngưỡng = phân vị `ML_TARGET_FP` (0,005) của điểm trên **tập giữ lại**: 20% cửa sổ mới nhất, tối thiểu 50 | Báo nhầm có chủ đích thay cho ngưỡng cứng |
| D4 | Trạng thái lưu dạng JSON (`DATA_DIR/models/ml-state.json`, version 2) chứa vector cửa sổ; fit lại khi nạp | Pickle scikit-learn vỡ giữa các phiên bản (máy dev Python 3.14, image 3.12) |
| D5 | Không học cửa sổ của IP có alert thật (không bóng) của nguồn khác trong cùng cửa sổ, cũng không học cửa sổ ML đã gắn cờ | Chống "đầu độc" baseline |
| D6 | Mỗi (model, IP) báo tối đa 1 lần mỗi `ML_COOLDOWN_MINUTES` (30) | Chống lặp alert |
| D7 | Alert ML: `rule.id` `ML-WEB` / `ML-AUTH`, `alert.source` `ml`, `alert.shadow=true` khi `ML_MODE=shadow` (mặc định). Bật chính thức = đặt `ML_MODE=active` khi đạt tiêu chí chạy bóng của SOC-OPERATIONS mục 4 (≥ 7 ngày, < 5 alert/ngày, báo nhầm < 30%) | Dùng lại cơ chế bóng sẵn có (SOAR bỏ qua, KPI không tính) |
| D8 | Giải thích: tối đa 3 đặc trưng có `(x + 1) / (trung vị + 1) ≥ 2`, xếp giảm dần, dạng `n_paths=340 (thường 8)` | Analyst đọc được, không cần hiểu điểm Isolation Forest |
| D9 | Mức độ theo khoảng cách dưới ngưỡng `m = ngưỡng − điểm`: `m > 0,15` high, `m > 0,05` medium, còn lại low | Đơn điệu, dễ kiểm |
| D10 | Mô hình live có thể khởi tạo offline: `tools/ml_eval.py train` đọc event trong ES (tool chạy trên máy host, đọc qua `docker compose exec elasticsearch curl` như `tools/es_snapshot.py`), ghi `ml-state.json`, chép vào volume của analyzer | Analyzer không có quyền đọc ES; lab đã thu dữ liệu từ 14/11 |
| D11 | Kịch bản tấn công chạy trên máy client của lab, từ IP 10.10.1.60–69 (khác dải người dùng 40–59); nhãn ở `/var/log/labsim/attacks.jsonl` | Kali không bắt buộc; nhãn rõ ràng theo IP và thời gian |

## Global Constraints

- Python: test chạy được trên CI (Python 3.12) **và** máy dev (`PY=D:/GSANM/BTL/siem-xdr/server/.venv/Scripts/python`, Python 3.14). Không dùng cú pháp hay hành vi khác nhau giữa hai bản; regex chạy trên cả hai.
- Không thêm dependency: chỉ numpy, scikit-learn, stdlib (`server/requirements.txt` hiện có). Script chạy trong VM chỉ dùng stdlib, `sshpass` và `curl`.
- Tên model, rule id, hằng số: `web` / `auth`, `ML-WEB` / `ML-AUTH`; cửa sổ 300 / 600 s; tối thiểu 5 / 1 event; mặc định `ML_LEARN_HOURS=48`, `ML_MIN_WINDOWS=200`, `ML_TARGET_FP=0.005`, `ML_COOLDOWN_MINUTES=30`, `ML_RETRAIN_HOURS=24`, `ML_MODE=shadow`, `ML_ENABLED=false`.
- Thử nghiệm KHÔNG đụng stack thật `siem-xdr-*`, trừ Task 4 khi chủ dự án đã gộp PR và đồng ý triển khai.
- Lab VM:
  - chỉ dùng `Ubuntu_GSANM` và `Ubuntu-lab-wazuh`; KHÔNG dùng VM Windows 11 / Windows Server (lab CEH của chủ máy);
  - tài khoản tạo ra trong VM luôn có tiền tố `lab_` và thuộc nhóm `labsim`, không bao giờ đổi mật khẩu tài khoản khác;
  - không dừng stack siem-xdr cũ trong `Ubuntu_GSANM`.
- Không in hay commit `secrets/` (`Lab_vms.txt`, `lab-sim-users.txt`, `enrollment_key`…).
- Thông điệp và tài liệu tiếng Việt có dấu; chi tiết pipeline và thí nghiệm ML ghi vào `AI-README.md`, `README.md` chỉ tóm tắt và link.

## Review Focus

1. **Máy host ngủ rồi thức:** agent dồn log cũ về một lúc. Mong đợi: event rơi đúng cửa sổ theo thời gian event; event tới muộn cho cửa sổ đã đóng thì bỏ và đếm, không mở lại cửa sổ thành nửa cửa sổ. Test `test_late_events_for_closed_window_dropped` (Task 1).
2. **Analyzer khởi động lại giữa giai đoạn học:** mong đợi học tiếp từ trạng thái đã lưu (giữ `first_seen` và số cửa sổ), không học lại từ đầu. Test `test_state_roundtrip_and_resume_learning` (Task 1).
3. **File trạng thái hỏng hoặc khác version:** mong đợi ghi cảnh báo và học lại từ đầu, analyzer không chết. Test `test_corrupt_state_starts_fresh` (Task 1).
4. **Một IP quét hàng chục nghìn đường dẫn hoặc rất nhiều IP trong một cửa sổ:** mong đợi bộ nhớ bị chặn (≤ 1000 phần tử mỗi tập, ≤ 50.000 IP mỗi cửa sổ, phần vượt bị bỏ và đếm). Test `test_caps_bound_memory` (Task 1).
5. **Tấn công trong giai đoạn học bị học thành bình thường:** mong đợi cửa sổ của IP có alert thật không vào tập học. Test `test_excluded_windows_not_learned` (Task 1) và `test_analyzer_excludes_alerted_ip` (Task 2).

---

### Task 1: Bộ phát hiện đa model (`server/siem/detection/ml.py`)

**Files:**
- Modify: `server/siem/detection/ml.py`. Viết lại; bỏ `synthetic_baseline`, `_Bucket`, `severity_for`, `describe`, `feature_dict` cũ.
- Test: `server/tests/test_ml.py` (mới).

**Interfaces:**
- Produces:
  - `FEATURES_WEB = ("n_requests", "n_paths", "ratio_4xx", "n_401", "n_404", "kb_out", "n_agents")`
  - `FEATURES_AUTH = ("n_attempts", "n_fail", "fail_ratio", "n_users", "n_success")`
  - `@dataclass(frozen=True) class ModelSpec: name: str; rule_id: str; title: str; window: int; min_events: int; features: tuple[str, ...]; tactic: str; technique: str`
  - `SPECS: dict[str, ModelSpec]`:
    - `web`: `ML-WEB`, "Hành vi web bất thường của IP nguồn", 300, 5, `FEATURES_WEB`, "Reconnaissance", "T1595";
    - `auth`: `ML-AUTH`, "Hành vi đăng nhập bất thường của IP nguồn", 600, 1, `FEATURES_AUTH`, "Credential Access", "T1110".
  - `accepts(spec: ModelSpec, doc: Doc) -> bool`:
    - `web`: `event.category == "web"` và có `source.ip` và `http.response.status_code`;
    - `auth`: `event.category == "authentication"` và có `source.ip`;
    - IP có `source.ip_scope == "loopback"` thì bỏ.
  - `class Window` (bộ cộng dồn của một (model, IP, cửa sổ)):
    - `add(doc) -> None`, `vector() -> list[float]`, `n: int`, `last_event: Doc`, `event_ids: list[str]` (≤ 20);
    - mỗi tập ≤ 1000 phần tử.
  - `@dataclass class Anomaly: model: str; entity: str; score: float; threshold: float; features: dict[str, float]; top: list[tuple[str, float, float]]; event: Doc; event_ids: list[str]; window_start: float`
  - `class AnomalyDetector`:
    - `__init__(self, state_path: Path | None = None, learn_hours: float = 48, min_windows: int = 200, target_fp: float = 0.005, cooldown: float = 1800, retrain_hours: float = 24, grace: int = 30, specs: dict[str, ModelSpec] = SPECS)`
    - `add(self, doc: Doc, ts: float) -> None`
    - `exclude(self, entity: str, ts: float) -> None`
    - `flush(self, now: float) -> list[Anomaly]`
    - `status(self) -> dict[str, dict]`: `{"phase": "learning"|"active", "windows": int, "threshold": float | None, "first_seen": float | None, "dropped_late": int}`
    - `save(self) -> None`
    - `seed(self, name: str, vectors: list[list[float]], first_seen: float) -> None`: khởi tạo offline cho Task 3.
  - `windows_from_events(docs: Iterable[tuple[Doc, float]], spec: ModelSpec) -> list[tuple[str, float, list[float], Window]]`: (IP, đầu cửa sổ, vector, cửa sổ), dùng chung với Task 3, cùng code cộng dồn như `add`.
  - `severity(a: Anomaly) -> str` (D9); `explain(a: Anomaly) -> str` (D8, chuỗi rỗng khi không có đặc trưng nào ≥ 2 lần).
- Định nghĩa đặc trưng:
  - **web:**
    - `n_requests` = số event;
    - `n_paths` = số `url.path` khác nhau;
    - `ratio_4xx` = tỉ lệ `status` trong [400, 500);
    - `n_401`, `n_404`;
    - `kb_out` = tổng `http.response.bytes` / 1024;
    - `n_agents` = số `user_agent.original` khác nhau.
  - **auth:**
    - `n_attempts` = số event;
    - `n_fail` = số `event.outcome == "failure"`;
    - `fail_ratio = n_fail / n_attempts`;
    - `n_users` = số `user.name` khác nhau;
    - `n_success` = số `outcome == "success"`.
  - Đặc trưng đếm qua `log1p` trước khi fit; tỉ lệ để nguyên.

- [ ] **Step 1: Viết test thất bại** (`server/tests/test_ml.py`)

```python
import json, random
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
    assert det.flush(end + 400) == [] and det.status()["web"]["phase"] == "learning"

def test_active_flags_scan_not_normals():
    det = ml.AnomalyDetector(learn_hours=1, min_windows=200)
    end = normal_traffic(det, 0, 6)                         # 72 cửa sổ x 50 IP
    assert det.status()["web"]["phase"] == "active"
    later = normal_traffic(det, end, 1, seed=2)             # thêm 12 cửa sổ x 50 IP bình thường
    assert det.flagged_ratio("web") <= 0.02                 # cửa sổ bình thường hầu như không bị gắn cờ
    for i in range(400):
        det.add(web("9.9.9.9", f"/x{i}", 404, 0, "scanner", i), later + 5 + i * 0.5)
    hits = [a for a in det.flush(later + 300 + 31) if a.entity == "9.9.9.9"]
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
    det.seed("web", [[10, 5, 0.0, 0, 0, 20.0, 1]] * 300, first_seen=0)
    det.add(web("8.8.8.8", "/a", 404), 10); det.add(web("8.8.8.8", "/b", 404), 11)
    assert det.flush(400) == []                              # 2 request < tối thiểu 5

def test_cooldown_suppresses_repeat():
    det = ml.AnomalyDetector(learn_hours=0, min_windows=1, cooldown=1800)
    det.seed("web", [[10, 5, 0.0, 0, 0, 20.0, 1]] * 300, first_seen=0)
    out = []
    for w in range(3):                                       # 3 cửa sổ liên tiếp đều quét
        for i in range(300):
            det.add(web("9.9.9.9", f"/x{w}-{i}", 404), w * 300 + i * 0.5)
        out += det.flush(w * 300 + 331)
    assert len([a for a in out if a.entity == "9.9.9.9"]) == 1

def test_excluded_windows_not_learned():
    det = ml.AnomalyDetector(learn_hours=48, min_windows=200)
    for i in range(10):
        det.add(web("7.7.7.7", f"/a{i}"), 5)
    det.exclude("7.7.7.7", 5)
    det.flush(400)
    assert det.status()["web"]["windows"] == 0

def test_late_events_for_closed_window_dropped():
    det = ml.AnomalyDetector()
    for i in range(6):
        det.add(web("1.2.3.4", f"/a{i}"), 10)
    det.flush(400)                                           # đóng cửa sổ [0, 300)
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
```

  `AnomalyDetector` có thêm hai thành phần mà test dùng:
  - tham số `max_entities: int = 50000`, cùng `status()[name]["dropped_entities"]`;
  - phương thức `flagged_ratio(name: str) -> float`: số cửa sổ bị gắn cờ / số cửa sổ đã chấm điểm, kể từ khi model chuyển sang active.

- [ ] **Step 2: Chạy test, phải thất bại**
  Run: `cd server && $PY -m pytest tests/test_ml.py -q`
  Expected: FAIL, `AttributeError: module 'siem.detection.ml' has no attribute 'Window'` hoặc tương tự.

- [ ] **Step 3: Viết lại `ml.py`**

  Cửa sổ:
  - Khóa theo `int(ts // spec.window)`.
  - `flush(now)` đóng mọi cửa sổ có `(idx + 1) * window + grace <= now`, rồi ghi `idx` vào tập đã đóng (giữ 2000 idx mới nhất mỗi model).
  - `add` cho cửa sổ đã đóng thì tăng `dropped_late` và bỏ event.

  Chấm điểm khi model active:
  - Bỏ qua cửa sổ có `n < min_events`.
  - Anomaly khi `decision_function < threshold`.
  - Cửa sổ của IP đang trong thời gian im lặng thì không báo lại, nhưng vẫn không đưa vào tập học.

  Học:
  - Thêm vào tập học các vector bình thường không bị gắn cờ, không bị `exclude` (cùng IP, cùng idx cửa sổ).
  - Giữ tối đa 20.000 vector mỗi model.

  Fit:
  - `IsolationForest(n_estimators=200, random_state=0)` trên phần đầu (80%).
  - Ngưỡng = `np.quantile(scores(holdout), target_fp)` với holdout là 20% vector mới nhất, tối thiểu 50.
  - Fit lại khi chuyển sang active, khi đủ `retrain_hours` kể từ lần fit trước, và khi nạp trạng thái.

  Lưu: JSON `{"version": 2, "models": {name: {"train": [...], "first_seen": float|null, "last_fit": float|null}}}`, ghi file tạm rồi `os.replace`. `explain` / `severity` theo D8 / D9.

- [ ] **Step 4: Chạy test, phải qua; chạy cả bộ**
  Run: `cd server && $PY -m pytest tests/test_ml.py -q && $PY -m pytest -q`
  Expected: `test_ml.py` qua hết.

  Test cũ nào gọi API ML cũ (`test_pipeline.py`) thì để nguyên ở task này và ghi lại; Task 2 sửa.

- [ ] **Step 5: Commit**
  `git add server/siem/detection/ml.py server/tests/test_ml.py && git commit -m "feat(ml): bộ phát hiện bất thường đa model (web/auth), học trên dữ liệu thật, ngưỡng hiệu chỉnh, giải thích"`

---

### Task 2: Gắn vào analyzer, alert, cấu hình, dashboard, tài liệu thiết kế

**Files:**
- Modify:
  - `server/siem/analyzer.py` (khởi tạo detector, `exclude` khi có alert thật, phát alert ML, log trạng thái mỗi giờ);
  - `server/siem/detection/alerts.py` (`from_anomaly`);
  - `server/siem/settings.py` (biến ML mới, bỏ biến cũ);
  - `.env.example`;
  - `tools/gen_dashboard.py` + JSON dashboard sinh ra + `DASHBOARDS.md`;
  - `tools/e2e_test.py` (nếu số panel đổi).
- Docs (phần thiết kế, chưa có số đo):
  - `AI-README.md`: mục ML mới;
  - `README.md`: thay đoạn "ML (tạm dừng…)";
  - `RULES.md`: dòng ML trong bảng nguồn phát hiện;
  - `SOC-OPERATIONS.md`: mục 4, bật chính thức ML;
  - `DEPLOY-VM.md`: lab ML và cách bật.
- Test: `server/tests/test_ml_alert.py` (mới); sửa test cũ gọi API ML cũ.

**Interfaces:**
- Consumes: Task 1 (`AnomalyDetector`, `Anomaly`, `SPECS`, `severity`, `explain`).
- Produces:
  - `alerts.from_anomaly(a: ml.Anomaly, spec: ml.ModelSpec, shadow: bool) -> Doc`;
  - settings `ML_ENABLED`, `ML_MODE`, `ML_LEARN_HOURS`, `ML_MIN_WINDOWS`, `ML_TARGET_FP`, `ML_COOLDOWN_MINUTES`, `ML_RETRAIN_HOURS`;
  - `ML_STATE_PATH = DATA_DIR / "models" / "ml-state.json"`.
- Bỏ: `ML_WINDOW_SECONDS`, `ML_MIN_SAMPLES`, `ML_CONTAMINATION`, `ML_BOOTSTRAP_SYNTHETIC`.

- [ ] **Step 1: Viết test thất bại**

```python
def test_from_anomaly_shadow_fields():
    a = ml.Anomaly("web", "9.9.9.9", -0.31, -0.08, {"n_requests": 400.0, "n_paths": 340.0}, [("n_paths", 340.0, 8.0)],
                   {"@timestamp": "2026-11-20T10:00:00Z", "source": {"ip": "9.9.9.9"}}, ["e1"], 0.0)
    al = alerts.from_anomaly(a, ml.SPECS["web"], shadow=True)
    assert al["rule"]["id"] == "ML-WEB" and al["alert"]["source"] == "ml" and al["alert"]["shadow"] is True
    assert al["rule"]["mode"] == "shadow" and al["severity"] == "high" and al["source"]["ip"] == "9.9.9.9"
    assert al["ml"]["model"] == "web" and al["ml"]["threshold"] == -0.08 and "n_paths=340 (thường 8)" in al["rule"]["description"]
    assert al["rule"]["mitre"]["technique"] == ["T1595"]

def test_from_anomaly_active_is_real_alert():
    ...al = alerts.from_anomaly(a, ml.SPECS["auth"], shadow=False); assert "shadow" not in al["alert"] and al["rule"]["id"] == "ML-AUTH"

def test_analyzer_excludes_alerted_ip(monkeypatch):
    # analyzer nhận một wazuh_alert (không bóng) có source.ip 5.5.5.5 → detector.exclude("5.5.5.5", ts) được gọi
    ...

def test_soar_ignores_shadow_ml_alert():
    # alert ML bóng không khớp playbook nào kể cả playbook có sources ["rule", "ml"]
    ...
```

- [ ] **Step 2: Chạy test, phải thất bại**
  Run: `cd server && $PY -m pytest tests/test_ml_alert.py -q`
  Expected: FAIL.

- [ ] **Step 3: Viết code**

  Analyzer:
  - Tạo `ml.AnomalyDetector(state_path=settings.ML_STATE_PATH, …)` khi `ML_ENABLED`.
  - Với `wazuh_alert`: nếu alert dựng được, không bóng, và có `source.ip`, thì `detector.exclude(ip, event_time)`.
  - Mỗi giờ: `detector.save()` và log `ML web: active, 812 cửa sổ, ngưỡng -0.071`.
  - Tick: phát `from_anomaly(a, ml.SPECS[a.model], shadow=settings.ML_MODE != "active")`.

  `from_anomaly`:
  - Giữ các trường chung như alert khác (`_copy_entities`, `_timing`, `_message`).
  - `severity = ml.severity(a)`.
  - Mô tả: `f"Điểm bất thường {a.score:.3f} (ngưỡng {a.threshold:.3f}). {ml.explain(a)}"`.
  - `ml = {"model", "score", "threshold", "features", "top"}`; `rule.mitre = {"tactic": spec.tactic, "technique": [spec.technique]}`.
  - Khi `shadow` thì `alert.shadow = true` và `rule.mode = "shadow"`.

  Dashboard: thêm 2 panel vào dashboard alert:
  - "Alert ML theo model (gồm bóng)": đếm theo `rule.id`, lọc `alert.source:ml`;
  - "IP bị ML gắn cờ nhiều nhất": top 10 `source.ip`.

  Cập nhật số panel kỳ vọng trong `e2e_test.py`, chạy lại generator.

  Tài liệu: D1–D11, cách bật (`ML_ENABLED=true`, mặc định chạy bóng), tiêu chí bật chính thức, lab ML (`tools/lab/mllab/`). Chưa ghi số đo.

- [ ] **Step 4: Chạy test, phải qua; chạy cả bộ; lint**
  Run: `cd server && $PY -m pytest -q && cd .. && $PY tools/wazuh_rule_lint.py`
  Expected: PASS, lint 0 lỗi.

- [ ] **Step 5: Commit**
  `git commit -m "feat(ml): alert ML-WEB/ML-AUTH chạy bóng, analyzer loại IP có alert khỏi tập học, dashboard, tài liệu"`

---

### Task 3: Kịch bản tấn công và công cụ đánh giá / khởi tạo offline

**Files:**
- Create:
  - `tools/lab/mllab/attacks.py` (chạy trong VM client, stdlib + `sshpass`);
  - `tools/ml_eval.py` (chạy trên máy host);
  - `server/tests/test_ml_eval.py`.

**Interfaces:**
- Consumes: Task 1 (`windows_from_events`, `AnomalyDetector`, `seed`, `SPECS`); `tools/es_snapshot.es(method, path, body)`.
- Produces:
  - `attacks.py`, CLI: `python3 attacks.py --web 10.10.1.132 --ips 10.10.1.60-69 --dev ens37 --users /opt/labsim/users.txt --scenario all|<tên> --log /var/log/labsim/attacks.jsonl`.
    - Mỗi kịch bản một IP riêng, theo thứ tự trong dải.
    - Nhãn mỗi dòng: `{"scenario", "ip", "start", "end"}` (ISO có múi giờ).
  - `ml_eval.py train --from ISO --to ISO --out PATH [--exclude-ips 10.10.1.60-69]`: ghi file trạng thái version 2 cho analyzer.
  - `ml_eval.py eval --train-from --train-to --test-from --test-to --attacks FILE --out REPORT.md`.
  - Hàm thuần dùng cho test:
    - `match(anomalies: list[ml.Anomaly], scenarios: list[dict]) -> dict[str, dict]`: theo IP và khoảng thời gian (± 1 cửa sổ);
    - `fp_rate(anomalies, normal_ips: set[str], scored_windows: int) -> float`.

Kịch bản (ghim giá trị):

| Tên | Hành vi |
|---|---|
| `scan_dirs` | 400 GET đường dẫn ngẫu nhiên kiểu wordlist trong ~60 s (chủ yếu 404) |
| `portal_bruteforce` | 150 lần Basic Auth sai cho user có thật trong 5 phút (401) |
| `password_spray` | 20 user × 2 mật khẩu sai trong 10 phút |
| `ssh_bruteforce` | 40 lần SSH sai mật khẩu vào `lab_an` trong 10 phút |
| `slow_scan` | 1 request mỗi 20 s tới đường dẫn khác nhau trong 30 phút |
| `scraper` | tải mọi trang công khai 3 lượt trong 3 phút |
| `exfil` | tải 8 tài liệu × 5 lượt trong 10 phút |

- [ ] **Step 1: Viết test thất bại** (`server/tests/test_ml_eval.py`; nạp `tools/ml_eval.py` theo đường dẫn)

```python
def test_match_anomalies_to_scenarios():
    sc = [{"scenario": "scan_dirs", "ip": "10.10.1.60", "start": "2026-11-17T10:00:00+07:00", "end": "2026-11-17T10:01:00+07:00"},
          {"scenario": "slow_scan", "ip": "10.10.1.61", "start": "2026-11-17T11:00:00+07:00", "end": "2026-11-17T11:30:00+07:00"}]
    a = anomaly("web", "10.10.1.60", window_start=epoch("2026-11-17T10:00:00+07:00"))
    out = ev.match([a], sc)
    assert out["scan_dirs"]["detected"] is True and out["slow_scan"]["detected"] is False

def test_fp_rate_counts_only_normal_ips():
    assert ev.fp_rate([anomaly("web", "10.10.1.41"), anomaly("web", "10.10.1.60")], {"10.10.1.41"}, 200) == 0.005

def test_train_excludes_attack_ips():
    vecs = ev.training_vectors(fake_events(ips=["10.10.1.41", "10.10.1.60"]), exclude={"10.10.1.60"})
    assert vecs["web"] and all(ip != "10.10.1.60" for ip in vecs_ips(vecs))
```

  Các helper `anomaly`, `epoch`, `fake_events`, `vecs_ips` viết trong file test. `training_vectors(events, exclude) -> dict[str, list[list[float]]]`.

- [ ] **Step 2: Chạy test, phải thất bại**
  Run: `cd server && $PY -m pytest tests/test_ml_eval.py -q`
  Expected: FAIL.

- [ ] **Step 3: Viết `attacks.py`, `ml_eval.py`**

  `ml_eval.py` đọc ES:
  - `siem-events-*` theo khoảng thời gian, `search_after`, mỗi trang 5000, sắp theo `@timestamp`;
  - `siem-alerts` để điền cột "rule Wazuh đã bắt?" (alert `alert.source:wazuh` không bóng, cùng IP, trong khoảng kịch bản).

  Báo cáo markdown gồm:
  - dải thời gian học / thử;
  - số cửa sổ;
  - ngưỡng từng model;
  - bảng kịch bản: bắt được?, lần đầu sau bao lâu, đặc trưng nổi bật, rule Wazuh có bắt không;
  - tỉ lệ báo nhầm trên IP 10.10.1.40–59.

- [ ] **Step 4: Chạy test, phải qua; thử nhanh trên lab**
  Run: `cd server && $PY -m pytest tests/test_ml_eval.py -q`. Sau đó chép `attacks.py` vào VM client và chạy `--scenario scan_dirs`. Kiểm `/var/log/labsim/attacks.jsonl` có 1 dòng, và ES có event từ 10.10.1.60.
  Expected: PASS; event về ES.

- [ ] **Step 5: Commit**
  `git commit -m "feat(ml): kịch bản tấn công lab và công cụ đánh giá / khởi tạo model từ ES"`

---

### Task 4: Học, đo, bật chạy bóng trên stack thật, số liệu vào tài liệu

Điều kiện: chủ dự án đã gộp PR của Task 1–3 và đồng ý triển khai; lab đã thu ≥ 48 giờ lưu lượng bình thường (từ 14/11 23:37).

**Files:** `AI-README.md` (số đo), `Test.md`, `README.md` (một dòng số đo), `.env` của máy chạy (không commit).

- [ ] **Step 1: Triển khai mã** theo `DEPLOY-VM.md` §9: sao lưu, build, `up` với cùng profile đang chạy; chạy E2E và ghi lại kết quả.
- [ ] **Step 2: Đo offline trước khi bật**
  1. `python tools/ml_eval.py eval`: học từ 14/11 23:37 tới mốc T, thử từ T.
  2. Chạy `attacks.py --scenario all` trong VM client sau mốc T.
  3. Chờ ≥ 15 phút cho cửa sổ đóng, chạy lại `eval`.
  4. Lưu báo cáo vào `docs/ml-eval-<ngày>.md`.
  - Báo nhầm trên 10.10.1.40–59 > 1% thì dừng, ghi lại, báo controller.
- [ ] **Step 3: Khởi tạo và bật chạy bóng**
  1. `python tools/ml_eval.py train --from <14/11 23:37> --to <now> --out build/ml-state.json --exclude-ips 10.10.1.60-69`.
  2. `docker compose cp build/ml-state.json analyzer:/data/models/ml-state.json`.
  3. Đặt `ML_ENABLED=true` trong `.env`; giữ `ML_MODE` mặc định là shadow.
  4. `up -d analyzer`.
  - Kiểm log có `ML web: active` và `ML auth: active` (hoặc `learning`, nếu chưa đủ cửa sổ auth).
- [ ] **Step 4: Kiểm trên live** bằng một kịch bản `scan_dirs`: trong ≤ 10 phút có alert `ML-WEB` bóng cho IP đó trên Grafana; SOAR không chạy playbook.
- [ ] **Step 5: Ghi số đo** vào AI-README (mục ML: bảng kịch bản, báo nhầm, ngưỡng, so với rule Wazuh) và Test.md. Commit, mở PR.

## Ngoài phạm vi (giai đoạn 2)

- ML theo hành vi tiến trình trên máy Windows (Sysmon). Cần máy Windows chủ dự án đề nghị thêm; KHÔNG dùng VM Windows 11 của lab CEH.
- Model mạng (cổng, kết nối bị chặn) khi lab có firewall OPNsense.
- Gắn ML với AI sinh rule: dùng alert ML đã xác nhận đúng làm gợi ý khoảng trống.
