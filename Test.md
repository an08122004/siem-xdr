# Kết quả kiểm thử toàn bộ siem-xdr — 15/10/2026

Mã được kiểm thử: nhánh `feature/wazuh-auth-grafana` @ `52c653d` (bản siem-xdr, trước khi đổi tên sang soc-platform).
Máy chạy: Windows 11, Docker Desktop 29.7.2, stack dựng lại bằng `docker compose --profile demo up -d --build`.

## 1. Tóm tắt

**Tất cả các bộ test của repo đều đạt.** Toàn bộ chuỗi xử lý chạy đúng trên hệ thống thật: tấn công → event → alert → SOAR → Wazuh agent → phản ứng.
Không có lỗi chức năng nào. Có **2 vấn đề bảo mật**, **2 lỗi nhỏ trong mã / cấu hình** và một số điểm yếu cần biết (mục 3).

| Hạng mục | Kết quả |
|---|---|
| Unit test (`pytest`, Python 3.12 như image server) | **180/180 đạt** (42 giây), độ phủ mã 79% (6.141 dòng) |
| Unit test cấu hình Vector (`vector test`) | **5/5 đạt** (syslog 2, Wazuh 3) |
| `docker compose config` (mọi profile + GPU) | **Hợp lệ**, 15 service |
| Cú pháp toàn repo | **0 lỗi**: 59 Python, 17 YAML, 4 JSON, 1 XML, 3 shell (`bash -n`), JS trong 2 trang console (`node --check`), 1 PowerShell |
| Dashboard Grafana sinh lại (`tools/gen_dashboard.py`) | **Khớp 100%** với 3 file JSON đã commit |
| Dựng stack | 11 container chạy (thêm `es-certs`, `es-setup` chạy một lần rồi thoát mã 0), `restarts=0`, mọi service có healthcheck đều `healthy` |
| Kafka | Lag = 0 ở cả `siem-analyzer` lẫn `siem-soar` |
| End-to-end trên stack thật (`tools/e2e_test.py`) | **44/44 đạt** (100 giây) |
| Giao diện bằng Edge thật (`tools/ui_test.py`) | **26/26 đạt**, không có lỗi JavaScript |
| Độ phủ rule trên dataset công khai (`python -m siem.ai.benchmark`) | Tái lập **đúng từng số** của `datasets/report.md`; báo nhầm 0% |

## 2. Chi tiết từng phần

### 2.1 Unit test
- Lệnh: `python -m pytest -q` trong thư mục `server/`, chạy trong container dùng một lần từ image `siem-xdr-server:latest`.
- 180 test đạt. Có 1 cảnh báo: `StarletteDeprecationWarning: Using httpx with starlette.testclient is deprecated` (xem mục 3.6).
- Module có độ phủ thấp nhất: `ai/__main__.py`, `soar/__main__.py` (0%, chỉ là điểm vào), `bus.py` 23% (Kafka), `ai/dataset.py` 30%,
  `store.py` 48% (Elasticsearch), `analyzer.py` 49%. Đây đều là phần chạy với hạ tầng thật. Test end-to-end đã kiểm tra các phần này.

### 2.2 End-to-end (stack thật, `--profile demo`)
| Kịch bản | Kết quả | Ghi chú |
|---|---|---|
| Đăng nhập / phân quyền console | 13/13 | mật khẩu tạm bị buộc đổi, chống CSRF, analyst bị chặn các thao tác của trưởng nhóm IR |
| SQL injection → chặn IP | 6/6 | alert WEB-001 sau 6 giây, SOAR chặn IP qua Wazuh sau 16 giây, analyst gỡ chặn được |
| Command injection → kill | 3/3 | alert LNX-002, SOAR kill cả cây tiến trình, request bị cắt ở giây 12,8 |
| Webshell → FIM → case | 3/3 | alert WZH-100100 (T1505.003) sau 10 giây, case PB-12 có 29 task |
| Grafana sau manager (SSO) | 15/15 | cổng 3000 không mở ra ngoài, header giả vô tác dụng, Viewer không sửa được, thư viện rule đủ 40/40 rule |
| Hồi quy các lỗi đã sửa | 4/4 | |

Script tự dọn: tài khoản `e2e-admin` và `e2e-an` đã bị xóa. Sau khi chạy, console chỉ còn tài khoản `admin`.

### 2.3 Giao diện (Edge, headless)
26/26 đạt: đăng nhập qua liên kết sâu, danh sách và chi tiết cảnh báo, case, dashboard Grafana nhúng (không tự tải lại),
điều tra thực thể, thư viện rule, so sánh đề xuất AI, các trang còn lại, màn hình điện thoại 390px không bị tràn ngang, đăng xuất. Không có lỗi JavaScript.

### 2.4 Kiểm tra hệ thống đang chạy
- `/health` trả `{"status":"ok"}`. Gọi `/api/v1/alerts|cases|users` và `/grafana/` khi chưa đăng nhập đều nhận 401.
- Header bảo mật: có `X-Content-Type-Options`, `X-Frame-Options`, `CSP frame-ancestors`, `Referrer-Policy`. Không có HSTS.
- Elasticsearch chỉ nghe trên `127.0.0.1:9200` và đòi xác thực. Tài khoản ES của manager bị giới hạn quyền (không đọc được snapshot hay thống kê index), đúng thiết kế RBAC.
- Wazuh: các daemon chính đều chạy. Chỉ có 1 agent (`001 demo-web`) đang online.
- Analyzer nạp 40 rule, SOAR sẵn sàng (`auto_response=True`).

### 2.5 Độ phủ phát hiện trên dataset công khai
| Lĩnh vực | Mẫu tấn công | Phát hiện | Báo nhầm |
|---|---|---|---|
| Web (CSIC 2010) | 15.088 | 1.659 (11,0%), 3/10 loại | 0 / 36.000 |
| Windows | 2.813 | 183 (6,5%), 39/134 kỹ thuật | 0 / 671 |
| Linux | 1.414 | 12 (0,8%), 7/78 kỹ thuật | 0 / 200 |

Web theo loại: XSS 100%, SQLi 67,4%, SSI 26,8%. Bốn loại có thể viết rule chữ ký vẫn ở mức 0%: dò file sao lưu (2.615 mẫu), dò đường dẫn nhạy cảm (885), CRLF (540) và mã hóa né tránh (466).

## 3. Lỗi và rủi ro phát hiện được (xếp theo mức độ)

### 3.1 [Trung bình, bảo mật] kafka-ui không xác thực và cho phép ghi vào Kafka
- Vị trí: `docker-compose.yml:96` (`kafka-ui`).
- Đã kiểm chứng: `GET http://127.0.0.1:8088/api/clusters` trả `"readOnly": false` cùng tính năng `TOPIC_DELETION`, và không đòi đăng nhập.
- Hệ quả: người hoặc tiến trình bất kỳ trên máy chạy Docker có thể gửi alert giả vào `siem.alerts`. Vì `SOAR_AUTO_RESPONSE=true`, SOAR sẽ chặn IP hoặc kill tiến trình thật trên agent.
  Kẻ đó cũng có thể xóa topic `siem.raw`. Điều này đi ngược ghi chú trong compose rằng Kafka "không publish ra ngoài".
  Lần kiểm thử này không gửi thử alert giả, vì làm vậy sẽ kích hoạt SOAR thật.
- Cách sửa (1 dòng): thêm `KAFKA_CLUSTERS_0_READONLY: "true"` vào môi trường của kafka-ui. Cách khác là đưa kafka-ui vào một profile riêng và chỉ bật khi cần gỡ lỗi.

### 3.2 [Thấp–Trung bình, bảo mật] Tài liệu API công khai không cần đăng nhập
- Vị trí: `server/siem/manager/api.py:77`, `FastAPI(...)` để mặc định nên mở `/docs`, `/redoc` và `/openapi.json`.
- Đã kiểm chứng: cả 3 đường dẫn trả 200 khi chưa đăng nhập, trên cổng 8000 mở ra `0.0.0.0`, làm lộ sơ đồ của 23 đường dẫn API (gồm luồng đăng nhập).
- Cách sửa: `FastAPI(..., docs_url=None, redoc_url=None, openapi_url=None)`.

### 3.3 [Thấp, lỗi mã] Index `console-users` làm cụm Elasticsearch luôn ở trạng thái yellow
- Vị trí: `server/siem/store.py` có template `number_of_replicas: 0` cho mọi index (`siem-*`, `ai-*`...) **trừ** `console-users`.
  Index này được tạo tự động ở lần ghi đầu tiên với mặc định 1 replica.
- Đã kiểm chứng: `cluster.health` trả `yellow`, có 1 shard chưa được gán, và index không xanh duy nhất là `console-users`. Trên ES một node, replica này không bao giờ được gán.
- Cách sửa: thêm `console-users` vào một template có `number_of_replicas: 0`, hoặc tạo index với setting đó trong `auth.setup()`.
  Với dữ liệu hiện có thì chạy `PUT console-users/_settings {"number_of_replicas": 0}`.

### 3.4 [Thấp, vận hành] analyzer, soar và ai-worker không thoát êm khi bị dừng
- Vị trí: `docker-compose.yml:294, 309, 336`. Lệnh `python -m siem.<x>` chạy làm PID 1, và `server/siem` không cài handler SIGTERM.
- Đã kiểm chứng (đọc `/proc/1/status`): PID 1 của analyzer và soar **không bắt SIGTERM**, chỉ bắt SIGINT. Kernel bỏ qua SIGTERM gửi tới PID 1 khi không có handler.
  Vì vậy mỗi lần `docker compose stop/down/restart`, các service này bị treo 10 giây rồi bị SIGKILL. `ai-worker` đã thoát với mã 137 (`OOMKilled=false`) đúng theo cách này.
  Manager (uvicorn) không bị lỗi này.
- Hệ quả: dừng hoặc khởi động lại chậm, consumer Kafka không được `close()` nên nhóm consumer cân bằng lại chậm.
  Thiết kế at-least-once (`bus.py:67`) giúp **không mất** dữ liệu, chỉ có thể xử lý lại một ít message.
- Cách sửa: thêm `stop_signal: SIGINT` (worker đã xử lý SIGINT) hoặc `init: true` vào anchor `x-app` (`docker-compose.yml:26`).

### 3.5 [Thấp, chất lượng phát hiện] Tỷ lệ phát hiện trên dataset công khai thấp
Không có báo nhầm, nhưng tỷ lệ phát hiện chỉ đạt Web 11%, Windows 6,5%, Linux 0,8%. Với log Linux ghi thật (Splunk), tỷ lệ là 0/22 kỹ thuật (mục 2.5).
Đây là giới hạn của bộ 40 rule chữ ký (RULES.md đã nêu), không phải lỗi. Nên ưu tiên viết thêm rule cho 4 loại web đang ở 0% và cho Linux.

### 3.6 [Thấp, độ ổn định khi build] Thư viện không được ghim phiên bản
- `server/requirements.txt` chỉ giới hạn theo major (`fastapi>=0.115,<1`...) và không có file lock. Bản build hôm nay đã cài fastapi 0.143.0, starlette 1.7.0, elasticsearch 8.19.3.
- Starlette đã báo `TestClient` dùng `httpx` sẽ bị bỏ, nên khi build lại sau này unit test có thể hỏng mà mã không đổi. Nên ghim phiên bản đã chạy được (`pip freeze`).

### 3.7 Log nhiễu, không ảnh hưởng chức năng
- Grafana: `Failed to read plugin/alerting provisioning files` (thiếu `grafana/provisioning/plugins` và `alerting`) và `plugin xychart is already registered`. Dashboard vẫn tải bình thường.
- Wazuh: 9 cảnh báo `indexer-connector ... retrying` lúc khởi động, dù `ossec.conf:64` đã đặt `<indexer><enabled>no</enabled>`. Sau đó log im lặng.
- SOAR: `NOTIFY (chưa cấu hình kênh)` nghĩa là Telegram/webhook để trống trong `.env`, nên thông báo chỉ được ghi vào log.

## 4. Dữ liệu và môi trường còn sót lại từ soc-platform
- Lúc Docker khởi động lại, các container cũ của stack soc-platform tự bật rồi thoát với mã 127, vì bind-mount trỏ tới thư mục `D:\GSANM\BTL\soc-platform` đã bị xóa.
  Lần chạy này đã thay chúng bằng stack siem-xdr. Các volume `siem-xdr_*` được giữ nguyên.
- Elasticsearch dùng chung volume với soc-platform nên vẫn còn đăng ký snapshot repository `siem-backup`, và mỗi lần khởi động lại báo `failed to create repository [siem-backup]`.
  Volume `siem-xdr_essnapshots` và image `soc-platform-server:latest` không còn được dùng. Case cũ từ soc-platform vẫn còn: e2e đã gộp alert webshell vào một case mở từ lần chạy trước.
- **Trên GitHub, `origin/main` (`ea615d4`) và `origin/feature/soc-platform` vẫn là mã soc-platform.** Nhánh của siem-xdr là `feature/wazuh-auth-grafana`.
  Nếu đã bỏ soc-platform thì cần quyết định lại nhánh `main`.

## 5. Chưa kiểm thử được
- Chưa có agent Windows/Linux thật (chỉ có `demo-web`), nên các rule `WIN-*` chỉ được kiểm qua unit test và dataset, chưa qua e2e.
- Profile `ai` (Ollama, ai-worker) không được bật trong lần chạy này. Phần AI chỉ được kiểm qua unit test.
- Chưa thử khóa tài khoản sau 5 lần đăng nhập sai (e2e cố ý bỏ qua vì sẽ khóa IP của máy chạy test 15 phút) và chưa đo tải syslog (`tools/bench_syslog.py`).

## 6. Cách chạy lại
```bash
# unit test (máy không có thư viện Python: chạy trong image server)
docker run --rm --user root -v "$PWD:/repo:ro" -w /repo/server --entrypoint sh siem-xdr-server:latest -c "pip install -q pytest httpx && python -m pytest -q"
# cấu hình Vector
docker run --rm -v "$PWD/vector:/etc/vector:ro" timberio/vector:0.58.0-alpine test /etc/vector/vector.yaml /etc/vector/tests.yaml
docker run --rm -v "$PWD/vector:/etc/vector:ro" timberio/vector:0.58.0-alpine test /etc/vector/wazuh.yaml /etc/vector/wazuh-tests.yaml
# stack thật
docker compose --profile demo up -d --build
python tools/e2e_test.py
pip install playwright && python tools/ui_test.py      # dùng Edge có sẵn
# độ phủ rule trên dataset
docker run --rm -v "$PWD:/repo:ro" -w /repo/server --entrypoint python siem-xdr-server:latest -m siem.ai.benchmark --datasets /repo/datasets/processed
```
