# Mọi dữ liệu đi qua wazuh-manager — kế hoạch triển khai

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Mục tiêu:** Kafka `siem.raw` chỉ còn một nguồn ghi vào là `wazuh-forwarder`. Syslog của thiết bị mạng và nhật ký console đều đi qua wazuh-manager trước. Vì vậy bộ rule Wazuh (kế hoạch `2026-10-31-wazuh-unified-ruleset.md`) thấy được mọi dữ liệu.

**Kiến trúc:**

```
Wazuh agent ──1514──▶ wazuh-manager ──▶ archives.json / alerts.json ──▶ wazuh-forwarder ──▶ Kafka siem.raw
Firewall/Suricata/router ──syslog 514──▶ wazuh-manager (remote syslog, allowed-ips)   ┘
Console (manager) ──ghi JSON──▶ volume console_audit ──▶ wazuh-manager <localfile> json ┘
```

- Bỏ container `syslog` (Vector) và bản Python cũ `server/siem/collector/`.
- Analyzer nhận diện hai nguồn mới trong event Wazuh, theo `location`, và trả ra đúng các trường như trước. Cụ thể:
  - syslog: `agent.id = syslog-<ip>`, `observer.ip`, host lấy từ header syslog;
  - console: `agent.id = soc-console`.
- Nhờ giữ nguyên các trường đó, HLT-002, dashboard và rule cũ không phải sửa.

**Công nghệ:** Wazuh manager 4.14.8 (`<remote>` syslog, `<localfile>` json), Python 3.12 / 3.14, `logging.handlers.RotatingFileHandler`, pytest, Vector 0.58 (chỉ còn `wazuh-forwarder`).

**Spec:** người dùng duyệt hướng này ngày 01/11/2026 ("phải cho toàn bộ data đi qua wazuh manager xong mới sửa rules chứ", rồi "ừ đồng ý, viết kế hoạch rồi làm luôn đi"). Hướng gồm 4 ý:
1. syslog vào wazuh-manager, bỏ Vector syslog;
2. nhật ký console ghi file, Wazuh đọc bằng localfile;
3. analyzer, CI, tài liệu đi kèm;
4. kiểm thử trên project thử.

Kế hoạch rule (`feature/wazuh-unified-ruleset`) tạm dừng ở Task 8 cho tới khi kế hoạch này xong.

## Quyết định

Các quyết định mình tự chọn được đánh dấu *(Claude)*, người dùng có thể đổi.

1. **Nhánh `feature/wazuh-ingest` tách từ `origin/main`**, gộp vào main trước. Nhánh rule rebase lên sau. *(Claude)*
2. **`allowed-ips` bắt buộc.** Wazuh chỉ nhận syslog từ IP trong danh sách. Biến `SYSLOG_ALLOWED_IPS` (danh sách phân tách bằng dấu phẩy, mặc định `10.10.40.254` = cổng SOC của firewall F001 trong DEPLOY-VM.md) được entrypoint ghi vào `ossec.conf`. Lý do: syslog giả có thể làm SOAR tự chặn IP tùy ý. *(Claude)*
3. **Syslog nhận cả UDP lẫn TCP 514** (hai khối `<remote>`), giống Vector hiện tại.
4. **Định danh nguồn giữ như cũ.** Event Wazuh có `agent.id` 000 và `location` là địa chỉ IP thì được coi là syslog. Khi đó:
   - `agent.id = syslog-<ip>`, `observer.ip = <ip>`, `host.name` = host trong header syslog, không có thì lấy IP;
   - `event.module` vẫn do bộ đọc syslog/filterlog/Suricata đặt như trước.
5. **Nhật ký console:**
   - `Audit` trong `server/siem/manager/auth.py` ghi mỗi sự kiện thành một dòng JSON vào `CONSOLE_AUDIT_FILE` (mặc định `/app/audit/console.json`). Dùng `RotatingFileHandler` 20 MB × 5.
   - Bỏ việc gửi thẳng vào Kafka. Ghi lỗi chỉ log cảnh báo, không chặn đăng nhập (giữ tính chất best effort).
   - Wazuh đọc file qua `<localfile>` `log_format json`. Analyzer chỉ tin event có `location` đúng đường dẫn file này (như `_SIEM_PROC_LOC`), rồi gọi `parse_console`.
6. **Volume `console_audit`:** mount `rw` vào manager (`/app/audit`) và `rw` vào wazuh-manager (`/var/log/siem-console`). Entrypoint `10-siem-setup.sh` chạy `install -d -o 10001 -m 0755` mỗi lần khởi động, cùng cách với `rules-dynamic` của nhánh rule. *(Claude)*
7. **Giữ nhánh `console_auth` trong `normalize`** cho message cũ còn trong Kafka lúc chuyển. Xóa ở lần dọn sau. *(Claude)*
8. **Triển khai lên stack thật là bước riêng, cần người dùng đồng ý** (Task 4). Kế hoạch này dừng ở PR.

## Global Constraints

- Wazuh manager `4.14.8`. Không đổi `event.module`, index `siem-*`, topic `siem.*`, tên lệnh agent `siem-xdr`.
- Không đổi các trường analyzer đang trả ra cho syslog và console: `agent.id` (`syslog-<ip>` / `soc-console`), `observer.ip`, `host.name`, `event.module`, `source.*`, `user.*`. HLT-002 và dashboard dựa vào chúng.
- Mọi lệnh docker khi thử dùng project riêng, không đụng project `siem-xdr` đang chạy. Cách dựng: `.superpowers/sdd/2026-11-01-wazuh-ingest/ENVIRONMENT.md`.
- Tiếng Việt có dấu trong chú thích và tài liệu. Commit kết thúc bằng dòng Co-Authored-By.

## Review Focus

1. **Syslog từ IP không có trong `allowed-ips`** bị bỏ, không vào `archives.json`. Ca thử ở Task 1.
2. **Dòng giả mạo:** dòng chứa JSON giống nhật ký console nhưng đến từ syslog hoặc log web không được thành event console. Ca thử ở Task 2.
3. **Console ghi file lỗi** (đầy đĩa, mất quyền): đăng nhập vẫn chạy, có log cảnh báo. Ca thử ở Task 2.
4. **File xoay vòng:** Wazuh vẫn đọc tiếp sau khi `RotatingFileHandler` đổi tên file. Ca thử ở Task 2.
5. **Syslog nhiều dòng một gói hoặc dòng dài** (Suricata eve > 2 KB): không bị cắt mất trường cần cho rule. Ca thử ở Task 1.

---

### Task 1: Syslog vào wazuh-manager, bỏ container `syslog`

**Files:**
- Modify:
  - `wazuh/manager/ossec.conf`: 2 khối `<remote>` syslog udp/tcp 514, `<allowed-ips>` giữ chỗ.
  - `wazuh/manager/entrypoint/10-siem-setup.sh`: ghi `SYSLOG_ALLOWED_IPS` vào `allowed-ips`, lặp lại được mỗi lần khởi động.
  - `docker-compose.yml`: chuyển `ports: 514/udp, 514/tcp` sang `wazuh-manager`, thêm env `SYSLOG_ALLOWED_IPS`, xóa service `syslog` và volume `vectordata`.
  - `.env.example`: thêm `SYSLOG_ALLOWED_IPS`.
  - `server/siem/pipeline/normalize.py`: `parse_wazuh` nhận diện syslog theo quyết định 4.
  - `.github/workflows/ci.yml`: job `vector` chỉ còn test `wazuh.yaml`.
  - `install.sh`: thông báo cổng 514 và sysctl. Không đổi hành vi nếu không cần.
- Delete: `vector/vector.yaml`, `vector/tests.yaml`, `server/siem/collector/`, `tools/bench_syslog.py`. Phần "Đánh giá syslog collector" trong README giữ làm lịch sử, thêm một dòng nói đã thay bằng wazuh-manager.
- Test: `server/tests/test_pipeline.py`.

**Interfaces:**
- Produces: event syslog đi qua Wazuh được chuẩn hóa thành doc có `agent.id = "syslog-<ip>"`, `observer.ip`, `host.name`, và các trường filterlog/Suricata/auth như hiện nay.

- [ ] **Step 1: Viết test hỏng** trong `test_pipeline.py`, dựng event Wazuh y như trong `archives.json` khi nhận syslog (`agent: {id: "000", name: "wazuh-manager"}`, `location: "10.10.40.254"`, `full_log: <dòng gốc>`):

```python
def test_wazuh_syslog_keeps_source_identity():
    d = normalize(wazuh_syslog("10.10.40.254", "<134>Nov  1 10:00:00 fw01 filterlog[1]: " + PF_BLOCK))
    assert get(d, "agent.id") == "syslog-10.10.40.254" and get(d, "observer.ip") == "10.10.40.254"
    assert get(d, "host.name") == "fw01" and get(d, "event.module") == "pfsense"

def test_wazuh_syslog_without_header_host_falls_back_to_ip():
    d = normalize(wazuh_syslog("10.10.40.254", "filterlog[1]: " + PF_BLOCK))
    assert get(d, "host.name") == "10.10.40.254"

def test_agent_event_is_not_treated_as_syslog():
    d = normalize(wazuh_agent_event("001", "/var/log/auth.log", SSH_FAIL))
    assert get(d, "agent.id") == "001" and get(d, "observer.ip") is None
```

  Thêm ca cho dòng Suricata eve qua syslog (JSON dài hơn 2 KB), kiểm `suricata.signature`.
- [ ] **Step 2:** `cd server && python -m pytest -q tests/test_pipeline.py` → FAIL.
- [ ] **Step 3:** sửa `parse_wazuh`. Điều kiện nhận diện: `agent.id == "000"` và `location` là IPv4/IPv6 hợp lệ (dùng `ipaddress`). Sửa ossec.conf, entrypoint, compose, CI, xóa file theo danh sách trên.
- [ ] **Step 4:** test → PASS, cả suite → PASS. Thử thật trên project thử:
  - (a) gửi filterlog, sshd và Suricata eve dài qua UDP lẫn TCP từ một container trong mạng thử có IP nằm trong `SYSLOG_ALLOWED_IPS` → có trong `archives.json`;
  - (b) chạy `normalize` trên dòng `archives.json` đó → các trường như Step 1;
  - (c) gửi từ IP không được phép → không vào `archives.json`;
  - (d) `docker compose config` hợp lệ, không còn service `syslog`.
- [ ] **Step 5:** commit `wazuh-manager nhận syslog 514, bỏ Vector syslog`.

### Task 2: Nhật ký console ghi file, Wazuh đọc

**Files:**
- Modify:
  - `server/siem/manager/auth.py`: `Audit` ghi file, bỏ Kafka.
  - `server/siem/settings.py`: `CONSOLE_AUDIT_FILE`.
  - `server/siem/pipeline/normalize.py`: `parse_wazuh` nhận diện `location` của file console.
  - `wazuh/manager/ossec.conf`: `<localfile>` json.
  - `wazuh/manager/entrypoint/10-siem-setup.sh`: `install -d -o 10001 -m 0755 /var/log/siem-console`.
  - `docker-compose.yml`: volume `console_audit`.
- Test: `server/tests/test_api.py` (hoặc file test auth hiện có), `server/tests/test_pipeline.py`.

**Interfaces:**
- Produces:
  - `Audit.__call__(action, outcome, user, ip, **extra) -> None`, giữ nguyên chữ ký vì mọi nơi gọi không đổi. Mỗi lần gọi ghi một dòng JSON `{"timestamp", "event_type": "console_auth", "action", "outcome", "user", "ip", ...extra}`.
  - Event Wazuh có `location == CONSOLE_AUDIT_WAZUH_PATH` (`/var/log/siem-console/console.json`) được chuẩn hóa giống hệt đường `console_auth` cũ, với `agent.id = "soc-console"` và `host.name = "soc-console"`.

- [ ] **Step 1: Viết test hỏng.**

```python
def test_audit_writes_one_json_line(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "CONSOLE_AUDIT_FILE", str(tmp_path / "console.json"))
    a = auth.Audit(); a("login", "success", "alice", "10.10.40.50", role="analyst")
    rec = json.loads((tmp_path / "console.json").read_text(encoding="utf-8").splitlines()[0])
    assert rec["action"] == "login" and rec["user"] == "alice" and rec["role"] == "analyst"

def test_audit_write_failure_does_not_raise(monkeypatch, caplog):
    monkeypatch.setattr(settings, "CONSOLE_AUDIT_FILE", "/khong/ton/tai/console.json")
    auth.Audit()("login", "failure", "bob", "1.2.3.4")
    assert "nhật ký" in caplog.text

def test_wazuh_console_event_normalizes_like_before():
    old = normalize(raw_console_auth(LOGIN_FAIL))      # đường Kafka cũ
    new = normalize(wazuh_localfile("/var/log/siem-console/console.json", LOGIN_FAIL))
    for f in ("event.module", "event.category", "event.outcome", "user.name", "source.ip", "agent.id", "host.name"):
        assert get(new, f) == get(old, f)

def test_console_json_from_other_location_is_not_trusted():
    d = normalize(wazuh_localfile("/var/log/apache2/access.log", LOGIN_FAIL))
    assert get(d, "event.module") != "console"
```

  Thêm ca xoay vòng: ghi tới khi file đổi tên, kiểm file mới có dòng tiếp theo.
- [ ] **Step 2:** chạy → FAIL.
- [ ] **Step 3:** cài đặt. Ghi file dùng `logging.getLogger("siem.console_audit")` với `RotatingFileHandler(maxBytes=20*1024*1024, backupCount=5, encoding="utf-8")`, `propagate=False`, formatter `%(message)s`. Lỗi mở hoặc ghi file thì `log.warning` một lần mỗi phút.
- [ ] **Step 4:** test → PASS, cả suite → PASS. Thử thật trên project thử: manager và wazuh-manager cùng mount `console_audit`. Đăng nhập sai và đúng qua API thử, hoặc gọi `Audit` trong container manager. Kiểm `archives.json` có event với đúng `location`, và `normalize` ra `event.module: console`.
- [ ] **Step 5:** commit `nhật ký console ghi file, wazuh-manager đọc bằng localfile`.

### Task 3: Tài liệu

**Files:**
- Modify:
  - `README.md`: sơ đồ, bảng thành phần, mục "Đường đi của dữ liệu và khi một thành phần chết". Bỏ dòng `syslog` (Vector). Dòng wazuh-manager chết giờ là: syslog UDP mất, syslog TCP tùy bộ đệm thiết bị, nhật ký console nằm chờ trong file.
  - `DEPLOY-VM.md`: syslog trỏ về `<IP>:514` như cũ, thêm `SYSLOG_ALLOWED_IPS`; OPNsense có thể cài agent Wazuh `os-wazuh-agent`.
  - Mục tương ứng trong `SOC-OPERATIONS.md` / `RULES.md` nếu có nhắc Vector syslog.
- [ ] **Step 1:** `grep -rn "Vector\|vector.yaml\|syslog (Vector)\|collector" *.md` → sửa từng chỗ còn đúng nghĩa. Giữ biên bản `Test.md`.
- [ ] **Step 2:** commit `docs: syslog và nhật ký console đi qua wazuh-manager`.

### Task 4: Triển khai lên stack thật (DỪNG, hỏi người dùng)

Sau khi PR gộp vào main. Stack thật đang chạy từ thư mục chính, mà thư mục đó còn việc dở của phiên SigmaHQ. Triển khai cần:
- build lại image server (`auth.py`, `normalize.py`);
- tạo lại `manager`, `analyzer`, `wazuh-manager`;
- xóa container `syslog`;
- đặt `SYSLOG_ALLOWED_IPS` trong `.env`;
- chạy lại E2E 44/44.

Controller báo người dùng, chờ đồng ý trước khi làm.

## Kết quả thử

Thử thật trong project `wzhingest` (Wazuh 4.14.8, không build image, stack `siem-xdr` giữ nguyên ID container trước/sau):

- **Syslog vào wazuh-manager (Task 1)**: filterlog, sshd và Suricata EVE dài 2,8 KB qua UDP và TCP đều vào `archives.json` (agent 000, `location` = IP gửi); `normalize` trên chính các dòng đó cho đúng `event.module`, `host.name`, `source.ip`, chữ ký Suricata. Gửi từ IP không có trong `SYSLOG_ALLOWED_IPS`: 0 dòng vào, remoted ghi `WARNING: (1213): Message from '<IP>' not allowed`.
- **Nhật ký console (Task 2)**: `Audit` ghi JSON từng dòng, Wazuh đọc bằng `<localfile>` json; decoder đổi `user` thành `dstuser` nên analyzer parse `full_log`. Xoay vòng 20 MB/5 bản: Wazuh đọc tiếp file mới (xoay quá nhanh, vài giây một lần, thì logcollector có thể bỏ lỡ dòng; với 20 MB không xảy ra). Event giống hệt đường Kafka cũ ở 14 trường.
- **Vòng sửa cuối (nhánh review toàn bộ)**: (1) `<only-future-events>no</only-future-events>` cho file console: tắt wazuh-manager, ghi 1 dòng, bật lại -> đúng 1 lần trong `archives.json` (18 -> 19 dòng console); khởi động lại thêm 2 lần -> vẫn 1 lần, `file_status.json` giữ offset 784. (2) RFC5424 qua remoted: `full_log` còn tiền tố `1 <ISO>`; sau khi sửa regex, dòng filterlog và Suricata RFC5424 thật cho `host.name` fwrfc / surrfc, `pfsense` / `suricata`, chữ ký ET đúng. (3) Bị từ chối: `Message from '172.20.0.3' not allowed. Cannot find the ID of the agent.`. (6) Validator `SYSLOG_ALLOWED_IPS` kiểm danh sách cho phép từng phần tử: 28 ca (11 ca sai chính tả mới bị bản cũ cho lọt, bản mới chặn hết) chạy tay bằng Git Bash; pytest bash chỉ chạy trên Linux CI.
- Chưa kiểm: tải syslog dồn dập trên đường mới, nhiều dòng trong một datagram, `SO_RCVBUF` của remoted, Docker Desktop thật với firewall OPNsense thật (IP nguồn bị NAT).
