# SIEM/XDR Lab — tự xây dựng

Hệ thống SIEM + XDR cho môn GSANM, dựng theo kiến trúc trong `BTL/SIEM.txt`
và danh mục tài sản `BTL/asset.txt`. Toàn bộ backend đóng gói bằng Docker.

```
 Endpoint / Server                        Backend (docker-compose)
 ┌───────────────────┐  1514 AES      ┌───────────────┐ archives.json ┌─────────────────┐   ┌─────────────────┐   ┌────────────┐   ┌──────────────┐   ┌─────────┐
 │ Wazuh agent 4.14.7│ ─────────────▶ │ wazuh-manager │ alerts.json ─▶│ wazuh-forwarder │──▶│ Kafka (KRaft)   │──▶│ Analyzer   │──▶│ Elasticsearch│──▶│ Grafana │
 │ log, FIM, SCA,    │ 1515 enroll    │ (trạm thu,    │               │ (Vector)        │   │ siem.raw        │   │ normalize  │   │ events/alerts│   └─────────┘
 │ rootcheck, kiểm kê│ ◀── active ────│ ruleset Wazuh)│               └─────────────────┘   │ siem.alerts     │   │ enrich (TI)│   └──────────────┘
 └───────────────────┘    response    └───────▲───────┘                                     │                 │   │ rules + ML │
 ┌───────────────────┐   syslog 514   ┌───────┼───────┐                                     │                 │   │ + cảnh báo │
 │ Firewall/Suricata │ ─────────────▶ │ Syslog│(Vector)│───────────────────────────────────▶│                 │◀──│   Wazuh    │
 └───────────────────┘                └───────┼───────┘                                     └───────┬─────────┘   └────────────┘
                                              │ Wazuh API (55000, nội bộ)                           ▼
                                              │  block_ip / kill_process / isolate_host   ┌──────────────┐
                                              └──────────────────────────────────────────│ SOAR         │ notify (webhook/Telegram), create_case
                                                                                          │ playbooks    │ đồng bộ danh sách agent từ Wazuh
                                                                                          └──────────────┘
                                                                                          ┌──────────────┐  chỉ đọc siem-*, ghi đề xuất vào ai-*
                                                                                          │ AI worker    │◀──▶ Ollama (LLM nội bộ)
                                                                                          │ (chỉ đề xuất)│  analyst duyệt trên console ─▶ Manager ghi rules/ai, rules/exceptions
                                                                                          └──────────────┘
```

| Thành phần | Công nghệ | Thư mục |
|---|---|---|
| Agent đa nền tảng (Windows/Linux) | **Wazuh agent 4.14.7** (bộ cài chính thức) + script phản ứng `siem-xdr` | `wazuh/agent/`, `demo/web/` |
| Trạm thu của agent | **Wazuh manager 4.14.7** (chỉ manager, không indexer/dashboard) | `wazuh/manager/` |
| Chuyển dữ liệu Wazuh vào Kafka | **Vector** 0.58, end-to-end acknowledgement | `vector/wazuh.yaml` |
| Manager API + SOC console | FastAPI | `server/siem/manager/` |
| Syslog collector (UDP/TCP 514) | **Vector** 0.58 (Rust), hàng đợi trên đĩa | `vector/vector.yaml` (bản Python cũ `server/siem/collector/` chỉ giữ để đối chiếu) |
| Message bus | Kafka 7.7 (Confluent) chế độ **KRaft**, không dùng ZooKeeper | `docker-compose.yml` |
| Chuẩn hóa log (ECS rút gọn) + làm giàu | Python | `server/siem/pipeline/` |
| Phân tích dựa trên luật | Rule engine YAML (match / threshold / sequence) + cảnh báo chọn lọc từ ruleset Wazuh | `server/siem/detection/`, `server/rules/` |
| Phân tích dựa trên ML (**tạm dừng**) | Isolation Forest (scikit-learn) | `server/siem/detection/ml.py` |
| SOAR + quản lý case | Playbook tự động + case playbook NIST, phản ứng qua Wazuh active response | `server/siem/soar/`, `server/config/playbooks.yml`, `server/config/case_playbooks.yml` |
| AI hỗ trợ viết rule (chỉ đề xuất) | Ollama (`qwen2.5-coder:7b`) + kiểm định tự động + duyệt trên console | `server/siem/ai/`, `tools/fetch_datasets.py`, `tools/convert_datasets.py` |
| Bảo mật nội bộ | TLS (CA nội bộ), RBAC Elasticsearch + Wazuh API, Docker secrets + keystore | `security/setup.sh`, `tools/init_secrets.py`, `wazuh/manager/entrypoint/` |
| Lưu trữ | Elasticsearch 8 (xpack security bật) | |
| Trực quan hóa | Grafana 11 (dashboard được provision sẵn) | `grafana/` |

## 1. Agent: Wazuh agent 4.14.7 (`wazuh/`)

Endpoint dùng **Wazuh agent** chính thức, thay cho agent Go tự viết trước đây (thiếu FIM, SCA, rootcheck, kiểm kê,
cấu hình tập trung, bộ cài chính thức). Agent kết nối tới **wazuh-manager** trong stack. Manager chỉ làm trạm thu:
nhận event, chạy ruleset Wazuh, chuyển lệnh phản ứng xuống agent. Phân tích bằng rule riêng, lưu trữ, AI, SOAR và console
vẫn là phần tự xây của siem-xdr. Không dùng Wazuh indexer, dashboard hay filebeat.

| Chức năng | Agent Go cũ | Wazuh agent |
|---|---|---|
| Đọc file log, Windows Event Log | có | có, kèm decoder của Wazuh |
| Toàn vẹn file (FIM), registry Windows | không | có, theo thời gian thực, kèm diff nội dung |
| Rootcheck (rootkit, trojan) | không | có |
| SCA: chấm cấu hình theo CIS | không | có |
| Kiểm kê: gói, cổng, tiến trình, phần cứng | không | có (syscollector) |
| Cấu hình tập trung từ manager | không | có (`wazuh/manager/agent.conf`, nhóm `default`) |
| Phản ứng: chặn IP, kill, cô lập | có | có, qua active response + script `siem-xdr` |
| Kênh truyền | HTTPS + token HMAC | AES; enroll qua TLS + mật khẩu |
| Bộ cài | tự build | MSI / DEB / RPM chính thức |

| File | Vai trò |
|---|---|
| `wazuh/manager/ossec.conf` | Cấu hình manager: ghi mọi event ra `archives.json` (`logall_json`), enroll bắt buộc mật khẩu, tắt module giám sát chính container manager, tắt vulnerability detection (từ 4.8 cần Wazuh indexer) |
| `wazuh/manager/agent.conf` | Cấu hình chung đẩy xuống mọi agent: Windows đọc Sysmon / PowerShell / Defender, FIM thư mục Startup và khóa Run; Linux đọc log Apache, FIM `/var/www`, `/etc/ssh`, cron |
| `wazuh/manager/local_rules.xml` | Rule Wazuh riêng: file mới / bị sửa trong thư mục web lên level 10 (có thể là webshell, T1505.003) |
| `wazuh/manager/entrypoint/` | Chạy mỗi lần manager khởi động: mật khẩu enroll lấy từ Docker secret, chứng chỉ Wazuh API do CA nội bộ ký, user API `siem-soar` quyền tối thiểu, khóa 2 user mặc định `wazuh` / `wazuh-wui`, tắt filebeat |
| `vector/wazuh.yaml` | Đưa `archives.json` (mọi event) và `alerts.json` (cảnh báo ruleset Wazuh) vào Kafka `siem.raw` |
| `wazuh/agent/linux/siem-xdr`, `wazuh/agent/windows/siem-xdr.cmd` + `.ps1` | Script phản ứng trên agent |
| `wazuh/agent/linux/siem-procs` | Telemetry tiến trình mới mỗi giây cho máy không có auditd (rule LNX-*) |

**Cài agent.** Phiên bản agent phải ≤ manager (4.14.7). Mật khẩu enroll là nội dung `secrets/enrollment_key`.
Máy agent cần tới được cổng 1514 và 1515 của máy chạy docker. Tên agent phải khớp `hostname` trong
`server/config/assets.yml` để event được gắn đúng tài sản.

- Windows (A001 PC-01). Bộ cài có sẵn ở `BTL/Wazuh/wazuh-agent-4.14.7-1.msi`. Mở PowerShell **Administrator**:
  ```powershell
  msiexec.exe /i wazuh-agent-4.14.7-1.msi /q WAZUH_MANAGER="<IP máy docker>" WAZUH_AGENT_NAME="PC-01" WAZUH_REGISTRATION_PASSWORD="<secrets\enrollment_key>"
  Copy-Item wazuh\agent\windows\siem-xdr.* "C:\Program Files (x86)\ossec-agent\active-response\bin\"
  NET START WazuhSvc
  ```
  Nên cài Sysmon (manager đã đẩy sẵn cấu hình đọc kênh Sysmon). Nếu không có Sysmon thì bật audit *Process Creation* (event 4688).
- Ubuntu (A003 Ubuntu-01, S001 Web-01):
  ```bash
  curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
  sudo chmod 644 /usr/share/keyrings/wazuh.gpg
  echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list
  sudo apt-get update
  sudo WAZUH_MANAGER="<IP máy docker>" WAZUH_AGENT_NAME="Ubuntu-01" WAZUH_REGISTRATION_PASSWORD="<secrets/enrollment_key>" apt-get install wazuh-agent=4.14.7-1
  sudo install -m 750 -o root -g wazuh wazuh/agent/linux/siem-xdr /var/ossec/active-response/bin/
  sudo systemctl enable --now wazuh-agent
  ```
  Telemetry tiến trình: dùng auditd (rule `execve`, Wazuh đọc `/var/log/audit/audit.log` với `log_format audit`),
  hoặc thêm `siem-procs` như máy demo. auditd không ghi tên tiến trình cha, nên rule LNX-002 (web server sinh shell) cần `siem-procs`.
- Máy web demo: image `demo/web/` cài sẵn agent, script và cấu hình (`demo/web/wazuh-agent.conf`), enroll tự động với tên `demo-web`.

Kiểm tra agent: `docker compose exec wazuh-manager /var/ossec/bin/agent_control -l`, hoặc tab *Agent* trên console
(SOAR đồng bộ từ Wazuh API mỗi 30 giây). `agent.id` trong event và alert là **ID Wazuh** (`001`...), `host.name` là tên agent.

**Phản ứng (XDR).** SOAR hoặc analyst tạo lệnh. SOAR gọi Wazuh API
`PUT /active-response {"command": "!siem-xdr", "arguments": [loại, đích, id lệnh]}` (Windows dùng `siem-xdr.cmd`).
Agent chạy script `siem-xdr` bằng quyền root/SYSTEM:

| Lệnh | Linux | Windows |
|---|---|---|
| `block_ip` / `unblock_ip` | iptables / ip6tables, chain INPUT | Windows Firewall, rule chặn chiều vào |
| `kill_process` (PID hoặc tên) | kill cả cây tiến trình | kill cả cây tiến trình |
| `isolate_host` / `unisolate_host` | chain riêng: chỉ cho phép loopback và IP wazuh-manager | rule chặn dải bù của IP manager (trong Windows Firewall rule chặn luôn thắng rule cho phép) |

Script kiểm tra chặt tham số: không chặn loopback hay IP manager, không kill PID 1 hay tiến trình của Wazuh / hệ thống.
Kết quả được ghi vào `active-responses.log`, agent gửi dòng đó về như log thường, và SOAR khớp theo ID lệnh để đánh dấu
`success` / `failed`. Agent chỉ báo được kết quả cho lệnh của chính nó. Active response của Wazuh là "gửi rồi quên" (API chỉ xác nhận
đã chuyển lệnh), nên đây là cách duy nhất biết lệnh có chạy thật hay không. Lệnh `sent` quá 10 phút chuyển sang `timeout`.

**Kết quả chạy thử end-to-end** (28/9/2026, máy `demo-web`):

| Kịch bản | Kết quả |
|---|---|
| SQL injection `?id=1 union select ...` | WEB-001 → SOAR `block_ip` → agent chặn `172.18.0.1` bằng iptables, báo `success`. Máy host không truy cập được web. Gỡ chặn thủ công từ console cũng đi qua Wazuh. |
| Command injection `ping.cgi?host=127.0.0.1;sleep 15` | `siem-procs` thấy `sh` có cha `httpd` → LNX-002 → kill cả cây tiến trình. Request kết thúc sau 5,7 giây thay vì 15. Agent báo `đã kill PID 947 (sh) và 1 tiến trình con`. |
| Tải webshell `htdocs/shell.php`, sửa `index.html` | FIM thời gian thực → rule 100100 / 100101 (level 10) → alert `WZH-100100` / `WZH-100101` (high, T1505.003) → thông báo + case PB-08. |
| Cô lập máy (thủ công) | Web không truy cập được. Agent vẫn `Active` với manager, nhận và chạy được lệnh bỏ cô lập. |
| Độ trễ agent → Kafka | Khoảng 2 giây. Bản đầu dùng hàng đợi đĩa của Vector: event bị giữ tới khi có event kế tiếp (6–10 giây), lệnh kill tới khi tiến trình đã chạy xong. Đã thay bằng end-to-end acknowledgement. |
| SCA máy demo | 207 kết quả CIS Debian, 83 mục không đạt. Không chuyển thành alert (xem mục 3). |

**Giới hạn**:
- Script Windows (`siem-xdr.ps1`) chưa chạy thử trên máy thật: máy lab hiện không có quyền Administrator.
- Vulnerability detection của Wazuh (từ 4.8) cần Wazuh indexer nên đang tắt.
- Tiến trình sống ngắn hơn khoảng 1 giây có thể lọt khỏi `siem-procs`.
- Rootcheck / SCA trên container demo chấm chính container, nên có nhiều mục không đạt.
- Agent Go cũ đã được gỡ khỏi repo. Mã vẫn còn trong lịch sử git (commit `32897dc`) và nhánh `worktree-agent-hardening`.

## 2. Backend

```bash
python tools/init_secrets.py   # sinh mật khẩu/key ngẫu nhiên vào secrets/ (chỉ lần đầu)
cp .env.example .env           # cấu hình không bí mật
docker compose up -d --build
docker compose ps              # es-setup phải Exited (0); kafka, elasticsearch, wazuh-manager healthy
```
Hệ thống đã chạy từ trước thì chạy lại `python tools/init_secrets.py` (sinh thêm `wazuh_api_password`, `console_admin_password`),
rồi `docker compose up -d --force-recreate es-certs es-setup` để sinh chứng chỉ Wazuh API và cập nhật quyền RBAC.

**Đăng nhập lần đầu**: mở https://localhost:8000, tài khoản `admin`, mật khẩu tạm trong `secrets/console_admin_password`.
Trang đăng nhập bắt đặt mật khẩu mới ngay, sau đó vào tab *Tài khoản* để tạo tài khoản riêng cho từng người (xem mục 7).
**Một tài khoản dùng cho cả console và Grafana**: Grafana nằm sau manager ở https://localhost:8000/grafana/ và dùng chung
phiên đăng nhập (mở Grafana khi đã đăng nhập console thì vào thẳng, không hỏi lại mật khẩu).
Phần AI (`--profile ai`, xem mục 5) và máy web demo (`--profile demo`, xem bên dưới) nằm trong profile riêng, không chạy mặc định.

| URL | Dùng để | Đăng nhập |
|---|---|---|
| https://localhost:8000 | SOC console: alert, agent, lệnh phản ứng, case, đề xuất AI, tài khoản | tài khoản riêng từng người (lần đầu: `admin` / `secrets/console_admin_password`) |
| https://localhost:8000/grafana/ | Grafana, dashboard *SIEM/XDR — Tổng quan SOC*: tổng quan, phát hiện, telemetry, **phiên đăng nhập**, phản ứng | **cùng tài khoản và phiên với console** |
| https://localhost:8000/docs | Swagger của Manager API | |
| http://127.0.0.1:8088 | Kafka UI (chỉ từ máy chạy docker) | |
| https://127.0.0.1:9200 | Elasticsearch (chỉ từ máy chạy docker) | `analyst` / `secrets/analyst_es_password` (chỉ đọc) |
| UDP/TCP 514 | Syslog từ firewall F001 / Suricata | |
| TCP 1514, 1515 | Wazuh agent gửi event (AES) / enroll (TLS) | mật khẩu enroll: `secrets/enrollment_key` |

**Kafka chạy KRaft** (Kafka tự quản lý metadata, không cần ZooKeeper): 1 node vừa là broker vừa là controller,
controller dùng listener riêng `CONTROLLER:9093` chỉ trong mạng nội bộ. Dữ liệu nằm ở volume `kafkadata`, `CLUSTER_ID` cố định
trong `docker-compose.yml`, nên tạo lại container không mất dữ liệu. Kiểm tra controller:
`docker compose exec kafka kafka-metadata-quorum --bootstrap-server localhost:9092 describe --status`.
KRaft là điều kiện bắt buộc để sau này nâng lên Kafka 4.x (bản 4.0 đã bỏ hẳn ZooKeeper). Chuyển sang KRaft không làm tăng
khả năng chịu tải: ZooKeeper không nằm trên đường đi của log, broker nhận khoảng 227–243 nghìn msg/s ở cả hai chế độ
(`kafka-producer-perf-test`, 200 byte/msg).

Trình duyệt sẽ cảnh báo chứng chỉ của `https://localhost:8000` vì nó do **CA nội bộ** ký.
Để hết cảnh báo, lấy CA rồi import vào *Trusted Root Certification Authorities* của Windows:
```bash
docker compose cp elasticsearch:/usr/share/elasticsearch/config/certs/ca/ca.crt ./ca.crt
```
Trên Windows, lệnh `curl` (Schannel) cần thêm `--ssl-no-revoke --cacert ca.crt`, vì CA nội bộ không có danh sách thu hồi (CRL).

**Máy web demo**: `docker compose --profile demo up -d --build demo-web` dựng thêm Apache kèm Wazuh agent tại
http://localhost:8081. Truy cập trang này sẽ sinh log thật đi qua toàn bộ pipeline.
Trang `/cgi-bin/ping.cgi` **cố ý có lỗ hổng command injection** để kiểm tra rule LNX-002 và lệnh kill/chặn IP.
Tạo file trong `/usr/local/apache2/htdocs` để thử FIM. Chỉ chạy máy này trong lab cô lập.

**Firewall F001**: cấu hình remote syslog trỏ về `<IP máy docker>:514`, **ưu tiên TCP** nếu thiết bị hỗ trợ (xem bảng đánh giá bên dưới).
Hệ thống parse được iptables/UFW, pfSense/OPNsense filterlog và Suricata eve (JSON qua syslog).

### Đánh giá syslog collector (vì sao chuyển sang Vector)

Syslog collector do **Vector** đảm nhận (`vector/vector.yaml`): nhận UDP/TCP 514, chuyển mỗi dòng thành đúng event thô
mà analyzer đọc (`{"timestamp","agent_id":"syslog-<ip>","source":"syslog","event_type":"syslog","data":{"message","sender_ip"}}`),
đưa qua **hàng đợi trên đĩa** (volume `vectordata`, 1 GiB, đầy thì chặn chứ không vứt log) rồi ghi vào Kafka `siem.raw`.
Unit test phần chuyển đổi: `docker run --rm -v ./vector:/etc/vector:ro timberio/vector:0.58.0-alpine test /etc/vector/vector.yaml /etc/vector/tests.yaml`.
Metrics (log nhận / gửi / bị loại) ở `http://syslog:9598/metrics`, chỉ truy cập được trong mạng docker.

Cách đo (28/9/2026): `tools/bench_syslog.py` bắn log bình thường (không kích hoạt rule), mỗi collector ghi vào topic Kafka riêng,
đếm số message thật sự vào Kafka qua offset. Số gói kernel bỏ lấy từ `RcvbufErrors` trong `/proc/net/snmp` của collector.

**A. Năng lực thuần của collector** (gửi trong cùng network namespace, không qua lớp mạng nào):

| Tải | Python (asyncio, cũ) | Vector |
|---|---|---|
| UDP 20.000 msg/s | 50,5% vào Kafka (kernel bỏ 99.092 gói) | **100%** |
| UDP 50.000 msg/s | 54,1% | **100%** |
| UDP đột biến (~96–325 nghìn msg/s) | 17,2% | **100%**, đưa vào Kafka ~60 nghìn msg/s |
| TCP đột biến | 100% | 100% |

Bản Python chỉ xử lý được ~10–20 nghìn msg/s qua UDP. Phần vượt quá bị kernel bỏ khi buffer nhận đầy, **không có log hay chỉ số nào báo**.
Số gói kernel bỏ cộng số log vào Kafka đúng bằng số đã gửi, nên toàn bộ chỗ hụt nằm ở khâu đọc UDP của collector.

**B. Gửi từ máy host qua cổng publish (Docker Desktop trên Windows)**:

| Tải | Python | Vector |
|---|---|---|
| UDP 5.000 msg/s | 99,9% | 100% |
| UDP 20.000 msg/s | 100% | 85,2% |
| UDP đột biến | 26,5% | 31,9% |
| TCP đột biến | 100% | 100% |

Ở đường này **cả hai mất gần như nhau và kernel phía collector không bỏ gói nào**: UDP bị mất ở lớp chuyển tiếp cổng của Docker Desktop
(từ Windows vào máy ảo), trước khi tới collector. Khi triển khai thật nên chạy trên máy Linux và đặt ở host
`sysctl -w net.core.rmem_max=33554432` (tham số này toàn cục, không đặt riêng cho container được; không đặt thì buffer 32 MB của Vector bị giới hạn),
và cho thiết bị gửi syslog qua **TCP** (không mất log nhờ đẩy ngược áp lực).

**C. Độ bền**: tắt Kafka, bắn 50.000 log vào mỗi collector, khởi động lại collector trong lúc Kafka vẫn chết, rồi bật Kafka:

| | Python | Vector |
|---|---|---|
| Log còn lại sau khi Kafka hồi phục | **0/50.000** (log chỉ nằm trong RAM) | **50.000/50.000** (hàng đợi trên đĩa) |

Ghi chú cấu hình: `topic` trong `vector.yaml` phải ghi thẳng `siem.raw`. Thử `${TOPIC_RAW}` thì broker trả lỗi `InvalidTopic`
(Vector 0.58 không thay biến môi trường vào trường này).

## 3. Phát hiện

**Luật** (`server/rules/*.yml`, 40 luật, có gắn MITRE ATT&CK):

| Nhóm | Luật |
|---|---|
| Web | SQLi, XSS, path traversal/LFI, command injection/Log4Shell, scanner UA, dirbusting, brute-force form, webshell, HTTP flood |
| Xác thực | SSH brute-force, brute-force **rồi thành công** (sequence), password spraying (distinct user), root login, tạo user, sudo shell |
| Windows | 4625 brute-force, xóa audit log, tạo user, thêm vào Administrators, PowerShell `-enc`, download cradle/AMSI bypass, Mimikatz/LSASS dump, Office sinh shell, service lạ, xóa shadow copy, Defender, LOLBins, schtasks |
| Linux | reverse shell, web server sinh shell, `curl \| sh`, crypto miner, trinh sát, persistence |
| Mạng | port scan (distinct port), firewall deny hàng loạt, dịch vụ nhạy cảm lộ ra Internet, Suricata severity cao, SMB lateral, Threat Intel IOC |

Cú pháp luật:
```yaml
- id: AUTH-001
  title: Brute-force đăng nhập
  severity: high                          # low|medium|high|critical
  mitre: {tactic: Credential Access, technique: [T1110.001]}
  type: threshold                         # match | threshold | sequence
  condition:
    all:
      - {field: event.category, op: eq, value: authentication}
      - {field: event.outcome,  op: eq, value: failure}
  threshold: {count: 5, window: 60, group_by: [source.ip]}   # distinct: <field> để đếm giá trị khác nhau
```
Toán tử: `eq, neq, in, contains, not_contains, startswith, endswith, regex, gt, gte, lt, lte, exists, cidr`.

**ML (tạm dừng, `ML_ENABLED=false`)**: Isolation Forest theo (IP nguồn, cửa sổ 60 giây). Thử nghiệm cho thấy
model bắt được tấn công nhưng **báo nhầm khoảng 32%** lưu lượng bình thường, và 100% với các IP chỉ có 1 event.
Nguyên nhân chính: baseline tổng hợp và một model chung cho mọi nguồn. Code được giữ lại trong `server/siem/detection/ml.py`.
Trước khi bật lại cần: giai đoạn học trên dữ liệu thật, tách model theo nguồn, hiệu chỉnh ngưỡng, chống lặp alert.

**Cảnh báo từ ruleset Wazuh** (`server/siem/detection/wazuh.py`): rule của siem-xdr chạy trên MỌI event lấy từ
`archives.json`. Ruleset Wazuh (hơn 3.000 rule) phần lớn trùng việc với rule tự viết (web, SSH, đăng nhập Windows...), nên
không chuyển hết sang để tránh mỗi sự cố thành 2 alert. Chỉ lấy cảnh báo trong `alerts.json` thuộc các nhóm siem-xdr không
có rule tương đương (`WAZUH_ALERT_GROUPS`, mặc định `syscheck`, `rootcheck`, `vulnerability-detector`, `virustotal`, `yara`) từ level 7,
cộng mọi cảnh báo level ≥ 12. Alert có `rule.id = WZH-<id rule Wazuh>`, `alert.source = wazuh`. Level ánh xạ sang severity:
7–9 medium, 10–11 high, ≥ 12 critical. Kết quả SCA (CIS) KHÔNG chuyển thành alert: máy demo có 83 mục không đạt ngay khi khởi động,
và đó là đánh giá cấu hình, không phải sự cố. Xem SCA trong event `event.module: sca`.
Rule Wazuh riêng đặt ở `wazuh/manager/local_rules.xml` (ID từ 100000).

**Làm giàu**: Threat Intel (`server/config/intel/*.txt`: IP/CIDR, domain, hash, tự nạp lại khi file đổi),
tài sản (`server/config/assets.yml`, lấy từ `asset.txt`) dùng để tính `risk_score` theo mức quan trọng của tài sản.

## 4. SOAR và quản lý case

**Phản ứng tự động** (`server/config/playbooks.yml`): ví dụ AUTH-001 → chặn IP trên **mọi** agent trong 1 giờ, gửi thông báo, tạo case.
AUTH-002 → chặn 24 giờ, còn cô lập máy thì chờ analyst duyệt (`approval: true`).
SOAR tự tạo lệnh gỡ chặn khi hết hạn, bỏ qua IP trong `SOAR_WHITELIST` và không chặn trùng. "Đang chặn" chỉ tính lệnh đang chờ
agent, lệnh còn hạn, hoặc lệnh thành công trong 10 phút gần đây. Luật iptables trên agent mất khi máy/container khởi động lại, nên
bản ghi chặn cũ không có hạn không được tin (lỗi E2E 30/9: SOAR bỏ qua kẻ tấn công vì tưởng IP đã bị chặn). Chặn lại cũng an toàn,
vì script kiểm tra luật trước khi thêm.
Đặt `SOAR_AUTO_RESPONSE=false` nếu chỉ muốn thông báo và tạo case.
Lệnh (của playbook hoặc analyst tạo trên console) được SOAR gửi xuống agent qua Wazuh API mỗi 2 giây,
kết quả thật lấy từ log agent gửi về (xem mục 1). Cảnh báo `WZH-*` từ ruleset Wazuh (FIM, rootcheck...) được thông báo và mở case PB-08.

**Case playbook** (`server/config/case_playbooks.yml`): khi tạo case, SOAR gắn quy trình xử lý sự cố phù hợp theo `rule.id`.
Mỗi playbook là checklist task theo 5 giai đoạn của NIST SP 800-61 (Phát hiện & phân tích → Ngăn chặn → Loại bỏ → Khôi phục → Rút kinh nghiệm).

| Playbook | Áp dụng cho |
|---|---|
| PB-01 Dò mật khẩu / tài khoản có thể bị chiếm | AUTH-001..004, WIN-001, WEB-007 |
| PB-02 Tấn công ứng dụng Web | WEB-*, NET-004 |
| PB-03 Thực thi mã độc trên endpoint | LNX-*, WIN-005..009, WIN-011..013 |
| PB-04 Thay đổi tài khoản / đặc quyền | WIN-003, WIN-004, AUTH-005, AUTH-006 |
| PB-05 Trinh sát / quét mạng | NET-001..003, NET-005 |
| PB-06 Kết nối tới IOC | TI-001 |
| PB-07 Xóa dấu vết / nghi ngờ ransomware | WIN-002, WIN-010 |
| PB-08 Thay đổi file trái phép / rootkit / cấu hình yếu | WZH-* (cảnh báo ruleset Wazuh) |
| PB-00 Điều tra chung | mọi rule còn lại |

- **Ưu tiên và hạn triage (SLA)** theo severity: critical = P1 / 15 phút, high = P2 / 1 giờ, medium = P3 / 8 giờ, low = P4 / 24 giờ.
  Case `open` quá hạn hiện chữ đỏ trên console.
- **Vòng đời case**: `open` → `in_progress` → `contained` → `closed` / `false_positive`. **Đóng case bắt buộc ghi kết luận.**
- **Theo dõi trách nhiệm**: mọi thao tác (tick task, giao việc, đổi trạng thái, ghi chú) được ghi vào lịch sử case kèm tài khoản
  thực hiện (lấy từ phiên đăng nhập, không tự khai được) và thời điểm. Lệnh phản ứng thủ công ghi `requested_by`.
  Có khóa lạc quan: hai người sửa cùng lúc thì người sau nhận lỗi 409.
- Task có nhãn **cần duyệt** chỉ được làm sau khi người có thẩm quyền đồng ý:

| Hành động | Ai được quyết định |
|---|---|
| Đóng alert false positive, chặn IP thủ công | Analyst L1 |
| Cô lập máy, khóa tài khoản | Trưởng nhóm IR |
| Cài lại máy, tắt dịch vụ production | Trưởng nhóm IR + chủ hệ thống |

## 5. AI hỗ trợ viết rule (`server/siem/ai/`)

AI **chỉ đề xuất**. Mọi thay đổi rule đều phải qua kiểm định tự động và người duyệt trên console.
LLM chạy nội bộ bằng Ollama, không publish cổng, log không rời khỏi máy.

```bash
python tools/fetch_datasets.py                           # tải dataset công khai vào datasets/raw (lần đầu)
server/.venv/Scripts/python tools/convert_datasets.py    # chuyển sang datasets/processed
docker compose --profile ai up -d                        # chạy trên CPU (chậm)
docker compose -f docker-compose.yml -f docker-compose.gpu.yml --profile ai up -d   # GPU NVIDIA
```
- Lần đầu worker tự tải model (`AI_MODEL`, mặc định `qwen2.5-coder:7b`, khoảng 4,7 GB).
- Khi đã dùng GPU thì **mọi** lệnh `up` sau đó đều phải kèm `-f docker-compose.gpu.yml`, nếu không Ollama bị tạo lại không có GPU.
- Chạy đúng 1 chu kỳ để thử: `docker compose exec ai-worker python -m siem.ai --once`.

**Mỗi chu kỳ** (mặc định 60 phút, hoặc bấm *Chạy phân tích AI ngay* trên tab *Đề xuất AI*) worker tìm ứng viên từ 3 nguồn:

| Nguồn | Khi nào | AI đề xuất |
|---|---|---|
| `exception` | Rule có ≥ 3 alert bị đánh dấu false positive (trên alert hoặc case đóng dạng `false_positive`) trong 30 ngày | Ngoại lệ hẹp cho rule đó |
| `gap-dataset` | Mẫu tấn công trong dataset công khai mà chưa rule `match` nào bắt, gom theo **loại tấn công** (≥ 10 mẫu, xem bên dưới) | Rule mới cho loại tấn công đó |
| `gap-own` | Nhóm event thật (module / category / action, ≥ 20 event trong 7 ngày) chưa rule nào xem xét | Rule mới, hoặc kết luận không cần rule |

Tối đa 5 đề xuất mỗi chu kỳ, và không tạo đề xuất mới cho mục tiêu đang có đề xuất chờ duyệt hoặc đã triển khai.
Rule mới bị người từ chối thì không đề xuất lại cho cùng mục tiêu trong 30 ngày. Nếu bị kiểm định tự động loại thì chỉ bị chặn
khi vẫn cùng model và prompt (xem *Kết quả chạy thử*). Ngoại lệ bị từ chối thì được đề xuất lại, kèm lý do từ chối trước đó trong prompt.

**Kiểm định tự động** (`validate.py`, không tin output của model):

| | Ngoại lệ (làm giảm cảnh báo, rủi ro cao) | Rule mới |
|---|---|---|
| Chung | Compile được, trường có thật trong dữ liệu, toán tử được phép, regex không có nguy cơ ReDoS, không chậm engine | như bên trái, thêm ID không trùng |
| Độ chính xác | Neo vào thực thể cụ thể (IP, user, host, process, URL), không được loại cả `event.category`. Khớp ≥ 50% alert báo nhầm | Bắt ≥ 30% mẫu nghi vấn. Với mẫu từ dataset thì đo trên **tập kiểm tra** (một nửa số mẫu giữ riêng, LLM không thấy) |
| An toàn | Không khớp event nào của case đã xác nhận thật. Không làm mất mẫu tấn công nào mà rule đang bắt trong bộ mẫu vàng | Báo nhầm ≤ 0,1% trên tập bình thường. Rule web không khớp URL nào trong 23 URL của một website bình thường (`ORDINARY_URLS`: `/`, `/images/`, `/search?q=...`). Replay 7 ngày ≤ 20 alert/ngày. Severity chỉ `low`/`medium` |
| Dùng chung được | | Rule từ dataset không được chứa đường dẫn hay tên file của ứng dụng mẫu (vd `tienda1`, `anadir.jsp`) |

**Duyệt và triển khai** (tab *Đề xuất AI* trên console):
- Rule mới cần 1 analyst duyệt. Ngoại lệ cần 2 analyst **khác nhau**.
- Ngay trước khi ghi file, manager kiểm tra lại với case thật mới nhất và bộ mẫu vàng. Không đạt thì không triển khai.
- Triển khai là ghi 1 file riêng: `server/rules/ai/AI-xxx.yml` hoặc `server/rules/exceptions/<id>.yml`. Analyzer tự nạp lại rule khi file đổi.
  Nút *Gỡ* xóa đúng file đó. Từ chối và gỡ đều bắt buộc ghi lý do.
- Manager là service duy nhất ghi được 2 thư mục này, còn rule gốc được mount chỉ đọc. Worker chỉ đọc `siem-*` và chỉ ghi `ai-*`.

**Chống prompt injection**: nội dung log (do kẻ tấn công kiểm soát) chỉ nằm trong khối `DATA`, đã cắt ngắn và lọc ký tự điều khiển.
Output bị ép theo JSON schema (structured output của Ollama) và giới hạn 1024 token. Mã MITRE không đúng dạng `Txxxx` bị bỏ.

**Dataset công khai** (`datasets/`, không đưa vào repo; nguồn, giấy phép và SHA-256 ghi trong `datasets/SOURCES.md`):

| Dataset | Dùng cho |
|---|---|
| HTTP DATASET CSIC 2010 (anomalous) | Mẫu tấn công web có nhãn: tìm khoảng trống và làm bộ mẫu vàng |
| HTTP DATASET CSIC 2010 (normal) | Đo báo nhầm của rule mới |
| SigmaHQ rules (DRL 1.1) | Rule cộng đồng tương tự đưa vào prompt làm tài liệu tham khảo (RAG) |
| EVTX-ATTACK-SAMPLES (tùy chọn) | Mẫu Windows event theo tactic ATT&CK. Cần `python-evtx`; antivirus có thể chặn file này |

Dataset chỉ được chạy offline qua bộ chuẩn hóa và rule engine, không bơm vào index thật.
Đo độ phủ rule hiện tại: `cd server && .venv/Scripts/python -m siem.ai.benchmark --write ../datasets/report.md`.
Kết quả hiện tại: bắt 11% mẫu tấn công quan sát được, 0 báo nhầm. Có thêm 9.977 mẫu tấn công nằm trong body POST, access log không ghi nên không thể phát hiện.

**Gom theo loại tấn công** (`attack_types.py`): mỗi mẫu tấn công web được gán một loại bằng heuristic thô, chỉ để gom nhóm.
Nhờ vậy mỗi lần gọi, LLM chỉ thấy một kiểu tấn công, kèm mô tả loại đó.
CSIC 2010 gán nhãn "bất thường" cho cả những request sai định dạng của riêng ứng dụng mẫu. Rule chữ ký cho các nhóm này
chỉ khớp ứng dụng đó, nên chúng chỉ được báo cáo, không giao cho AI. Muốn bắt cần mô hình hành vi hoặc allowlist theo từng ứng dụng.
Dấu nháy đơn lẻ giữa chữ (tên riêng như `D'estats`, hoặc dataset chèn nháy ngẫu nhiên) không tính là SQLi, vì không viết được
chữ ký chung cho nó mà không báo nhầm tên người hay địa chỉ hợp lệ.

Mỗi mẫu còn được gán **biến thể** (kiểu con trong cùng loại, vd SQLi `tautology-quoted` / `quote-breakout`, hay thư mục bị dò
`/_vti_bin/`) và **payload** (đoạn làm request bị nghi vấn). LLM nhận 8 mẫu trải đều theo biến thể, biến thể đông trước,
thống kê biến thể của cả tập train và payload của từng mẫu. URL dài bị cắt khi đưa vào prompt, còn payload thì không bị cắt.
Chuỗi giữ chỗ `INJECTED_PARAM` của CSIC bị bỏ khỏi payload, và rule chứa nó bị kiểm định loại.

| Loại | Mẫu rule hiện tại chưa bắt | Giao cho AI |
|---|---|---|
| Dò file sao lưu / mã nguồn (`.bak`, `.old`, `~`, `.inc`...) | 2.615 | có |
| Dò tài nguyên nhạy cảm / mặc định (`/_vti_bin`, `/cfide`, `.nsf`...) | 885 | có |
| CRLF / chèn header (`%0A Set-cookie:`) | 540 | có |
| Mã hóa né tránh (`%25xx`, `%00`) | 466 | có |
| SQL Injection (dạng rule hiện tại bỏ sót, vd `'OR'a='a`, `AND 1=1`) | 392 | có |
| Server-Side Include (`<!--#exec`) | 265 | có |
| Tham số lạ / giá trị sai định dạng / đường dẫn không tồn tại (riêng ứng dụng) | 8.266 | không |

**Ghép rule theo biến thể** (`worker._refine`, chỉ cho nhóm web): câu trả lời đầu của LLM được tách thành từng mẫu (giá trị
của mệnh đề). Mỗi mẫu được đo trên tập train và nửa tập bình thường, và chỉ được giữ nếu bắt thêm được tấn công mà không khớp
request bình thường, không khớp URL thông thường, không gắn với ứng dụng mẫu. Sau đó, tối đa `AI_REFINE_ROUNDS` (mặc định 6)
lượt bổ sung hỏi riêng **một biến thể** còn sót nhiều nhất. Mỗi lượt dùng prompt mới, kèm mẫu đã giữ và mẫu bị loại (có lý do),
nhưng không kèm câu trả lời cũ và không nêu tên loại tấn công. Hỏi lại cùng biến thể thì tăng temperature và luân phiên kiểu payload
(khúc URL / đúng cặp tham số=giá trị). Rule cuối là OR các mẫu đã giữ, rồi mới qua kiểm định trên tập kiểm tra. Tập kiểm tra
không được dùng ở bước ghép. Lý do thiết kế như vậy, rút ra khi chạy thử với `qwen2.5-coder:7b`:
- Gửi lại rule cũ kèm phản hồi chi tiết từng giá trị thì model chỉ chép lại nguyên văn, kể cả ở temperature 0,8.
- Prompt có nhắc "SQL injection" thì model viết payload sách giáo khoa (`' OR 1=1`), dù cả 8 payload đưa vào đều là `'OR'a='a`.
- Model hay viết cú pháp regex (`AND\s*1=1`) nhưng lại để op là `contains`. Worker tự đổi op sang `regex`.
- Thêm ví dụ mẫu (few-shot) từ loại tấn công khác làm kết quả tệ hơn.

Các biến cấu hình `AI_*` nằm trong `.env.example`.

**Kết quả chạy thử** (27/9/2026, `qwen2.5-coder:7b` trên GPU Quadro RTX 4000 8 GB, mỗi lần gọi LLM 30–60 giây):

| Cách làm | Đề xuất qua kiểm định |
|---|---|
| Gom theo `url.path` (bản đầu) | 0/10: 7 học vẹt chuỗi trong mẫu (bắt 0–9% tập kiểm tra), 2 quá rộng (báo nhầm 100%), 1 không đề xuất |
| Gom theo loại tấn công | 2/6 (file sao lưu, mã hóa né tránh). SSI và SQLi hỏng vì LLM so payload đã giải mã với `url.query` còn mã hóa |
| Gom theo loại + prompt nói rõ `url.query` thô / `url.decoded` đã giải mã | **4/6**: file sao lưu (bắt 82% tập kiểm tra), CRLF (100%), mã hóa né tránh (60%), SSI (100%), đều 0 báo nhầm |

- Hai loại vẫn chưa đạt: SQLi (bắt 18%) và tài nguyên nhạy cảm (15%). Model chỉ chép lại vài chuỗi cụ thể trong mẫu.
- Nếu duyệt cả 4 rule đạt, độ phủ trên mẫu tấn công quan sát được tăng từ 11,0% lên **32,3%** (riêng các loại có chữ ký dùng chung: 23% → 69%),
  báo nhầm vẫn 0/36.000. Các rule này đang chờ duyệt trên console. Người duyệt nên xem kỹ nội dung
  (vd AI-010 dùng regex chưa neo cuối đường dẫn, phần mô tả bị lặp).
- Chính sách thử lại: đề xuất do con người từ chối hoặc gỡ thì mục tiêu đó bị chặn 30 ngày. Đề xuất bị kiểm định tự động loại
  thì chỉ bị chặn khi vẫn cùng model và cùng prompt; đổi `AI_MODEL` hoặc sửa prompt là được thử lại ngay.
- Luồng đề xuất ngoại lệ đã chạy trên dữ liệu thật: máy backup nội bộ `10.50.0.7` đăng nhập SSH bằng root theo lịch,
  làm AUTH-004 bắn 5 lần và analyst đánh dấu cả 5 là false positive. LLM đề xuất ngoại lệ `source.ip eq 10.50.0.7`
  (37,5 giây), qua đủ 9 bước kiểm định (khớp 5/5 báo nhầm, replay 5 → 0 alert). Hệ thống đánh giá **rủi ro cao** vì rule
  chưa có case thật hay mẫu vàng để đối chứng và ngoại lệ tắt 100% alert của rule. Đề xuất đang chờ 2 người duyệt.

## 6. Kiểm thử

```bash
cd server && python -m venv .venv && .venv/Scripts/pip install -r requirements.txt pytest httpx
.venv/Scripts/python -m pytest -q      # 82 test: parser, rule, ML, SOAR, case playbook, API + đăng nhập, Grafana proxy, AI, Wazuh
cd .. && docker run --rm -v ./vector:/etc/vector:ro timberio/vector:0.58.0-alpine test /etc/vector/wazuh.yaml /etc/vector/wazuh-tests.yaml
```
**Kiểm thử end-to-end trên stack đang chạy** (cần `--profile demo`): `python tools/e2e_test.py`. Script không dùng tài
khoản `admin` thật mà tự tạo quản trị viên tạm `e2e-admin`. Nó tấn công thật vào máy demo và kiểm tra cả chuỗi: SQLi → WEB-001 →
chặn IP qua Wazuh → gỡ chặn; command injection → LNX-002 → kill cả cây tiến trình; webshell → FIM → case PB-08; phân quyền /
phiên console; Grafana sau manager (cổng 3000 đóng, giả header vô tác dụng, Viewer không sửa được dashboard, Sign out trong
Grafana thoát luôn phiên console). Mọi thứ nó tạo ra đều được dọn sau khi chạy. Lần chạy 30/9/2026: 34/34 đạt, mất khoảng 70 giây.
Lần chạy đầu tìm ra 2 lỗi, đã sửa: SOAR tin bản ghi chặn cũ, và SOAR thiếu quyền refresh index khi đánh dấu lệnh chặn đã gỡ.

Sinh lại dashboard Grafana: `python tools/gen_dashboard.py` (Grafana tự nạp lại file sau vài giây).
Mục *Phiên đăng nhập* gồm đăng nhập hệ thống (SSH, PAM, Windows logon 4624/4625: thành công / thất bại, tài khoản đặc quyền,
IP nguồn, máy, hình thức) và đăng nhập form web (POST tới đường dẫn `login`: access log chỉ có IP và mã HTTP, không có tên tài khoản).

## 7. Bảo mật nội bộ

| Lớp | Cách làm |
|---|---|
| **TLS** | `es-certs` sinh CA nội bộ và chứng chỉ cho `elasticsearch`, `manager` và `wazuh-manager` (Wazuh API). Elasticsearch bật TLS cho HTTP và transport. Manager API và Wazuh API chạy HTTPS. Grafana và các service Python (kể cả SOAR khi gọi Wazuh API) đều **xác thực chứng chỉ bằng CA** (không dùng `insecure`). |
| **Kênh agent** | Wazuh agent mã hóa event bằng AES với khóa riêng từng agent. Enroll (1515) qua TLS và **bắt buộc mật khẩu** (`secrets/enrollment_key`, manager chép vào `etc/authd.pass` mỗi lần khởi động). |
| **Wazuh API** | Không publish cổng 55000. SOAR dùng user `siem-soar` chỉ có 2 quyền: `active-response:command` và `agent:read` (đọc rule hay sửa cấu hình → 403). Hai user mặc định `wazuh` / `wazuh-wui` (mật khẩu mặc định công khai) bị đổi sang mật khẩu ngẫu nhiên mỗi lần khởi động. |
| **Đăng nhập console** | Trang đăng nhập chung `/login` cho console và Grafana (`server/siem/manager/static/login.html`). Tài khoản riêng từng người thay cho API key dùng chung (`server/siem/manager/auth.py`). Mật khẩu băm scrypt, tối thiểu 12 ký tự, không chứa tên đăng nhập. Phiên nằm trong cookie `HttpOnly` + `Secure` + `SameSite=Strict`, JavaScript không đọc được, không lưu gì vào localStorage. Hết hạn sau 30 phút không thao tác (lần tự làm mới 5 giây/lần của console không được tính) và tối đa 8 giờ. Sai mật khẩu 5 lần / 15 phút (theo tài khoản hoặc IP) thì khóa 15 phút. Request thay đổi dữ liệu phải có header `X-Requested-With` (chống CSRF). Cấu hình: `CONSOLE_IDLE_MINUTES`, `CONSOLE_SESSION_HOURS`, `CONSOLE_MAX_FAILURES`. |
| **Grafana dùng chung phiên** | Grafana không mở cổng ra ngoài. Mọi request đi qua manager (`server/siem/manager/grafana_proxy.py`), nên Grafana có cùng chính sách phiên, khóa tài khoản và nhật ký đăng nhập với console. Manager kiểm tra phiên (chưa đăng nhập → `/login`), xóa header `X-WEBAUTH-*` do trình duyệt gửi, rồi gửi tên và vai trò sang Grafana ở chế độ *auth proxy*. Form đăng nhập, basic auth và phiên riêng của Grafana đều tắt. Grafana chỉ tin header từ IP của manager (`10.250.30.10`) trên mạng riêng `grafana-auth`, và chỉ lắng nghe trên mạng đó, nên container khác trong lab (vd. máy web demo bị chiếm) không gọi thẳng được. Vai trò: `admin` → Admin, `lead` → Editor (sửa dashboard), `analyst` → Viewer (chỉ xem). Dashboard tự làm mới 10 giây/lần không gia hạn phiên. Bấm *Sign out* trong Grafana là đăng xuất cả console. Lúc khởi động, manager gán quyền mặc định (Viewer xem, Editor sửa) cho thư mục SIEM-XDR, vì Grafana 11 tạo thư mục provisioning mà không kèm quyền nào. |
| **Vai trò console** | `analyst` (L1): xử lý alert/case, chặn IP, kill, duyệt đề xuất AI. `lead` (Trưởng nhóm IR): thêm cô lập / bỏ cô lập máy. `admin`: thêm tạo, khóa, đổi vai trò, đặt lại mật khẩu tài khoản (tab *Tài khoản*). Tài khoản mới và mật khẩu vừa đặt lại luôn phải đổi ở lần đăng nhập đầu. Không tự khóa được chính mình, và luôn phải còn ít nhất 1 admin. |
| **Nhật ký đăng nhập** | Đăng nhập (đúng/sai/bị khóa), đăng xuất, đổi mật khẩu, quản lý tài khoản của console được gửi vào Kafka thành event của chính SIEM (`event.module: console`). Chúng hiện ở mục *Phiên đăng nhập* trên Grafana, và rule brute-force AUTH-001 áp dụng được cho console. Hash mật khẩu nằm ở index `console-users` (ngoài `siem-*`), nên Grafana và tài khoản ES chỉ đọc không thấy. |
| **RBAC** | Mỗi service có một user Elasticsearch với quyền tối thiểu (bảng dưới). Superuser `elastic` chỉ dùng trong `es-setup` và khi khẩn cấp. |
| **Bí mật** | `tools/init_secrets.py` sinh ngẫu nhiên vào `secrets/` (đã gitignore). Mỗi service chỉ được mount **đúng** secret nó cần qua Docker secrets (`/run/secrets/...`), không có bí mật trong `.env`, biến môi trường hay compose. Mật khẩu `elastic` được Elasticsearch ghi vào **keystore** (`bootstrap.password`). |
| **Khóa riêng** | Khóa CA chỉ root đọc được. Khóa của ES và manager chỉ uid của service tương ứng đọc được. Các container khác chỉ mount thư mục `ca/` (chứng chỉ công khai). |
| **Mạng** | Elasticsearch, Kafka UI chỉ bind `127.0.0.1`. Kafka và Grafana không publish ra ngoài (Grafana chỉ vào qua manager). |

| User Elasticsearch | Role | Quyền |
|---|---|---|
| `siem_manager` | siem_manager | đọc/ghi `siem-actions`, `siem-alerts`, `siem-cases`, `ai-*`, `console-users`; chỉ đọc `siem-events-*`, `siem-agents` |
| `siem_analyzer` | siem_analyzer | chỉ ghi `siem-events-*`, `siem-alerts` (không đọc được action/case) |
| `siem_soar` | siem_soar | đọc/ghi `siem-alerts`, `siem-actions`, `siem-cases`, `siem-agents` (đồng bộ từ Wazuh); chỉ đọc `siem-events-*` (kết quả lệnh) |
| `siem_ai` | siem_ai | chỉ đọc `siem-events-*`, `siem-alerts`, `siem-cases`; đọc/ghi `ai-*` |
| `grafana`, `analyst` | siem_reader | chỉ đọc `siem-*` |

Đã kiểm chứng khi chạy: truy cập không có tài khoản → 401; `analyst` ghi/xóa → 403; `siem_analyzer` đọc `siem-actions` → 403;
`siem_manager` gọi API quản trị user → 403; HTTP thường tới ES/manager bị từ chối.
Console (30/9/2026, server thật): chưa đăng nhập hoặc dùng API key cũ → 401. Đăng nhập thiếu header chống CSRF → 403.
Mật khẩu tạm → buộc đổi (các API khác trả 403). Tài khoản `analyst` cô lập máy hoặc xem danh sách tài khoản → 403.
Lệnh do analyst tạo ghi đúng `requested_by`. Sau khi đăng xuất, dùng lại cookie cũ → 401. Cả 9 thao tác đăng nhập / quản lý
tài khoản đều thành event trong `siem-events-*`.

**Agent ở máy khác**: mở cổng 1514, 1515 của máy chạy docker cho dải IP của endpoint, rồi cài agent theo mục 1.
Truy cập console từ máy khác thì đặt `MANAGER_TLS_IPS=<IP máy docker>` trong `.env` và xóa volume `certs` để sinh lại chứng chỉ.

**Giới hạn còn lại**:
- Kafka chạy plaintext trong mạng docker nội bộ.
- Phiên đăng nhập console nằm trong bộ nhớ manager: khởi động lại manager thì mọi người phải đăng nhập lại. Chưa có
  xác thực 2 lớp (2FA) hay đăng nhập qua LDAP/SSO.
- Đổi `elastic_password` sau lần chạy đầu phải đổi qua API của ES, hoặc xóa volume `esdata`.
- Ollama gọi qua HTTP thường trong mạng docker nội bộ (không publish cổng ra ngoài).
- Agent chưa kiểm tra chứng chỉ của wazuh-manager khi enroll (tùy chọn `server_ca_path` của Wazuh). Mật khẩu enroll lộ thì
  máy lạ enroll được agent giả, nhưng agent giả chỉ gửi được dữ liệu dưới tên của chính nó, không nhận hay báo kết quả lệnh của máy khác.
