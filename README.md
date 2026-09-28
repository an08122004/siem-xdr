# SIEM/XDR Lab — tự xây dựng

Hệ thống SIEM + XDR cho môn GSANM, dựng theo kiến trúc trong `BTL/SIEM.txt`
và danh mục tài sản `BTL/asset.txt`. Toàn bộ backend đóng gói bằng Docker.

```
 Endpoint / Server                       Backend (docker-compose)
 ┌───────────────────┐   HTTPS/JSON   ┌──────────┐   ┌─────────────────┐   ┌────────────┐   ┌──────────────┐   ┌─────────┐
 │ siem-agent (Go)   │ ─────────────▶ │ Manager  │──▶│ Kafka           │──▶│ Analyzer   │──▶│ Elasticsearch│──▶│ Grafana │
 │ file/eventlog/proc│ ◀── lệnh XDR ──│ API      │   │ (KRaft)         │   │ normalize  │   │ events/alerts│   └─────────┘
 └───────────────────┘                └──────────┘   │ siem.raw        │   │ enrich (TI)│   └──────────────┘
 ┌───────────────────┐   syslog 514   ┌──────────┐   │ siem.alerts     │   │ rules + ML │
 │ Firewall/Suricata │ ─────────────▶ │ Syslog   │──▶│                 │◀──┘            │
 └───────────────────┘                └──────────┘   └───────┬─────────┘                │
                                                             ▼
                                                     ┌──────────────┐  tạo lệnh block_ip / kill_process / isolate_host
                                                     │ SOAR         │──────────────────────▶ Manager ──▶ Agent
                                                     │ playbooks    │  notify (webhook/Telegram), create_case
                                                     └──────────────┘
                                                     ┌──────────────┐  chỉ đọc siem-*, ghi đề xuất vào ai-*
                                                     │ AI worker    │◀──▶ Ollama (LLM nội bộ)
                                                     │ (chỉ đề xuất)│  analyst duyệt trên console ─▶ Manager ghi rules/ai, rules/exceptions
                                                     └──────────────┘
```

| Thành phần | Công nghệ | Thư mục |
|---|---|---|
| Agent đa nền tảng (Windows/Linux) | Go, không dependency ngoài | `agent/` |
| Manager API + SOC console | FastAPI | `server/siem/manager/` |
| Syslog collector (UDP/TCP 514) | **Vector** 0.58 (Rust), hàng đợi trên đĩa | `vector/` (bản Python cũ `server/siem/collector/` chỉ giữ để đối chiếu) |
| Message bus | Kafka 7.7 (Confluent) chế độ **KRaft**, không dùng ZooKeeper | `docker-compose.yml` |
| Chuẩn hóa log (ECS rút gọn) + làm giàu | Python | `server/siem/pipeline/` |
| Phân tích dựa trên luật | Rule engine YAML (match / threshold / sequence) | `server/siem/detection/rules.py`, `server/rules/` |
| Phân tích dựa trên ML (**tạm dừng**) | Isolation Forest (scikit-learn) | `server/siem/detection/ml.py` |
| SOAR + quản lý case | Playbook tự động + case playbook NIST | `server/siem/soar/`, `server/config/playbooks.yml`, `server/config/case_playbooks.yml` |
| AI hỗ trợ viết rule (chỉ đề xuất) | Ollama (`qwen2.5-coder:7b`) + kiểm định tự động + duyệt trên console | `server/siem/ai/`, `tools/fetch_datasets.py`, `tools/convert_datasets.py` |
| Bảo mật nội bộ | TLS (CA nội bộ), RBAC Elasticsearch, Docker secrets + keystore | `security/setup.sh`, `tools/init_secrets.py` |
| Lưu trữ | Elasticsearch 8 (xpack security bật) | |
| Trực quan hóa | Grafana 11 (dashboard được provision sẵn) | `grafana/` |

## 1. Agent (`agent/`)

Phát triển tiếp từ `Wazuh/agent-core`, giữ nguyên thiết kế: collector → hàng đợi trên đĩa → sender (at-least-once).
Chỉ dùng thư viện chuẩn của Go (không dependency ngoài).

**Không mất event**: collector ghi từng lô vào queue và chờ fsync xong rồi mới lưu offset/bookmark,
nên agent crash hay bị dừng giữa chừng thì lần sau đọc lại đúng chỗ (có thể gửi trùng, không bỏ sót).
Queue chia thành segment 16 MB; segment đã gửi xong bị xóa. Tổng dung lượng giới hạn bởi `queue.max_mb`
(mặc định 512): manager mất kết nối lâu, queue đầy thì collector tạm dừng chứ không vứt event
(nguồn log vẫn giữ dữ liệu, đọc tiếp khi có chỗ). Queue của bản cũ (`queue.log`) được tự chuyển đổi.

**Collector**
- `filetail`: tail file log trên mọi OS (Apache access/error, `auth.log`, Suricata `eve.json`, syslog), có wildcard.
  Giữ handle file nên khi log bị xoay vòng vẫn đọc nốt file cũ rồi mới chuyển sang file mới (Windows mở với
  `FILE_SHARE_DELETE`, không cản ứng dụng xoay vòng log). Lưu fingerprint 1 KB đầu file cùng offset: agent tắt đúng lúc
  log xoay vòng thì khi chạy lại vẫn đọc nốt phần còn lại ở `<file>.1` và đọc file mới từ đầu. Phát hiện cả copytruncate.
- `winevent`: đọc Windows Event Log bằng `wevtutil` (Security, System, Sysmon, PowerShell, Defender). Mỗi vòng đọc hết
  tồn đọng (tới 10.000 bản ghi/channel), đọc cả `UserData` (vd người xóa audit log trong event 1102), phát hiện log bị xóa
  (đánh số lại) và báo `agent_health` khi bản ghi bị ghi đè trước khi kịp đọc.
- `process`: tiến trình mới trên Linux. `process_mode: auto` dùng netlink proc connector (kernel báo ngay mỗi `execve`,
  bắt được cả tiến trình sống vài mili giây); không dùng được (container có network/PID namespace riêng, thiếu root)
  thì lùi về quét `/proc`. Windows dùng Sysmon / 4688 qua `winevent`.
- `fim`: giám sát toàn vẹn file bằng cách băm SHA-256 định kỳ (`fim.paths`, mặc định 5 phút). Lần đầu chỉ lập baseline;
  sau đó báo file thêm / sửa nội dung / đổi quyền / xóa kèm hash trước và sau (rule FIM-001..003).
- `mock`: sinh dữ liệu giả để test.

**Response (XDR)**: agent định kỳ hỏi manager xem có lệnh mới không rồi thực thi. Mọi tham số được validate,
lệnh chạy không qua shell, chạy lại cùng lệnh không tạo luật trùng. Bật `response.dry_run: true` để chỉ ghi log.

| Lệnh | Linux | Windows |
|---|---|---|
| `block_ip` / `unblock_ip` | iptables / ip6tables, chặn cả vào lẫn ra (cắt kết nối ngược ra C2) | netsh, luật `dir=in` + `dir=out` |
| `isolate_host` | chain riêng: chỉ loopback, DHCP, manager; áp cho cả IPv4 và IPv6 | luật block mọi IP trừ manager (thắng mọi luật allow sẵn có), không đổi chính sách mặc định |
| `kill_process` | theo pid (đối chiếu tên với alert, tránh giết nhầm khi PID bị tái sử dụng) hoặc theo tên | như Linux |

- Chặn có hạn thì **agent tự gỡ** đúng hạn (lưu ở `response.state.json`), kể cả khi mất kết nối manager lúc đó.
- Khi cô lập, DNS bị chặn nên agent ghim IP manager và gọi thẳng IP đó (TLS vẫn xác thực theo tên), kể cả sau khi khởi động lại.
- Từ chối: chặn IP manager, kill tiến trình hệ thống (lsass, csrss, systemd…) kể cả theo pid, kill theo tên các tiến trình
  dùng chung (bash, powershell.exe, explorer.exe…) — những tiến trình này chỉ được kill theo pid.

**Bảo mật kênh và danh tính**: agent enroll bằng `enrollment_key` dùng chung, nhận **token ngẫu nhiên** riêng
(manager chỉ lưu hash). Khóa enroll chỉ đủ để đăng ký agent MỚI: xin token cho `agent_id` đã tồn tại thì phải trình token
hiện tại của agent đó, nếu không manager trả 409 và sinh alert AGENT-001 (nghi giả mạo agent). Máy cài lại / mất token:
analyst bấm **Cho enroll lại** trên tab Agents (có hạn 60 phút, nên giới hạn theo IP máy thật). Nút **Thu hồi** vô hiệu hóa
token ngay. Server ghi đè `agent_id` trong payload bằng danh tính đã xác thực. Thư mục trạng thái (token, queue, offset)
được agent tự siết quyền: `chmod 700` trên Linux; trên Windows bỏ quyền thừa kế từ `C:\ProgramData`, chỉ còn SYSTEM,
Administrators và tài khoản chạy agent.

```bash
cd agent
go test ./...
GOOS=linux   GOARCH=amd64 go build -o bin/siem-agent     ./cmd/agent
GOOS=windows GOARCH=amd64 go build -o bin/siem-agent.exe ./cmd/agent
```
- Linux (S001 Web-01, A003 Ubuntu-01): sửa `config.linux.yaml` (IP manager, key), `chmod 600` file này, rồi cài service
  systemd (tự khởi động cùng máy, tự chạy lại khi chết): `sudo ./siem-agent -install -config /etc/siem-agent/config.yaml`.
  Gỡ: `sudo ./siem-agent -uninstall`. Chạy thử ở foreground: `sudo ./siem-agent -config config.linux.yaml`.
- Windows (A001 PC-01): chép `config.windows.yaml` vào `C:\ProgramData\siem-agent\config.yaml`, mở PowerShell **Administrator**:
  `.\siem-agent.exe -install -config C:\ProgramData\siem-agent\config.yaml` (Windows Service chạy bằng LocalSystem, SCM tự
  khởi động lại nếu agent chết). Gỡ: `.\siem-agent.exe -uninstall`. Nên cài Sysmon để có telemetry process/network.

**Nâng cấp từ bản cũ**: agent cũ dùng token HMAC; manager mới không nhận token đó để gọi API nữa, agent mới tự trình
token cũ để đổi sang token ngẫu nhiên (không cần thao tác). Agent **bản cũ** chạy với manager mới sẽ bị 409 khi enroll lại:
build lại agent, hoặc bấm "Cho enroll lại" cho agent đó.

## 2. Backend

```bash
python tools/init_secrets.py   # sinh mật khẩu/key ngẫu nhiên vào secrets/ (chỉ lần đầu)
cp .env.example .env           # cấu hình không bí mật; đặt MANAGER_TLS_IPS nếu agent ở máy khác
docker compose up -d --build
docker compose ps              # es-setup phải Exited (0); kafka, elasticsearch healthy
```
Phần AI (`--profile ai`, xem mục 5) và máy web demo (`--profile demo`, xem bên dưới) nằm trong profile riêng, không chạy mặc định.

| URL | Dùng để | Đăng nhập |
|---|---|---|
| https://localhost:8000 | SOC console: alert, agent, lệnh phản ứng, case | API key: `secrets/api_key` + tên analyst |
| https://localhost:8000/docs | Swagger của Manager API | |
| http://localhost:3000 | Grafana, dashboard *SIEM/XDR — Tổng quan SOC* | `admin` / `secrets/grafana_admin_password` |
| http://127.0.0.1:8088 | Kafka UI (chỉ từ máy chạy docker) | |
| https://127.0.0.1:9200 | Elasticsearch (chỉ từ máy chạy docker) | `analyst` / `secrets/analyst_es_password` (chỉ đọc) |
| UDP/TCP 514 | Syslog từ firewall F001 / Suricata | |

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

**Máy web demo**: `docker compose --profile demo up -d --build demo-web` dựng thêm Apache kèm agent tại
http://localhost:8081. Truy cập trang này sẽ sinh log thật đi qua toàn bộ pipeline.
Trang `/cgi-bin/ping.cgi` **cố ý có lỗ hổng command injection** để kiểm tra rule LNX-002 và lệnh kill/chặn IP.
Chỉ chạy máy này trong lab cô lập.

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

**Luật** (`server/rules/*.yml`, 45 luật, có gắn MITRE ATT&CK):

| Nhóm | Luật |
|---|---|
| Web | SQLi, XSS, path traversal/LFI, command injection/Log4Shell, scanner UA, dirbusting, brute-force form, webshell, HTTP flood |
| Xác thực | SSH brute-force, brute-force **rồi thành công** (sequence), password spraying (distinct user), root login, tạo user, sudo shell |
| Windows | 4625 brute-force, xóa audit log, tạo user, thêm vào Administrators, PowerShell `-enc`, download cradle/AMSI bypass, Mimikatz/LSASS dump, Office sinh shell, service lạ, xóa shadow copy, Defender, LOLBins, schtasks |
| Linux | reverse shell, web server sinh shell, `curl \| sh`, crypto miner, trinh sát, persistence |
| Mạng | port scan (distinct port), firewall deny hàng loạt, dịch vụ nhạy cảm lộ ra Internet, Suricata severity cao, SMB lateral, Threat Intel IOC |
| FIM | file hệ thống / cơ chế duy trì bị sửa (passwd, sudoers, SSH key, cron, systemd, Startup, hosts), webshell mới trong web root, thay đổi khác trong vùng giám sát |
| Hệ thống giám sát | enroll trùng `agent_id` đang có (nghi giả mạo agent), dò khóa enroll |

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

**Làm giàu**: Threat Intel (`server/config/intel/*.txt`: IP/CIDR, domain, hash, tự nạp lại khi file đổi),
tài sản (`server/config/assets.yml`, lấy từ `asset.txt`) dùng để tính `risk_score` theo mức quan trọng của tài sản.

## 4. SOAR và quản lý case

**Phản ứng tự động** (`server/config/playbooks.yml`): ví dụ AUTH-001 → chặn IP trên **mọi** agent trong 1 giờ, gửi thông báo, tạo case.
AUTH-002 → chặn 24 giờ, còn cô lập máy thì chờ analyst duyệt (`approval: true`).
SOAR tự tạo lệnh gỡ chặn khi hết hạn (agent cũng tự gỡ đúng hạn nếu mất kết nối), bỏ qua IP trong `SOAR_WHITELIST` và không chặn trùng.
FIM-001/002 và AGENT-* chỉ thông báo và mở case; cô lập máy khi có webshell phải được duyệt.
Đặt `SOAR_AUTO_RESPONSE=false` nếu chỉ muốn thông báo và tạo case.

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
| PB-08 Tấn công vào hệ thống giám sát (giả mạo / chiếm agent) | AGENT-* |
| PB-09 Thay đổi file trái phép (FIM) | FIM-* |
| PB-00 Điều tra chung | mọi rule còn lại |

- **Ưu tiên và hạn triage (SLA)** theo severity: critical = P1 / 15 phút, high = P2 / 1 giờ, medium = P3 / 8 giờ, low = P4 / 24 giờ.
  Case `open` quá hạn hiện chữ đỏ trên console.
- **Vòng đời case**: `open` → `in_progress` → `contained` → `closed` / `false_positive`. **Đóng case bắt buộc ghi kết luận.**
- **Theo dõi trách nhiệm**: mọi thao tác (tick task, giao việc, đổi trạng thái, ghi chú) được ghi vào lịch sử case kèm tên analyst và thời điểm.
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
| An toàn | Không khớp event nào của case đã xác nhận thật. Không làm mất mẫu tấn công nào mà rule đang bắt trong bộ mẫu vàng | Báo nhầm ≤ 0,1% trên tập bình thường. Replay 7 ngày ≤ 20 alert/ngày. Severity chỉ `low`/`medium` |
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
Nhờ vậy mỗi lần gọi, LLM chỉ thấy một kiểu tấn công, kèm mô tả loại đó và 8 mẫu trải đều nhiều đường dẫn.
CSIC 2010 gán nhãn "bất thường" cho cả những request sai định dạng của riêng ứng dụng mẫu. Rule chữ ký cho các nhóm này
chỉ khớp ứng dụng đó, nên chúng chỉ được báo cáo, không giao cho AI. Muốn bắt cần mô hình hành vi hoặc allowlist theo từng ứng dụng.

| Loại | Mẫu rule hiện tại chưa bắt | Giao cho AI |
|---|---|---|
| Dò file sao lưu / mã nguồn (`.bak`, `.old`, `~`, `.inc`...) | 2.615 | có |
| Dò tài nguyên nhạy cảm / mặc định (`/_vti_bin`, `/msadc`, `.htr`...) | 885 | có |
| SQL Injection (dạng rule hiện tại bỏ sót, vd `AND 1=1` không có dấu nháy) | 679 | có |
| CRLF / chèn header (`%0A Set-cookie:`) | 540 | có |
| Mã hóa né tránh (`%25xx`, `%00`) | 465 | có |
| Server-Side Include (`<!--#exec`) | 265 | có |
| Tham số lạ / giá trị sai định dạng / đường dẫn không tồn tại (riêng ứng dụng) | 7.980 | không |

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
.venv/Scripts/python -m pytest -q      # 66 test: parser, rule (gồm FIM, AGENT), ML, SOAR, case playbook, API (enroll/thu hồi), AI
cd ../agent && go test ./...            # queue, filetail (xoay vòng log), winevent, FIM, response, service, test đầu-cuối với manager giả
```
Test với môi trường thật (Linux, cần container): `go test -c` rồi chạy file test trong container
- iptables/ip6tables thật: `docker run --rm --cap-add NET_ADMIN -e SIEM_IPTABLES_IT=1 ... response.test`
- netlink proc connector: chạy bằng root trên máy Linux (không phải container có namespace riêng).
Sinh lại dashboard Grafana: `python tools/gen_dashboard.py`.

## 7. Bảo mật nội bộ

| Lớp | Cách làm |
|---|---|
| **TLS** | `es-setup` sinh CA nội bộ và chứng chỉ cho `elasticsearch` và `manager`. Elasticsearch bật TLS cho HTTP và transport. Manager API chạy HTTPS. Agent, Grafana và các service Python đều **xác thực chứng chỉ bằng CA** (không dùng `insecure`). |
| **RBAC** | Mỗi service có một user Elasticsearch với quyền tối thiểu (bảng dưới). Superuser `elastic` chỉ dùng trong `es-setup` và khi khẩn cấp. |
| **Bí mật** | `tools/init_secrets.py` sinh ngẫu nhiên vào `secrets/` (đã gitignore). Mỗi service chỉ được mount **đúng** secret nó cần qua Docker secrets (`/run/secrets/...`), không có bí mật trong `.env`, biến môi trường hay compose. Mật khẩu `elastic` được Elasticsearch ghi vào **keystore** (`bootstrap.password`). |
| **Khóa riêng** | Khóa CA chỉ root đọc được. Khóa của ES và manager chỉ uid của service tương ứng đọc được. Các container khác chỉ mount thư mục `ca/` (chứng chỉ công khai). |
| **Mạng** | Elasticsearch, Kafka UI chỉ bind `127.0.0.1`. Kafka không publish ra ngoài. |

| User Elasticsearch | Role | Quyền |
|---|---|---|
| `siem_manager` | siem_manager | đọc/ghi `siem-agents`, `siem-actions`, `siem-alerts`, `siem-cases`, `ai-*`; chỉ đọc `siem-events-*` |
| `siem_analyzer` | siem_analyzer | chỉ ghi `siem-events-*`, `siem-alerts` (không đọc được action/case) |
| `siem_soar` | siem_soar | đọc/ghi `siem-alerts`, `siem-actions`, `siem-cases`; chỉ đọc `siem-agents` |
| `siem_ai` | siem_ai | chỉ đọc `siem-events-*`, `siem-alerts`, `siem-cases`; đọc/ghi `ai-*` |
| `grafana`, `analyst` | siem_reader | chỉ đọc `siem-*` |

Đã kiểm chứng khi chạy: truy cập không có tài khoản → 401; `analyst` ghi/xóa → 403; `siem_analyzer` đọc `siem-actions` → 403;
`siem_manager` gọi API quản trị user → 403; HTTP thường tới ES/manager bị từ chối.

**Agent ở máy khác**:
1. Đặt `MANAGER_TLS_IPS=<IP máy docker>` trong `.env`, rồi xóa volume `certs` để sinh lại chứng chỉ.
2. Copy `ca.crt` sang máy agent và khai báo `server.ca_file` trong config agent.
3. Có thể đặt enrollment key qua `SIEM_ENROLLMENT_KEY_FILE` thay vì ghi trong config.

**Danh tính agent**: token ngẫu nhiên riêng cho từng agent, manager chỉ lưu SHA-256, thu hồi được từng agent.
Khóa enroll dùng chung bị lộ (đọc được từ bất kỳ endpoint nào) cũng không đủ để giả mạo agent đang có: manager trả 409
và alert AGENT-001 chỉ ra máy đã thử. Mọi thao tác enroll / thu hồi / cho enroll lại đều ghi thành event `agent_audit`.

**Giới hạn còn lại**:
- Khóa enroll vẫn dùng chung: ai có khóa vẫn đăng ký được agent MỚI (gửi event rác dưới một agent_id mới) —
  theo dõi tab Agents / event `agent_enrolled`.
- Agent chưa có alert khi ngừng gửi dữ liệu (chỉ hiện `offline` trên console).
- Kafka chạy plaintext trong mạng docker nội bộ.
- Console dùng một API key chung, còn tên analyst là do người dùng tự khai (chưa có đăng nhập theo từng người).
- Đổi `elastic_password` sau lần chạy đầu phải đổi qua API của ES, hoặc xóa volume `esdata`.
- Ollama gọi qua HTTP thường trong mạng docker nội bộ (không publish cổng ra ngoài).
