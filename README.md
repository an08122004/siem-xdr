# SIEM/XDR Lab — tự xây dựng

Hệ thống SIEM + XDR cho môn GSANM, dựng theo kiến trúc trong `BTL/SIEM.txt`
và danh mục tài sản `BTL/asset.txt`. Toàn bộ backend đóng gói bằng Docker.

```
 Endpoint / Server                       Backend (docker-compose)
 ┌───────────────────┐   HTTPS/JSON   ┌──────────┐   ┌─────────────────┐   ┌────────────┐   ┌──────────────┐   ┌─────────┐
 │ siem-agent (Go)   │ ─────────────▶ │ Manager  │──▶│ Kafka           │──▶│ Analyzer   │──▶│ Elasticsearch│──▶│ Grafana │
 │ file/eventlog/proc│ ◀── lệnh XDR ──│ API      │   │ (+ Zookeeper)   │   │ normalize  │   │ events/alerts│   └─────────┘
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
| Syslog collector (UDP/TCP 514) | asyncio | `server/siem/collector/` |
| Message bus | Kafka + Zookeeper | `docker-compose.yml` |
| Chuẩn hóa log (ECS rút gọn) + làm giàu | Python | `server/siem/pipeline/` |
| Phân tích dựa trên luật | Rule engine YAML (match / threshold / sequence) | `server/siem/detection/rules.py`, `server/rules/` |
| Phân tích dựa trên ML (**tạm dừng**) | Isolation Forest (scikit-learn) | `server/siem/detection/ml.py` |
| SOAR + quản lý case | Playbook tự động + case playbook NIST | `server/siem/soar/`, `server/config/playbooks.yml`, `server/config/case_playbooks.yml` |
| AI hỗ trợ viết rule (chỉ đề xuất) | Ollama (`qwen2.5-coder:7b`) + kiểm định tự động + duyệt trên console | `server/siem/ai/`, `tools/fetch_datasets.py`, `tools/convert_datasets.py` |
| Bảo mật nội bộ | TLS (CA nội bộ), RBAC Elasticsearch, Docker secrets + keystore | `security/setup.sh`, `tools/init_secrets.py` |
| Lưu trữ | Elasticsearch 8 (xpack security bật) | |
| Trực quan hóa | Grafana 11 (dashboard được provision sẵn) | `grafana/` |

## 1. Agent (`agent/`)

Phát triển tiếp từ `Wazuh/agent-core`, giữ nguyên thiết kế: collector → hàng đợi trên đĩa → sender (at-least-once, không mất event khi mất mạng hoặc agent crash).

**Collector**
- `filetail`: tail file log trên mọi OS (Apache access/error, `auth.log`, Suricata `eve.json`, syslog). Lưu offset và xử lý log rotation.
- `winevent`: đọc Windows Event Log bằng `wevtutil` (Security, System, Sysmon, PowerShell, Defender). Lưu bookmark theo channel.
- `process`: phát hiện tiến trình mới trên Linux qua `/proc`.
- `mock`: sinh dữ liệu giả để test.

**Response (XDR)**: agent định kỳ hỏi manager xem có lệnh mới không rồi thực thi:
`block_ip`/`unblock_ip` (iptables / netsh advfirewall), `kill_process`, `isolate_host`/`unisolate_host`
(chỉ giữ kết nối tới manager). Mọi tham số đều được validate và lệnh chạy không qua shell.
Agent từ chối chặn IP của manager và từ chối kill tiến trình hệ thống.
Bật `response.dry_run: true` nếu chỉ muốn ghi log lệnh mà không thực thi.

**Bảo mật kênh**: agent enroll bằng `enrollment_key`, nhận token HMAC riêng theo `agent_id`.
Server ghi đè `agent_id` trong payload bằng danh tính đã xác thực, nên agent không giả mạo được agent khác.

```bash
cd agent
go test ./...
GOOS=linux   GOARCH=amd64 go build -o bin/siem-agent     ./cmd/agent
GOOS=windows GOARCH=amd64 go build -o bin/siem-agent.exe ./cmd/agent
```
- Linux (S001 Web-01, A003 Ubuntu-01): sửa `config.linux.yaml` (IP manager, key) rồi chạy `sudo ./siem-agent -config config.linux.yaml`
- Windows (A001 PC-01): sửa `config.windows.yaml`, mở PowerShell **Administrator**, chạy `.\siem-agent.exe -config config.windows.yaml`.
  Nên cài Sysmon để có telemetry process/network.

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

**Firewall F001**: cấu hình remote syslog trỏ về `<IP máy docker>:514`.
Hệ thống parse được iptables/UFW, pfSense/OPNsense filterlog và Suricata eve (JSON qua syslog).

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

**Làm giàu**: Threat Intel (`server/config/intel/*.txt`: IP/CIDR, domain, hash, tự nạp lại khi file đổi),
tài sản (`server/config/assets.yml`, lấy từ `asset.txt`) dùng để tính `risk_score` theo mức quan trọng của tài sản.

## 4. SOAR và quản lý case

**Phản ứng tự động** (`server/config/playbooks.yml`): ví dụ AUTH-001 → chặn IP trên **mọi** agent trong 1 giờ, gửi thông báo, tạo case.
AUTH-002 → chặn 24 giờ, còn cô lập máy thì chờ analyst duyệt (`approval: true`).
SOAR tự tạo lệnh gỡ chặn khi hết hạn, bỏ qua IP trong `SOAR_WHITELIST` và không chặn trùng.
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
.venv/Scripts/python -m pytest -q      # 46 test: parser, rule, ML, SOAR, case playbook, API, AI (phân loại tấn công, kiểm định, worker với LLM giả, duyệt/gỡ)
cd ../agent && go test ./...
```
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

**Giới hạn còn lại**:
- Kafka/Zookeeper chạy plaintext trong mạng docker nội bộ.
- Console dùng một API key chung, còn tên analyst là do người dùng tự khai (chưa có đăng nhập theo từng người).
- Đổi `elastic_password` sau lần chạy đầu phải đổi qua API của ES, hoặc xóa volume `esdata`.
- Ollama gọi qua HTTP thường trong mạng docker nội bộ (không publish cổng ra ngoài).
