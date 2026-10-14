# Vận hành SOC trên SOC Platform

Tài liệu này là quy trình vận hành của SOC chạy trên SOC Platform, cập nhật ngày 14/10/2026. Mỗi mục ghi quy định, thao tác
trên console, nơi thực thi trong mã và biến cấu hình. Các mục được đánh số giống chỗ mã nguồn tham chiếu (vd "SOC-OPERATIONS.md
mục 4"), nên khi thêm mục mới thì đặt ở cuối, không đánh số lại. Kiến trúc và cài đặt: [README.md](README.md). Phát hiện:
[RULES.md](RULES.md). Case playbook: [PLAYBOOKS.md](PLAYBOOKS.md). AI viết rule: [AI-README.md](AI-README.md).

| Mục | Nội dung | Mã chính |
|---|---|---|
| 1 | Vai trò, phân quyền, xác thực 2 lớp | `server/siem/manager/auth.py` |
| 2 | Mức ưu tiên P1–P4 và SLA | `server/config/priority.yml`, `server/siem/priority.py` |
| 3 | Kết luận bắt buộc khi đóng | `server/siem/manager/api.py` (`VERDICTS`) |
| 4 | Detection-as-code, chạy bóng, risk-based alerting | `server/siem/detection/lint.py`, `ruletest.py`, `server/siem/soar/risk.py` |
| 5 | Giám sát sức khỏe nền tảng, sao lưu và khôi phục | `server/siem/soar/health.py`, `tools/es_snapshot.py` |
| 6 | Sự cố lớn và hạn thông báo 72 giờ | `server/siem/manager/api.py` (`case_incident`) |
| 7 | KPI | `server/siem/manager/kpi.py`, dashboard *SOC KPI* |
| 8 | AI hỗ trợ SOC | `server/siem/ai/triage.py` |
| 9 | Threat intelligence: IOC, MISP, dò ngược | `server/siem/pipeline/misp.py`, `server/siem/soar/retrohunt.py` |
| 10 | Threat hunting và giao ca | `server/siem/manager/soc.py` |
| 11 | Lịch việc định kỳ | — |

## 1. Vai trò và phân quyền

Mỗi người có tài khoản riêng. Quyền tính theo năng lực, không theo thang bậc: Detection Engineer duyệt rule nhưng không cô lập
được máy, còn analyst xử lý cảnh báo thì không tự duyệt được rule mình đang dùng.

| Vai trò trên console | Vị trí trong SOC | Quyền | Grafana |
|---|---|---|---|
| `analyst` | Analyst (Tier 1), CTI analyst | triage | Viewer |
| `lead` | Trưởng nhóm IR (Tier 2) | triage, contain | Editor |
| `hunter` | Threat Hunter / DFIR (Tier 3) | triage, contain, hunt | Editor |
| `detection` | Detection Engineer | rules, hunt | Editor |
| `manager` | SOC Manager | triage, contain, hunt, declare | Editor |
| `admin` | Quản trị nền tảng (SOC Platform Engineer) | tất cả, thêm users | Admin |

| Quyền | Được làm |
|---|---|
| triage | Xử lý alert / case, chặn IP, kill tiến trình, đánh dấu task cần *Analyst L1* duyệt |
| contain | Cô lập / bỏ cô lập máy, duyệt bước SOAR cô lập, task cần *Trưởng nhóm IR* duyệt, đổi mức ưu tiên case |
| hunt | Ghi nhật ký threat hunting (mục 10) |
| rules | Duyệt / từ chối / gỡ đề xuất AI, bật chính thức rule AI đang chạy bóng, chạy phân tích AI |
| declare | Tuyên bố sự cố lớn, ghi nhận đã thông báo cơ quan chức năng (mục 6), task cần *SOC Manager* duyệt |
| users | Tạo, khóa, đổi vai trò, đặt lại mật khẩu tài khoản |

- **Nhãn duyệt trong case playbook** (`approval` trong `server/config/case_playbooks.yml`): *Analyst L1* cần triage,
  *Trưởng nhóm IR* cần contain, *Trưởng nhóm IR + chủ hệ thống* cần contain và ghi chú ai đã đồng ý (chủ hệ thống không có
  tài khoản), *SOC Manager* cần declare (việc dính tới nhân sự / pháp chế, vd đóng băng quyền của người trong nội bộ).
  Nhãn lạ cần contain. API kiểm tra quyền; console làm mờ ô đánh dấu với người không đủ quyền.
- **Hai người khác nhau** phải duyệt một ngoại lệ do AI đề xuất (làm giảm cảnh báo); rule mới cần một người.
- **Người thực hiện** mọi thao tác lấy từ phiên đăng nhập, không tự khai được. Đăng nhập, đổi mật khẩu, quản lý tài khoản
  được ghi thành event của chính SIEM (`event_type: console_auth`), rule AUTH-001 áp dụng được.
- **Xác thực 2 lớp TOTP** (RFC 6238, ứng dụng Google / Microsoft Authenticator): mỗi người tự bật bằng nút *Bật 2 lớp* dưới
  tên tài khoản ở menu trái; admin đặt lại MFA cho người mất điện thoại ở trang *Tài khoản*. Đặt
  `CONSOLE_MFA_REQUIRED_ROLES=admin,manager,lead,hunter,detection` để bắt buộc với các vai trò có quyền thay đổi hệ thống;
  chưa bật thì phiên chỉ dùng được để bật MFA. Mỗi mã dùng một lần, nhập sai tính như sai mật khẩu.
- **Phiên**: hết hạn sau `CONSOLE_IDLE_MINUTES` (30) phút không thao tác, tối đa `CONSOLE_SESSION_HOURS` (8) giờ; sai
  `CONSOLE_MAX_FAILURES` (5) lần trong 15 phút thì khóa 15 phút.
- **Rà soát quyền** hằng quý (mục 11): khóa tài khoản người đã chuyển việc, hạ vai trò không còn cần.

## 2. Mức ưu tiên và SLA

Ưu tiên = severity của rule × mức quan trọng của tài sản trong `server/config/assets.yml`. Tài sản không có trong danh mục
được coi là medium. Analyzer gắn `priority` và hạn SLA vào alert, SOAR gắn vào case mới.

| Severity \ tài sản | low | medium | high | critical |
|---|---|---|---|---|
| critical | P2 | P1 | P1 | P1 |
| high | P3 | P2 | P2 | P1 |
| medium | P4 | P3 | P3 | P2 |
| low | P4 | P4 | P4 | P3 |

| Ưu tiên | Xác nhận (ack) | Khoanh vùng (contain) | Cập nhật cho lãnh đạo |
|---|---|---|---|
| P1 | 15 phút | 1 giờ | mỗi 1 giờ |
| P2 | 30 phút | 4 giờ | mỗi 4 giờ |
| P3 | 2 giờ | 1 ngày (1440 phút) | khi đóng |
| P4 | 8 giờ | 3 ngày (4320 phút) | khi đóng |

- SLA tính từ lúc alert / case được tạo. **Xác nhận** = lần đầu có người nhận xử lý (giao người, đổi trạng thái, đánh dấu
  task hoặc ghi chú). **Khoanh vùng** = case chuyển *Đã ngăn chặn* (`contained`). "1 ngày / 3 ngày làm việc" trong kế hoạch
  tạm tính theo lịch (24 / 72 giờ).
- Case quá hạn hiện chữ đỏ trên console và vào biên bản giao ca (mục 10). Đổi mức ưu tiên cần quyền contain và được ghi
  lịch sử. Nâng mức thì hạn chưa đạt được kéo về sớm hơn (lúc nâng + SLA mức mới, không bao giờ lùi hạn); hạ mức thì hạn tính
  lại từ lúc tạo.
- Sửa ma trận hoặc SLA trong `server/config/priority.yml`, rồi khởi động lại analyzer, soar, manager.

## 3. Kết luận bắt buộc khi đóng

Đóng alert hoặc case phải chọn một kết luận. Nếu không có kết luận thì không đo được tỉ lệ báo nhầm, AI không có nhãn để học,
và không có căn cứ bật chính thức rule chạy bóng.

| Kết luận | Khi nào dùng | Tính là báo nhầm |
|---|---|---|
| Đúng - độc hại (`true_positive`) | Hoạt động độc hại thật | không |
| Đúng - hoạt động hợp lệ (`benign_true_positive`) | Rule bắt đúng hành vi nhưng là việc hợp lệ: pentest, quản trị | không |
| Báo nhầm (`false_positive`) | Rule bắt sai | có |
| Trùng lặp (`duplicate`) | Đã có alert / case khác cho cùng sự việc | không |

- Chọn *Báo nhầm* thì trạng thái thành `false_positive`. AI worker lấy nhãn báo nhầm theo trạng thái này để đề xuất ngoại lệ.
- Đóng case thì mặc định đóng luôn các alert còn mở trong case, với cùng kết luận.
- Hoạt động hợp lệ lặp lại (vd quét lỗ hổng định kỳ) thì xin ngoại lệ thay vì đóng tay mãi: Detection Engineer thêm vào
  `server/rules/exceptions/`, hoặc duyệt đề xuất ngoại lệ của AI.

## 4. Detection-as-code, chạy bóng, risk-based alerting

**Kho rule là mã nguồn.** Rule viết tay nằm ở `server/rules/*.yml`, ca test ở `server/rules/cases/`, ngoại lệ ở
`server/rules/exceptions/`, rule AI đã duyệt ở `server/rules/ai/`. Mọi thay đổi đi qua pull request; CI
(`.github/workflows/ci.yml`) chạy pytest và `tools/rule_lint.py`, lỗi thì chặn merge. Lint kiểm tra:

- Metadata bắt buộc: `id`, `title`, `severity`, `mitre` (tactic + technique hợp lệ), `tags`, `logsource`, `owner`, `falsepositives`.
- Rule biên dịch được, `mode` hợp lệ, id không trùng, regex không có nguy cơ ReDoS.
- Mỗi rule viết tay có ít nhất 1 ca test **dương** (phải bắn) và 1 ca **âm** (gần giống nhưng hợp lệ, không được bắn), mọi ca đạt.
- Mỗi rule có case playbook riêng (không rơi về PB-00), ngoại lệ trỏ tới rule có thật.

Hiện trạng ngày 14/10/2026: 41 rule (FIM-001 chạy bóng từ 14/10), 89 ca test đạt, 0 lỗi. Độ phủ kỹ thuật ưu tiên trong
`server/config/threat_profile.yml` là 83,3%: 10/12 kỹ thuật có rule chạy chính thức đã kiểm thử. T1547 (Boot or Logon Autostart
Execution) đã có FIM-001 đang chạy bóng, tính vào độ phủ khi được bật chính thức (sớm nhất 21/10); T1486 (Data Encrypted for
Impact) chưa có rule. Layer cho MITRE ATT&CK Navigator: `python tools/rule_lint.py --layer build/attack-layer.json`.

**Quy trình đưa một rule vào chạy:**

1. Viết rule (`mode: shadow`) kèm ca test dương / âm, chạy `python tools/rule_lint.py` trên máy.
2. Mở pull request; CI đạt và một người khác review thì merge. Khi mã mới lên máy chủ (`git pull`, hoặc
   `tools/deploy-vm.ps1 -Update`), analyzer thấy file rule đổi và tự nạp lại; nạp lỗi thì giữ bộ rule cũ.
3. Rule **chạy bóng**: vẫn sinh alert (gắn `alert.shadow`) để đo số alert và tỉ lệ báo nhầm, nhưng SOAR bỏ qua (không thông
   báo, không mở case, không phản ứng), console ẩn khỏi danh sách mặc định, KPI không tính.
4. Bật chính thức khi đạt cả ba tiêu chí: chạy bóng ít nhất `SHADOW_MIN_DAYS` (7) ngày, dưới `SHADOW_MAX_ALERTS_PER_DAY` (5)
   alert/ngày, tỉ lệ báo nhầm dưới `SHADOW_MAX_FP_RATE` (30%) trên các alert đã có kết luận. Rule AI: Detection Engineer bấm
   *Bật chính thức* ở trang *Đề xuất AI*; nút chỉ hiện khi đã đạt, API kiểm tra lại. Rule viết tay: commit đổi
   `mode: active`, đi qua CI như bước 2.
5. Rà soát hằng quý theo cột báo nhầm trong *Thư viện rule*: rule báo nhầm nhiều thì sửa điều kiện, thêm ngoại lệ hoặc hạ mức.

**Risk-based alerting (RBA-001).** SOAR cộng `risk_score` của từng alert (severity × mức quan trọng tài sản) vào máy
(`host.name`) và tài khoản (`user.name`) liên quan, trong cửa sổ `RBA_WINDOW_HOURS` (24) giờ. Khi tổng điểm ≥ `RBA_THRESHOLD`
(150) và đến từ ≥ `RBA_MIN_RULES` (2) rule khác nhau, SOAR sinh RBA-001 (high; critical khi gấp đôi ngưỡng) gom mọi alert góp
điểm. Nhờ vậy rule mức low (không mở case) dùng được làm tín hiệu: một lần tạo tài khoản không đáng mở case, nhưng nhiều tín
hiệu khác loại trên cùng một máy trong một ngày thì đáng. Alert chạy bóng, alert RBA và alert sức khỏe không góp điểm.

## 5. Giám sát sức khỏe nền tảng, sao lưu và khôi phục

SOAR kiểm tra mỗi phút và sinh alert HLT-* ghi thẳng vào Elasticsearch (không qua Kafka / analyzer), nên vẫn báo được khi
đường ống đang hỏng. Mỗi sự cố chỉ có một alert đang mở. Khi hết sự cố, SOAR ghi "đã hồi phục" vào lịch sử alert để analyst
đóng. Xử lý theo playbook **PB-20**; trước khi coi là lỗi kỹ thuật, phải loại trừ khả năng kẻ tấn công cố ý tắt giám sát
(MITRE T1562.001).

| Mã | Điều kiện | Biến cấu hình (mặc định) |
|---|---|---|
| HLT-001 | Agent Wazuh mất kết nối (theo keepalive), mức theo tài sản | `AGENT_DOWN_MINUTES` (15) |
| HLT-002 | Nguồn log không gửi event nào, dù trung bình 7 ngày phải có ≥ N event trong khoảng đó | `SOURCE_SILENT_MINUTES` (30), `SOURCE_MIN_EXPECTED` (10) |
| HLT-003 | Lưu lượng 1 giờ lệch quá X so với trung bình 7 ngày (nguồn ≥ 100 event/giờ) | `VOLUME_DEVIATION` (0.5), `VOLUME_MIN_PER_HOUR` (100) |
| HLT-004 | SOAR không gọi được Wazuh API (mất đồng bộ trạng thái agent) | — |
| HLT-005 | Consumer analyzer / SOAR tụt sau nhiều message liên tục | `KAFKA_LAG_MAX_MESSAGES` (5000), `KAFKA_LAG_MINUTES` (5) |
| HLT-006 | Elasticsearch đỏ, hoặc đĩa dùng quá ngưỡng | `ES_DISK_MAX_PCT` (80) |
| HLT-007 | Chưa có chính sách snapshot, lần chạy gần nhất lỗi, hoặc bản thành công gần nhất quá cũ | `SNAPSHOT_MAX_AGE_HOURS` (36) |

Trạng thái từng nguồn nằm ở index `siem-sources`, hiện trên dashboard *SOC KPI*.

**Sao lưu.** Elasticsearch chụp snapshot hằng ngày bằng SLM (chính sách `daily-snapshots`, repository `siem-backup`) lúc
`SNAPSHOT_SCHEDULE` = `0 30 18 * * ?` theo giờ UTC (01:30 giờ Việt Nam), giữ `SNAPSHOT_RETENTION_DAYS` (30) ngày. Snapshot
gồm cả alert, case, lệnh phản ứng và tài khoản console. Trong lab, repository là volume `essnapshots` trên cùng máy. Khi triển
khai thật phải gắn thư mục này vào ổ / NAS / object storage khác máy, vì để chung ổ thì mất máy là mất cả dữ liệu lẫn bản sao lưu.

```bash
python tools/es_snapshot.py status     # chính sách, lần chạy gần nhất, danh sách snapshot
python tools/es_snapshot.py now        # chụp ngay (trước khi nâng cấp, trước khi sửa dữ liệu lớn)
python tools/es_snapshot.py verify     # diễn tập: khôi phục bản mới nhất sang index tạm restore-test-*, so số bản ghi, xóa index tạm
```

**Khôi phục thật** (ghi đè index đang có) làm tay, có Trưởng nhóm IR hoặc SOC Manager chứng kiến và ghi vào case sự cố nền tảng:

1. Chụp snapshot hiện trạng (`python tools/es_snapshot.py now`) để còn quay lại được, rồi chọn snapshot cần khôi phục (`status`).
2. Dừng các service ghi dữ liệu: `docker compose stop analyzer soar manager ai-worker`.
3. Đóng index cần khôi phục (Elasticsearch không khôi phục đè lên index đang mở), vd `siem-cases`:
   ```bash
   docker compose exec elasticsearch sh -c 'curl -s --cacert config/certs/ca/ca.crt -u "elastic:$(cat config/certs/bootstrap/elastic_password)" -X POST "https://localhost:9200/siem-cases/_close"'
   ```
4. Khôi phục đúng các index đó, không khôi phục global state (giữ user / role RBAC hiện tại):
   ```bash
   docker compose exec elasticsearch sh -c 'curl -s --cacert config/certs/ca/ca.crt -u "elastic:$(cat config/certs/bootstrap/elastic_password)" -H "Content-Type: application/json" -X POST "https://localhost:9200/_snapshot/siem-backup/<tên snapshot>/_restore?wait_for_completion=true" -d "{\"indices\": \"siem-cases\", \"include_global_state\": false}"'
   ```
   Index khôi phục xong tự mở lại.
5. Khởi động lại: `docker compose start analyzer soar manager ai-worker`, kiểm tra console và HLT-006 / HLT-007.

## 6. Sự cố lớn và hạn thông báo 72 giờ

SOC Manager tuyên bố sự cố lớn trên case (nút *Tuyên bố sự cố lớn*, API `POST /api/v1/cases/{id}/incident`, `action: declare`).
Phải ghi căn cứ; nếu sự cố có dữ liệu cá nhân thì đánh dấu thêm. Case chuyển P1. Khi có dữ liệu cá nhân, hệ thống đặt **hạn
thông báo** = thời điểm tạo case + 72 giờ, hiện trong ngăn chi tiết case. Biên bản giao ca liệt kê mọi sự cố lớn đang mở.

- Căn cứ: [Luật Bảo vệ dữ liệu cá nhân 2025 (91/2025/QH15), Điều 23 khoản 1](https://hethongphapluat.com/luat-bao-ve-du-lieu-ca-nhan-2025/dieu-23),
  hiệu lực từ 01/01/2026. Bên kiểm soát dữ liệu phải thông báo cho cơ quan chuyên trách bảo vệ dữ liệu cá nhân chậm nhất 72 giờ
  kể từ khi phát hiện vi phạm, nếu vi phạm có thể gây tổn hại theo luật định. Bên xử lý dữ liệu phải báo kịp thời cho bên kiểm
  soát. Nội dung thông báo do Chính phủ quy định; pháp chế xác nhận có phải thông báo hay không.
- Hệ thống đếm từ lúc **hệ thống phát hiện** (tạo case), không từ lúc tuyên bố. Đây là cách tính thận trọng, vì "phát hiện" có
  thể được hiểu là thời điểm sớm nhất tổ chức có dấu hiệu.
- Sau khi thông báo, SOC Manager bấm *Ghi nhận đã thông báo* và ghi rõ đã báo cho ai, lúc nào, qua kênh nào.
- Phối hợp tiếp theo (lãnh đạo, pháp chế, truyền thông, nhân sự) theo case playbook, vd PB-21 rò rỉ dữ liệu, PB-22 mối đe dọa nội bộ.

## 7. KPI

Manager tính KPI tự động từ dữ liệu, không nhập tay. Cứ `KPI_SECONDS` (300) giây, manager tính trên cửa sổ `KPI_WINDOW_DAYS`
(30) ngày và lưu một bản ghi vào index `siem-kpi`. Xem ở dashboard *SOC KPI* (giá trị mới nhất tô màu theo đích, kèm xu hướng),
trang *KPI* trên console hoặc `GET /api/v1/kpi`. Alert của rule chạy bóng không tính.

| KPI | Cách đo | Đích cuối giai đoạn 2 | Đích cuối giai đoạn 4 |
|---|---|---|---|
| MTTD (alert critical) | Từ event đầu tiên của chuỗi tới lúc sinh alert | ≤ 30 phút | ≤ 15 phút |
| MTTA P1 | Từ lúc mở case tới khi có người nhận | ≤ 30 phút | ≤ 15 phút |
| MTTC P1 | Từ lúc mở case tới khi khoanh vùng xong | ≤ 4 giờ | ≤ 1 giờ |
| Đạt SLA | % case xác nhận và khoanh vùng trong hạn (mục 2) | ≥ 85% | ≥ 95% |
| Tỉ lệ báo nhầm | Alert kết luận báo nhầm / alert đã đóng (mục 3) | ≤ 50% | ≤ 30% |
| Tải analyst | Alert mỗi analyst mỗi ca (`SOC_SHIFTS_PER_DAY` ca / ngày) | ≤ 60 | ≤ 40 |
| Làm giàu | % alert có ngữ cảnh tài sản | ≥ 50% | ≥ 80% |
| Độ phủ ATT&CK | % kỹ thuật ưu tiên có rule chạy chính thức đã kiểm thử (mục 4) | ≥ 50% | ≥ 70% |
| Sức khỏe nguồn log | % nguồn đã onboard không im lặng (mục 5) | ≥ 95% | ≥ 98% |
| Threat hunting | Số cuộc hunt hoàn thành trong tháng (mục 10) | — | ≥ 2 |

Ngoài ra manager đo tỉ lệ chấp nhận của AI hỗ trợ (mục 8). `SOC_SHIFTS_PER_DAY=1` là trực 8x5 (giai đoạn 1–2); đổi thành 2 khi
chuyển sang hai ca 12 giờ (24/7). "Analyst" trong KPI tải là người đã xử lý alert / case trong kỳ.

## 8. AI hỗ trợ SOC

AI chạy trên LLM nội bộ (Ollama, `--profile ai`), nên log không rời tổ chức. AI **chỉ đọc** dữ liệu và ghi kết quả vào
`ai-jobs`: không ra lệnh SOAR, không sửa alert / case. Người có quyền triage, hunt hoặc rules gọi được AI.

| Việc | Ở đâu trên console | Rào chắn |
|---|---|---|
| Tóm tắt alert / case, dòng thời gian, bước kiểm tra tiếp theo | Ngăn chi tiết alert / case, mục *AI hỗ trợ* | Mỗi ý phải dẫn chứng nhãn alert (A1, A2...) có thật trong ngữ cảnh; ý dẫn chứng nhãn không tồn tại bị bỏ |
| Giải thích dòng lệnh | Ngăn chi tiết alert có dòng lệnh / PowerShell | `-EncodedCommand`, `FromBase64String('...')` được giải mã bằng mã trước; LLM chỉ giải thích bản đã giải mã |
| Nháp báo cáo sau sự cố | Ngăn chi tiết case | Lấy từ dòng thời gian, task, ghi chú; người viết báo cáo vẫn chịu trách nhiệm nội dung |
| Câu hỏi tiếng Việt → truy vấn Lucene | Trang *Điều tra* | Elasticsearch kiểm tra cú pháp trước khi trả về |

- Nội dung lấy từ log (URL, dòng lệnh, tên tài khoản) có thể do kẻ tấn công kiểm soát. Vì vậy nội dung này được đặt trong khối
  `<data>...</data>`, và system prompt yêu cầu coi đó là dữ liệu, không làm theo chỉ dẫn trong đó (chống prompt injection).
- Mọi kết quả đều gắn nhãn "AI - bản tham khảo, cần người kiểm tra". Analyst đánh giá *Hữu ích / Không*. Nếu tỉ lệ chấp nhận
  thấp kéo dài thì cân nhắc tắt tính năng.
- AI đề xuất rule / ngoại lệ là phần riêng, Detection Engineer duyệt: xem [AI-README.md](AI-README.md).

## 9. Threat intelligence: IOC, MISP, dò ngược

- **IOC thủ công**: file trong `server/config/intel/` (IP, tên miền, hash). Analyzer khớp event lúc vào và sinh **TI-001**.
- **Feed MISP** (tùy chọn): đặt `MISP_URL` trong `.env` và auth key trong `secrets/misp_api_key`. Cứ `MISP_INTERVAL_MINUTES` (60)
  phút, hệ thống lấy thuộc tính `to_ids` và bỏ những thuộc tính khớp warninglist. **Hạn sống** tính từ lần MISP thấy gần nhất:
  IP 30 ngày, domain 90 ngày, hash 365 ngày (`MISP_TTL_IP_DAYS`, `MISP_TTL_DOMAIN_DAYS`, `MISP_TTL_HASH_DAYS`). MISP lỗi thì giữ
  bộ IOC lần trước; analyzer không bao giờ chờ MISP.
- **Dò ngược (TI-002)**: event vào trước khi biết IOC thì lúc đó không khớp được. Vì vậy, mỗi 10 phút SOAR tìm IOC mới trong
  `RETROHUNT_DAYS` (30) ngày log cũ, tối đa `RETROHUNT_MAX_PER_RUN` (300) IOC mỗi chu kỳ. Có khớp thì sinh TI-002 (high), mở case
  theo PB-06. Vòng đời từng IOC (nguồn, lần đầu thấy, hạn, số event khớp, active / expired) nằm ở index `siem-intel`. IOC hết
  hạn chỉ chuyển sang expired, không bị xóa.
- CTI analyst cập nhật `server/config/threat_profile.yml` hằng quý theo nhóm tấn công nhắm vào ngành; hồ sơ này quyết định KPI
  độ phủ ATT&CK.

## 10. Threat hunting và giao ca

**Threat hunting** (trang *Threat hunting*, quyền hunt) theo mô hình PEAK: giả thuyết gắn kỹ thuật ATT&CK → nguồn dữ liệu và
truy vấn → phát hiện → kết luận (*Tìm thấy mối đe dọa*, *Không thấy dấu hiệu*, *Chưa kết luận được*) → rule mới nếu tìm ra mẫu
(đưa vào chạy bóng theo mục 4) và dữ liệu còn thiếu. Console có sẵn 5 giả thuyết mở đầu: Kerberoasting, tác vụ hẹn giờ trên
server, DNS tunneling, cặp tiến trình cha - con hiếm gặp, tài khoản dịch vụ đăng nhập tương tác. Nhật ký nằm ở index `siem-hunts`;
đích là ít nhất 2 cuộc hunt hoàn thành mỗi tháng.

**Giao ca** (trang *Giao ca*): biên bản tự lập gồm alert đang mở theo mức ưu tiên, case đang xử lý, case quá hạn SLA, lệnh chặn
sắp hết hạn, bước SOAR chờ duyệt, sự cố nền tảng (HLT-*) và sự cố lớn. Người giao ca thêm ghi chú rồi lưu
(index `siem-handovers`), người nhận ca đọc bản đã lưu. Mọi case P1 / P2 đang mở phải có người nhận ở ca sau.

## 11. Lịch việc định kỳ

| Tần suất | Việc | Ai | Công cụ |
|---|---|---|---|
| Mỗi ca | Lập và lưu biên bản giao ca; xử lý HLT-* đang mở | Analyst ca trực | Trang *Giao ca* |
| Hằng ngày | Kiểm tra snapshot đêm qua (HLT-007 không mở) | Quản trị nền tảng | `python tools/es_snapshot.py status` |
| Hằng tuần | Duyệt đề xuất AI; xét bật chính thức rule chạy bóng | Detection Engineer | Trang *Đề xuất AI* |
| Hằng tháng | Diễn tập khôi phục; xem KPI tháng; ít nhất 2 cuộc hunt | Quản trị nền tảng, SOC Manager, Threat Hunter | `es_snapshot.py verify`, *SOC KPI*, *Threat hunting* |
| Hằng quý | Rà soát rule báo nhầm nhiều; cập nhật hồ sơ mối đe dọa; rà soát quyền tài khoản | Detection Engineer, CTI, admin | *Thư viện rule*, `threat_profile.yml`, trang *Tài khoản* |
| Sau mỗi sự cố lớn | Họp rút kinh nghiệm, cập nhật playbook / rule | SOC Manager | Nháp báo cáo AI, `case_playbooks.yml` |
