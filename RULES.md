# Hệ thống rule phát hiện

Tài liệu về phần **phát hiện bằng luật** của SOC Platform: rule chạy thế nào, có bao nhiêu rule, phủ được tới đâu, điểm mạnh và
điểm yếu. Số liệu đo ngày 12/10/2026 trên mã nguồn hiện tại. Tài liệu liên quan:
- `README.md` mục 3: tóm tắt phần phát hiện, ML, so sánh với ruleset Wazuh.
- `PLAYBOOKS.md`: quy trình xử lý sự cố (case playbook) gắn vào case khi rule bắn.
- `AI-README.md`: AI đề xuất rule mới và ngoại lệ.
- `datasets/report.md`, `datasets/report_wazuh.md`: báo cáo độ phủ đầy đủ.

## Mục lục

1. [Tổng quan](#1-tổng-quan)
2. [Cơ chế hoạt động](#2-cơ-chế-hoạt-động)
3. [Danh sách rule](#3-danh-sách-rule)
4. [Độ phủ](#4-độ-phủ)
5. [Điểm mạnh](#5-điểm-mạnh)
6. [Điểm yếu](#6-điểm-yếu)
7. [Hướng cải thiện](#7-hướng-cải-thiện)
8. [Đo lại](#8-đo-lại)

## 1. Tổng quan

Alert trong hệ thống đến từ 4 nguồn:

| Nguồn | Số lượng | Mã alert | Trạng thái |
|---|---|---|---|
| Rule viết tay (`server/rules/*.yml`) | 40 rule | `WEB-`, `WIN-`, `LNX-`, `AUTH-`, `NET-`, `TI-` | Đang chạy |
| Ruleset gốc của Wazuh 4.14.7 (hơn 3.000 rule) + 2 rule riêng | Chỉ chuyển một phần thành alert (mục 2.8) | `WZH-<id rule Wazuh>` | Đang chạy |
| Rule do AI đề xuất (`server/rules/ai/`) | 0 rule đã triển khai; 28 đề xuất chờ duyệt (11/10) | `AI-xxx` | Chờ người duyệt |
| ML (Isolation Forest) | — | `ML-001` | Tắt (`ML_ENABLED=false`, báo nhầm khoảng 32%) |

Tóm tắt 40 rule viết tay:

| | |
|---|---|
| Theo lĩnh vực | Windows 13, Web 9, Xác thực 6, Linux 6, Mạng 6 (gồm 1 rule Threat Intel) |
| Theo mức độ | critical 9, high 20, medium 11 |
| Theo kiểu | so khớp từng event 29, theo ngưỡng 10, chuỗi sự kiện 1 |
| MITRE ATT&CK | 11 chiến thuật, 42 kỹ thuật (31 kỹ thuật gốc); mọi rule đều gắn kỹ thuật |
| Phản ứng | 40/40 rule mở case kèm case playbook riêng; 17 rule có phản ứng tự động (chặn IP / diệt tiến trình) |
| Độ phủ trên dataset công khai | Web 11,0%, Windows 6,5%, Linux 0,8% mẫu tấn công; 0 báo nhầm trên tập bình thường |

## 2. Cơ chế hoạt động

### 2.1 Luồng xử lý

```
Wazuh agent ──> wazuh-manager ──> archives.json (mọi event) ──> Vector ──> Kafka siem.raw
syslog (firewall, Suricata) ──> Vector syslog ──────────────────────────────┘
                                                                            │
analyzer (server/siem/analyzer.py):  normalize ──> enrich (Threat Intel, tài sản)
                                       │
                                       ├──> Elasticsearch siem-events-*
                                       └──> rule engine ──> alert ──> ES siem-alerts + Kafka siem.alerts ──> SOAR
wazuh-manager alerts.json ──> cầu nối Wazuh (lọc theo nhóm + level) ──> alert WZH-* ┘
```

- Mọi event đều được chuẩn hóa về một bộ trường chung (`event.category`, `process.command_line`, `url.decoded`,
  `source.ip`…), nên một rule viết một lần dùng được cho mọi agent cùng loại log.
- Làm giàu trước khi chạy rule: so IP / domain / hash với Threat Intel (`server/config/intel/*.txt`, tự nạp lại khi file đổi),
  gắn tài sản và mức quan trọng (`server/config/assets.yml`).
- Rule engine chạy mọi rule trên mọi event, theo thứ tự trong file. Một event có thể làm nhiều rule bắn.

### 2.2 Định dạng rule

Rule viết bằng YAML, cú pháp gần với Sigma nhưng gọn hơn:

```yaml
- id: AUTH-003
  title: Password Spraying
  description: ...                     # tùy chọn
  severity: high                       # low | medium | high | critical
  mitre: {tactic: Credential Access, technique: [T1110.003]}
  tags: [linux, bruteforce]
  type: threshold                      # match | threshold | sequence
  condition:
    all:
      - {field: event.category, op: eq, value: authentication}
      - {field: event.outcome, op: eq, value: failure}
  threshold: {count: 5, window: 120, distinct: user.name, group_by: [source.ip]}
  suppress: 300                        # tùy chọn: không bắn lại cho cùng nhóm trong N giây
  exceptions: [...]                    # tùy chọn: ngoại lệ ngay trong rule
  enabled: true                        # false = tắt rule mà không xóa
```

### 2.3 Điều kiện và toán tử

Điều kiện là một cây `all` (và), `any` (hoặc), `not` (phủ định); mỗi lá là `{field, op, value}`.

| Toán tử | Ý nghĩa |
|---|---|
| `eq`, `neq`, `in` | bằng / khác / thuộc danh sách |
| `contains`, `not_contains`, `startswith`, `endswith` | so chuỗi con |
| `regex` | biểu thức chính quy (`re.search`), có thể là danh sách (khớp một là đủ) |
| `gt`, `gte`, `lt`, `lte` | so sánh số |
| `exists` | trường có mặt hay không |
| `cidr` | IP thuộc dải mạng |

- So chuỗi **không phân biệt hoa thường** (regex có thể bật `case_sensitive: true`).
- Trường là mảng thì chỉ cần một phần tử khớp.
- Trường không có trong event thì lá chỉ đúng với `neq`, `not_contains`, `exists: false`.

### 2.4 Ba kiểu rule

| Kiểu | Bắn khi | Ví dụ |
|---|---|---|
| `match` | 1 event khớp điều kiện | SQLi trong URL, `vssadmin delete shadows` |
| `threshold` | ≥ `count` event khớp trong cửa sổ trượt `window` giây, cùng giá trị `group_by`; có `distinct` thì đếm số **giá trị khác nhau** của một trường | ≥ 5 lần đăng nhập sai từ 1 IP trong 60 giây; ≥ 20 cổng đích khác nhau từ 1 IP (quét cổng) |
| `sequence` | các bước xảy ra **theo thứ tự** trong `within` giây, cùng `group_by`; mỗi bước có thể cần nhiều event | ≥ 5 lần sai rồi 1 lần đăng nhập thành công từ cùng IP (AUTH-002) |

- Event thiếu trường `group_by` thì rule ngưỡng / chuỗi bỏ qua event đó (không tương quan được).
- Chặn lặp (`suppress`): mặc định 0 với `match`, 300 giây với `threshold` / `sequence`. Rule ngưỡng bắn xong thì xóa cửa sổ
  đếm. Ở SOAR, mỗi cặp (rule, thực thể) còn được gộp thông báo và gom vào case đang mở.
- Trạng thái cửa sổ đếm nằm trong bộ nhớ của analyzer và được dọn định kỳ.

### 2.5 Ngoại lệ

Ngoại lệ là điều kiện **loại trừ** gắn vào một rule: event khớp ngoại lệ thì rule bỏ qua. Dùng để giảm báo nhầm theo môi
trường (vd máy quét lỗ hổng được phép) mà không sửa điều kiện gốc. Khai báo trong `server/rules/exceptions/*.yml` (mỗi mục có
`rule_id`) hoặc ngay trong rule bằng khóa `exceptions:`. Hiện chưa có ngoại lệ nào được triển khai. AI có thể đề xuất ngoại lệ
cho rule ồn; ngoại lệ cần 2 analyst khác nhau duyệt (`AI-README.md` mục 8).

### 2.6 Nạp lại khi đổi rule

Analyzer kiểm tra dấu vân tay thư mục `rules/` (tên, thời điểm sửa, kích thước file) mỗi 10 giây. Có thay đổi thì nạp lại
toàn bộ. Nạp lỗi (YAML hỏng, trùng ID) thì giữ bộ rule cũ và ghi log lỗi. Rule lỗi đơn lẻ bị bỏ qua, các rule khác vẫn chạy.
Nhờ vậy duyệt rule AI hay sửa rule không cần khởi động lại dịch vụ.

### 2.7 Alert, mức độ, điểm rủi ro

Mỗi lần rule bắn sinh một alert (index `siem-alerts`, topic Kafka `siem.alerts`) gồm rule, event kích hoạt, nhóm, các event
liên quan (tối đa 50) và:
- `severity_score`: low 1, medium 2, high 3, critical 4;
- `risk_score` = severity × 25 × hệ số tài sản (low 0,8 / medium 1,0 / high 1,3 / critical 1,6), cộng 0,2 vào hệ số nếu
  trùng IOC, tối đa 100.

### 2.8 Cảnh báo từ ruleset Wazuh

Rule viết tay chạy trên **mọi** event Wazuh thu về (`archives.json`). Ruleset gốc của Wazuh phần lớn trùng việc với rule viết
tay, nên chỉ chuyển sang alert những cảnh báo trong `alerts.json` mà SOC Platform không có rule tương đương:
- nhóm `syscheck`, `rootcheck`, `vulnerability-detector`, `virustotal`, `yara` (`WAZUH_ALERT_GROUPS`) từ level 7;
- mọi cảnh báo level ≥ 12, bất kể nhóm.

Level Wazuh (0–15) đổi sang mức độ: 7–9 medium, 10–11 high, ≥ 12 critical. Kết quả đánh giá cấu hình SCA (CIS) không thành
alert. Hai rule Wazuh riêng trong `wazuh/manager/local_rules.xml`: 100100 (file mới trong thư mục web, có thể là webshell) và
100101 (nội dung web bị sửa), cùng level 10.

### 2.9 Rule do AI đề xuất

AI worker tìm lỗ hổng phát hiện (nhóm mẫu tấn công trong dataset chưa rule nào bắt, nhóm event thật chưa rule nào xét), viết
rule Sigma, biên dịch sang cú pháp ở mục 2.2, kiểm định tự động (bắt ≥ 30% bài thử chưa thấy, không báo nhầm, không dấu vết lab)
rồi đưa lên console. Rule chỉ chạy khi analyst duyệt: lúc đó file `server/rules/ai/AI-xxx.yml` được ghi và analyzer tự nạp
(mục 2.6). Chi tiết ở `AI-README.md`.

### 2.10 Sau khi rule bắn

SOAR nhận alert và:
1. chạy **playbook phản ứng** (`server/config/playbooks.yml`) khớp mã rule và mức độ: chặn IP, diệt tiến trình, cô lập máy
   (luôn chờ duyệt), thông báo, mở case. Mọi alert từ medium mở case, từ high được thông báo;
2. gắn **case playbook** (`server/config/case_playbooks.yml`): chọn theo mã rule, rồi kỹ thuật ATT&CK của rule, rồi tag, cuối
   cùng PB-00 điều tra chung. Ưu tiên và hạn xử lý theo mức độ: critical P1 15 phút, high P2 60 phút, medium P3 8 giờ, low P4
   24 giờ. Chi tiết ở `PLAYBOOKS.md`.

### 2.11 Detection-as-code: metadata bắt buộc, ca test, chạy bóng

Từ 13/10/2026 kho rule được kiểm tra như mã nguồn (`SOC-OPERATIONS.md` mục 4):
- **Metadata bắt buộc** mỗi rule: `id`, `title`, `severity`, `mitre` (tactic + kỹ thuật), `tags`, `logsource` (nguồn log),
  `owner` (người / nhóm phụ trách), `falsepositives` (khi nào rule có thể báo nhầm). Case playbook liên kết được tính tự động
  (mục 2.10) và phải là playbook riêng, không phải PB-00.
- **Ca test** ở `server/rules/cases/*.yml`: mỗi rule viết tay có ít nhất 1 ca dương (phải bắn) và 1 ca âm (gần giống nhưng hợp
  lệ). Ca test là event đã chuẩn hóa hoặc dòng access log thật (đi qua parser). Hiện có 81 ca cho 40 rule, đều đạt.
- **`tools/rule_lint.py`** chạy mọi kiểm tra trên, kiểm ReDoS cho mọi regex, in độ phủ theo hồ sơ mối đe dọa
  (`server/config/threat_profile.yml`, 12 kỹ thuật ưu tiên: 10/12 có rule, thiếu T1547 và T1486) và xuất layer ATT&CK
  Navigator (`--layer`). CI (`.github/workflows/ci.yml`) chạy nó cùng unit test trước khi merge.
- **Chạy bóng** (`mode: shadow`, `shadow_since`): rule vẫn sinh alert (gắn `alert.shadow`) nhưng SOAR bỏ qua, console ẩn khỏi
  danh sách mặc định (mục *Chạy bóng* của trang Cảnh báo). Rule AI vừa duyệt luôn vào chế độ này; Detection Engineer bật chính
  thức sau tối thiểu 7 ngày nếu dưới 5 alert/ngày và tỉ lệ báo nhầm dưới 30%.

## 3. Danh sách rule

Cột *Dataset* là số mẫu tấn công rule bắt được / số mẫu bình thường bắt nhầm trên dataset công khai (mục 4.2):
- **—**: rule theo ngưỡng hoặc chuỗi, cần nhiều event liên tiếp nên không đo trên từng event;
- **không có dữ liệu**: dataset không có loại log rule cần (xác thực, firewall, IDS, Windows Security, Defender, Threat Intel).

| Mã | Tên | Mức độ | Kiểu | Kỹ thuật ATT&CK | Phản ứng SOAR | Case playbook | Dataset |
|---|---|---|---|---|---|---|---|
| AUTH-001 | Brute-force đăng nhập (SSH/Linux) | high | ngưỡng ≥ 5 / 60 giây, theo `source.ip` | T1110.001 | chặn IP, thông báo, case | PB-01 | — |
| AUTH-002 | Brute-force thành công (thất bại liên tiếp rồi đăng nhập được) | critical | chuỗi 2 bước / 600 giây, theo `source.ip` | T1110, T1078 | chặn IP, cô lập (duyệt), thông báo, case | PB-09 | — |
| AUTH-003 | Password spraying | high | ngưỡng ≥ 5 `user.name` khác nhau / 120 giây, theo `source.ip` | T1110.003 | chặn IP, thông báo, case | PB-01 | — |
| AUTH-004 | Đăng nhập SSH bằng root | medium | so khớp | T1078.003 | case | PB-09 | không có dữ liệu |
| AUTH-005 | Tạo tài khoản người dùng mới trên Linux | medium | so khớp | T1136.001 | case | PB-04 | không có dữ liệu |
| AUTH-006 | Sudo mở shell root / sudo thất bại | medium | so khớp | T1548.003 | case | PB-04 | không có dữ liệu |
| LNX-001 | Reverse shell | critical | so khớp | T1059.004 | diệt tiến trình, cô lập (duyệt), thông báo, case | PB-03 | 1 / 0 |
| LNX-002 | Web server sinh ra shell (webshell / RCE) | critical | so khớp | T1505.003, T1059.004 | diệt tiến trình, cô lập (duyệt), thông báo, case | PB-12 | 0 / 0 |
| LNX-003 | Tải về và thực thi script (`curl/wget \| sh`) | high | so khớp | T1105, T1059.004 | thông báo, case | PB-03 | 8 / 0 |
| LNX-004 | Crypto miner | high | so khớp | T1496 | diệt tiến trình, cô lập (duyệt), thông báo, case | PB-14 | 0 / 0 |
| LNX-005 | Trinh sát hệ thống sau xâm nhập | medium | ngưỡng ≥ 4 `process.name` khác nhau / 60 giây, theo `agent.id` | T1082, T1033, T1016 | case | PB-03 | — |
| LNX-006 | Can thiệp cơ chế duy trì (crontab / authorized_keys / systemd) | high | so khớp | T1053.003, T1098.004, T1543.002 | thông báo, case | PB-13 | 3 / 0 |
| NET-001 | Quét cổng | medium | ngưỡng ≥ 20 `destination.port` khác nhau / 60 giây, theo `source.ip` | T1046 | case | PB-05 | — |
| NET-002 | Lượng lớn kết nối bị firewall chặn | medium | ngưỡng ≥ 50 / 60 giây, theo `source.ip` | T1595.001 | case | PB-05 | — |
| NET-003 | Kết nối từ Internet tới dịch vụ quản trị nhạy cảm | high | so khớp | T1133 | thông báo, case | PB-05 | không có dữ liệu |
| NET-004 | Cảnh báo IDS Suricata mức cao | high | so khớp | T1190 | thông báo, case | PB-18 | không có dữ liệu |
| NET-005 | Dò quét SMB nội bộ (lateral movement) | high | ngưỡng ≥ 10 `destination.ip` khác nhau / 60 giây, theo `source.ip` | T1021.002 | thông báo, case | PB-16 | — |
| TI-001 | Kết nối với IOC trong Threat Intelligence | high | so khớp | T1071 | chặn IP, thông báo, case | PB-06 | không có dữ liệu |
| WEB-001 | SQL Injection | high | so khớp | T1190 | chặn IP, thông báo, case | PB-02 | 810 / 0 |
| WEB-002 | Cross-Site Scripting (XSS) | medium | so khớp | T1189 | case | PB-02 | 752 / 0 |
| WEB-003 | Path traversal / Local File Inclusion | high | so khớp | T1190 | chặn IP, thông báo, case | PB-02 | 97 / 0 |
| WEB-004 | Command injection / RCE qua web | critical | so khớp | T1059, T1190 | chặn IP, thông báo, case | PB-02 | 97 / 0 |
| WEB-005 | Công cụ quét lỗ hổng web | medium | so khớp | T1595.002 | case | PB-02 | 0 / 0 |
| WEB-006 | Dò quét thư mục (directory brute-force) | medium | ngưỡng ≥ 30 / 60 giây, theo `source.ip` | T1083, T1595.003 | case | PB-02 | — |
| WEB-007 | Brute-force form đăng nhập web | high | ngưỡng ≥ 10 / 60 giây, theo `source.ip` | T1110.001 | chặn IP, thông báo, case | PB-01 | — |
| WEB-008 | Truy cập webshell | critical | so khớp | T1505.003 | chặn IP, thông báo, case | PB-12 | 0 / 0 |
| WEB-009 | HTTP flood (dấu hiệu DoS) | high | ngưỡng ≥ 300 / 60 giây, theo `source.ip` | T1498, T1499.002 | chặn IP, thông báo, case | PB-15 | — |
| WIN-001 | Brute-force đăng nhập Windows (RDP/SMB) | high | ngưỡng ≥ 5 / 60 giây, theo `source.ip` | T1110.001 | chặn IP, thông báo, case | PB-01 | — |
| WIN-002 | Xóa nhật ký bảo mật | critical | so khớp | T1070.001 | thông báo, case | PB-17 | không có dữ liệu |
| WIN-003 | Tạo tài khoản Windows mới | medium | so khớp | T1136.001 | case | PB-04 | không có dữ liệu |
| WIN-004 | Thêm tài khoản vào nhóm quản trị | high | so khớp | T1098 | thông báo, case | PB-04 | không có dữ liệu |
| WIN-005 | PowerShell chạy lệnh mã hóa (`-EncodedCommand`) | high | so khớp | T1059.001, T1027 | thông báo, case | PB-03 | 3 / 0 |
| WIN-006 | Script PowerShell độc hại (download cradle / bypass AMSI / Mimikatz) | critical | so khớp | T1059.001 | diệt tiến trình, cô lập (duyệt), thông báo, case | PB-03 | 71 / 0 |
| WIN-007 | Đánh cắp thông tin đăng nhập (Mimikatz / dump LSASS) | critical | so khớp | T1003.001 | diệt tiến trình, cô lập (duyệt), thông báo, case | PB-10 | 32 / 0 |
| WIN-008 | Ứng dụng Office sinh ra shell (macro độc hại) | high | so khớp | T1204.002, T1566.001 | thông báo, case | PB-11 | 0 / 0 |
| WIN-009 | Cài đặt service đáng ngờ | high | so khớp | T1543.003 | thông báo, case | PB-13 | không có dữ liệu |
| WIN-010 | Xóa shadow copy (dấu hiệu ransomware) | critical | so khớp | T1490 | diệt tiến trình, cô lập (duyệt), thông báo, case | PB-07 | 16 / 0 |
| WIN-011 | Windows Defender phát hiện mã độc | high | so khớp | T1204 | thông báo, case | PB-03 | không có dữ liệu |
| WIN-012 | Lạm dụng LOLBin để tải / thực thi mã | high | so khớp | T1218, T1105 | thông báo, case | PB-03 | 47 / 0 |
| WIN-013 | Tạo scheduled task (cơ chế duy trì truy cập) | medium | so khớp | T1053.005 | case | PB-13 | 14 / 0 |

Ngày 12/10/2026 đã chỉnh 3 rule sau khi tập bình thường mở rộng lộ ra báo nhầm (`AI-README.md` mục 9.1):
- WIN-005 bỏ qua lớp vỏ PowerShell của Ansible khi quản trị qua WinRM;
- WIN-013 chỉ bắt tác vụ chạy trình thông dịch, LOLBin, file script hoặc file trong thư mục người dùng ghi được;
- LNX-003 bỏ qua các bộ cài chính thức (Docker, nvm, rustup…).

Ngày 13/10/2026, khi viết ca test dương / âm cho từng rule (`server/rules/cases/`, mục 2.11) và chạy `tools/rule_lint.py`,
tìm ra và sửa 3 lỗi:
- **WEB-001 có regex ReDoS.** `union(\s|/\*.*?\*/|\+)+` quay lui theo cấp số nhân với chuỗi `union/**//**/...` không có
  `select` (20 comment: 0,25 giây, mỗi 2 comment thêm chậm gấp 4): một request treo được analyzer. Viết lại phần comment SQL
  dạng không mơ hồ; vẫn bắt đúng 810 mẫu SQLi như trước. Từ nay rule nào có regex bị `regex_risk` đánh giá nguy hiểm đều không
  được nạp (trước chỉ áp cho rule AI).
- **WEB-004 báo nhầm URL bình thường.** Vế `[;|&]\s*(id|cat|ls|sh|...)\b` khớp `?page=2&id=5`, `?lang=vi&cat=3` (`&` là dấu
  tách tham số): alert critical, SOAR tự chặn IP người dùng thật. Tên lệnh theo sau là `=` (tên tham số) không còn tính. Số mẫu
  CSIC WEB-004 bắt giảm 192 → 97: cả 95 mẫu chênh lệch đều chỉ khớp do `&id=`, và vẫn bị rule đúng loại bắt (tổng web không đổi).
- **WEB-008 khớp mọi tham số kết thúc bằng `c`.** `(cmd|exec|command|c)=` không neo nên `thumb.php?src=` trong thư mục
  `images/` (timthumb của nhiều theme WordPress) thành "truy cập webshell". Giờ phải là tên tham số đầy đủ.

## 4. Độ phủ

### 4.1 MITRE ATT&CK

| Chiến thuật | Số rule |
|---|---|
| Persistence (duy trì truy cập) | 7 |
| Execution (thực thi) | 7 |
| Credential Access (đánh cắp thông tin đăng nhập) | 6 |
| Initial Access (truy cập ban đầu) | 5 |
| Privilege Escalation (leo thang đặc quyền) | 3 |
| Impact (gây tác động) | 3 |
| Discovery (khám phá) | 3 |
| Reconnaissance (trinh sát) | 2 |
| Defense Evasion (né tránh phòng thủ) | 2 |
| Lateral Movement (di chuyển ngang) | 1 |
| Command and Control (điều khiển) | 1 |

Chưa có rule nào cho **Collection** (thu thập), **Exfiltration** (đánh cắp dữ liệu ra ngoài) và **Resource Development** (chuẩn
bị tài nguyên). Trong dataset endpoint (Atomic Red Team + Splunk) có 139 kỹ thuật gốc; rule viết tay gắn với 27 trong số đó.

### 4.2 Trên dataset công khai

Rule chạy trên mẫu tấn công có nhãn, đúng định dạng agent gửi (`python -m siem.ai.benchmark`). Chỉ đo được 18/40 rule: rule
so khớp trên log web hoặc log tạo tiến trình. 13 rule bắt được ít nhất một mẫu.

| Lĩnh vực | Mẫu tấn công | Bị bắt | Nhóm có ít nhất 1 mẫu bị bắt | Báo nhầm |
|---|---|---|---|---|
| Web (CSIC 2010) | 15.088 | 1.659 (11,0%) | 3/10 loại tấn công | 0/36.000 request |
| Windows, dựng lại từ Atomic Red Team | 2.218 | 127 (5,7%) | 37/133 kỹ thuật | 0/671 lệnh |
| Windows, log ghi thật (Splunk) | 595 | 56 (9,4%) | 11/35 kỹ thuật | (chung tập trên) |
| Linux, dựng lại từ Atomic Red Team | 1.146 | 12 (1,0%) | 7/76 kỹ thuật | 0/200 lệnh |
| Linux, log ghi thật (Splunk) | 268 | 0 (0%) | 0/22 kỹ thuật | (chung tập trên) |

Web theo loại tấn công: XSS 100%, SQL injection 67,4%, SSI injection 26,8%; dò file sao lưu (2.615 mẫu), dò tài nguyên nhạy cảm
(885), chèn header CRLF (540), mã hóa né tránh (466) đều 0%. Ba loại "riêng ứng dụng" (tham số lạ, giá trị sai định dạng, đường
dẫn không tồn tại) không viết được rule dùng chung nên không tính là lỗ hổng.

**Đo theo bộ log ghi thật** (log chỉ biết cả bộ thuộc kỹ thuật nào; một bộ tính là bị phát hiện khi rule bắn trên ít nhất một
tiến trình của bộ): Windows Splunk 60/417 bộ (14,4%, 29/142 kỹ thuật), Windows OTRF 25/117 (21,4%, 18/51), Linux Splunk 5/62
(8,1%, 3/22).

### 4.3 So với ruleset gốc Wazuh

Cùng dataset, bơm vào một wazuh-manager tạm (`tools/wazuh_coverage.py`, đo 6/10/2026; rule viết tay không đổi về độ phủ trên tập
dựng lại từ đó). Wazuh chỉ tính các rule phát hiện theo hành vi, bỏ rule khớp mọi event cùng loại.

| Lĩnh vực | Wazuh | Rule viết tay | Cả hai cộng lại |
|---|---|---|---|
| Web | 5,8% | 11,0% | 11,8% |
| Windows (Atomic) | 8,0% | 5,7% | 13,5% |
| Linux (Atomic) | 0,3% | 1,0% | 1,3% |

Ở Windows hai bộ bổ sung cho nhau: hợp lại gấp đôi rule viết tay. Ở Linux cả hai đều gần như không phủ. Chi tiết, kèm 2 lỗi regex
tìm thấy trong ruleset gốc của Wazuh (92041, 92021): `README.md` mục 3 và `datasets/report_wazuh.md`.

### 4.4 Độ phủ của khâu phản ứng

| Hành động | Số rule |
|---|---|
| Mở case | 40/40 |
| Thông báo | 29 |
| Chặn IP | 11 |
| Cô lập máy (cần duyệt) | 7 |
| Diệt tiến trình | 6 |

Cả 40 rule nhận case playbook riêng theo mã rule (không rule nào rơi về PB-00). Rule AI mới được gắn playbook theo kỹ thuật
ATT&CK: trong 310 kỹ thuật (kể cả kỹ thuật con) của dataset endpoint, 135 (44%) có playbook riêng. Các kỹ thuật thuộc Defense
Impairment (0/24), Collection (0/17), Exfiltration (0/9) và Discovery (2/35) gần như đều rơi về PB-00.

## 5. Điểm mạnh

- **Cú pháp gọn, đọc được, đủ tương quan cơ bản.** Ba kiểu rule (so khớp, ngưỡng có đếm giá trị khác nhau, chuỗi có thứ tự)
  diễn đạt được brute-force, password spraying, quét cổng, "sai nhiều lần rồi đăng nhập được" mà không cần ngôn ngữ truy vấn.
- **Độ chính xác cao trên phần đo được.** 0 báo nhầm trên 36.000 request web bình thường, 671 lệnh Windows và 200 lệnh Linux
  bình thường (sau khi chỉnh 3 rule ngày 12/10). Ngưỡng 0,1% áp cho rule AI cũng áp được cho rule viết tay.
- **Rule bắn là có người xử lý.** Mọi rule gắn kỹ thuật ATT&CK, mở case kèm quy trình xử lý riêng theo NIST SP 800-61; 17 rule
  có phản ứng tự động; cô lập máy luôn chờ người duyệt.
- **Đổi rule không cần dừng hệ thống.** Nạp lại sau tối đa 10 giây; rule lỗi không làm hỏng bộ rule đang chạy.
- **Giảm báo nhầm không phải sửa rule gốc.** Ngoại lệ gắn theo `rule_id`, có thể do AI đề xuất và 2 người duyệt.
- **Kết hợp với Wazuh mà không trùng alert.** Rule viết tay chạy trên mọi event; Wazuh chỉ bổ sung FIM, rootcheck, lỗ hổng,
  VirusTotal, YARA và cảnh báo rất nghiêm trọng. Ở Windows phần hợp gấp đôi từng bộ.
- **Đo được và có kiểm thử.** Có công cụ đo độ phủ trên dataset công khai (`siem.ai.benchmark`), so với ruleset Wazuh
  (`tools/wazuh_coverage.py`), unit test (gồm test hồi quy báo nhầm) và E2E chạy tấn công trên hệ thống thật.
- **Có đường mở rộng có kiểm soát.** AI đề xuất rule cho lỗ hổng đo được, nhưng chỉ chạy sau kiểm định tự động và người duyệt.

## 6. Điểm yếu

- **Độ phủ phát hiện thấp.** Windows 6,5%, Linux 0,8% mẫu tấn công; Linux log ghi thật 0%. Web bỏ trống 4/7 loại tấn công dùng
  chung (dò file sao lưu, tài nguyên nhạy cảm, CRLF, mã hóa né tránh). Rule bắt được ít nhất một mẫu ở 39/134 kỹ thuật
  Windows và 7/78 kỹ thuật Linux của dataset.
- **Hơn nửa số rule chưa được đo độ phủ.** 22/40 rule (11 rule ngưỡng / chuỗi, 11 rule trên log xác thực, mạng, Windows
  Security, Defender, Threat Intel) không có dataset có nhãn để đo. Unit test và E2E nhắc tới 24/40 rule, mỗi rule một vài
  kịch bản; 16 rule còn lại chưa có test nào (vd AUTH-003 password spraying, NET-005 SMB lateral, WIN-009 service lạ).
- **Chỉ nhìn từng event, chủ yếu dòng lệnh và URL.** Không có rule trên registry, file, kết nối mạng của tiến trình, PowerShell
  script block. Không tương quan giữa các rule khác nhau trên cùng máy hay tài khoản: 5 alert medium trên một máy trong 10 phút
  vẫn là 5 alert medium.
- **Mức độ tĩnh, không có tầng "săn tìm".** SOAR mở case cho mọi alert từ medium, nên không thêm được rule rộng mức thấp (tạo
  tài khoản, tạo dịch vụ, dò tài khoản domain: những hành vi giống hệt quản trị viên). `risk_score` có tính tài sản và IOC nhưng
  không dùng để quyết định mở case.
- **Danh sách loại trừ có thể bị lợi dụng.** WIN-005 bỏ qua đúng chuỗi tham số của Ansible, LNX-003 bỏ qua một số URL bộ cài;
  kẻ tấn công chép đúng những dạng đó sẽ lọt. Danh sách phải chỉnh theo công cụ tổ chức thật sự dùng.
- **Tập bình thường do người soạn.** Kết luận "0 báo nhầm" chỉ đúng với 671 lệnh Windows, 200 lệnh Linux và 36.000 request của
  một website mẫu; chưa có log vài tuần của chính tổ chức. Mỗi lần mở rộng tập này (8/10, 11/10) đều lộ thêm báo nhầm.
- **Trạng thái tương quan nằm trong bộ nhớ.** Cửa sổ đếm của rule ngưỡng / chuỗi mất khi analyzer khởi động lại, và không chia
  sẻ được nếu chạy nhiều analyzer song song.
- **Rule viết tay không được kiểm tra ReDoS khi nạp.** Hàm `regex_risk` chỉ áp cho rule AI; một regex viết tay có lượng từ lồng
  nhau có thể làm chậm analyzer.
- **Bỏ qua một phần phát hiện của Wazuh.** Rule tấn công web của Wazuh ở level 6 (vd SQLi 31164) không bao giờ thành alert vì
  cầu nối chỉ lấy từ level 7 trong các nhóm đã chọn; 124 mẫu SQLi Wazuh bắt được mà rule viết tay bỏ sót đang bị bỏ qua.
- **Chưa có rule AI nào chạy thật.** 28 đề xuất đang chờ duyệt; AI chưa đóng góp vào độ phủ.

## 7. Hướng cải thiện

Theo mức tác động:
1. **Điểm rủi ro theo thực thể** (máy, tài khoản, IP): cộng dồn khi nhiều rule khác nhau cùng bắn trong một khoảng thời gian,
   cộng thêm khi tài sản quan trọng / trùng IOC / tài khoản đặc quyền; mở case theo ngưỡng điểm thay vì theo từng alert. Đi kèm
   một tầng `low` chỉ ghi nhận, không mở case, để thêm được rule săn tìm.
2. **Thu log tiến trình thật của lab vài tuần** làm tập bình thường, thay cho danh sách tự soạn.
3. **Lấp chỗ trống lớn nhất**: Linux (auditd, `siem-procs`), Collection / Exfiltration, 4 loại tấn công web đang 0%. Có thể duyệt
   các đề xuất AI đang chờ, hoặc nhập rule SigmaHQ cùng kỹ thuật (bộ biên dịch Sigma đã có trong `server/siem/ai/sigma.py`).
4. **Chuyển cảnh báo web của Wazuh** (nhóm `web`, `attack` từ level 6) thành alert mức thấp, để không bỏ phí các mẫu SQLi chỉ
   Wazuh bắt được.
5. **Kiểm tra ReDoS cho mọi rule** khi nạp, không chỉ rule AI.
6. **Đo rule ngưỡng / chuỗi** bằng cách phát lại log theo thời gian (replay) thay vì đo từng event.

## 8. Đo lại

```bash
cd server
.venv/Scripts/python -m pytest tests/test_pipeline.py -q            # unit test từng rule, gồm test báo nhầm
.venv/Scripts/python -m siem.ai.benchmark --write ../datasets/report.md   # độ phủ trên dataset công khai
cd .. && python tools/wazuh_coverage.py                              # so với ruleset Wazuh (cần Docker, xem README mục 3)
python tools/e2e_test.py                                             # chạy tấn công thật trên stack đang chạy
```

Dataset công khai cần tải và chuyển đổi trước (`tools/fetch_datasets.py`, `tools/convert_datasets.py`, xem `AI-README.md`
mục 12).
