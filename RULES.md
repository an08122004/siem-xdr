# Hệ thống rule phát hiện

Tài liệu về phần **phát hiện bằng luật** của SIEM/XDR: rule chạy ở đâu, viết và kiểm thử thế nào, dải id, chạy bóng, độ phủ,
điểm mạnh và điểm yếu. Từ 05/11/2026 (R65) mọi phát hiện bằng luật chạy trong `wazuh-analysisd`: ruleset gốc Wazuh 4.14.8 cộng
rule XML riêng của dự án, rule SigmaHQ và rule AI. Tài liệu liên quan:
- `README.md` mục 3: tóm tắt phần phát hiện.
- `PLAYBOOKS.md`: quy trình xử lý sự cố (case playbook) gắn vào case khi rule bắn.
- `AI-README.md`: AI đề xuất rule mới (ra Wazuh XML, kiểm định trên sandbox Wazuh) và ngoại lệ.
- `SOC-OPERATIONS.md` mục 4: quy trình detection-as-code, chạy bóng, bật chính thức.
- [docs/wazuh-ruleset-decisions.md](docs/wazuh-ruleset-decisions.md): sổ quyết định R1–R83 của bộ rule Wazuh XML.

> **Lịch sử.** Trước 05/11/2026 phát hiện chạy bằng engine YAML trong analyzer (`server/rules/*.yml`, 41 rule). Engine tắt
> ở R65 (05/11/2026) và **đã xóa khỏi mã ở Task 25** của kế hoạch P4 (08/11/2026). Mã của 41 rule cũ (`WEB-001`, `LNX-002`...)
> sống tiếp trong nhóm `legacy_<MÃ>` của rule XML tương ứng (mục 9.4). Mục 3 và các số đo 4.1 đến 4.4 là của rule YAML, giữ
> làm lịch sử.

## Mục lục

1. [Tổng quan](#1-tổng-quan)
2. [Cơ chế hoạt động](#2-cơ-chế-hoạt-động)
3. [Danh sách 41 mã rule cũ (lịch sử)](#3-danh-sách-41-mã-rule-cũ-lịch-sử)
4. [Độ phủ](#4-độ-phủ)
5. [Điểm mạnh](#5-điểm-mạnh)
6. [Điểm yếu](#6-điểm-yếu)
7. [Kế hoạch bổ sung độ phủ](#7-kế-hoạch-bổ-sung-độ-phủ-16102026)
8. [Đo lại](#8-đo-lại)
9. [Bộ rule Wazuh XML thống nhất (đã chuyển sang Wazuh, R65)](#9-bộ-rule-wazuh-xml-thống-nhất-đã-chuyển-sang-wazuh-r65)

## 1. Tổng quan

Alert trong hệ thống đến từ các nguồn sau (đếm rule trên mã ngày 08/11/2026):

| Nguồn | Số lượng | Mã alert | Trạng thái |
|---|---|---|---|
| Ruleset gốc Wazuh 4.14.8 | khoảng 4,5 nghìn rule; 9 rule được chỉnh bằng `overwrite` ở `0999-tuning.xml` (mục 9.8) | `WZH-<id>` | Alert thật từ level 7 (R65), trừ nhóm `sca` |
| Rule XML của dự án (`wazuh/manager/rules/`, 9 file) | 88 rule; phủ 41 mã cũ qua nhóm `legacy_<MÃ>` (mục 9.4) | `WZH-100xxx` đến `WZH-107xxx`, mã cũ ở đầu mô tả | Chạy thật (R65) |
| SigmaHQ lô 1 (`0966-sigmahq.xml`) | 30 rule Windows (mục 2.10) | `WZH-108000` đến `WZH-108029`, mã `SHQ-NNN` | Chạy bóng từ 08/11/2026 (sinh lại sau review cuối P4) |
| Rule do AI đề xuất (`rules-dynamic/ai.xml`) | chưa rule nào được triển khai (06/11/2026: 178 đề xuất, 0 đã triển khai) | `WZH-109xxx`, mã `AI-NNN` | Bóng khi duyệt, bật chính thức trên console (mục 2.9) |
| Ngoại lệ (`rules-dynamic/exceptions.xml`) | rule level 0, không sinh alert | 110000–110999 | Hai người khác nhau duyệt (mục 2.5) |
| Phát hiện của nền tảng | RBA-001 (`soar/risk.py`), HLT-* (`soar/health.py`) | `RBA-001`, `HLT-*` | Đang chạy |
| ML (Isolation Forest) | — | `ML-001` | Tắt (`ML_ENABLED=false`, báo nhầm khoảng 32%) |

## 2. Cơ chế hoạt động

### 2.1 Luồng xử lý

```
Wazuh agent ──> wazuh-manager: decoder ──> wazuh-analysisd (ruleset gốc + wazuh/manager/rules + rules-dynamic/)
syslog 514 (firewall) ──┘                     │
        archives.json (mọi event) ──> Vector ──> Kafka siem.raw ──> analyzer: normalize, enrich ──> ES siem-events-*
        alerts.json (rule đã khớp) ──> Vector ──> Kafka siem.raw ──> analyzer: cầu nối Wazuh ──> alert WZH-<id>
                                                                       ──> ES siem-alerts + Kafka siem.alerts ──> SOAR
```

- Phát hiện chỉ còn một chỗ: `wazuh-analysisd` của `wazuh-manager`. Analyzer không chạy rule; nó chuẩn hóa event (ECS rút
  gọn), làm giàu (Threat Intel, tài sản) và chuyển cảnh báo của Wazuh thành alert qua cầu nối (`server/siem/detection/wazuh.py`).
- Mỗi event chỉ ra **một** alert Wazuh: rule thắng cuối cùng trong cây rule (mục 2.4).
- Rule của repo mount chỉ đọc vào `etc/rules`; rule động (`ai.xml`, `exceptions.xml`) nằm trong volume `wazuh_dynamic_rules`,
  chỉ console ghi.

### 2.2 Định dạng rule

Rule viết bằng XML của Wazuh. Ví dụ rule LNX-002 (`0102-linux.xml`):

```xml
<rule id="102002" level="12">
  <if_sid>102000</if_sid>                                      <!-- cha: dòng siem-proc của agent -->
  <field name="parent" type="pcre2">^(apache2|httpd|nginx|php-fpm|php|lighttpd|tomcat|java)$</field>
  <field name="name" type="pcre2">^(sh|bash|dash|zsh|nc|ncat|python|python3|perl|curl|wget|whoami|id|uname)$</field>
  <description>LNX-002 Web server $(parent) sinh ra $(name) (khả năng webshell / RCE)</description>
  <mitre><id>T1505.003</id><id>T1059.004</id></mitre>
  <group>siem,linux,legacy_LNX-002,</group>
</rule>
```

Quy ước bắt buộc (lint kiểm, mục 9.3): mã rule ở đầu `<description>`, có `<mitre><id>`, nhóm chứa `siem`, `type="pcre2"` cho
`<regex>` / `<field>`, id nằm trong dải của file, không dùng `ignore`, rule có nhóm `shadow` phải có
`<info type="text">shadow_since=YYYY-MM-DD</info>`. Mức độ: level 7–9 là medium, 10–11 high, ≥ 12 critical.

### 2.3 Dải id

Dải của từng file nằm ở `ID_RANGES` (`server/siem/wazuh_rules.py`); lint và console đọc bảng này.

| File | Dải id | Ai ghi |
|---|---|---|
| `0100-platform.xml`, `0101-auth.xml`, `0102-linux.xml`, `0851-linux-audit.xml`, `0541-network.xml`, `0271-web.xml`, `0965-windows.xml`, `0106-fim.xml`, `0845-ti.xml` | 100000–107999 (từng file ở mục 9.2) | Repo (pull request + CI) |
| `0966-sigmahq.xml` | 108000–108999 | `tools/sigmahq_import.py --write` (không sửa tay) |
| `rules-dynamic/ai.xml` | 109000–109999 | Console, khi duyệt đề xuất AI (mục 2.9) |
| `rules-dynamic/exceptions.xml` | 110000–110999 | Console, khi ngoại lệ đủ hai người duyệt (mục 2.5) |
| Ứng viên của cổng AI | từ 119000 | Chỉ tồn tại trong `wazuh-sandbox`, không bao giờ vào manager thật |
| `0999-tuning.xml` | không có dải | Chỉ `overwrite="yes"` trên rule gốc (id < 100000) |

### 2.4 Thứ tự nạp và rule anh em

- Wazuh nạp mọi file rule (gốc lẫn dự án) theo **tên file**; rule con bị bỏ nếu `if_sid` trỏ tới rule chưa nạp (cảnh báo 7617 /
  7619 trong `ossec.log`). Vì vậy tên file quyết định được móc vào đâu (R45). Ví dụ SigmaHQ phải là `0966-…`, xếp sau
  `0595-win-sysmon_rules.xml` và `0800-sysmon_id_1.xml` (R76).
- Trong các rule cùng cha: **level cao hơn thắng**, bằng level thì **rule nạp trước thắng**; rule thắng ở một tầng thì cả cây con
  của các anh em thua bị bỏ. Rule mới có thể vì thế "cướp" alert thật của rule gốc. Chốt chặn: `tools/wazuh_stock_reach.py` trong
  CI (mục 9.6), cổng "không che rule khác" cho rule AI (R79), level của rule sinh tự động không quá 10 (R70).
- Rule gom level 0 của ruleset gốc có thể nuốt event trước anh em: rule Windows sinh tự động treo dưới 61603 **và** 92025, 92028,
  92042, 92069 (R75).

### 2.5 Ngoại lệ

Ngoại lệ là rule con **level 0** của rule cần làm yên, luôn có điều kiện trường, ghi vào `rules-dynamic/exceptions.xml`
(110000–110999). Ngoại lệ chỉ vào XML khi hai người **khác nhau** có quyền `rules` duyệt; gỡ thì một người đủ, lịch sử được giữ;
id không bao giờ dùng lại (R48). AI có thể đề xuất ngoại lệ cho rule Wazuh hay báo nhầm: người duyệt trên trang *Đề xuất AI* tạo
ngoại lệ chờ duyệt, người thứ hai duyệt ở trang ngoại lệ (R73). Quy trình đầy đủ: `SOC-OPERATIONS.md` mục 4.

### 2.6 Nạp lại khi đổi rule

- Rule động: console ghi qua `wazuh_rules.write_dynamic`: kiểm cú pháp cục bộ, ghi file tạm, đổi tên nguyên tử, gọi
  `PUT /manager/analysisd/reload` và xét cả `error`, `failed_items`, `msg` (Wazuh âm thầm bỏ rule trùng id hay sai `if_sid`, HTTP vẫn
  200). Nạp lỗi thì khôi phục file cũ, nạp lại, và thao tác trên console báo lỗi (R1, R11).
- Mỗi lần khởi động, `wazuh/manager/entrypoint/10-siem-setup.sh` chạy `wazuh-analysisd -t`; ruleset lỗi thì chuyển file trong
  `rules-dynamic` sang `rules-dynamic.quarantine/` để manager vẫn lên (R12).
- Rule của repo: cập nhật mã trên máy chủ rồi reload (hoặc khởi động lại wazuh-manager). Wazuh không cần build lại image.

### 2.7 Alert, mức độ, điểm rủi ro

Mỗi cảnh báo Wazuh qua cầu nối thành một alert (index `siem-alerts`, topic Kafka `siem.alerts`) có `rule.id = WZH-<id>`,
`rule.groups`, `rule.legacy_id` (từ nhóm `legacy_*`), event kích hoạt và:
- `severity`: level 7–9 medium, 10–11 high, ≥ 12 critical; `severity_score`: low 1, medium 2, high 3, critical 4;
- `risk_score` = severity × 25 × hệ số tài sản (low 0,8 / medium 1,0 / high 1,3 / critical 1,6), cộng 0,2 vào hệ số nếu
  trùng IOC, tối đa 100.

### 2.8 Cầu nối, chạy bóng và chống trùng

- Cầu nối lấy mọi cảnh báo level ≥ 7 trong `alerts.json`, trừ nhóm `sca` (`WAZUH_ALERT_EXCLUDE_GROUPS`, R22).
- **Chạy bóng:** rule có nhóm `shadow` ra alert gắn `alert.shadow`; SOAR bỏ qua (không thông báo, không mở case, không phản ứng),
  console ẩn khỏi danh sách mặc định (mục *Chạy bóng* của trang Cảnh báo), KPI không tính. Từ R65 rule gốc level 7–11 là alert
  thật (`WAZUH_STOCK_SHADOW=false`), rule XML của dự án hiện có cũng chạy thật; chạy bóng dành cho rule MỚI (SigmaHQ, AI).
- **Chống trùng:** cùng `(rule.id, nguồn hoặc agent, agent, file.path)` trong `WAZUH_ALERT_SUPPRESS` (60) giây chỉ ra một alert;
  alert bóng không bị dập để đếm đủ (R40). Rule `frequency` có thể báo lại trong cùng cửa sổ; dập trùng làm ở đây vì không dùng
  `ignore` (R55).

### 2.9 Rule do AI đề xuất

AI worker tìm mẫu tấn công trong dataset công khai mà Wazuh **chưa** bắt (khoảng trống tính trên alert Wazuh thật), cho LLM viết
rule Sigma, dịch sang Wazuh XML (`ai/wazuh_xml.py`) rồi kiểm định trên `wazuh-sandbox`, một wazuh-manager cô lập cùng image (R66,
R67): bắt ≥ 30% tập kiểm tra, báo nhầm ≤ 0,1%, không che alert thật của rule khác. Đề xuất đạt chờ người duyệt trên console.
Khi duyệt, console ghi khối XML của đề xuất vào `rules-dynamic/ai.xml` ở chế độ **bóng** (id 109000–109999, không dùng lại, R81).
Detection Engineer bấm *Bật chính thức* khi đạt tiêu chí chạy bóng (mục 2.12); *Gỡ* dựng lại file không có khối đó (R72).
Chi tiết: `AI-README.md` mục 7, 8, 9.11.

### 2.10 SigmaHQ

`tools/sigmahq_import.py` nhập rule cộng đồng SigmaHQ (giấy phép DRL 1.1) bằng cùng bộ dịch với AI:
- chọn rule `process_creation` Windows và `webserver`, status stable / test, level ≥ medium, kỹ thuật có case playbook riêng;
  chọn tham lam theo số mẫu tấn công **mới** bắt được (mẫu chưa có phát hiện Wazuh), không khớp mẫu bình thường nào;
- ghi `wazuh/manager/rules/0966-sigmahq.xml` (id 108000–108999, mã `SHQ-NNN`, nhóm `siem,sigmahq,shadow,`, `<info>` giữ
  `sigmahq_id` và `author`, đầu file chú thích giấy phép) và ca test `tests/cases/0966-sigmahq.yml` (mỗi rule một ca dương, một
  ca âm);
- bỏ rule Windows có `>`, `<`, `&` (Wazuh giữ thực thể XML trong trường Windows, chưa hỗ trợ, R77);
- rule khớp (cây Python) một mẫu mà Wazuh **đang** phát hiện thì level tối đa 7: thua rule level ≥ 8, hòa level 7 thì rule nạp
  trước thắng, nên không cắt cây con của rule đang bắt mẫu đó (R84);
- `--measure` chạy hai lượt trên manager tạm, có và không có `0966`, cùng bộ mẫu; mẫu nào mất phát hiện level ≥ 7 ngoài 108xxx
  (lô "cướp" alert thật) thì thoát mã 1 và liệt kê.

Lô 1 (07/11/2026): 30 rule Windows 108000–108029, 60 ca 0 sai trên manager thật, chạy bóng; không có rule web. Tên file là
`0966` chứ không phải `0108` như kế hoạch ban đầu (R76). Rule Linux SigmaHQ hoãn: theo R68 rule Linux nhắm decoder `siem-proc`.
Review cuối P4 (08/11/2026) đo lô cũ: 2 mẫu bị cướp (92024 level 14 thành 108017 SHQ-018; 105013 WIN-013 thành 108002 SHQ-003).
Lô sinh lại bằng tool với quy tắc level tối đa 7: cùng 30 rule, cùng ca test, 4 rule hạ từ 10 xuống 7 (108001, 108002, 108007,
108017); đo lại 0 mẫu bị cướp.

### 2.11 Sau khi rule bắn

SOAR nhận alert (không bóng) và:
1. chạy **playbook phản ứng** (`server/config/playbooks.yml`) theo `WZH-<id>` và mức độ: chặn IP, diệt tiến trình, cô lập máy
   (luôn chờ duyệt), thông báo, mở case. Hành động phá hủy chỉ chọn theo id rõ ràng đã duyệt (R60); mọi alert từ medium mở case;
2. gắn **case playbook** (`server/config/case_playbooks.yml`): chọn theo `legacy_id` / mã rule, rồi kỹ thuật ATT&CK, nhóm, tag,
   cuối cùng PB-00 điều tra chung. Ưu tiên và hạn xử lý theo mức độ: critical P1 15 phút, high P2 60 phút, medium P3 8 giờ, low P4
   24 giờ. Chi tiết ở `PLAYBOOKS.md`.

### 2.12 Detection-as-code: lint, ca test, rule gốc còn tới được, chạy bóng

Kho rule là mã nguồn (`SOC-OPERATIONS.md` mục 4). Mỗi file rule có file ca test cùng tên trong `wazuh/manager/tests/cases/`, ca
test là **log gốc** (mục 9.5). Job CI `wazuh-rules` (`.github/workflows/ci.yml`) chạy theo thứ tự:
1. `tools/wazuh_rule_lint.py`: quy ước ở mục 2.2, ca dương / âm cho mỗi rule, `shadow_since`, cha nạp trước; xuất layer ATT&CK
   Navigator (`--layer build/attack-layer.json`, lưu làm artifact của lần chạy, kể cả lần chạy hằng tuần);
2. dựng `wazuh/wazuh-manager:4.14.8` với rule của repo, quét `ossec.log` không có 7612 / 7617 / 7619 hay ERROR của analysisd;
3. `tools/wazuh_stock_reach.py`: mọi alert thật của rule gốc dưới rule cha mà rule dự án móc vào đều có ca ghim hoặc bảo đảm cấu trúc;
4. `tools/wazuh_rule_test.py`: chạy cả thư mục ca qua manager thật (logtest, hoặc bơm hàng đợi cho eventchannel / syscheck).

Rule mới (viết tay, SigmaHQ, AI) vào **chạy bóng** trước. Bật chính thức khi đạt cả ba: chạy bóng ≥ `SHADOW_MIN_DAYS` (7) ngày,
dưới `SHADOW_MAX_ALERTS_PER_DAY` (5) alert/ngày, tỉ lệ báo nhầm dưới `SHADOW_MAX_FP_RATE` (30%) trên alert đã có kết luận.
Rule AI bật bằng nút trên console; rule trong repo (gồm SigmaHQ) bật bằng commit bỏ nhóm `shadow` và `shadow_since`.

## 3. Danh sách 41 mã rule cũ (lịch sử)

Bảng dưới là 41 rule YAML (engine YAML đã xóa ở Task 25), giữ vì mã của chúng còn dùng: rule XML tương ứng mang nhóm
`legacy_<MÃ>`, alert mang `rule.legacy_id`, case playbook chọn theo mã này. Rule XML thay cho từng mã: **mục 9.4**. Cột *Kiểu*
và *Dataset* là của rule YAML (đo 12/10/2026); rule XML có thể khác ngưỡng (vd NET-002 theo 87702 đã chỉnh, mục 9.8).

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
| FIM-001 | Thay đổi file / khóa registry dùng để duy trì truy cập (Startup, Run, cron, systemd, PAM, sudoers, authorized_keys...). **Chạy bóng từ 14/10/2026** | high | so khớp | T1547.001, T1053.003, T1543.002, T1098.004, T1556.003, T1574.006, T1546.004, T1037.004, T1548.003 | khi chạy chính thức: thông báo, case | PB-13 | không có dữ liệu |
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

**Giới hạn đã biết (rule WEB dạng XML của Wazuh):** web server đẩy log truy cập qua syslog (không qua agent) KHÔNG được các rule WEB phủ, vì rule ràng vị trí agent để thiết bị syslog không giả mạo được alert web; cần cài agent trên web server.

Ngày 12/10/2026 đã chỉnh 3 rule sau khi tập bình thường mở rộng lộ ra báo nhầm (`AI-README.md` mục 9.1):
- WIN-005 bỏ qua lớp vỏ PowerShell của Ansible khi quản trị qua WinRM;
- WIN-013 chỉ bắt tác vụ chạy trình thông dịch, LOLBin, file script hoặc file trong thư mục người dùng ghi được;
- LNX-003 bỏ qua các bộ cài chính thức (Docker, nvm, rustup…).

Ngày 13/10/2026, khi viết ca test dương / âm cho từng rule (`server/rules/cases/`) và chạy `tools/rule_lint.py` (cả hai đã xóa ở Task 25),
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

Mục 4.1 đến 4.4 đo trên 41 rule YAML (6–12/10/2026), giữ làm lịch sử: rule XML thay thế phủ cùng các mã (mục 9.4) nhưng chưa được
đo lại theo cùng cách. Mục 4.5 là đối chiếu mã cũ với ruleset gốc (cơ sở của việc chuyển). Số đo trên Wazuh sau P4: **mục 4.6**.

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

Rule chạy trên mẫu tấn công có nhãn, đúng định dạng agent gửi (`python -m siem.ai.benchmark`, đã xóa ở Task 25). Chỉ đo được 18/40 rule: rule
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

### 4.5 Đối chiếu 41 rule cũ với ruleset gốc Wazuh 4.14.8 (31/10/2026)

Chuyển phát hiện sang rule XML của `wazuh-analysisd` (kế hoạch `docs/superpowers/plans/2026-10-31-wazuh-unified-ruleset.md`)
cần biết rule nào ruleset gốc (4.515 rule) đã phủ. `tools/cases_to_raw.py` (đã xóa ở Task 25, cùng `server/rules/cases/` và `--report`) đổi các ca ECS trong `server/rules/cases/` về log gốc
(Apache, sshd/sudo/useradd, filterlog, `eve.json`, Windows Security/Sysmon/PowerShell/Defender, syscheck, `siem-proc:`, auditd) vào
`wazuh/manager/tests/legacy/`; `python tools/wazuh_rule_test.py --report` chạy mọi ca qua manager chỉ có ruleset gốc (cộng 100100/100101,
không tính) và ghi `wazuh/manager/tests/legacy_map.yml`. Quyết định:

- `builtin`: ca dương phủ MỌI nhánh điều kiện của rule cũ (mỗi giá trị regex / danh sách; ca bổ sung gắn nhãn `[bổ sung phủ nhánh]`), mỗi ca có
  ít nhất một rule gốc CỤ THỂ level >= 7 (không thuộc nhóm `sca`), và không ca âm nào báo rule gốc level >= 7.
- `approx`: có rule gốc cụ thể báo trên ca dương nhưng chưa đủ (thiếu ca hoặc nhánh, báo nhầm ca âm, hoặc chỉ level < 7: ứng viên nâng level ở `0999-tuning.xml`).
  Ghi chú `chỉ chứng minh: ...; thiếu: ...` liệt kê nhánh đã/chưa phủ.
- `convert`: không rule gốc cụ thể nào (hoặc chỉ trúng rule CHUNG trong `GENERIC_IDS` của `tools/wazuh_rule_test.py`, vd. 80792 mọi lệnh auditd,
  31106 / 31101 mọi phản hồi tấn công 200 / lỗi 4xx, 86601 mọi cảnh báo Suricata; hoặc ca không dựng được log gốc): phải viết rule XML riêng.

Kết quả: 1 `builtin`, 14 `approx`, 26 `convert`.

| Mã | Quyết định | Rule gốc | Ghi chú |
|---|---|---|---|
| AUTH-001 | convert | — | chỉ trúng rule chung 5760 (sshd: authentication failed.), không chỉnh; 0/1 ca dương có rule gốc cụ thể level>=7; LƯU Ý: rule dự án 101000 (0101-auth.xml) nhận thay 5760/5710 nên alert từng lần thất bại là 101000 level 2 (không vào alerts.json),; hệ quả: 5763/5712 gốc (8 lần/120 s) không còn báo, hở nhịp 4-5 lần/phút (xem comment 0101-auth.xml); đếm chung sshd + console (R42): thất bại hai dịch vụ cùng IP cộng dồn, và thành công trên một dịch vụ sau chuỗi thất bại ở dịch vụ kia cũng ra 101002 (critical) |
| AUTH-002 | convert | — | chỉ trúng rule chung 5715 (sshd: authentication success.), 5760 (sshd: authentication failed.), không chỉnh; 0/1 ca dương có rule gốc cụ thể level>=7; LƯU Ý: rule dự án 101000 (0101-auth.xml) nhận thay 5760/5710 nên alert từng lần thất bại là 101000 level 2 (không vào alerts.json),; hệ quả: 5763/5712 gốc (8 lần/120 s) không còn báo, hở nhịp 4-5 lần/phút (xem comment 0101-auth.xml); đếm chung sshd + console (R42): thất bại hai dịch vụ cùng IP cộng dồn, và thành công trên một dịch vụ sau chuỗi thất bại ở dịch vụ kia cũng ra 101002 (critical) |
| AUTH-003 | convert | — | chỉ trúng rule chung 5760 (sshd: authentication failed.), không chỉnh; 0/1 ca dương có rule gốc cụ thể level>=7; LƯU Ý: rule dự án 101000 (0101-auth.xml) nhận thay 5760/5710 nên alert từng lần thất bại là 101000 level 2 (không vào alerts.json),; hệ quả: 5763/5712 gốc (8 lần/120 s) không còn báo, hở nhịp 4-5 lần/phút (xem comment 0101-auth.xml); đếm chung sshd + console (R42): thất bại hai dịch vụ cùng IP cộng dồn, và thành công trên một dịch vụ sau chuỗi thất bại ở dịch vụ kia cũng ra 101002 (critical) |
| AUTH-004 | convert | — | chỉ trúng rule chung 5715 (sshd: authentication success.), không chỉnh; 0/1 ca dương có rule gốc cụ thể level>=7 |
| AUTH-005 | builtin | 5902 | 1/1 ca dương có rule gốc cụ thể level>=7; builtin: 5902 (level 8: New user added to the system.) |
| AUTH-006 | convert | — | chỉ trúng rule chung 5403 (First time user executed sudo.), không chỉnh; 0/1 ca dương có rule gốc cụ thể level>=7 |
| FIM-001 | approx | 550, 554 | không dựng được log gốc: ca registry: bộ bơm syscheck chỉ dựng được sự kiện file, không có sự kiện registry; 1/3 ca dương có rule gốc cụ thể level>=7; rule chung, không tính phủ: 554 (level 5: File added to the system.) [level 5 'File added to the system.': mọi file mới trong thư mục được giám sát]; ca âm báo level>=7: [550, 553]; rule dự án 106001-106003 (0106-fim.xml, con của 550/554 và 750/752 lọc theo đường dẫn `file`, level 10, chạy bóng): Linux (cron, systemd, PAM, ld.so.preload, profile.d, rc.local, tài khoản, sudoers, authorized_keys, sshd_config), thư mục Startup Windows, khóa registry Run/RunOnce (ca registry nay bơm được qua value_name); xóa file (553) không báo như rule cũ; thư mục web vẫn do 100100/100101 |
| LNX-001 | convert | — | chỉ trúng rule chung 80792 (Audit: Command: $(audit.exe).), không chỉnh; 0/2 ca dương có rule gốc cụ thể level>=7 |
| LNX-002 | convert | — | 0/1 ca dương có rule gốc cụ thể level>=7; không rule gốc nào báo |
| LNX-003 | convert | — | chỉ trúng rule chung 80792 (Audit: Command: $(audit.exe).), không chỉnh; 0/2 ca dương có rule gốc cụ thể level>=7 |
| LNX-004 | convert | — | chỉ trúng rule chung 80792 (Audit: Command: $(audit.exe).), không chỉnh; 0/2 ca dương có rule gốc cụ thể level>=7 |
| LNX-005 | convert | — | chỉ trúng rule chung 80792 (Audit: Command: $(audit.exe).), không chỉnh; 0/2 ca dương có rule gốc cụ thể level>=7 |
| LNX-006 | convert | — | chỉ trúng rule chung 80792 (Audit: Command: $(audit.exe).), không chỉnh; 0/2 ca dương có rule gốc cụ thể level>=7 |
| NET-001 | approx | 87702, 87701 | 1/2 ca dương có rule gốc cụ thể level>=7; chỉ chứng minh: deny; thiếu: allow; rule chung, không tính phủ: 87701 (level 5: pfSense firewall drop event.) [level 5 'pfSense firewall drop event.': MỘT gói bị chặn, không có ngưỡng]; ca âm báo level>=7: [87702]; rule dự án 0541-network.xml: 103001 (không phải block) và 103002 (block, level 11 = high trong khi bản pass 103001 là medium, vì 87702 level 10 đã đánh dấu event; báo SAU 87702 nên một đợt quét cho hai alert) đếm `different_dstport` >= 20/60 s cùng nguồn, chạy bóng; giới hạn S4: Wazuh đếm event trước có giá trị khác, nên một chuỗi DÀI hai cổng xen kẽ (>= 2N-2 dòng) VẪN báo (dương tính giả, không chỉ bỏ sót); một cổng lặp lại không báo; 103002 báo ở dòng 21 (sau 87702 ở dòng 18) |
| NET-002 | approx | 87702, 87701 | 1/1 ca dương có rule gốc cụ thể level>=7; rule chung, không tính phủ: 87701 (level 5: pfSense firewall drop event.) [level 5 'pfSense firewall drop event.': MỘT gói bị chặn, không có ngưỡng]; ca âm báo level>=7: [87702]; không có rule dự án: chỉ khác 87702 ở ngưỡng (18/45 s so với 50/60 s), Task 12 ĐÃ chỉnh: 0999-tuning.xml đè 87702 thành 50 chặn/60 s, level 7 (medium), bỏ ignore, nhóm legacy_NET-002 |
| NET-003 | convert | — | 0/1 ca dương có rule gốc cụ thể level>=7; không rule gốc nào báo; rule dự án 103003 (0541-network.xml, con của bộ đếm 103000): pass + nguồn ngoài 10/8, 172.16/12, 192.168/16, 100.64/10, 169.254/16, 127/8 + cổng quản trị; chạy bóng; IPv6 chưa phủ |
| NET-004 | convert | — | chỉ trúng rule chung 86601 (Suricata: Alert - $(alert.signature)), không chỉnh; 0/1 ca dương có rule gốc cụ thể level>=7; rule dự án 103004 (0541-network.xml, con của 86601): alert.severity <= 2, chạy bóng; CHỈ qua agent OPNsense đọc eve.json (Suricata qua syslog không có decoder, S6); loại IP trong danh sách malicious-ip bằng lookup phủ định nên rule IOC gốc 99915/99916 (level 9) thắng NET-004 (R44), NET-004 chỉ ra với IP sạch |
| NET-005 | convert | — | 0/1 ca dương có rule gốc cụ thể level>=7; không rule gốc nào báo; rule dự án 103005 (0541-network.xml): `different_dstip` >= 10 trên cổng 445/60 s cùng nguồn, chỉ kết nối không bị chặn, chạy bóng; giới hạn S4 như NET-001: chuỗi dài (>= 18 dòng) hai IP đích xen kẽ vẫn báo (dương tính giả); quét SMB từ IP public đã bị NET-003 báo từng event nên không vào đếm |
| TI-001 | convert | — | không dựng được log gốc: phụ thuộc làm giàu MISP (threat.matched do pipeline gắn), log gốc của kết nối không có trường này; không có ca dương; rule dự án 107001-107010 (0845-ti.xml, chạy bóng): IP nguồn/đích của firewall (con của 87701/103000/103003) và Suricata (con của 86601/103004) khớp danh sách etc/lists/siem-misp-ip do SOAR đẩy lên mỗi chu kỳ đồng bộ MISP (server/siem/pipeline/misp_cdb.py); chỉ IP (CIDR /24-/31 triển khai từng địa chỉ), CHƯA có domain/hash; R53: phủ thêm sshd (107008), web access log (107009), đăng nhập Windows (107010); DNS/proxy/VPN chưa phủ; RESIDUAL: domain và hash IOC chỉ có ở analyzer (người dùng quyết trước khi tắt rule YAML, Task 18); IOC cục bộ config/intel/bad_ips.txt cũng được xuất; IP có trong danh sách gốc malicious-ip thì 99915/99916 giữ ngữ cảnh |
| WEB-001 | approx | 31103, 31106 | 1/2 ca dương có rule gốc cụ thể level>=7; rule chung, không tính phủ: 31106 (level 6: A web attack returned code 200 (success).) [level 6 'A web attack returned code 200 (success)': con chung của 31103/31104/31105, không nói loại tấn công] |
| WEB-002 | approx | 31105, 31106 | 0/2 ca dương có rule gốc cụ thể level>=7; level<7 (ứng viên nâng level): ['31105 (level 6: XSS (Cross Site Scripting) attempt.)']; rule chung, không tính phủ: 31106 (level 6: A web attack returned code 200 (success).) [level 6 'A web attack returned code 200 (success)': con chung của 31103/31104/31105, không nói loại tấn công] |
| WEB-003 | approx | 31104, 31106 | 0/2 ca dương có rule gốc cụ thể level>=7; level<7 (ứng viên nâng level): ['31104 (level 6: Common web attack.)']; rule chung, không tính phủ: 31106 (level 6: A web attack returned code 200 (success).) [level 6 'A web attack returned code 200 (success)': con chung của 31103/31104/31105, không nói loại tấn công] |
| WEB-004 | convert | — | chỉ trúng rule chung 31101 (Web server 400 error code.), không chỉnh; 0/4 ca dương có rule gốc cụ thể level>=7 |
| WEB-005 | convert | — | chỉ trúng rule chung 31101 (Web server 400 error code.), không chỉnh; 0/2 ca dương có rule gốc cụ thể level>=7 |
| WEB-006 | approx | 31151, 31101 | 1/1 ca dương có rule gốc cụ thể level>=7; rule chung, không tính phủ: 31101 (level 5: Web server 400 error code.) [level 5 'Web server 400 error code.': mọi phản hồi 4xx, không nhìn URL hay payload]; ca âm báo level>=7: [31151] |
| WEB-007 | approx | 31509, 31510 | 1/5 ca dương có rule gốc cụ thể level>=7; chỉ chứng minh: wp-login; thiếu: signin, login, auth, admin; level<7 (ứng viên nâng level): ['31509 (level 3: CMS (WordPress or Joomla) login attempt.)'] |
| WEB-008 | convert | — | chỉ trúng rule chung 31101 (Web server 400 error code.), không chỉnh; 0/2 ca dương có rule gốc cụ thể level>=7 |
| WEB-009 | convert | — | 0/1 ca dương có rule gốc cụ thể level>=7; không rule gốc nào báo |
| WIN-001 | convert | — | chỉ trúng rule chung 60122 (Logon Failure - Unknown user or bad password), không chỉnh; 0/1 ca dương có rule gốc cụ thể level>=7; rule dự án 105001 (0965-windows.xml, con của 60122): >= 5 lần 4625 / 60 s cùng win.eventdata.ipAddress (IP '-' / ::1 / 127.0.0.1 không đếm), chạy bóng; IP trong danh sách malicious-ip: 99919 (level 9, nạp sau) giữ mọi event nên 105001 không báo cho IP đó; che rule gốc 60204 (>= 8 / 240 s) khi cả hai cùng đủ điều kiện, 60204 vẫn báo khi nhịp chậm hơn 5/60 s |
| WIN-002 | approx | 63103 | 0/1 ca dương có rule gốc cụ thể level>=7; level<7 (ứng viên nâng level): ['63103 (level 5: The audit log was cleared)']; rule dự án 105002 (0965-windows.xml, con của 63104): nhánh System/104 (log Windows khác bị xóa) thiếu ở rule gốc, level 12, chạy bóng; riêng 1102 chỉ khác 63103 ở mức độ (level 5 so với critical): Task 12 ĐÃ nâng 63103 lên level 12 trong 0999-tuning.xml, nhóm shadow + legacy_WIN-002 (alert thật mới nên chạy bóng, R58) |
| WIN-003 | approx | 60109 | 1/1 ca dương có rule gốc cụ thể level>=7; ca âm báo level>=7: [60109]; không có rule dự án: 60109 level 8 đã đủ; Task 12 ĐÃ loại 4722 (bật lại tài khoản) bằng 0999-tuning.xml, nhóm legacy_WIN-003 |
| WIN-004 | approx | 60141, 60154, 60159, 60179 | 3/4 ca dương có rule gốc cụ thể level>=7; chỉ chứng minh: administrators, domain admins, remote desktop users; thiếu: enterprise admins; level<7 (ứng viên nâng level): ['60141 (level 5: Security Enabled Global Group Member Added $(win.eventdata.memberSid))']; rule dự án 105004 (0965-windows.xml, con của 60141 và 60144): nhánh Enterprise Admins theo SID -519 cho 4728 / 4732, chạy bóng; 4756 (universal) đã có rule gốc 60167 level 12; Task 12 quyết định KHÔNG nâng 60141 (level 5): đó là cha chung của mọi nhóm global; các nhóm quản trị đã có con level 10-12 (60154/60159/60167/60179) và 105004 |
| WIN-005 | convert | — | 0/1 ca dương có rule gốc cụ thể level>=7; không rule gốc nào báo; rule dự án 105005 (0965-windows.xml, con của 61603 Sysmon 1): powershell/pwsh -EncodedCommand mọi dạng viết tắt, trừ hai lớp vỏ Ansible/WinRM, chạy bóng; chỉ qua agent (eventchannel), JSON giả mạo qua syslog không lọt (R51) |
| WIN-006 | approx | 91837 | 0/1 ca dương có rule gốc cụ thể level>=7; level<7 (ứng viên nâng level): ['91837 (level 4: Powershell executed "Get-Content -Stream or Invoke-Expresion". Possible string execution as code)']; rule dự án 105006 (0965-windows.xml, con của 61603): nhánh dòng lệnh Sysmon 1 (downloadstring(, iwr | iex, invoke-webrequest | iex, -nop -w hidden) thiếu ở rule gốc, level 12, chạy bóng, loại -EncodedCommand (thuộc 105005); nhánh script block 4104: Task 12 ĐÃ đè 91837 thành level 12 với regex theo YAML cũ (regex gốc khớp IEX trần và gõ sai Invoke-Expresion), nhóm shadow + legacy_WIN-006 (R58) |
| WIN-007 | convert | — | 0/1 ca dương có rule gốc cụ thể level>=7; không rule gốc nào báo; rule dự án 105007 (dòng lệnh sekurlsa::, lsadump::, procdump lsass, comsvcs minidump), 105107 (mimikatz.exe), 105207 (Sysmon 10 mở LSASS 0x1010/0x1410/0x1fffff/0x143a) trong 0965-windows.xml, chạy bóng; rule gốc 92900 (level 12) đứng trước 105207 cho 0x1010 / 0x40 từ nguồn ngoài Program Files |
| WIN-008 | convert | — | 0/1 ca dương có rule gốc cụ thể level>=7; không rule gốc nào báo; rule dự án 105008 (0965-windows.xml, con của 61603): parentImage Office và image là shell / trình thông dịch, chạy bóng |
| WIN-009 | convert | — | chỉ trúng rule chung 61138 (New Windows Service Created), không chỉnh; 0/1 ca dương có rule gốc cụ thể level>=7; rule dự án 105009 (0965-windows.xml, con của 61138): ImagePath chứa thư mục ghi được, powershell, cmd /c hoặc %comspec%, chạy bóng; che 61138 cho service đáng ngờ; rule 105109 (con của 60103) cho nhánh Security 4697 (ServiceFileName đáng ngờ) |
| WIN-010 | convert | — | 0/1 ca dương có rule gốc cụ thể level>=7; không rule gốc nào báo; rule dự án 105010 (0965-windows.xml, con của 61603): vssadmin / wmic shadowcopy delete, bcdedit recoveryenabled no, wbadmin delete catalog, chạy bóng |
| WIN-011 | approx | 62123 | 1/2 ca dương có rule gốc cụ thể level>=7; chỉ chứng minh: 1116; thiếu: 1117; rule dự án 105011 (0965-windows.xml, con của 62124): nhánh 1117 level 10, chạy bóng; Defender thật ghi 1117 ở mức Information; ca legacy ghi mức Warning (Level 3) rơi vào 62101 và không nhận |
| WIN-012 | approx | 92018, 92075 | 2/6 ca dương có rule gốc cụ thể level>=7; chỉ chứng minh: certutil-urlcache, certutil-decode; thiếu: mshta, regsvr32, rundll32-javascript, bitsadmin; rule dự án 105012 (0965-windows.xml, con của 61603): bốn nhánh thiếu mshta, regsvr32 /i:http, rundll32 javascript:, bitsadmin /transfer, chạy bóng; certutil dùng rule gốc 92018 / 92075 |
| WIN-013 | convert | — | 0/1 ca dương có rule gốc cụ thể level>=7; không rule gốc nào báo; rule dự án 105013 (schtasks /create chạy trình thông dịch, LOLBin, file script hoặc thư mục ghi được; con của 61603) và 105113 (Security 4698 mọi tác vụ, con của 60228 level 4), 0965-windows.xml, chạy bóng; giữ giới hạn của YAML cũ: tác vụ chạy .bat / .exe trong thư mục thường không báo |

Lưu ý khi đọc bảng:

- Request web trả 200 chỉ ra 31106 (rule con chung, level 6); mỗi ca dương web có thêm bản status 404 của cùng request để thấy rule tấn công cụ thể
  (31103 SQL injection level 7, 31104 / 31105 level 6). Cột "Rule gốc" ghi cả hai. Wazuh giữ nguyên chuỗi URL (không giải mã), chi tiết ở spike S5.
- Ngưỡng của rule gốc khác rule cũ (vd. 87702 là 18 lần chặn trong 45 giây từ một nguồn, mọi cổng: không phân biệt quét cổng của NET-001 với NET-002;
  31151 là 14 lỗi 4xx trong 90 giây nên báo cả ca 29 lần 404 của WEB-006).
- Rule gốc 60109 báo cả tạo (4720) lẫn bật lại (4722) tài khoản nên WIN-003 báo nhầm ca âm.
- TI-001 phụ thuộc làm giàu MISP (trường `threat.matched` do pipeline gắn, log gốc không có), ca registry của FIM-001 không bơm được qua syscheck: cả hai không bịa log.
- Ca Linux dựng thêm bản auditd (trừ ca cần tên tiến trình cha); `siem-proc:` là định dạng riêng của dự án nên ruleset gốc không có decoder.

### 4.6 Đo trên Wazuh sau P4 (07–08/11/2026)

**Khoảng trống trên Wazuh** (job nền của cổng AI, Task 21, 07/11/2026): bơm log thô của toàn bộ dataset vào `wazuh-sandbox` với
ruleset của nhánh P4 (ruleset gốc + rule dự án, chưa có SigmaHQ), không bỏ event nào. "Bắt" = có alert level ≥ 7 của rule không
thuộc nhóm khớp chung chung (`GENERIC`, R79).

| Nhóm mẫu tấn công (có log thô) | Mẫu | Wazuh bắt | Khoảng trống |
|---|---|---|---|
| Web CSIC 2010 | 15.088 | 1.484 | 13.604 |
| Windows, dựng lại từ Atomic Red Team | 2.218 | 74 | 2.144 |
| Linux, dựng lại từ Atomic Red Team (dòng `siem-proc`) | 1.146 | 12 | 1.134 |

- Tổng: 16.882/19.315 mẫu tấn công là khoảng trống. 863 mẫu Splunk không có log thô nên không tính (không đo được trên Wazuh).
- 4 mẫu bình thường có alert phát hiện ở job nền.

**SigmaHQ lô 1** (đo lại ở review cuối P4, 08/11/2026, lượt có và không có `0966`): trên 17.306 mẫu tấn công Windows + web,
1.558 mẫu có phát hiện khi không có lô; 30 rule SigmaHQ bắt thêm **186 mẫu mới** (cây Python ước 186), 0 mẫu bị lô cướp phát
hiện, không event nào bị bỏ. Lô toàn Windows nên không thêm mẫu CSIC nào. Số 188 của Task 24 tính "mẫu có alert 108xxx trừ mẫu có
phát hiện khác" trên cùng ruleset có lô, nên đếm cả 2 mẫu bị lô cướp thành mẫu mới.

Lưu ý khi so với số cũ: `tools/wazuh_coverage.run_wazuh`, `wazuh_noise.py` và `wazuh_rule_test.inject` vẫn dùng vòng gửi cũ, vòng
này đo được mất âm thầm 15% event ở 50.000 event (R80). Số đo cũ trên tập lớn bằng các công cụ đó có thể thấp hơn thật. Sandbox
của AI gửi có chờ hàng đợi nên không mất event.

## 5. Điểm mạnh

- **Một bộ rule, một nơi chạy.** Ruleset gốc và rule dự án cùng chạy trong `wazuh-analysisd`, mỗi event ra một alert; không còn
  cặp alert YAML / Wazuh cho cùng một sự việc.
- **Kiểm thử trên chính Wazuh.** Ca test là log gốc, chạy qua wazuh-manager thật trong CI (cả eventchannel / syscheck bằng bơm hàng
  đợi); CI quét `ossec.log` vì Wazuh bỏ rule hỏng chỉ bằng một dòng log.
- **Không cướp alert thật một cách âm thầm.** `wazuh_stock_reach.py` đòi ca ghim hoặc bảo đảm cấu trúc cho mọi alert thật của rule
  gốc dưới rule cha bị móc; cổng AI đo "che rule khác" trên alert Wazuh (R79).
- **Rule mới có đường vào có kiểm soát.** Rule AI và SigmaHQ dùng chung bộ dịch, chạy bóng trước, bật chính thức theo tiêu chí đo
  được; rule AI được kiểm trên sandbox Wazuh thật trước khi tới người duyệt.
- **Chống giả mạo nguồn.** Rule web chỉ nhận location của agent, rule Windows là con của chuỗi eventchannel, rule auditd ràng buộc
  location (S7, F8).
- **Độ ồn đo được.** Windows 0,596 alert / 100 event bình thường sau tuning (cổng ≤ 1), web 0 / 36.000 (mục 9.8, `Test.md` mục 0).
- **Phản ứng có người xử lý.** Mỗi alert từ medium mở case kèm case playbook theo mã; hành động phá hủy chỉ theo id đã duyệt (R60).

## 6. Điểm yếu

- **Độ phủ trên dataset vẫn thấp** (mục 4.6): Wazuh bắt 1.484/15.088 mẫu web, 74/2.218 mẫu Windows, 12/1.146 mẫu Linux dựng lại.
  SigmaHQ lô 1 chỉ thêm 186 mẫu.
- **Rule Windows sinh tự động có giới hạn:** chưa khớp được giá trị có `>`, `<`, `&` (R77); regex Windows có `\` trần bị từ chối.
  Rule dự án `0965-windows.xml` dưới 61603 có thể bị rule gom level 0 (92025...) che như ứng viên AI từng bị (R75): **chưa kiểm**.
- **Rule anh em và cây con:** rule thắng ở tầng cha cắt cả cây con của anh em (mục 9.6); ca ghim chỉ chứng minh đường tới được, không
  chứng minh mọi event.
- **Giới hạn của Wazuh:** không giải mã URL (S5), `different_*` đếm theo event trước chứ không theo giá trị phân biệt (S4), danh sách
  CDB khớp chính xác (không CIDR, không subdomain), tối đa hai `<list>` mỗi rule (mục 9.7).
- **Log không có dạng thô thì không đo được:** 863 mẫu Splunk và EVTX không có log thô nên không tính vào khoảng trống (R79).
- **Chưa đo trên log thật đủ dài:** độ ồn chưa có ≥ 24 giờ syslog và nhật ký console thật (mục 9.7).
- **Chưa có rule AI hay rule SigmaHQ nào chạy chính thức.**
- **Gỡ rule AI cuối cùng / ngoại lệ cuối cùng:** đã sửa ở Task 26b (mục 9.10).

## 7. Kế hoạch bổ sung độ phủ (16/10/2026)

> **Trạng thái 08/11/2026.** Việc 2.4 xong lô 1 dưới dạng Wazuh XML: `0966-sigmahq.xml`, 30 rule Windows chạy bóng (mục 2.10).
> Việc 1.1 xong theo đường khác: FIM-001 là rule XML 106001–106003, chạy thật từ R65. Đường dẫn `server/rules/...`,
> `python -m siem.ai.benchmark` và `tools/rule_lint.py` trong các bảng dưới thuộc engine YAML đã xóa ở Task 25: rule mới viết
> thành XML (mục 9.5) hoặc nhập bằng `tools/sigmahq_import.py`, đo bằng `tools/wazuh_coverage.py` và `sigmahq_import.py --measure`.

Cách rẻ nhất để tăng độ phủ là **dùng lại rule có sẵn** (SigmaHQ, ruleset Wazuh) trước khi viết mới bằng tay hay bằng AI. Bộ
biên dịch Sigma đã có (`server/siem/ai/sigma.py`), và 341 rule SigmaHQ `process_creation` vừa khớp ít nhất một mẫu tấn công vừa
không khớp mẫu bình thường nào (đo 8/10, `AI-README.md` mục 11). Chỉ viết tay cho chỗ SigmaHQ không có; phần AI theo kế hoạch ở
`AI-README.md` mục 15.

**Hiện trạng và đích**

| Thước đo | 16/10/2026 | Đích |
|---|---|---|
| Kỹ thuật ưu tiên (`config/threat_profile.yml`) có rule chạy chính thức | 10/12: thiếu T1547 (FIM-001 đang chạy bóng) và T1486 (chưa có rule) | 12/12 trước 05/11 (`ROADMAP.md`) |
| Windows, dataset (mục 4.2) | 6,5% mẫu, 39/134 kỹ thuật | ≥ 20% |
| Linux, dataset | 0,8% mẫu, 7/78 kỹ thuật; log ghi thật 0/22 | ≥ 10% |
| Web, CSIC 2010 | 11,0%; 4/7 loại tấn công dùng chung chưa có rule | ≥ 15%; 7/7 loại có rule |
| Loại log có rule | dòng lệnh, URL, xác thực, firewall / IDS, FIM | thêm file, registry, kết nối mạng của tiến trình, DNS, PowerShell script block |

Đích dataset là đích tạm, chốt lại sau khi đo việc 2.1. Đã xong từ danh sách cũ: điểm rủi ro theo thực thể (RBA-001, 13/10), kiểm
ReDoS cho mọi rule khi nạp (13/10), rule FIM-001 cho registry / file dùng để duy trì truy cập (14/10; chỉ thật sự chạy bóng khi stack chạy code mới, `ROADMAP.md` tuần 1).

**Đợt 1 — trước demo (16/10–02/11).** Chỉ việc nhỏ, vì code đóng băng ngày 07/11.

| # | Việc | Làm ở đâu | Xong khi |
|---|---|---|---|
| 1.1 | Bật FIM-001 chính thức sau 7 ngày chạy bóng không báo nhầm trên stack chạy code mới | `server/rules/fim.yml` (`mode: active`) | khoảng 29/10; T1547 được tính vào KPI |
| 1.2 | Rule T1486: chữ ký dòng lệnh mã hóa hàng loạt (gpg, openssl, 7z có mật khẩu, `cipher /e` như các bài thử Atomic) và rule ngưỡng "một tiến trình tạo ≥ 100 file cùng một đuôi lạ trong 60 giây" (Sysmon 11) | `windows.yml`, `linux.yml`, `rules/cases` | chạy bóng 23/10, chính thức 30/10 sau khi đo báo nhầm trên log lab (1.4) |
| 1.3 | Chuyển cảnh báo web của Wazuh từ level 6 (nhóm `web`, `attack`) thành alert `low`: chỉ cộng điểm RBA, không mở case | `detection/wazuh.py` (ngưỡng level theo nhóm), test | 124 mẫu SQLi chỉ Wazuh bắt được thành tín hiệu |
| 1.4 | Thu log hoạt động bình thường của lab (PC-01, Ubuntu-01, Web-01) liên tục ≥ 7 ngày | lab tuần 2–4 | có tập bình thường thật cho đợt 2 |

**Đợt 2 — dùng lại rule có sẵn.** Trước 16/11 chỉ làm 2.1, 2.2 và lô đầu (≤ 30 rule) của 2.4 (`ROADMAP.md` tuần 3); phần còn lại
17/11–30/11.

| # | Việc | Làm ở đâu | Xong khi |
|---|---|---|---|
| 2.1 | Đo trước khi nhập: chạy mọi rule SigmaHQ `process_creation`, `webserver` biên dịch được trên dataset, tính độ phủ nếu nhập | `python -m siem.ai.benchmark` thêm tùy chọn chạy bộ rule SigmaHQ | có số để chốt đích ở bảng trên |
| 2.2 | Bộ biên dịch Sigma hiểu thêm 6 loại log mà parser đã chuẩn hóa: `file_event` (Sysmon 11), `registry_*` (12–14), `network_connection` (3), `dns_query` (22), `process_access` (10), `ps_script` (PowerShell 4104) | bảng trường trong `ai/sigma.py`, test | các loại log này có rule; mở thêm phần lớn rule SigmaHQ cho Windows |
| 2.3 | Chuyển dataset giữ lại các event trên (hiện chỉ giữ event tạo tiến trình) | `ai/endpoint_logs.py`, `tools/convert_datasets.py` | đo được rule của 2.2 |
| 2.4 | Công cụ nhập SigmaHQ: chọn rule biên dịch được, `status` stable / test, `level` ≥ medium, khớp ≥ 1 mẫu tấn công, 0 mẫu bình thường (kể cả log lab 1.4), kỹ thuật có case playbook. Ghi `rules/sigmahq/*.yml` ở chế độ chạy bóng, giữ `id`, tác giả và giấy phép DRL 1.1; sinh ca test dương (mẫu khớp) và âm (mẫu bình thường gần nhất). Nhập theo lô 20–30 rule | `tools/sigmahq_import.py` (mới), lint | ≥ 100 rule chạy bóng, lint đạt |
| 2.5 | Bật chính thức từng rule đạt tiêu chí chạy bóng (mục 2.12) | Thư viện rule | theo từng rule |
| 2.6 | Linux: tìm vì sao log ghi thật đạt 0/22 (parser thiếu trường hay thiếu rule); bật auditd `execve` trên Ubuntu-01, Web-01 bên cạnh `siem-procs`; nhập SigmaHQ Linux (biên dịch được 97%) | `endpoint_logs.py`, `DEPLOY-VM.md` mục 3 | Linux ≥ 10% |

**Đợt 3 — viết mới cho chỗ còn trống (12/2026).**

| # | Việc | Làm ở đâu | Xong khi |
|---|---|---|---|
| 3.1 | 4 loại tấn công web đang 0%: dò file sao lưu (`.bak`, `.old`, `~`, `.swp`), tài nguyên nhạy cảm (`/.git/`, `/.env`, `web.config`, `phpinfo`), CRLF (`%0d%0a` trong URL), mã hóa né tránh (mã hóa hai lần `%25..`, UTF-8 dài `%c0%af`) | `web.yml` hoặc luồng AI web | 7/7 loại có rule, 0 báo nhầm trên 36.000 request |
| 3.2 | Collection, Exfiltration: nén hàng loạt có mật khẩu, `rclone`, `curl -T`; lượng dữ liệu ra ngoài lớn bất thường (log firewall) | rule viết tay + SigmaHQ | 2 chiến thuật có rule |
| 3.3 | 3 case playbook cho nhóm đang rơi về PB-00 (mục 4.4): né tránh phòng thủ, khám phá, thu thập / đánh cắp dữ liệu | `config/case_playbooks.yml` | rule SigmaHQ của các nhóm này nhập được ở 2.4 |
| 3.4 | Đo rule ngưỡng / chuỗi bằng phát lại log theo thời gian | `siem.ai.benchmark` | 22/40 rule chưa đo có số |
| 3.5 | Mở rộng hồ sơ mối đe dọa từ 12 lên khoảng 20 kỹ thuật theo bản tin CTI | `config/threat_profile.yml` | KPI độ phủ tính trên hồ sơ mới |

Mỗi đợt đo lại bằng `python -m siem.ai.benchmark` và `python tools/rule_lint.py`, ghi kết quả vào mục 4. Rủi ro:
- **Ngập alert khi nhập hàng trăm rule:** chạy bóng, nhập theo lô, trần alert / ngày (mục 2.12); trước 16/11 chỉ nhập lô đầu.
- **Độ phủ ảo:** nhiều rule SigmaHQ viết dựa trên chính bài thử Atomic, nên tỉ lệ trên phần dựng lại từ Atomic cao hơn thực tế.
  Báo cáo riêng kết quả trên log ghi thật (Splunk, OTRF) và trên lab.
- **Lint đòi case playbook cho mọi rule:** làm 3.3 sớm nếu 2.4 bị chặn nhiều vì kỹ thuật chưa có playbook.

## 8. Đo lại

```bash
cd server && .venv/Scripts/python -m pytest -q          # unit test: cầu nối Wazuh, bộ dịch XML, cổng AI (sandbox giả), SOAR...
cd .. && python tools/wazuh_rule_lint.py                  # lint rule XML; --layer build/attack-layer.json ra layer ATT&CK
# ca test log gốc và rule gốc còn tới được: cần một wazuh-manager thử (project Compose riêng, mục 9.5; CI làm sẵn)
python tools/wazuh_rule_test.py --url https://localhost:<cổng> --insecure wazuh/manager/tests/cases
python tools/wazuh_stock_reach.py <thư mục ruleset/rules chép từ manager>
python tools/wazuh_noise.py --data datasets/processed     # độ ồn trên tập bình thường (manager tạm, cần Docker)
python tools/wazuh_coverage.py                            # độ phủ trên dataset (manager tạm, cần Docker)
python tools/sigmahq_import.py --measure                  # mẫu mới chỉ SigmaHQ (108xxx) bắt; mã 1 nếu lô cướp phát hiện
python tools/wazuh_stock_reach.py <...> --min-level 7     # như trên, alert thật theo R65 (level >= 7); CI giữ mặc định 12
python tools/e2e_test.py                                  # tấn công thật trên stack đang chạy
```

Dataset công khai cần tải và chuyển đổi trước (`tools/fetch_datasets.py`, `tools/convert_datasets.py`, xem `AI-README.md`
mục 12). Khoảng trống của AI được tính lại mỗi chu kỳ AI trên `wazuh-sandbox` (`AI-README.md` mục 9.11).

## 9. Bộ rule Wazuh XML thống nhất (đã chuyển sang Wazuh, R65)

Nhánh `feature/wazuh-unified-ruleset` chuyển phát hiện từ engine YAML (đã xóa ở Task 25) sang một bộ rule duy nhất chạy trong
`wazuh-analysisd`: ruleset gốc Wazuh 4.14.8 cộng rule XML riêng của dự án. Kế hoạch: [docs/superpowers/plans/2026-10-31-wazuh-unified-ruleset.md](docs/superpowers/plans/2026-10-31-wazuh-unified-ruleset.md).
Sổ quyết định (R1–R83, phát hiện chính): [docs/wazuh-ruleset-decisions.md](docs/wazuh-ruleset-decisions.md).

### 9.1 Trạng thái (06/11/2026)

- Task 0 đến 18 của kế hoạch đã xong. **Đã triển khai lên stack thật 05–06/11/2026** (main `597cd5d` = PR #13, sửa nóng #14 thư viện rule gọi đúng `WazuhApi`, #15 đọc `mitre` dạng list của API và gộp rule gốc bị đè). E2E trên stack thật **45/45** (06/11): đăng nhập 13/13, SQLi → chặn IP 6/6, command injection → kill 3/3, webshell → FIM → case 3/3, Grafana 16/16 (thư viện 4600/4600 rule Wazuh), hồi quy 4/4.
  CI (5 job) xanh ở `397a774`: 663 unit test trên Linux, 597 ca log gốc qua wazuh-manager thật 0 sai, `ossec.log` không lỗi nạp rule,
  93 alert thật của rule gốc dưới cha bị móc đều có ca ghim hoặc bảo đảm cấu trúc, lint 10 file 0 lỗi (1 cảnh báo: `lsass.exe` chép nguyên từ rule gốc).
- **Đã chuyển (R65, 05/11/2026): chủ dự án quyết định chuyển hẳn.** Engine YAML tắt (`RULE_ENGINE_ENABLED=false`, mặc định); mọi rule XML
  riêng bỏ nhóm `shadow` và là alert thật (trừ `0845-ti.xml`, bỏ chạy bóng cùng đợt khi phần TI domain/hash được gộp); rule gốc Wazuh level 7 đến 11
  ngoài nhóm cũ cũng là alert thật (`WAZUH_STOCK_SHADOW=false`, mặc định). Chạy bóng vẫn dùng được cho rule mới sau này (SOC-OPERATIONS mục 4).
  Lint không còn bắt buộc rule mới phải chạy bóng, chỉ đòi `shadow_since` khi có nhóm `shadow`.
- **Hai quyết định của chủ dự án, kèm rủi ro đã biết:** (1) **bỏ tiêu chí 7 ngày chạy bóng** của SOC-OPERATIONS mục 4 cho đợt chuyển này; rule chưa được đo trên ≥ 24 giờ syslog + nhật ký console thật,
  nên số báo nhầm thật chưa biết, theo dõi tỉ lệ báo nhầm và alert/ngày trong tuần đầu rồi hạ level hoặc thêm ngoại lệ ở `0999-tuning.xml`. (2) **rule gốc level 7 đến 11 là alert thật**: có thể thêm vài chục alert medium / high mỗi ngày
  (dư địa đo ở Task 2 là ≤ 1 alert / 100 event bình thường), mỗi alert mở case; playbook phá hủy vẫn chỉ theo id đã duyệt (R60) nên rủi ro là ngập case, không phải chặn nhầm. Quay lui nhanh: `WAZUH_STOCK_SHADOW=true`.
- Playbook SOAR theo mã YAML (AUTH-/WEB-/LNX-/WIN-/TI-001) đã xóa; chỉ còn playbook theo `WZH-<id>` (bản XML tương ứng), RBA / HLT / retrohunt giữ qua playbook chung. Đề xuất AI và ngoại lệ YAML bị chặn khi engine tắt (409) tới Task 19 đến 22 (đã gỡ ở P4).
  Độ phủ ATT&CK chỉ tính từ rule Wazuh.
- Việc kiểm trên stack thật: thư viện rule và số kỳ vọng E2E (Task 14) **đã đạt** trên stack thật 06/11/2026 (4600/4600). Báo cáo song song `build/parity.md` (Task 13)
  **không còn làm được** (engine YAML tắt ở R65, xóa ở Task 25). Còn hoãn: thử ngoại lệ Wazuh trên manager thật (Task 16) và đo lại độ ồn trên ≥ 24 giờ syslog + nhật ký console thật (số đo hiện tại chưa có hai nguồn này).
- Danh sách việc triển khai: mục *Task 18* của kế hoạch.
- **P4 (06–08/11/2026, kế hoạch [2026-11-06-p4-ai-wazuh-xml.md](docs/superpowers/plans/2026-11-06-p4-ai-wazuh-xml.md)):** rule AI ra
  `rules-dynamic/ai.xml`, kiểm định trên `wazuh-sandbox`; ngoại lệ AI qua luồng ngoại lệ Wazuh; SigmaHQ lô 1 là `0966-sigmahq.xml`;
  engine YAML, `server/rules/` và `RULE_ENGINE_ENABLED` đã xóa ở Task 25. Mô tả ở mục 2, quyết định R66–R83.

### 9.2 Các file rule

Wazuh nạp rule theo thứ tự **tên file**, và rule con bị bỏ nếu `if_sid` trỏ tới rule chưa nạp, nên tên file (số đầu) quyết định
được móc vào đâu. Vì vậy tên không theo bảng số 0100 đến 0108 ban đầu của kế hoạch. Dải id của từng file nằm ở `ID_RANGES` trong
`server/siem/wazuh_rules.py`; lint đọc bảng này.

| File | Dải id | Số rule | Phủ |
|---|---|---|---|
| `0100-platform.xml` | 100000–100999 | 2 | WEB-010 / WEB-011: file mới / file bị sửa trong thư mục web (con của 554 / 550), chạy thật từ trước |
| `0101-auth.xml` | 101000–101999 | 10 | AUTH-001..004, AUTH-006 trên sshd và console. 101000 là bộ đếm chung (level 2); 101020..101022 nhận nhật ký đăng nhập console (JSON) |
| `0102-linux.xml` (+ decoder `decoders/0102-siem-procs.xml`) | 102000–102499 | 9 | LNX-001..006 trên dòng `siem-proc:` do script `siem-procs` của agent gửi |
| `0851-linux-audit.xml` | 102500–102999 | 8 | LNX-001, 003..006 trên bản ghi auditd EXECVE (payload hex). Phải nạp sau 0850 nên tách khỏi 0102 |
| `0541-network.xml` | 103000–103999 | 6 | NET-001, 003, 004, 005 trên filterlog (pf) và Suricata `eve.json`. 103000 là bộ đếm filterlog không phải block |
| `0271-web.xml` | 104000–104999 | 18 | WEB-001..009 trên access log Apache; 104095 là cổng IOC (9.3). Phải nạp sau 0245 (rule web gốc) |
| `0965-windows.xml` | 105000–105999 | 16 | WIN-001, 002, 004..013 trên eventchannel (Sysmon, Security, System). Con của chuỗi rule gốc 60000 / 61600 / 92000 |
| `0106-fim.xml` | 106000–106999 | 3 | FIM-001 (Linux, thư mục Startup Windows, khóa Run của registry), con của 550 / 554 / 750 / 752 |
| `0845-ti.xml` | 107000–107999 | 16 | TI-001: IP (firewall, Suricata, sshd, web, đăng nhập Windows) và domain + hash (R64: Suricata DNS / HTTP, Sysmon 22, FIM) (9.9). Phải nạp sau 0840, 0541 và 0475 |
| `0966-sigmahq.xml` | 108000–108999 | 30 | SigmaHQ lô 1, Windows, chạy bóng (mục 2.10). Phải nạp sau 0595 và 0800 (R76) |
| `0999-tuning.xml` | không có dải | 9 | Chỉ `overwrite="yes"` trên rule gốc (id < 100000), xem 9.8. Nạp cuối cùng |

SigmaHQ nằm ở `0966-sigmahq.xml` chứ không phải `0108-sigmahq.xml` như kế hoạch ban đầu: cha 61603 và các cha gom nhóm nằm ở file
gốc `0595` và `0800`, file `0108` nạp trước nên mọi rule bị bỏ (R76). `rules-dynamic/ai.xml` (109000–109999) do console ghi khi
duyệt đề xuất AI (mục 2.9), `rules-dynamic/exceptions.xml` (110000–110999) cho ngoại lệ. Hai file trong `rules-dynamic/` nằm trong
volume riêng `wazuh_dynamic_rules`, console ghi qua `write_dynamic`, không nằm trong repo.

### 9.3 Quy ước viết rule

Lint (`tools/wazuh_rule_lint.py`, chạy trong CI) bắt buộc:

- `<description>` bắt đầu bằng mã rule (`WEB-001`, `LNX-005`...); có `<mitre><id>` (trừ file tuning); nhóm chứa `siem`.
- Nhóm theo dạng `siem,<lĩnh vực>,shadow,legacy_<MÃ>,` (vd `siem,web,shadow,legacy_WEB-001,`). Nhóm `legacy_<MÃ>` nối rule XML với
  mã YAML cũ: alert mang `rule.legacy_id`, SOAR chọn case playbook theo đó, báo cáo song song ghép theo đó.
- Rule bóng có thêm `<info type="text">shadow_since=YYYY-MM-DD</info>` (08/11/2026: 30 rule, đều ở `0966-sigmahq.xml`; 78 rule bóng cũ của dự án đã bỏ nhóm ở R65). Bật chính thức = bỏ nhóm `shadow` rồi reload.
- Regex dùng `type="pcre2"` cho `<regex>` và `<field>` (mặc định của chúng là OS_Regex). Không lồng lượng từ kiểu `(a+)+`.
- Mức độ: critical → level 12, high → 10, medium → 7. Alert chỉ sinh từ level ≥ 7; level thấp hơn là bộ đếm hoặc rule cha.
- Id nằm trong dải của file; id không trùng giữa các file; mỗi rule riêng có ≥ 1 ca dương và ≥ 1 ca âm (rule cha level 0 trong cùng file
  không đòi ca dương); rule level 0 phải có điều kiện trường ngoài `if_sid`.
- **Không dùng thuộc tính `ignore`** (ràng buộc toàn cục 7). Dập trùng làm ở cầu nối: cùng `(rule.id, nguồn, agent, file.path)` trong
  `WAZUH_ALERT_SUPPRESS` giây (60) thì chỉ ra 1 alert, và alert bóng không bị dập để báo cáo song song đếm đủ.
- `overwrite="yes"` chỉ ở `0999-tuning.xml`; file đó chỉ chứa rule id < 100000 có `overwrite`.
- Cảnh báo (không chặn): `<field>` chỉ là một từ trần không neo `^…$`; `frequency` dựa trên `if_matched_group` (chưa chứng minh được là chạy, 9.6).

Hai dấu đánh dấu trong `<info type="text">`:

- `port_of_stock=<id>`: rule không bóng, là bản sao hành vi rule gốc đang chạy thật. Hiện có một: **104095** (level 14, nhóm `siem,web,accesslog,attack`)
  chép 99906 "tấn công web từ IP trong danh sách IOC trả mã 200" sang nhánh rule web của dự án. Lý do: rule WEB (level 10 đến 12) thắng
  mọi rule tấn công web gốc (level ≤ 7) nên nếu không có bản sao thì 99906 (alert thật level 14 hôm nay) sẽ biến mất. 104095 mở rộng hơn 99906:
  bắt cả dòng chỉ rule WEB nhận ra (RCE) và gồm các tấn công web chỉ rule dự án thấy.
- `real_before=yes`: rule gốc bị `overwrite` đã là alert thật trước khi sửa (61627, 61640), nên lint cho phép level ≥ 12 mà không cần `shadow`.

Trong file tuning, rule đè lên level mới ≥ 12 từng phải mang nhóm `shadow` hoặc có `real_before=yes` (R58, tới cổng chuyển). Từ R65 lint không còn đòi: 63103 và 91837 đã bỏ `shadow`; `real_before=yes` giữ như ghi chú cho 61627 / 61640.
Thay đổi `overwrite` có hiệu lực ngay khi triển khai.

### 9.4 Bảng mã cũ → rule XML

Nguồn: `wazuh/manager/tests/legacy_map.yml` (quyết định của Task 5, cột *Quyết định*) và nhóm `legacy_*` trong các file XML (cột *Rule XML*).
`builtin` là rule gốc báo đủ mọi nhánh; `approx` có rule gốc gần đúng, phần thiếu được viết thêm hoặc chỉnh ở file tuning; `convert` viết mới.
Cả 41 mã đều có dòng. Dòng "tuning" nghĩa là chỉnh rule gốc, "rule gốc" nghĩa là dùng rule gốc không đổi.

| Mã cũ | Quyết định | Rule XML (id) | Ghi chú |
|---|---|---|---|
| AUTH-001 | convert | 101000 (bộ đếm), 101001 | đếm chung sshd + console |
| AUTH-002 | convert | 101010, 101002 | 101002 cũng nhận "thất bại ở một dịch vụ, thành công ở dịch vụ kia" |
| AUTH-003 | convert | 101003 | `different_srcuser` |
| AUTH-004 | convert | 101004 | |
| AUTH-005 | builtin | rule gốc 5902 | |
| AUTH-006 | convert | 101006 | |
| FIM-001 | approx | 106001, 106002, 106003 | |
| LNX-001 | convert | 102001, 102501, 102511 | auditd: chỉ nhánh payload hex |
| LNX-002 | convert | 102002 | chỉ có trên `siem-procs` (auditd không có tên tiến trình cha) |
| LNX-003 | convert | 102003, 102503 | `curl \| sh` không phủ được trên auditd |
| LNX-004 | convert | 102004, 102014, 102504 | |
| LNX-005 | convert | 102090 + 102005; 102590 + 102505 | bộ đếm + rule báo, bản siem-proc và bản auditd |
| LNX-006 | convert | 102006, 102506, 102516 | |
| NET-001 | approx | 103000 (bộ đếm), 103001, 103002 | `different_dstport`; 103002 là mức cao hơn |
| NET-002 | approx | tuning 87702 | |
| NET-003 | convert | 103003 | |
| NET-004 | convert | 103004 | chỉ qua agent OPNsense đọc `eve.json` (9.6) |
| NET-005 | convert | 103005 | `different_dstip` |
| TI-001 | convert | 107001..107016 | IP (107001..107010) + domain / hash (107011..107016, R64), còn giới hạn (9.9) |
| WEB-001 | approx | 104001, 104011..104014 | rule gốc 31103 / 31106 chỉ phủ một phần nhánh |
| WEB-002 | approx | 104002, 104021 | |
| WEB-003 | approx | 104003, 104031 | |
| WEB-004 | convert | 104004, 104041 | |
| WEB-005 | convert | 104005 | |
| WEB-006 | approx | tuning 31151 | |
| WEB-007 | approx | 104070 (bộ đếm), 104007 | |
| WEB-008 | convert | 104008 | |
| WEB-009 | convert | 104090 (bộ đếm), 104009 | |
| WEB-010 / WEB-011 | (không có trong `legacy_map`) | 100100 / 100101 | đang chạy thật từ trước nhánh |
| WIN-001 | convert | 105001 | |
| WIN-002 | approx | tuning 63103 + 105002 | 105002 là nhánh System/104 |
| WIN-003 | approx | tuning 60109 | |
| WIN-004 | approx | 105004 | cộng rule gốc 60141, 60154, 60159, 60179 |
| WIN-005 | convert | 105005 | |
| WIN-006 | approx | tuning 91837 + 105006 | 105006 là nhánh dòng lệnh |
| WIN-007 | convert | 105007, 105107, 105207 | |
| WIN-008 | convert | 105008 | |
| WIN-009 | convert | 105009, 105109 | 105109 là Security 4697 |
| WIN-010 | convert | 105010 | |
| WIN-011 | approx | 105011 | |
| WIN-012 | approx | 105012 | |
| WIN-013 | convert | 105013, 105113 | 105113 là Security 4698 |

Phần chưa chuyển được và đã ghi để người dùng quyết trước Task 18: TI-001 domain và hash đã chuyển ở R64, còn giới hạn ghi ở 9.9.

### 9.5 Viết và kiểm thử một rule XML

Mỗi file rule có một file ca test cùng tên trong `wazuh/manager/tests/cases/` (ví dụ `0271-web.yml` cho `0271-web.xml`). Ca test là
**log gốc**, không phải event đã chuẩn hóa:

```yaml
- rule: 104001            # id phải báo; hoặc `none: [104001]` cho ca ÂM
  legacy: WEB-001         # (tùy chọn) mã rule cũ
  log_format: apache      # syslog | json | apache | eventchannel | syscheck
  location: '(demo-web) any->/usr/local/apache2/logs/access_log'
  events:                 # nhiều dòng = cùng một session logtest (rule đếm ngưỡng)
    - '203.0.113.5 - - [31/Oct/2026:10:00:00 +0700] "GET /p.php?id=1%27%20union%20select%201 HTTP/1.1" 200 12 "-" "curl/8"'
```

Các khóa tùy chọn: `last: true` (chỉ tính rule của dòng cuối: ca "nguồn thứ hai vẫn báo"), `delay: <giây>` (nghỉ sau mỗi dòng để thử
`timeframe` thật), một dòng có thể là map `{event, location, log_format}` để đổi nguồn riêng dòng đó, `sha256` (dòng syscheck, để thử
rule IOC hash), `list_file: {name, content}` (không phải ca: đẩy một danh sách CDB lên manager thử trước khi chạy). Một ca dương cần ca âm đi kèm
(cùng dạng nhưng hợp lệ). Rule web phải có ca dạng thô và dạng mã hóa (`%27`, `%2527`, `+`, `%u0027`, `%55NION`). Rule đếm ngưỡng phải có ca N−1 dòng (không báo)
và ca `different_*` "hai giá trị xen kẽ" (không báo).

`tools/wazuh_rule_test.py` có hai chế độ:

| Chế độ | Định dạng | Cách chạy |
|---|---|---|
| logtest | syslog, json, apache | `PUT /logtest` của manager, giữ token qua các dòng của ca, xóa session sau mỗi ca, gặp HTTP 429 thì chờ rồi thử lại. Kết quả là mọi rule đã báo, kể cả rule trung gian |
| inject (bơm hàng đợi) | eventchannel, syscheck | logtest không giải mã được hai loại này, nên bộ chạy dựng một wazuh-manager tạm không nối mạng và bơm thẳng vào hàng đợi analysisd. Bơm **không giữ thứ tự dòng**, nên ca nhiều dòng loại này chỉ khẳng định "báo ít nhất một lần". Chỉ thấy rule có trong `alerts.json` (level ≥ 3 theo `log_alert_level`) |

Chạy với một manager thử đã dựng (CI dựng đúng như compose, mount `wazuh/manager/rules` chỉ đọc, API riêng nâng `max_request_per_minute`):

```bash
python tools/wazuh_rule_lint.py                                   # 0 lỗi; --layer build/attack-layer.json ra layer ATT&CK Navigator
python tools/wazuh_rule_test.py --url https://localhost:55000 --insecure wazuh/manager/tests/cases/0271-web.yml   # một file
python tools/wazuh_rule_test.py --url https://localhost:55000 --insecure                                          # cả thư mục
```

Quy trình đưa một rule vào: viết ca dương và ca âm, chạy thấy hỏng; viết rule; chạy lại **cả thư mục ca** (rule mới có thể chiếm sự kiện của rule khác,
nhiều lỗi chỉ lộ ở file khác); lint; đo độ ồn. Test trên máy dev phải dùng project Compose riêng vì `docker-compose.yml` có `name: siem-xdr`.

Các công cụ đo đi kèm:

| Công cụ | Việc |
|---|---|
| `tools/wazuh_noise.py` | Dựng wazuh-manager tạm, bơm tập bình thường (web CSIC 2010 36.000 dòng, lệnh Windows / Linux nền), đếm alert level ≥ 7 theo rule. Cổng: ≤ 1 alert / 100 event. `--rules <file>` chỉ báo cáo rule của một file. Dùng location agent (`[001] (demo-web) any->…`) như thật |
| `tools/wazuh_coverage.py` | Độ phủ trên dataset công khai và các hàm bơm event (dùng chung với noise và harness) |
| `tools/parity_report.py` | Đối chiếu alert YAML với alert XML (`rule.legacy_id`) theo event kích hoạt; ghi `build/parity.md`. Hết dùng từ Task 25 (không còn alert YAML) |
| `tools/misp_to_cdb.py` | In danh sách CDB (IOC IP) từ kết quả MISP `restSearch` để xem trước; logic ở `server/siem/pipeline/misp_cdb.py`, SOAR dùng chính hàm này |

CI: job `wazuh-rules` (`.github/workflows/ci.yml`) chạy lint, dựng `wazuh/wazuh-manager:4.14.8` mới mỗi lần, **quét `ossec.log`** (bước dưới), chạy `tools/wazuh_stock_reach.py`, rồi chạy cả thư mục ca.

Lint (`tools/wazuh_rule_lint.py`) còn giữ hai quy tắc: (1) rule có nhóm `shadow` phải có `<info type="text">shadow_since=YYYY-MM-DD</info>` (từ R65 không còn bắt rule dự án phải chạy bóng; rule mới được chọn vào chạy bóng theo SOC-OPERATIONS mục 4);
(2) `if_sid` / `if_matched_sid` trỏ tới một rule dự án thì rule cha phải được định nghĩa **trước** (cùng file ở trên, hoặc file xếp trước theo tên), vì analysisd bỏ rule có cha chưa nạp.

Bước CI quét log (`ossec.log không có lỗi nạp rule của analysisd`) chạy ngay sau khi manager healthy, vì analysisd bỏ rule hỏng chỉ bằng một dòng log (HTTP vẫn 200). Chỉ lấy dòng `wazuh-analysisd` / `wazuh-testrule`
(manager CI không có indexer nên ERROR của indexer-connector, filebeat, vulnerability-detector là bình thường), đã đo trên 4.14.8 bằng rule cố ý hỏng:

| Mã | Thông điệp | Nguyên nhân |
|---|---|---|
| WARNING 7617 | `Signature ID '999998' was not found and will be ignored in the 'if_sid' option of rule '109101'.` | cha không tồn tại, hoặc nằm ở file nạp sau |
| WARNING 7619 | `Empty 'if_sid' value. Rule '109101' will be ignored.` | rule bị bỏ vì mọi cha đều không có |
| WARNING 7612 | `Rule ID '109102' is duplicated. Only the first occurrence will be considered.` | id trùng |
| ERROR 5107 / CRITICAL 1220 | `Syntax error on tag 'regex' in rule 109103` / `Error loading the rules: '…'` | regex hỏng, file không nạp được |

Cảnh báo 7605 (`It is not possible to overwrite 'if_group' value in rule '92021' / '61627' / '61640'`, từ `0999-tuning.xml`) là vô hại (Wazuh giữ `if_group` gốc) và không bị bắt.

### 9.6 Hành vi của Wazuh đã đo (S1 đến S7 và các lần kiểm sau)

Đo ngày 31/10 đến 05/11/2026 trên manager 4.14.8, agent 4.14.7; chi tiết ở mục *Kết quả P0 / P1* của kế hoạch.

- **S1, nạp lại.** `PUT /manager/analysisd/reload` trả lời trong 1 giây, không mất event (10.000 dòng gửi, 10.000 lưu, 0 rớt). File hỏng: HTTP vẫn 200,
  lỗi cú pháp thì `error: 1` và giữ ruleset cũ; trùng id hoặc `if_sid` không tồn tại thì chỉ có `msg` cảnh báo và rule bị bỏ âm thầm. Vì vậy `write_dynamic` xét
  `error`, `failed_items` và `msg`, không xét HTTP status, và khôi phục file cũ khi lỗi. File hỏng còn trên đĩa làm manager không khởi động lại được, nên
  `10-siem-setup.sh` chạy `wazuh-analysisd -t` mỗi lần khởi động và chuyển file của `rules-dynamic` sang `rules-dynamic.quarantine/` khi lỗi.
- **S2, thư mục rule.** `wazuh/manager/rules` mount chỉ đọc vào `etc/rules`; `local_rules.xml` đã bỏ. File rule động nằm trong volume riêng, thư mục được chown cho user `10001` mỗi lần khởi động.
  analysisd chỉ nạp file đuôi `.xml` (file tạm `ai.xml.tmp` bị bỏ qua). `GET /rules` KHÔNG thấy `rules-dynamic` (đo lại 08/11/2026), nên thư viện rule cần đọc thêm các file này bằng `wazuh_rules.parse` (R17); mã chưa làm (R83).
- **S3, logtest.** Chạy được với syslog, json, apache (giữ token, đếm ngưỡng đúng dòng thứ N). Không giải mã được eventchannel, vì decoder `windows_eventchannel` nằm trong mã analysisd: đó là lý do có chế độ inject.
  Logtest đọc ruleset trên đĩa, không chứng minh analysisd đang chạy đã nạp.
- **S4, đếm giá trị khác nhau.** Có `different_srcip / dstip / dstport / srcuser / url / field...`, nhưng Wazuh đếm "N−1 event trước có giá trị khác giá trị hiện tại", không đếm số giá trị phân biệt.
  Giá trị phân tán (quét cổng, spraying) cho kết quả như rule cũ; chỉ vài giá trị lặp xen kẽ thì báo muộn, sau khoảng 2N−2 event. Áp cho NET-001, NET-005, AUTH-003, LNX-005.
  `<field name="x">proc</field>` là regex tìm chuỗi con (khớp cả `proc2`), phải neo `^proc$`. `frequency` + `if_matched_group` không tái hiện được (kể cả rule gốc 40111); `if_matched_sid` thì chạy.
- **S5, không giải mã URL.** Trường `url` giữ nguyên chuỗi trong log. Rule gốc bỏ sót `%2527`, `+`, `%u0027` và từ khóa mã hóa từng chữ (`%55NION`); rule web của dự án bắt cả các dạng này. Trạng thái 200 thì rule gốc ra 31106 thay cho rule tấn công cụ thể.
- **S6, syslog.** `remoted` không tách được RFC 5424 (không có `program_name`): sshd và filterlog qua RFC 5424 không có decoder. **Phải gửi RFC 3164**
  (DEPLOY-VM.md và LAB-VMWARE.md ghi bắt buộc; CI ghim bằng ca `0100-platform.yml`, `0101-auth.yml`). Suricata qua syslog 514 không có decoder Wazuh ở cả hai dạng: rule Suricata (86601, NET-004, TI-001 Suricata)
  **chỉ chạy khi agent OPNsense đọc `eve.json`** (`log_format json`). Agent này chưa cài; trước đó các rule đó không có hiệu lực.
- **S7, location của agent.** analysisd so `<location>` của rule với chuỗi có tiền tố agent: `(demo-web) any->siem-procs`, `(demo-web) any->/var/log/audit/audit.log`. Rule dùng `(^|/|->)siem-procs$` và `audit\.log$`; bản neo `(^|/)` ban đầu không bao giờ khớp agent thật.
  Syslog (location = IP gửi) có thể giả bất kỳ dòng nào, nên **mọi rule web chỉ nhận agent** bằng `<location type="pcre2">^\(</location>`, rule Windows là con của chuỗi rule gốc eventchannel, rule auditd ràng buộc location. Đã thấy lỗ hổng cũ (F8) trên `main`: syslog từ IP được phép giả `auditd` hoặc JSON `win.*`; đã vá bằng PR #12.
- **Thứ tự anh em.** Trong các rule cùng cha, analysisd thử theo level giảm dần: rule **level cao hơn thắng**; bằng level thì **rule nạp trước thắng** (rule gốc nạp trước rule của repo, đổi thứ tự file không đủ để né). Rule thắng ở một tầng cha thì **cả cây con của các rule anh em thua bị bỏ**, nên rule dự án có thể chặn alert thật của rule gốc ở cấp cháu.
  Kiểm có hệ thống (05/11): rule dự án móc vào 43 rule cha gốc; 22 hậu duệ gốc là alert thật (level ≥ 12 hoặc nhóm hoạt động level ≥ 7); 8 đã có ca chứng minh còn tới được và 14 chưa
  (60154, 60156, 60159, 60162, 60164, 60166, 60171, 60176, 60187, 60188, 60189, 92602, 92650, 99920). 13 trong 14 rule thắng nhờ level cao hơn rule dự án cùng nhánh; 92602 bằng level 12 với 102501 / 102511 nhưng nạp trước.
  Cả 14 đã có ca ghim (`wazuh/manager/tests/cases/0998-stock-real-alerts.yml`, 17 ca; 99920 và 92602 thử cả rule dự án cùng nhánh). Công cụ `tools/wazuh_stock_reach.py` (đọc `ruleset/rules`, dựng cây `if_sid` / `if_matched_sid` **và `if_group`**, liệt kê hậu duệ gốc là alert thật của từng cha mà rule dự án móc vào) chạy trong job CI `wazuh-rules`. Với mỗi alert thật nó đòi MỘT trong hai và in rule nào có cái nào: (a) ca `rule:` ghim; (b) bảo đảm cấu trúc: mọi rule dự án móc cùng cha thua con trực tiếp của cha đó trên đường tới nó (level thấp hơn, hoặc bằng level và file gốc xếp trước theo tên). Không có cái nào thì CI đỏ; cũng đỏ khi `if_sid` của rule dự án trỏ tới cha gốc không tồn tại hoặc nằm ở file xếp sau.
  **`if_group` (R63):** rule có `<if_group>g</if_group>` là con của MỌI rule mang nhóm `g` (thẻ `<group>` trong rule hoặc `<group name>` bao ngoài), nên lộ ra thêm 72 rule gốc alert thật (sysmon_event1 dưới 61603: 61618-61640, 92016-92081, 91000, 91006, 91007; 92900 / 92910 / 92920 dưới 61612; 40101 / 40112 dưới 5715...) mà công cụ cũ không thấy. Kết quả trên 4.14.8: 93 alert thật dưới cha bị móc; 39 có ca ghim, 52 chỉ nhờ bảo đảm cấu trúc, 2 (40112, 40501) là rule tương quan `if_matched_group` mà harness không tái hiện được (S4) nên công cụ liệt kê tường minh trong `UNPINNABLE`. `if_matched_group` không phải cạnh cây (chỉ tra cứu event cũ).
  **Khoảng trống thật được tìm thấy (R63):** 40101 (hòa level 12 với 101002, 101002 nạp trước) và 15 rule gốc sysmon sâu dưới 61603 (92008-92015, 92024, 92026, 92038, 92040, 92044, 92045, 92071: rule dự án 105005-105007 level 10-12 cao hơn con trực tiếp level 0-8 của 61603) chưa có ca; đã thêm 16 ca ghim ở `0997-stock-if-group.yml`, tất cả báo. Lưu ý: rule dự án vẫn có thể cắt các rule gốc đó khi một event khớp cả hai (chưa thấy trong ca; ca chỉ chứng minh đường tới được).
  **Ngưỡng R65 (review cuối P4, 08/11/2026):** từ R65 rule gốc level 7–11 cũng là alert thật, nhưng công cụ vẫn mặc định ngưỡng
  cũ (level ≥ 12, R38). `--min-level 7` xét theo R65: 165 alert thật dưới cha bị móc; 54 có ca ghim, 55 chỉ nhờ bảo đảm cấu trúc, 2
  `UNPINNABLE`, **54 chưa có cả hai**. Không cái nào do `0966`: số rule gốc có đối thủ ở từng file (một rule có thể có đối thủ ở
  nhiều file) là `0965-windows.xml` 44, `0271-web.xml` 8, `0845-ti.xml` 7, `0101-auth.xml` 2; theo file gốc: `0580-win-security_rules.xml`
  39, `0245-web_rules.xml` 7, `0800-sysmon_id_1.xml` 3 (92077–92079), `0095-sshd_rules.xml` 2, `0215-policy_rules.xml` 2,
  `0999-malicious-ioc-rules.xml` 1. Ba rule gốc
  có cả `0966` lẫn `0965` làm đối thủ (92023, 92043, 92080) đã có ca ghim ở `0997-stock-if-group.yml`, đều báo. CI giữ ngưỡng 12 vì
  ghim 54 rule có từ trước không phải phạm vi P4; danh sách ghi cho chủ dự án.
  **Thứ tự nạp (đo R63):** analysisd nạp mọi file rule (gốc lẫn dự án) theo tên chung; rule dự án đặt ở file xếp trước `0095-sshd_rules.xml` bị bỏ vì cha 5715 chưa nạp.
  **99919 thắng 107010 dù level 9 < 10 (R63, đã đo):** 4625 từ 196.251.85.62 (có ở cả `siem-misp-ip` lẫn `malicious-ip`) ra 99919 chứ không ra 107010, kể cả khi danh sách MISP đã nạp (bơm 3 event, danh sách có IP: chỉ 99919 báo). Nguyên nhân: 99919 có `if_sid` 60105, 60122, tức **con trực tiếp của 60105 (level 9)** và là *anh em* của 60122 (level 5);
  107010 treo dưới 60122 (và 60106, 92657). 99919 thắng 60122 ở tầng 60105 nên cả cây con của 60122, trong đó có 107010, bị bỏ. Vậy 107010 và 99919 không cùng cha, "level cao thắng" áp ở tầng 60105 (9 > 5), không phải giữa 107010 và 99919. Cùng cơ chế "thắng ở tầng cha cao hơn, cắt cây con", nhưng KHÁC ngoại lệ Kerberos bên dưới (không có rule IOC gốc nào dính, IP chỉ có trong MISP). Ca `0965-windows.yml` (99919) vì thế vốn đúng, chỉ là 107010 vô tình nhường. R63 thêm `not_match_key` vào 107010 cho nhất quán và để không phụ thuộc cơ chế đó.
  **Ngoại lệ đã thấy (05/11):** đăng nhập 4624 thành công không qua NTLM (Kerberos) từ IP chỉ có trong `siem-misp-ip` ra rule gốc 92651 (level 0) chứ không ra 107010 (TI-001, level 10) — trái với quy tắc level cao thắng; chưa rõ nguyên nhân, ghi ở checklist Task 18 (khoảng trống TI, không mất alert thật).
  Ví dụ đã được xử lý: Shellshock 31168 / 31169 (level 15) vẫn tới được dù 104090 / 104005 cùng cha 31108; 31115 (level 13); 99906 (level 14) giữ bằng 104095; 99903 / 99904 và IOC web, sshd, Windows bằng cách loại IP khỏi con TI (cả 107008, 107009, 107010 từ R63).
- **Cầu nối alert.** `log_alert_level` của `ossec.conf` là 3, nên rule đếm phụ level 2 (101000, 101010, 103000...) không vào `alerts.json`.

### 9.7 Giới hạn đã biết

- **R52, IOC gốc chiếm sự kiện.** Rule IOC gốc trong `0999-malicious-ioc-rules.xml` (99903 / 99904 sshd, 99905 / 99906 web, 99919 Windows, 99915 / 99916 Suricata...) nạp **sau** file dự án và chiếm sự kiện của IP trong
  `etc/lists/malicious-ioc/malicious-ip`. Hệ quả: các bộ đếm của dự án (AUTH-001, WEB-006, 007, 009, WIN-001) không đếm sự kiện từ IP đó. Chấp nhận, vì rule IOC gốc báo từng event (99903 / 99906 là level 14, alert thật). Số liệu parity của các mã này sẽ thấp hơn YAML với IP trong danh sách. Có ca ghim trong `0999-tuning.yml`.
- **`different_*`:** báo muộn khi chỉ có vài giá trị lặp xen kẽ (S4); mỗi rule có ca âm ghi rõ ranh giới 2N−2 dòng.
- **Không giải mã URL:** rule web liệt kê từng dạng mã hóa, dạng lồng mã mới hơn sẽ lọt.
- **Danh sách CDB không khớp khóa CIDR** (đã thử, cả `address_match_key`): MISP có CIDR /24 đến /31 được bung thành từng IP, tối đa /24. Dải lớn hơn bị bỏ.
- **Rule có từ 3 thẻ `<list>` trở lên bị xét sai**, nên mỗi rule TI chỉ có tối đa hai thẻ. Hệ quả: nguồn trong danh sách MISP còn đích trong danh sách gốc (hoặc ngược lại) thì TI-001 (level 10) thắng 99915 / 99916 (level 9); chỉ IP có ở cả hai danh sách cùng một trường mới nhường rule gốc.
- **Console và sshd dùng chung bộ đếm 101000** (R42): thất bại ở hai dịch vụ cùng IP cộng dồn, và thất bại ở dịch vụ này rồi thành công ở dịch vụ kia cũng ra AUTH-002 (101002, critical). Rộng hơn YAML cũ.
- **5763 / 5712 gốc không còn báo** (sshd 8 lần / 120 giây): bộ đếm chung 101000 nhận trước. Phần hở là 4 đến 5 lần sai mỗi phút từ một IP không kèm thành công; rule YAML cũ cũng không bắt. Không có cách chữa nhỏ (rule `frequency` "tiêu" sự kiện đã đếm), nên chỉ ghi lại.
- **102505 (LNX-005, auditd) báo nhầm** 2,0 / 100 event trên tập Linux nền, giữ ở chế độ bóng: chuỗi `id; whoami; uname -a; ...` liền nhau đúng nghĩa "≥ 4 lệnh trinh sát khác nhau trong 60 giây", và tập đo bơm dồn trong vài giây. Cần đo lại với dữ liệu giãn theo thời gian thật. Còn theo dõi 102511 (`/dev/tcp/` trong hex) với script healthcheck.
- **Syslog và nhật ký console:** số đo độ ồn hiện chưa có hai nguồn này; cần đo lại trên ≥ 24 giờ `archives.json` của agent 000.
- **auditd:** `curl | sh` và một số tách tham số (`socat exec:`, python tách tham số, `/dev/tcp` tách tham số) không phủ được vì auditd mã hóa hex payload trong `bash -c`.
- **TI-001** phủ IP, domain (Suricata DNS / HTTP, Sysmon 22) và hash file của FIM; không khớp subdomain, không phủ hash tiến trình Sysmon 1 (9.9).
- Nhóm `sca` không thành alert (cấu hình CIS, không phải phát hiện), mặc định `WAZUH_ALERT_EXCLUDE_GROUPS=sca`.
- 104095 mang mã `WEB-012` (trước 05/11 ghi nhầm `WEB-010`, trùng với 100100).

### 9.8 File tuning `0999-tuning.xml`

Tên xếp **sau** `0999-malicious-ioc-rules.xml` (chữ `t` > `m`), nên nạp sau mọi file gốc và mọi file dự án; `overwrite` chỉ có hiệu lực khi rule gốc đã được nạp (tên cũ `0190-tuning` nạp trước web, Windows, Sysmon nên không đè được gì).
Mỗi rule chép đủ định nghĩa gốc (nhóm, mitre, tuân thủ, điều kiện), chỉ đổi phần ghi trong chú thích. `if_sid` / `if_group` do Wazuh giữ nguyên khi overwrite.

| Rule gốc | Trước | Sau | Vì sao |
|---|---|---|---|
| 92041 | level 10, regex khớp **mọi** `reg add ... /d` | level 10, chỉ khớp giá trị Base64-like (≥ 8 ký tự có đệm `=`, hoặc ≥ 20 ký tự có chữ số) | Lỗi regex của Wazuh (mọi nhóm sau `/d` đều tùy chọn) |
| 92021 | level 3, thiếu `\b` đầu nhánh | thêm `\b` đầu từ | `ri` khớp trong `-Uri` |
| 61627 | level 12 | thêm ngoại lệ `efsui.exe` trong System32 (con của `lsass.exe` khi dùng EFS), `real_before=yes` | Báo nhầm trong log nền ghi thật |
| 61640 | level 12 | thêm ngoại lệ `explorer.exe /factory,{GUID} -Embedding` (DCOM do svchost mở), `real_before=yes` | Báo nhầm trong log nền ghi thật |
| 63103 | level 5, xóa nhật ký Security | level 12, **bóng**, mã WIN-002 | Phủ WIN-002 (approx chỉ lệch level) |
| 91837 | level 4, PowerShell script block | level 12, **bóng**, mã WIN-006 | Phủ WIN-006 |
| 60109 | level 8, tạo hoặc bật tài khoản (sự kiện 624, 626, 4720, 4722) | level 8, bỏ sự kiện 4722 (bật tài khoản), mã WIN-003 | WIN-003 chỉ tính tạo tài khoản; bật lại tài khoản là việc thường ngày |
| 87702 | level 10, 18 lần / 45 giây, `ignore` | level 7, 50 lần / 60 giây, bỏ `ignore`, mã NET-002 | Khớp ngưỡng YAML cũ; bản gốc nhạy hơn |
| 31151 | level 10, 14 lần mã 4xx / 90 giây | level 7, 30 lần / 60 giây, mã WEB-006 | Khớp ngưỡng YAML cũ (WEB-006 chỉ mức medium); level 7 không còn là high nên 31151 đã bị bỏ khỏi playbook chặn IP (R61) |

Ba hệ quả cần nói rõ:

- **Độ ồn Windows** trên tập bình thường: từ 1,341 xuống 0,596 alert / 100 event (đạt cổng ≤ 1) nhờ sửa 61627, 61640 và 92041. Linux: 2,0 / 100, toàn bộ là 102505 (giữ bóng, 9.7).
- **Độ phủ trên dataset Windows trong phép đo của Task 12 giảm từ 297 xuống 76 (trên 2.218 mẫu đo)**, mất 221. Cả 221 là rule 92041 trước khi sửa, khớp **mọi** lệnh `reg add /d`, tức khớp chung chung chứ không phải phát hiện. Những khớp ngẫu nhiên này vốn đã bị loại khỏi số liệu *Wazuh cụ thể*
  ở mục 4.3 và README (danh sách `GENERIC` của `wazuh_coverage.py`). Con số 76 là số thật; 297 là số thổi phồng bởi một lỗi regex của Wazuh. Số mục 4 ghi theo đo ngày 6/10 chưa được đo lại sau tuning.
- **Alert thật mất đi sau tuning**, đã ghi ở từng rule: chỉ 61627 (efsui.exe) và 61640 (`/factory`), có log ghi thật làm chứng; 92041 mất mọi `reg add /d` giá trị thường (khoảng 220 sự kiện atomic T1112 trong tập đo, vốn không đặc hiệu).

Đã xét nhưng không đè: 61618 (ồn do cách dựng event thiếu ParentImage), 60141 (cha chung; Administrators, Domain Admins, Enterprise Admins đã có con), 92043 / 92074 / 92057 (không phân biệt được với tấn công), 102505 (không phân biệt được bằng nội dung lệnh).

### 9.9 TI-001 và các danh sách CDB

- Danh sách gốc `etc/lists/malicious-ioc/malicious-ip` của Wazuh (199 IP đơn) **không bị đụng**: rule gốc 99915 / 99916 và loại trừ của 103004 (NET-004) dùng nó (R50).
- IOC của dự án nằm trong danh sách **riêng** `etc/lists/siem-misp-ip`. SOAR mỗi chu kỳ đồng bộ MISP (`MISP_INTERVAL_MINUTES`) gộp IOC MISP loại IP còn hạn với `config/intel/*.txt` (và xuất độc lập với retrohunt), đẩy lên bằng Wazuh API
  (`PUT /lists/files/...`) rồi reload analysisd. Chỉ user API `siem-soar` có quyền ghi danh sách (thử thật: `PUT` vào danh sách gốc bằng token đó bị từ chối); `siem-rules` không còn quyền đó. Hệ quả: `siem-soar` có thêm `manager:restart` (cần cho reload).
- API Wazuh từ chối file danh sách rỗng, nên entrypoint tạo file giữ chỗ một dòng `240.0.0.0:empty` để analysisd chạy được khi chưa có IOC.
- Rule TI dùng `match_key` / `not_match_key` (khớp chuỗi chính xác), vì CIDR không khớp (9.7). Phủ: firewall pf (107001, 107002, 107003), Suricata (107004 đến 107007), sshd (107008), web (107009 chỉ nhận location agent), đăng nhập Windows (107010). Cả ba (R63) loại IP có trong danh sách gốc `malicious-ip` bằng `not_match_key`, để rule IOC gốc (99903 / 99904, 99905 / 99906, 99919 / 99920) giữ ngữ cảnh; trước R63 chỉ 107009 làm vậy nên 107008 thay 99904 (level 9 < 10) cho đăng nhập sshd thất bại từ IP ở cả hai danh sách.
- **Domain và hash (R64, 05/11):** hai danh sách riêng `etc/lists/siem-misp-domain` và `etc/lists/siem-misp-hash` (md5 / sha1 / sha256 chung một danh sách, khóa là chuỗi hex), cùng nguồn và cùng đường đẩy với IP (`pipeline/misp_cdb.py`, một lần reload cho cả ba), cũng tách khỏi danh sách gốc `malicious-domains` / `malware-hashes`. Kiểm chặt: domain đổi chữ thường, IDN sang punycode, bỏ dấu `.` cuối, nhãn `[a-z0-9-]` không đầu / cuối `-`, tối thiểu hai nhãn, TLD không toàn số, tối đa 253 ký tự, loại `*`, khoảng trắng, `:`, xuống dòng; hash là hex 32 / 40 / 64 chữ thường; trần 100000 dòng mỗi danh sách; rỗng thì dòng giữ chỗ (`placeholder.invalid:empty`, `000...0:empty`). Quyền: `siem-soar` có thêm `lists:delete` trên đúng hai file này (policy `siem_soar_misp_list_dh`; policy cũ giữ nguyên vì entrypoint không sửa policy đã có); danh sách gốc `malicious-ioc/*` nằm trong thư mục con mà `PUT /lists/files` không với tới (404), danh sách gốc ở thư mục gốc như `audit-keys` vẫn bị từ chối (thử thật trên 4.14.8).
  - Rule (level 10, shadow): 107011 Suricata DNS (con 86603, `dns.rrname`), 107012 Suricata HTTP (con 86602, `http.hostname`), cả hai chỉ nhận location agent `^\(` (JSON giả qua syslog 514 không ra TI-001) và loại domain có trong danh sách gốc (`not_match_key`) để 99918 / 99917 (level 9, nạp trước) giữ ngữ cảnh; 107013 Sysmon 22 (con 61650, `win.eventdata.queryName`); 107014 / 107015 / 107016 FIM 550 / 554 theo `sha256` / `sha1` / `md5` (rule gốc 99901 level 14 vẫn thắng nhờ level; 107014 loại luôn danh sách gốc cho rõ ý). Mỗi rule tối đa hai thẻ `<list>`.
  - **Giới hạn đã chấp nhận:** (1) khóa CDB khớp chính xác và phân biệt hoa thường nên `www.evil.example` KHÔNG khớp khi IOC là `evil.example`, và `EVIL.example` không khớp (rule YAML cũ khớp subdomain; không có cách thuần CDB: cần liệt kê từng tên được hỏi, hoặc một decoder rút domain gốc, nhưng decoder không chạy được trên eventchannel / JSON nên không thử); (2) Sysmon sự kiện 1 `win.eventdata.hashes` là một chuỗi `SHA1=..,MD5=..,SHA256=..` mà CDB không tách được, nên hash tiến trình (`process.hash` của rule YAML) chưa phủ, chỉ có hash file của FIM; (3) FIM-001 (106001-106003) và WEB-010 / 011 (100100 / 100101), level 10 và nạp trước, thắng TI-001 hash khi cùng cha cùng khớp đường dẫn (alert vẫn ra, mất ngữ cảnh IOC); (4) DNS qua proxy / VPN, và domain chỉ có trong log không phải Suricata / Sysmon, chưa phủ.
- Với IP trong MISP, rule cuối của event là TI-001 nên event đó không vào bộ đếm 5763 / 31151 / 60204: TI-001 báo từng event (level 10 như các rule đếm) thay cho đếm. Rule gốc level > 10 cùng cha (31115, 31168...) vẫn thắng TI-001.

### 9.10 Những việc còn lại

- **Triển khai P4 lên stack thật** (`DEPLOY-VM.md` mục 9): chưa làm, chờ chủ dự án gộp PR. Profile `ai` cần thêm `wazuh-sandbox`.
  Đã thử trên project thử `p4e2e` (08/11/2026): E2E 43/43; `ai.xml` do `emit` + `render_ai_file` sinh nạp được vào wazuh-manager thật,
  event thật từ agent demo-web ra alert bóng `WZH-109001` (Linux) và `WZH-109003` (web).
- **Gỡ rule AI cuối cùng / ngoại lệ cuối cùng (đã sửa, Task 26b):** trước đây khi không còn khối nào, `render_ai_file` (và
  `wazuh_exceptions._render`) ghi `<group>` rỗng và Wazuh từ chối reload, nên thao tác trên console báo lỗi. Đo trên wazuh-manager 4.14.8 tạm: `<group>` rỗng và file chỉ có chú thích đều bị từ chối (reload `error: 1`, lần lượt `Group 'group' without any rule.` và `Configuration error`); xóa file thì reload thành công và rule biến mất. Cách sửa: `write_dynamic(name, None, api)` xóa file rồi reload (reload lỗi thì khôi phục file cũ và reload lại); `render_ai_file` không còn sinh group rỗng.
- **Thư viện rule không có rule AI / ngoại lệ** (R83): Wazuh API không liệt kê `rules-dynamic/`, danh mục chưa đọc file trực tiếp (R17).
  Dashboard đếm rule AI theo đề xuất đã triển khai.
- Thực thể XML trong trường Windows (R77, Task 19c) và rule Linux SigmaHQ (`siem-proc`) chưa làm.
- Ngoại lệ Wazuh: chưa kiểm trên manager thật (ngoại lệ con level 0 so với rule anh em như 31106, che cây con, `pcre2` trên `<url>`).
- SOAR: phản ứng phá hủy chỉ theo id đã duyệt; `SOAR_WHITELIST` phải thêm IP proxy, relay, NAT nội bộ ([PLAYBOOKS.md](PLAYBOOKS.md) mục 6).
- Mục 1 đến 8 của tài liệu này đã viết lại ở Task 26 (P4) theo bộ rule Wazuh XML.
