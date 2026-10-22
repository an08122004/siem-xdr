# Đưa bộ rule Elastic vào thay rule viết tay — các phương án

Ngày 22/10/2026. Trạng thái: **chờ chọn phương án**. Kế hoạch triển khai chi tiết sẽ viết sau khi chốt.

## Yêu cầu

Người dùng: "đưa toàn bộ 2.297 rule của `elastic/detection-rules` vào repo, áp dụng trong thực tế, thay rule viết tay".

Đích: lớp phát hiện chính của siem-xdr là bộ rule do Elastic duy trì, thay cho 41 rule viết tay. Giữ nguyên các phần riêng của repo: console, SOAR, case và playbook, RBA, AI sinh rule.

## Số đo (22/10/2026)

Nguồn đo: `elastic/detection-rules` nhánh `main` commit `9431b803`, bỏ rule deprecated; gói EPR `security_detection_engine`; event đã chuẩn hóa từ `datasets/processed`.

| Hạng mục | Số |
|---|---|
| Rule trên `main` | 2.295 (bỏ rule deprecated) |
| Rule đòi stack 9.3–9.6 | 296 (lab đang chạy Elasticsearch **8.15.3**, chưa có Kibana) |
| Gói rule dựng sẵn cho Kibana 8.15 (`security_detection_engine` 8.15.18) | **1.340** rule (745 eql, 337 query, 102 new_terms, 74 ML, 48 esql, 29 threshold, 5 threat_match; 108 building block) |
| Rule chỉ dùng nguồn lab không có: cloud/SaaS (AWS, Azure, GCP, M365, Okta, GitHub, K8s…), EDR bên thứ ba, macOS | 953 (= 2.295 − 1.236 có nguồn − 106 ML) |
| Rule ML | 106, cần giấy phép Platinum; Basic chỉ dùng được bản dùng thử 30 ngày |

Số rule có nguồn log để chạy trong lab:

| Điều kiện | Số rule |
|---|---|
| Log Wazuh hiện có (Windows event log, auth/syslog Linux, Apache, FIM) | **519** |
| Thêm auditd trên Linux và đưa alert vào ES | **697** |
| Thêm Elastic Defend trên PC-01, Ubuntu-01, Web-01 | **1.236** |

Trong 697 rule (thêm auditd), chia theo cách chạy:

| Cách chạy | Số rule |
|---|---|
| Một event: EQL không phải chuỗi (438), KQL (73), threshold (8) | **519** |
| Phải truy vấn trên Elasticsearch: chuỗi EQL (68), ES\|QL (61), new_terms (44), threat_match (5) | **178** |

Khi thêm Elastic Defend, tỉ lệ là 851 so với 385.

**Độ khớp trường với parser hiện tại:** trong 697 rule có nguồn log, **chỉ 7 rule có đủ mọi trường**. Trường thiếu nhiều nhất:

| Trường | Số rule dùng |
|---|---|
| `host.os.type` | 594 |
| `process.args` | 244 |
| `process.pe.original_file_name` (repo đang để ở `winlog.event_data`) | 92 |
| `host.id` | 72 |
| `file.path` | 71 |
| `powershell.file.script_block_text` (repo dùng tên `powershell.script_block`) | 48 |
| `process.parent.args`, `registry.*`, `process.entity_id`, `data_stream.dataset`… | ít hơn |

Ngoài tên trường, giá trị cũng phải theo từ vựng của Elastic: `event.type: start`, `event.action` theo từng integration, chỉ mục `logs-<dataset>-<namespace>`.

**Giấy phép:**
- Bản Basic (miễn phí) có engine phát hiện, rule dựng sẵn, và Elastic Defend gồm thu telemetry và chặn mã độc.
- Rule ML, tính năng gộp alert, và các lớp chặn ransomware, chặn theo hành vi, bảo vệ bộ nhớ của Defend cần Platinum.
- Nội dung rule dùng Elastic License 2.0: được dùng, sao chép, chỉnh sửa; không được cung cấp dưới dạng dịch vụ quản lý cho bên thứ ba; phải giữ thông báo giấy phép.

**Kết luận:** "đưa toàn bộ 2.297 rule vào" thì làm được, theo nghĩa cài đặt hết. Nhưng trong lab này, số rule **có dữ liệu để bắn** tối đa khoảng 1.236 rule, và chỉ đạt được khi có Elastic Defend cùng stack 9.x. Các rule còn lại cài vào nhưng tắt, đến khi có nguồn log tương ứng.

## Nền tảng chung: dữ liệu theo chuẩn ECS của Elastic

Phương án nào cũng cần event giống hệt dữ liệu mà integration của Elastic sinh ra. Có hai cách:

| | DL-A: parser của repo sinh ECS chuẩn (giữ Wazuh) | DL-B: Elastic Agent cài song song Wazuh trên 3 máy lab |
|---|---|---|
| Cách làm | Sửa `pipeline/normalize.py`: thêm `host.os.type`, `process.args`, `process.parent.*`, `file.*`, `registry.*`, `powershell.file.*`, `host.id`; đổi từ vựng `event.*`; ghi vào chỉ mục khớp mẫu của rule (vd `logs-windows.sysmon_operational-siem`) | Integration System, Windows, Sysmon, Auditd Manager, Apache, cùng Elastic Defend; dữ liệu đúng chuẩn ngay từ đầu |
| Rule chạy được | tối đa 697 (không có Defend) | tối đa 1.236 |
| Độ đúng | xấp xỉ: tự bắt chước hàng trăm trường và giá trị, khó khớp tuyệt đối | đúng như Elastic kiểm thử |
| Chi phí | viết và kiểm thử lớn, phải theo kịp mỗi khi Elastic đổi integration | cài agent, chạy Fleet Server (hoặc agent standalone), log trùng với Wazuh |
| Wazuh | giữ nguyên | giữ cho FIM, SCA, phản ứng chủ động; có thể bỏ dần |

## Ba phương án cho lớp phát hiện

### PA1 — Chạy rule bằng Elastic Security (Kibana), cầu nối alert sang SOAR của repo

- **Cách làm:**
  - Thêm container Kibana cùng phiên bản ES.
  - Cài gói rule dựng sẵn; bật rule có dữ liệu.
  - Engine của Kibana chạy rule theo lịch (mặc định 5 phút, có `from` để nhìn lùi).
  - Một cầu nối (giống cầu nối Wazuh) đọc `.alerts-security.alerts-*` rồi chuyển thành alert của repo vào Kafka `siem.alerts`. Từ đó SOAR, case, RBA và console chạy như cũ.
- **Rule:** 1.340 rule ngay trên 8.15; khoảng 2.295 rule sau khi nâng cấp 8.15 → 8.19 → 9.x.
- **Ưu điểm:**
  - Rule chạy **đúng 100%** kể cả chuỗi EQL, ES|QL, new_terms, threshold, building block.
  - Cập nhật bằng gói của Elastic (hằng tuần).
  - Có giao diện ngoại lệ (exception) và xem trước rule (`_preview`) để đo trên dữ liệu cũ.
  - Ít mã phát hiện phải tự viết nhất.
- **Nhược điểm:**
  - Thêm một giao diện cho detection engineer (Kibana); SOC vẫn dùng console.
  - Độ trễ phát hiện khoảng 5 phút, so với vài giây của engine hiện tại.
  - Tốn tài nguyên: Kibana khoảng 2 GB RAM, heap ES nên lên ≥ 4 GB khi bật vài trăm rule. Máy host có 32 GB nhưng còn chạy các VM lab, và ổ đĩa chỉ còn 30–41 GB.
  - Chuỗi AI → rule, lint và benchmark của repo phải chuyển sang ghi rule Kibana. Đường đi tự nhiên: Sigma → pySigma backend Elasticsearch → Detection API.

### PA2 — Tự viết engine chạy truy vấn trên Elasticsearch (không dùng Kibana)

- **Cách làm:** một dịch vụ lập lịch trong repo, gọi:
  - `_eql/search` cho EQL;
  - `_query` cho ES|QL;
  - KQL chuyển sang Query DSL, dùng lại thư viện `kql` trong repo Elastic, giấy phép ELv2;
  - aggregation cho threshold và new_terms;
  - kết quả ghi thẳng vào `siem-alerts` hoặc Kafka.
- **Rule:** như PA1 trừ ML; phiên bản stack cũng quyết định số rule.
- **Ưu điểm:** không thêm Kibana; một giao diện duy nhất; độ đúng cao vì ES tự chạy EQL và ES|QL.
- **Nhược điểm:**
  - Phải làm lại phần lõi của engine Kibana: lịch, nhìn lùi, chống trùng, `max_signals`, ngoại lệ, building block, `timestamp_override`.
  - Nhiều chỗ sai ngữ nghĩa khó thấy; khối lượng test lớn nhất.

### PA3 — Biên dịch rule Elastic sang engine YAML của repo (như cách đã nhập SigmaHQ)

- **Cách làm:**
  - Bộ biên dịch mới `ai/elastic.py`: EQL một event và KQL chuyển thành cây điều kiện; threshold chuyển thành `type: threshold`.
  - Engine thêm toán tử `like` (wildcard `*`/`?`), `args_count`, trường tùy chọn `?field`.
  - Nhập theo lô, chạy bóng, có ca test, giống `sigmahq_import.py`.
- **Rule:**
  - 519 rule ở mức tối đa nếu có thêm auditd; 851 nếu có Elastic Defend.
  - Bỏ ngoài 178–385 rule: chuỗi EQL, ES|QL, new_terms, threat_match, cùng mọi rule ML.
- **Ưu điểm:**
  - Giữ engine thời gian thực (vài giây), giữ lint, ca test, benchmark trên dataset, chuỗi AI.
  - Không thêm Kibana, không nâng cấp stack.
  - Đo được độ phủ và báo nhầm trên dataset trước khi bật.
- **Nhược điểm:**
  - Bộ biên dịch phải theo kịp cú pháp EQL/KQL.
  - Mỗi lần Elastic cập nhật phải biên dịch lại, và có rủi ro lệch ngữ nghĩa.
  - Mất phần mạnh nhất của Elastic: chuỗi sự kiện và rule thống kê.

### So sánh

| | PA1 Kibana | PA2 engine truy vấn ES | PA3 biên dịch sang YAML |
|---|---|---|---|
| Rule có dữ liệu để chạy (cùng DL-B, stack 9.x) | 1.236 | gần 1.236 (tùy phần tự làm: new_terms, threat_match) | 851 |
| Độ đúng so với Elastic | 100% | cao | trung bình |
| Độ trễ phát hiện | khoảng 5 phút | khoảng 1–5 phút | vài giây |
| Mã tự viết | ít (cầu nối, ánh xạ playbook) | rất nhiều | nhiều (bộ biên dịch, toán tử) |
| Cập nhật rule | gói Elastic | tải repo, chạy lại | tải repo, biên dịch lại |
| Tài nguyên thêm | Kibana khoảng 2 GB, heap ES ≥ 4 GB | heap ES ≥ 4 GB | gần như không |
| Giữ lint, benchmark, chuỗi AI hiện có | phải chuyển | phải chuyển | giữ |

## Đề xuất (lựa chọn của mình, chờ duyệt)

**Chọn PA1 kết hợp DL-B, làm theo từng giai đoạn, và không thay rule viết tay trước v1.0.**

Lý do chọn:
- Yêu cầu là "áp dụng thực tế toàn bộ". Chỉ PA1 chạy rule đúng như Elastic, và có nhiều rule có dữ liệu nhất.
- Bộ rule được Elastic cập nhật hằng tuần; tự biên dịch (PA3) hay tự viết engine (PA2) thì phải tự theo kịp mãi.
- DL-B cho dữ liệu đúng chuẩn ngay; tự bắt chước ECS (DL-A) là phần dễ sai nhất.

Các giai đoạn:

| GĐ | Thời gian | Việc | Xong khi |
|---|---|---|---|
| 0. Thử nghiệm (throwaway) | 23–25/10 | Kibana 8.15.3 theo profile `elastic` trong compose; cài 1.340 rule; Elastic Agent standalone với integration Windows và Sysmon trên PC-01; bật các rule Windows có dữ liệu; chạy vài bài Atomic; đo RAM/CPU của ES và Kibana | có alert Kibana từ bài Atomic; số tài nguyên; quyết định đi tiếp hay chuyển sang PA3 |
| 1. Chạy song song | 26/10–08/11 | Cầu nối `.alerts-security` → Kafka, alert Elastic ở **chế độ bóng** (SOAR bỏ qua); agent trên cả 3 máy lab; bật auditd Linux; Defend chỉ ở chế độ phát hiện | so được alert Elastic với alert viết tay trên cùng bài e2e |
| — | 09/11–16/11 | v1.0 đóng băng: rule viết tay vẫn là lớp chính, e2e và demo giữ nguyên | v1.0 |
| 2. Chuyển hẳn | sau 16/11 | Gắn lại playbook theo `rule_id` của Elastic và kỹ thuật ATT&CK (không tự phản ứng cho tới khi có danh sách duyệt); e2e đổi sang rule Elastic; Thư viện rule đọc từ Kibana API; KPI độ phủ tính trên rule Elastic đang bật; tắt rule viết tay | e2e xanh với rule Elastic |
| 3. Đủ bộ | sau GĐ2 | Nâng cấp 8.15 → 8.19 → 9.x để nhận khoảng 2.295 rule; chuỗi AI ra rule Kibana qua pySigma | gói rule bản mới nhất |

**Ảnh hưởng tới kế hoạch phân bậc** (`docs/superpowers/plans/2026-10-22-rule-tiers.md`):
- Nếu chọn PA1 hoặc PA2, phần viết lại 41 rule (Task 8–11) và SigmaHQ (Task 12–13) không cần nữa.
- Vẫn giữ: bản sửa RBA (đã xong), alert low ra khỏi KPI và danh sách mặc định, e2e so đúng mã rule (Task 6), RBA-002 (Task 15).
- Tách `process.args` (Task 5) chỉ cần nếu chọn DL-A.
- Nếu chọn PA3, kế hoạch phân bậc vẫn dùng được: building block của Elastic đúng là bậc `-L`.

## Rủi ro chung

- **Bỏ rule viết tay thì mất những thứ Elastic không có:**
  - rule cho log firewall OPNsense (NET-001/002/003/005);
  - log Suricata dạng syslog (NET-004);
  - brute-force SSH qua log Wazuh (AUTH-001/002/003);
  - FIM của Wazuh (FIM-001).

  Elastic có rule tương đương nhưng đọc nguồn khác (`logs-system.auth`, `logs-fim.event`, `logs-network_traffic`). Phải kiểm từng rule trước khi tắt; có thể giữ lại vài rule viết tay cho các nguồn này.
- **Phản ứng tự động:** rule Elastic không được thiết kế để tự diệt tiến trình hay chặn IP. Danh sách rule được phép phản ứng tự động phải do người duyệt, bắt đầu từ rỗng.
- **Lượng alert:** 1.340 rule thì có 497 rule low và 108 building block. Kết hợp phần ẩn alert low (Task 6) với RBA đã sửa.
- **Đĩa:** chỉ mục Elastic Agent cùng Defend tăng nhanh. Cần ILM giữ 7–14 ngày trong lab.
