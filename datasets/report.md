# Báo cáo độ phủ rule trên dataset công khai

Sinh bởi `python -m siem.ai.benchmark`. Chỉ tính rule dạng `match` ở mức từng event (rule ngưỡng/chuỗi cần nhiều event liên tiếp nên không đánh giá trên request độc lập).

| Chỉ số | Giá trị |
|---|---|
| Mẫu tấn công quan sát được | 15,088 |
| Mẫu tấn công ngoài tầm nhìn (payload trong body POST/PUT, access log không ghi) | 9,977 |
| Mẫu bình thường (lấy mẫu) | 36,000 |
| Phát hiện (recall trên mẫu quan sát được) | 1,659 (11.0%) |
| Báo nhầm trên mẫu bình thường | 0 (0.0%) |
| Precision | 100.0% |

## Theo loại tấn công

Nhóm do heuristic thô trong `siem/ai/attack_types.py` gán, chỉ để gom ứng viên cho AI. Loại *riêng ứng dụng* là bất thường của chính ứng dụng mẫu (tham số lạ, giá trị sai định dạng, đường dẫn không tồn tại): không viết được rule chữ ký dùng chung nên không giao cho AI.

| Loại | Tổng | Phát hiện | Tỉ lệ | Giao cho AI viết rule |
|---|---|---|---|---|
| Dò file sao lưu / mã nguồn (`backup-file`) | 2,615 | 0 | 0.0% | có |
| SQL Injection (`sqli`) | 1,489 | 810 | 54.4% | có |
| Dò tài nguyên nhạy cảm / mặc định (`sensitive-path`) | 885 | 0 | 0.0% | có |
| Cross-Site Scripting (`xss`) | 752 | 752 | 100.0% | có |
| CRLF / chèn header (`crlf`) | 540 | 0 | 0.0% | có |
| Mã hóa né tránh (kép / null byte) (`encoding-evasion`) | 465 | 0 | 0.0% | có |
| Server-Side Include injection (`ssi`) | 362 | 97 | 26.8% | có |
| Tham số lạ (riêng ứng dụng) (`unknown-param`) | 3,546 | 0 | 0.0% | không (riêng ứng dụng) |
| Giá trị sai định dạng (riêng ứng dụng) (`invalid-value`) | 2,426 | 0 | 0.0% | không (riêng ứng dụng) |
| Đường dẫn không tồn tại (riêng ứng dụng) (`unknown-resource`) | 2,008 | 0 | 0.0% | không (riêng ứng dụng) |

## Theo rule (chỉ rule có kết quả)

| Rule | Tên | Bắt mẫu tấn công | Báo nhầm mẫu bình thường |
|---|---|---|---|
| WEB-001 | Tấn công SQL Injection | 810 | 0 |
| WEB-002 | Tấn công Cross-Site Scripting (XSS) | 752 | 0 |
| WEB-004 | Command Injection / RCE qua Web | 192 | 0 |
| WEB-003 | Path Traversal / Local File Inclusion | 97 | 0 |
