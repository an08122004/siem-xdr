# Báo cáo độ phủ rule trên dataset công khai

Sinh bởi `python -m siem.ai.benchmark`. Chỉ tính rule dạng `match` ở mức từng event (rule ngưỡng/chuỗi cần nhiều event liên tiếp nên không đánh giá trên request độc lập).

| Lĩnh vực | Mẫu tấn công | Phát hiện | Nhóm có ít nhất 1 mẫu bị bắt | Mẫu bình thường | Báo nhầm |
|---|---|---|---|---|---|
| Web (CSIC 2010) | 15,088 | 1,659 (11.0%) | 3/10 loại | 36,000 | 0 (0.0%) |
| Windows (tổng) | 2,813 | 183 (6.5%) | 39/134 kỹ thuật | 671 | 0 (0.0%) |
| &nbsp;&nbsp;Windows: dựng lại từ Atomic Red Team | 2,218 | 127 (5.7%) | 37/133 kỹ thuật |  |  |
| &nbsp;&nbsp;Windows: log ghi thật (Splunk) | 595 | 56 (9.4%) | 11/35 kỹ thuật |  |  |
| Linux (tổng) | 1,414 | 12 (0.8%) | 7/78 kỹ thuật | 200 | 0 (0.0%) |
| &nbsp;&nbsp;Linux: dựng lại từ Atomic Red Team | 1,146 | 12 (1.0%) | 7/76 kỹ thuật |  |  |
| &nbsp;&nbsp;Linux: log ghi thật (Splunk) | 268 | 0 (0.0%) | 0/22 kỹ thuật |  |  |

Ngoài ra 9,977 mẫu web nằm ngoài tầm nhìn (payload trong body POST/PUT, access log không ghi) — không tính. Mẫu endpoint gồm event tiến trình DỰNG LẠI từ lệnh của bài thử Atomic Red Team (`siem/ai/atomic.py`) và event tạo tiến trình GHI THẬT khi chạy tấn công (Splunk attack_data, `siem/ai/endpoint_logs.py`). Mẫu bình thường endpoint gồm lệnh quản trị tự soạn (`siem/ai/baseline.py`) và hoạt động nền ghi thật của máy Splunk Attack Range (chỉ Windows; giữ tiến trình lặp lại ở ≥ 2 kỹ thuật).

Đo theo bộ (log ghi thật chỉ biết cả bộ thuộc kỹ thuật nào: Splunk ngoài thư mục `atomic_red_team`, OTRF). Một bộ tính là bị phát hiện khi rule bắn trên ít nhất một tiến trình của bộ:

| Bộ dữ liệu | Số bộ | Tiến trình | Bộ bị phát hiện | Kỹ thuật có ít nhất 1 bộ bị phát hiện |
|---|---|---|---|---|
| Windows, Splunk | 417 | 11,062 | 60 (14.4%) | 29/142 |
| Windows, OTRF | 117 | 2,783 | 25 (21.4%) | 18/51 |
| Linux, Splunk | 62 | 1,576 | 5 (8.1%) | 3/22 |

## Web theo loại tấn công

Nhóm do heuristic thô trong `siem/ai/attack_types.py` gán, chỉ để gom ứng viên cho AI. Loại *riêng ứng dụng* là bất thường của chính ứng dụng mẫu (tham số lạ, giá trị sai định dạng, đường dẫn không tồn tại): không viết được rule chữ ký dùng chung nên không giao cho AI.

| Loại | Tổng | Phát hiện | Tỉ lệ | Giao cho AI viết rule |
|---|---|---|---|---|
| Dò file sao lưu / mã nguồn (`backup-file`) | 2,615 | 0 | 0.0% | có |
| SQL Injection (`sqli`) | 1,202 | 810 | 67.4% | có |
| Dò tài nguyên nhạy cảm / mặc định (`sensitive-path`) | 885 | 0 | 0.0% | có |
| Cross-Site Scripting (`xss`) | 752 | 752 | 100.0% | có |
| CRLF / chèn header (`crlf`) | 540 | 0 | 0.0% | có |
| Mã hóa né tránh (kép / null byte) (`encoding-evasion`) | 466 | 0 | 0.0% | có |
| Server-Side Include injection (`ssi`) | 362 | 97 | 26.8% | có |
| Tham số lạ (riêng ứng dụng) (`unknown-param`) | 3,565 | 0 | 0.0% | không (riêng ứng dụng) |
| Giá trị sai định dạng (riêng ứng dụng) (`invalid-value`) | 2,693 | 0 | 0.0% | không (riêng ứng dụng) |
| Đường dẫn không tồn tại (riêng ứng dụng) (`unknown-resource`) | 2,008 | 0 | 0.0% | không (riêng ứng dụng) |

## Endpoint theo kỹ thuật ATT&CK

Nhóm = kỹ thuật gốc theo hệ điều hành. AI chỉ nhận nhóm có từ 4 bài thử chưa bị bắt (tách đôi train / kiểm tra theo bài thử).

| Hệ điều hành | Kỹ thuật | Tên | Bài thử | Bài thử bị bắt | Tiến trình | Phát hiện | Tỉ lệ |
|---|---|---|---|---|---|---|---|
| Linux | T1548 | Abuse Elevation Control Mechanism | 18 | 0 | 119 | 0 | 0.0% |
| Linux | T1552 | Unsecured Credentials | 39 | 0 | 114 | 0 | 0.0% |
| Linux | T1569 | System Services | 10 | 0 | 63 | 0 | 0.0% |
| Linux | T1685 | Disable or Modify Tools | 29 | 0 | 63 | 0 | 0.0% |
| Linux | T1059 | Command and Scripting Interpreter | 21 | 3 | 58 | 3 | 5.2% |
| Linux | T1070 | Indicator Removal on Host | 20 | 0 | 45 | 0 | 0.0% |
| Linux | T1140 | Deobfuscate/Decode Files or Information | 8 | 0 | 42 | 0 | 0.0% |
| Linux | T1003 | OS Credential Dumping | 9 | 0 | 39 | 0 | 0.0% |
| Linux | T1027 | Obfuscated Files or Information | 9 | 0 | 38 | 0 | 0.0% |
| Linux | T1053 | Scheduled Task/Job | 10 | 2 | 37 | 2 | 5.4% |
| Linux | T1555 | Credentials from Password Stores | 3 | 0 | 37 | 0 | 0.0% |
| Linux | T1222 | File and Directory Permissions Modification | 15 | 0 | 35 | 0 | 0.0% |
| Linux | T1083 | File and Directory Discovery | 4 | 0 | 34 | 0 | 0.0% |
| Linux | T1082 | System Information Discovery | 8 | 0 | 32 | 0 | 0.0% |
| Linux | T1078 | Valid Accounts | 5 | 0 | 30 | 0 | 0.0% |
| Linux | T1686 | Disable or Modify System Firewall | 13 | 0 | 30 | 0 | 0.0% |
| Linux | T1546 | Event Triggered Execution | 12 | 0 | 29 | 0 | 0.0% |
| Linux | T1036 | Masquerading | 7 | 0 | 26 | 0 | 0.0% |
| Linux | T1543 | Create or Modify System Process | 4 | 0 | 24 | 0 | 0.0% |
| Linux | T1560 | Archive Collected Data | 9 | 0 | 24 | 0 | 0.0% |
| Linux | T1105 | Ingress Tool Transfer | 8 | 1 | 23 | 1 | 4.3% |
| Linux | T1056 | Input Capture | 6 | 0 | 21 | 0 | 0.0% |
| Linux | T1136 | Create Account | 7 | 0 | 20 | 0 | 0.0% |
| Linux | T1048 | Exfiltration Over Alternative Protocol | 7 | 0 | 19 | 0 | 0.0% |
| Linux | T1529 | System Shutdown/Reboot | 10 | 0 | 19 | 0 | 0.0% |
| Linux | T1690 | Prevent Command History Logging | 9 | 0 | 19 | 0 | 0.0% |
| Linux | T1040 | Network Sniffing | 8 | 0 | 18 | 0 | 0.0% |
| Linux | T1087 | Account Discovery | 8 | 0 | 18 | 0 | 0.0% |
| Linux | T1018 | Remote System Discovery | 7 | 0 | 17 | 0 | 0.0% |
| Linux | T1110 | Brute Force | 5 | 3 | 17 | 3 | 17.6% |
| Linux | T1016 | System Network Configuration Discovery | 3 | 0 | 15 | 0 | 0.0% |
| Linux | T1518 | Software Discovery | 2 | 0 | 13 | 0 | 0.0% |
| Linux | T1614 | System Location Discovery | 5 | 0 | 13 | 0 | 0.0% |
| Linux | T1001 | Data Obfuscation via Steganography | 1 | 0 | 12 | 0 | 0.0% |
| Linux | T1014 | Rootkit | 4 | 0 | 12 | 0 | 0.0% |
| Linux | T1055 | Process Injection | 6 | 0 | 12 | 0 | 0.0% |
| Linux | T1572 | Protocol Tunneling | 5 | 0 | 12 | 0 | 0.0% |
| Linux | T1553 | Subvert Trust Controls | 3 | 0 | 11 | 0 | 0.0% |
| Linux | T1049 | System Network Connections Discovery | 3 | 0 | 10 | 0 | 0.0% |
| Linux | T1115 | Clipboard Data | 3 | 0 | 10 | 0 | 0.0% |
| Linux | T1201 | Password Policy Discovery | 5 | 0 | 10 | 0 | 0.0% |
| Linux | T1497 | Virtualization/Sandbox Evasion | 3 | 0 | 10 | 0 | 0.0% |
| Linux | T1489 | Service Stop | 5 | 0 | 9 | 0 | 0.0% |
| Linux | T1037 | Boot or Logon Initialization Scripts | 2 | 0 | 8 | 0 | 0.0% |
| Linux | T1485 | Data Destruction | 4 | 0 | 8 | 0 | 0.0% |
| Linux | T1005 | Data from Local System | 1 | 0 | 7 | 0 | 0.0% |
| Linux | T1046 | Network Service Discovery | 3 | 0 | 7 | 0 | 0.0% |
| Linux | T1113 | Screen Capture | 4 | 0 | 7 | 0 | 0.0% |
| Linux | T1071 | Application Layer Protocol | 1 | 0 | 6 | 0 | 0.0% |
| Linux | T1090 | Proxy | 2 | 0 | 6 | 0 | 0.0% |
| Linux | T1195 | Compromise Software Supply Chain | 1 | 0 | 6 | 0 | 0.0% |
| Linux | T1217 | Browser Bookmark Discovery | 2 | 0 | 6 | 0 | 0.0% |
| Linux | T1556 | Modify Authentication Process | 3 | 0 | 6 | 0 | 0.0% |
| Linux | T1562 |  | 1 | 0 | 6 | 0 | 0.0% |
| Linux | T1030 | Data Transfer Size Limits | 2 | 0 | 5 | 0 | 0.0% |
| Linux | T1132 | Data Encoding | 2 | 0 | 5 | 0 | 0.0% |
| Linux | T1486 | Data Encrypted for Impact | 4 | 0 | 5 | 0 | 0.0% |
| Linux | T1574 | Hijack Execution Flow | 3 | 0 | 5 | 0 | 0.0% |
| Linux | T1578 | Create Cloud Instance | 2 | 0 | 5 | 0 | 0.0% |
| Linux | T1659 | Content Injection | 1 | 0 | 5 | 0 | 0.0% |
| Linux | T1033 | System Owner/User Discovery | 1 | 0 | 4 | 0 | 0.0% |
| Linux | T1069 | Permission Groups Discovery | 2 | 0 | 4 | 0 | 0.0% |
| Linux | T1102 | Web Service | 1 | 1 | 4 | 1 | 25.0% |
| Linux | T1547 | Boot or Logon Autostart Execution | 2 | 0 | 4 | 0 | 0.0% |
| Linux | T1564 | Hide Artifacts | 2 | 0 | 4 | 0 | 0.0% |
| Linux | T1567 | Exfiltration Over Web Service | 2 | 0 | 4 | 0 | 0.0% |
| Linux | T1652 | Device Driver Discovery | 2 | 0 | 4 | 0 | 0.0% |
| Linux | T1007 | System Service Discovery | 2 | 0 | 3 | 0 | 0.0% |
| Linux | T1057 | Process Discovery | 1 | 0 | 3 | 0 | 0.0% |
| Linux | T1074 | Data Staged | 1 | 1 | 3 | 1 | 33.3% |
| Linux | T1135 | Network Share Discovery | 2 | 0 | 3 | 0 | 0.0% |
| Linux | T1124 | System Time Discovery | 1 | 0 | 2 | 0 | 0.0% |
| Linux | T1496 | Resource Hijacking | 1 | 0 | 2 | 0 | 0.0% |
| Linux | T1531 | Account Access Removal | 1 | 0 | 2 | 0 | 0.0% |
| Linux | T1568 | Dynamic Resolution | 1 | 0 | 2 | 0 | 0.0% |
| Linux | T1571 | Non-Standard Port | 1 | 0 | 2 | 0 | 0.0% |
| Linux | T1098 | SSH Authorized Keys | 1 | 1 | 1 | 1 | 100.0% |
| Linux | T1200 |  | 1 | 0 | 1 | 0 | 0.0% |
| Windows | T1218 | Signed Binary Proxy Execution | 82 | 4 | 268 | 17 | 6.3% |
| Windows | T1112 | Modify Registry | 92 | 0 | 203 | 0 | 0.0% |
| Windows | T1546 | Event Triggered Execution | 42 | 0 | 123 | 0 | 0.0% |
| Windows | T1685 | Disable or Modify Tools | 66 | 1 | 118 | 1 | 0.8% |
| Windows | T1003 | OS Credential Dumping | 47 | 10 | 117 | 26 | 22.2% |
| Windows | T1105 | Ingress Tool Transfer | 29 | 3 | 99 | 12 | 12.1% |
| Windows | T1547 | Boot or Logon Autostart Execution | 44 | 1 | 92 | 2 | 2.2% |
| Windows | T1059 | Command and Scripting Interpreter | 37 | 4 | 77 | 10 | 13.0% |
| Windows | T1082 | System Information Discovery | 30 | 10 | 72 | 10 | 13.9% |
| Windows | T1018 | Remote System Discovery | 17 | 0 | 68 | 0 | 0.0% |
| Windows | T1548 | Abuse Elevation Control Mechanism | 29 | 4 | 58 | 4 | 6.9% |
| Windows | T1036 | Masquerading | 17 | 1 | 56 | 1 | 1.8% |
| Windows | T1564 | Hide Artifacts | 23 | 1 | 51 | 2 | 3.9% |
| Windows | T1069 | Permission Groups Discovery | 19 | 0 | 45 | 0 | 0.0% |
| Windows | T1070 | Indicator Removal on Host | 26 | 0 | 45 | 0 | 0.0% |
| Windows | T1087 | Account Discovery | 26 | 1 | 42 | 1 | 2.4% |
| Windows | T1490 | Inhibit System Recovery | 12 | 4 | 41 | 16 | 39.0% |
| Windows | T1518 | Software Discovery | 14 | 3 | 41 | 3 | 7.3% |
| Windows | T1053 | Scheduled Task/Job | 15 | 7 | 38 | 12 | 31.6% |
| Windows | T1033 | System Owner/User Discovery | 8 | 0 | 35 | 0 | 0.0% |
| Windows | T1012 | Query Registry | 6 | 0 | 34 | 0 | 0.0% |
| Windows | T1047 | Windows Management Instrumentation | 12 | 1 | 33 | 1 | 3.0% |
| Windows | T1531 | Account Access Removal | 4 | 0 | 32 | 0 | 0.0% |
| Windows | T1555 | Credentials from Password Stores | 25 | 7 | 32 | 7 | 21.9% |
| Windows | T1027 | Obfuscated Files or Information | 20 | 1 | 31 | 1 | 3.2% |
| Windows | T1222 | File and Directory Permissions Modification | 9 | 0 | 31 | 0 | 0.0% |
| Windows | T1055 | Process Injection | 26 | 2 | 30 | 3 | 10.0% |
| Windows | T1552 | Unsecured Credentials | 22 | 7 | 30 | 7 | 23.3% |
| Windows | T1021 | Remote Services | 15 | 0 | 29 | 0 | 0.0% |
| Windows | T1197 | BITS Jobs | 4 | 1 | 29 | 6 | 20.7% |
| Windows | T1543 | Create or Modify System Process | 6 | 0 | 29 | 0 | 0.0% |
| Windows | T1574 | Hijack Execution Flow | 14 | 0 | 29 | 0 | 0.0% |
| Windows | T1016 | System Network Configuration Discovery | 13 | 0 | 27 | 0 | 0.0% |
| Windows | T1569 | System Services | 7 | 1 | 27 | 1 | 3.7% |
| Windows | T1558 | Steal or Forge Kerberos Tickets | 13 | 5 | 26 | 5 | 19.2% |
| Windows | T1686 | Disable or Modify System Firewall | 14 | 0 | 26 | 0 | 0.0% |
| Windows | T1482 | Domain Trust Discovery | 8 | 0 | 23 | 0 | 0.0% |
| Windows | T1110 | Brute Force | 12 | 1 | 22 | 1 | 4.5% |
| Windows | T1136 | Create Account | 7 | 1 | 22 | 1 | 4.5% |
| Windows | T1137 | Office Application Startup | 14 | 0 | 20 | 0 | 0.0% |
| Windows | T1219 | Remote Access Software | 15 | 0 | 17 | 0 | 0.0% |
| Windows | T1078 | Valid Accounts | 6 | 2 | 16 | 2 | 12.5% |
| Windows | T1140 | Deobfuscate/Decode Files or Information | 3 | 2 | 16 | 7 | 43.8% |
| Windows | T1204 | User Execution | 14 | 0 | 16 | 0 | 0.0% |
| Windows | T1220 | XSL Script Processing | 4 | 0 | 16 | 0 | 0.0% |
| Windows | T1134 | Access Token Manipulation | 13 | 2 | 15 | 2 | 13.3% |
| Windows | T1202 | Indirect Command Execution | 5 | 0 | 15 | 0 | 0.0% |
| Windows | T1553 | Subvert Trust Controls | 10 | 0 | 15 | 0 | 0.0% |
| Windows | T1562 |  | 1 | 0 | 14 | 0 | 0.0% |
| Windows | T1057 | Process Discovery | 9 | 0 | 13 | 0 | 0.0% |
| Windows | T1071 | Application Layer Protocol | 7 | 1 | 13 | 1 | 7.7% |
| Windows | T1529 | System Shutdown/Reboot | 6 | 0 | 13 | 0 | 0.0% |
| Windows | T1559 | Inter-Process Communication | 8 | 0 | 13 | 0 | 0.0% |
| Windows | T1560 | Archive Collected Data | 8 | 0 | 13 | 0 | 0.0% |
| Windows | T1614 | System Location Discovery | 7 | 0 | 13 | 0 | 0.0% |
| Windows | T1040 | Network Sniffing | 5 | 0 | 12 | 0 | 0.0% |
| Windows | T1135 | Network Share Discovery | 9 | 1 | 12 | 1 | 8.3% |
| Windows | T1007 | System Service Discovery | 5 | 0 | 11 | 0 | 0.0% |
| Windows | T1098 | Account Manipulation | 10 | 0 | 11 | 0 | 0.0% |
| Windows | T1119 | Automated Collection | 4 | 0 | 10 | 0 | 0.0% |
| Windows | T1046 | Network Service Discovery | 9 | 4 | 9 | 4 | 44.4% |
| Windows | T1113 | Screen Capture | 4 | 0 | 9 | 0 | 0.0% |
| Windows | T1124 | System Time Discovery | 5 | 0 | 9 | 0 | 0.0% |
| Windows | T1127 | Trusted Developer Utilities Proxy Execution | 4 | 0 | 9 | 0 | 0.0% |
| Windows | T1216 | Signed Script Proxy Execution | 3 | 0 | 9 | 0 | 0.0% |
| Windows | T1048 | Exfiltration Over Alternative Protocol | 7 | 0 | 8 | 0 | 0.0% |
| Windows | T1049 | System Network Connections Discovery | 4 | 0 | 8 | 0 | 0.0% |
| Windows | T1083 | File and Directory Discovery | 6 | 0 | 8 | 0 | 0.0% |
| Windows | T1201 | Password Policy Discovery | 5 | 0 | 8 | 0 | 0.0% |
| Windows | T1217 | Browser Bookmark Discovery | 6 | 0 | 8 | 0 | 0.0% |
| Windows | T1484 | Domain Policy Modification | 2 | 0 | 8 | 0 | 0.0% |
| Windows | T1489 | Service Stop | 4 | 0 | 8 | 0 | 0.0% |
| Windows | T1505 | Server Software Component | 6 | 0 | 7 | 0 | 0.0% |
| Windows | T1550 | Use Alternate Authentication Material | 5 | 2 | 7 | 2 | 28.6% |
| Windows | T1615 | Group Policy Discovery | 5 | 3 | 7 | 4 | 57.1% |
| Windows | T1025 | Data from Removable Media | 1 | 0 | 6 | 0 | 0.0% |
| Windows | T1068 | Exploitation for Privilege Escalation | 2 | 0 | 6 | 0 | 0.0% |
| Windows | T1106 | Native API | 5 | 3 | 6 | 3 | 50.0% |
| Windows | T1485 | Data Destruction | 3 | 0 | 6 | 0 | 0.0% |
| Windows | T1567 | Exfiltration Over Web Service | 4 | 0 | 6 | 0 | 0.0% |
| Windows | T1095 | Non-Application Layer Protocol | 4 | 2 | 5 | 2 | 40.0% |
| Windows | T1115 | Clipboard Data | 3 | 0 | 5 | 0 | 0.0% |
| Windows | T1120 | Peripheral Device Discovery | 4 | 1 | 5 | 1 | 20.0% |
| Windows | T1486 | Data Encrypted for Impact | 4 | 0 | 5 | 0 | 0.0% |
| Windows | T1491 | Defacement | 4 | 0 | 5 | 0 | 0.0% |
| Windows | T1539 | Steal Web Session Cookie | 3 | 0 | 5 | 0 | 0.0% |
| Windows | T1572 | Protocol Tunneling | 4 | 0 | 5 | 0 | 0.0% |
| Windows | T1654 | Log Enumeration | 2 | 0 | 5 | 0 | 0.0% |
| Windows | T1056 | Input Capture | 3 | 0 | 4 | 0 | 0.0% |
| Windows | T1090 | Proxy | 3 | 0 | 4 | 0 | 0.0% |
| Windows | T1123 | Audio Capture | 2 | 0 | 4 | 0 | 0.0% |
| Windows | T1556 | Modify Authentication Process | 3 | 0 | 4 | 0 | 0.0% |
| Windows | T1563 | Remote Service Session Hijacking | 1 | 0 | 4 | 0 | 0.0% |
| Windows | T1689 | Downgrade Attack | 2 | 0 | 4 | 0 | 0.0% |
| Windows | T1072 | Software Deployment Tools | 3 | 0 | 3 | 0 | 0.0% |
| Windows | T1125 | Video Capture | 1 | 0 | 3 | 0 | 0.0% |
| Windows | T1129 | Shared Modules | 1 | 0 | 3 | 0 | 0.0% |
| Windows | T1187 | Forced Authentication | 3 | 1 | 3 | 1 | 33.3% |
| Windows | T1497 | Virtualization/Sandbox Evasion | 3 | 0 | 3 | 0 | 0.0% |
| Windows | T1566 | Phishing | 3 | 0 | 3 | 0 | 0.0% |
| Windows | T1570 | Lateral Tool Transfer | 2 | 0 | 3 | 0 | 0.0% |
| Windows | T1620 | Reflective Code Loading | 3 | 1 | 3 | 1 | 33.3% |
| Windows | T1659 | Content Injection | 1 | 0 | 3 | 0 | 0.0% |
| Windows | T1680 | Local Storage Discovery | 2 | 0 | 3 | 0 | 0.0% |
| Windows | T1690 | Prevent Command History Logging | 2 | 0 | 3 | 0 | 0.0% |
| Windows | T1001 | Data Obfuscation via Steganography | 2 | 0 | 2 | 0 | 0.0% |
| Windows | T1010 | Application Window Discovery | 1 | 0 | 2 | 0 | 0.0% |
| Windows | T1020 | Automated Exfiltration | 2 | 0 | 2 | 0 | 0.0% |
| Windows | T1037 | Boot or Logon Initialization Scripts | 1 | 0 | 2 | 0 | 0.0% |
| Windows | T1039 | Data from Network Shared Drive | 2 | 0 | 2 | 0 | 0.0% |
| Windows | T1041 | Exfiltration Over C2 Channel | 2 | 0 | 2 | 0 | 0.0% |
| Windows | T1074 | Data Staged | 2 | 0 | 2 | 0 | 0.0% |
| Windows | T1114 | Email Collection | 1 | 0 | 2 | 0 | 0.0% |
| Windows | T1195 | Supply Chain Compromise | 1 | 1 | 2 | 1 | 50.0% |
| Windows | T1688 | Safe Mode Boot | 1 | 0 | 2 | 0 | 0.0% |
| Windows | T1005 | Data from Local System | 1 | 0 | 1 | 0 | 0.0% |
| Windows | T1006 | Direct Volume Access | 1 | 0 | 1 | 0 | 0.0% |
| Windows | T1030 | Data Transfer Size Limits | 1 | 0 | 1 | 0 | 0.0% |
| Windows | T1091 | Replication Through Removable Media | 1 | 0 | 1 | 0 | 0.0% |
| Windows | T1132 | Data Encoding | 1 | 0 | 1 | 0 | 0.0% |
| Windows | T1133 | External Remote Services | 1 | 0 | 1 | 0 | 0.0% |
| Windows | T1176 | Browser Extensions | 1 | 0 | 1 | 0 | 0.0% |
| Windows | T1207 | Rogue Domain Controller | 1 | 1 | 1 | 1 | 100.0% |
| Windows | T1221 | Template Injection | 1 | 0 | 1 | 0 | 0.0% |
| Windows | T1496 | Resource Hijacking | 1 | 0 | 1 | 0 | 0.0% |
| Windows | T1542 | Pre-OS Boot | 1 | 0 | 1 | 0 | 0.0% |
| Windows | T1557 | Adversary-in-the-Middle | 1 | 0 | 1 | 0 | 0.0% |
| Windows | T1571 | Non-Standard Port | 1 | 0 | 1 | 0 | 0.0% |
| Windows | T1573 | Encrypted Channel | 1 | 0 | 1 | 0 | 0.0% |
| Windows | T1592 | Gather Victim Host Information | 1 | 0 | 1 | 0 | 0.0% |
| Windows | T1595 | Active Scanning | 1 | 0 | 1 | 0 | 0.0% |
| Windows | T1622 | Debugger Evasion | 1 | 0 | 1 | 0 | 0.0% |
| Windows | T1649 | Steal or Forge Authentication Certificates | 1 | 0 | 1 | 0 | 0.0% |
| Windows | T1652 | Device Driver Discovery | 1 | 0 | 1 | 0 | 0.0% |

## Theo rule (chỉ rule có kết quả)

| Rule | Tên | Bắt mẫu tấn công | Báo nhầm mẫu bình thường |
|---|---|---|---|
| WEB-001 | Tấn công SQL Injection | 810 | 0 |
| WEB-002 | Tấn công Cross-Site Scripting (XSS) | 752 | 0 |
| WEB-004 | Command Injection / RCE qua Web | 192 | 0 |
| WEB-003 | Path Traversal / Local File Inclusion | 97 | 0 |
| WIN-006 | Script PowerShell độc hại (download cradle / bypass AMSI / Mimikatz) | 71 | 0 |
| WIN-012 | Lạm dụng LOLBins để tải/thực thi mã | 47 | 0 |
| WIN-007 | Đánh cắp thông tin đăng nhập (Mimikatz / dump LSASS) | 32 | 0 |
| WIN-010 | Xóa Shadow Copy (dấu hiệu Ransomware) | 16 | 0 |
| WIN-013 | Tạo Scheduled Task (cơ chế duy trì truy cập) | 14 | 0 |
| LNX-003 | Tải về và thực thi script (curl/wget | sh) | 8 | 0 |
| LNX-006 | Can thiệp cơ chế duy trì (crontab / authorized_keys / systemd) | 3 | 0 |
| WIN-005 | PowerShell chạy lệnh mã hóa (-EncodedCommand) | 3 | 0 |
| LNX-001 | Reverse shell | 1 | 0 |
