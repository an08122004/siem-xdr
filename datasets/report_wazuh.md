# Độ phủ ruleset gốc Wazuh 4.14.7 so với rule tự viết

Sinh bởi `tools/wazuh_coverage.py`: dataset được bơm vào hàng đợi analysisd của một wazuh-manager tạm (ruleset gốc, không rule tùy chỉnh), đúng định dạng agent gửi. Một event được tính là Wazuh **bắt** khi alert có level ≥ ngưỡng (Wazuh tự ghi alert từ level 3; rule tấn công web của Wazuh đều ở level 6). Cột **Wazuh cụ thể** bỏ các rule khớp theo cấu trúc chung chung (bảng cuối), chỉ giữ phát hiện theo hành vi.

## Tổng quan

| Lĩnh vực | Mẫu tấn công | Wazuh mọi alert (≥ 3) | Wazuh ≥ 7 | **Wazuh cụ thể** | **Rule tự viết** | **Hợp (Wazuh cụ thể + tự viết)** | Báo nhầm Wazuh ≥ 3 / cụ thể | Báo nhầm tự viết |
|---|---|---|---|---|---|---|---|---|
| Web (CSIC 2010) | 15,088 | 5.8% | 0.0% | **5.8%** | **11.0%** | **11.8%** | 0/36,000 / 0/36,000 | 0/36,000 |
| Windows (Atomic Red Team) | 2,218 | 40.8% | 11.0% | **8.0%** | **5.7%** | **13.5%** | 16/102 / 14/102 | 1/102 |
| Linux (Atomic Red Team) | 1,146 | 98.9% | 0.0% | **0.3%** | **1.0%** | **1.3%** | 88/94 / 1/94 | 0/94 |

## Rule Wazuh khớp nhiều nhất

Cột *bình thường* cho biết rule có thật sự phân biệt được tấn công hay chỉ ghi nhận mọi event cùng loại.

| Lĩnh vực | Rule | Level | Mô tả | Mẫu tấn công | Mẫu bình thường | Chung chung? |
|---|---|---|---|---|---|---|
| web | 31164 | 6 | SQL injection attempt. | 481 | 0 |  |
| web | 31106 | 6 | A web attack returned code 200 (success). | 388 | 0 |  |
| windows | 92032 | 3 | Suspicious Windows cmd shell execution | 450 | 0 | có |
| windows | 92041 | 10 | Value added to registry key has Base64-like pattern | 223 | 2 | có |
| windows | 92021 | 3 | Powershell was used to delete files or directories | 102 | 2 |  |
| windows | 92036 | 3 | A C:\\Windows\\System32\\net.exe binary was started by a Windows cmd shell | 55 | 0 | có |
| windows | 92052 | 4 | Windows command prompt started by an abnormal process | 28 | 5 |  |
| windows | 92027 | 4 | Powershell process spawned powershell instance | 8 | 0 |  |
| windows | 92034 | 3 | Discovery activity spawned via cmd shell execution | 4 | 0 |  |
| windows | 92043 | 10 | Netsh used to add firewall rule | 4 | 1 |  |
| windows | 92074 | 12 | Curl.exe launched with commands to create a binary file | 4 | 0 |  |
| windows | 92033 | 3 | Discovery activity spawned via powershell execution | 4 | 0 |  |
| windows | 92029 | 6 | Powershell executed script from suspicious location | 3 | 0 |  |
| windows | 92035 | 3 | A net.exe domain discovery command was executed | 2 | 0 |  |
| linux | 80792 | 3 | Audit: Command: /usr/bin/sleep. | 1,130 | 87 | có |
| linux | 92604 | 6 | Processes running for all users were queried with ps command. | 2 | 1 |  |
| linux | 92601 | 6 | Executed python script from /tmp/ folder. | 1 | 0 |  |

## Web theo loại tấn công (Wazuh level ≥ 3)

| Loại | Mẫu | Wazuh | Tự viết | Hợp | Chỉ Wazuh bắt | Chỉ tự viết bắt | Rule Wazuh khớp |
|---|---|---|---|---|---|---|---|
| Tham số lạ (riêng ứng dụng) (`unknown-param`) | 3,565 | 0.0% | 0.0% | 0.0% | 0 | 0 |  |
| Giá trị sai định dạng (riêng ứng dụng) (`invalid-value`) | 2,693 | 0.0% | 0.0% | 0.0% | 0 | 0 |  |
| Dò file sao lưu / mã nguồn (`backup-file`) | 2,615 | 0.0% | 0.0% | 0.0% | 0 | 0 |  |
| Đường dẫn không tồn tại (riêng ứng dụng) (`unknown-resource`) | 2,008 | 0.0% | 0.0% | 0.0% | 0 | 0 |  |
| SQL Injection (`sqli`) | 1,202 | 48.5% | 67.4% | 77.7% | 124 | 351 | 31164 (481), 31106 (102) |
| Dò tài nguyên nhạy cảm / mặc định (`sensitive-path`) | 885 | 0.0% | 0.0% | 0.0% | 0 | 0 |  |
| Cross-Site Scripting (`xss`) | 752 | 38.0% | 100.0% | 100.0% | 0 | 466 | 31106 (286) |
| CRLF / chèn header (`crlf`) | 540 | 0.0% | 0.0% | 0.0% | 0 | 0 |  |
| Mã hóa né tránh (kép / null byte) (`encoding-evasion`) | 466 | 0.0% | 0.0% | 0.0% | 0 | 0 |  |
| Server-Side Include injection (`ssi`) | 362 | 0.0% | 26.8% | 26.8% | 0 | 97 |  |

## Windows (Atomic Red Team) theo kỹ thuật (Wazuh cụ thể, theo bài thử)

Một bài thử được tính là bị bắt khi ít nhất 1 tiến trình của nó bị bắt.

| Kỹ thuật | Tên | Bài thử | Wazuh | Tự viết | Hợp |
|---|---|---|---|---|---|
| **Tổng** | 133 kỹ thuật | 1,251 | 12.8% | 8.4% | 20.9% |
| Kỹ thuật có ≥ 1 bài thử bị bắt | | | 62 | 37 | 76 |
| T1112 | Modify Registry | 92 | 3 | 0 | 3 |
| T1218 | Signed Binary Proxy Execution | 81 | 2 | 4 | 6 |
| T1685 | Disable or Modify Tools | 66 | 17 | 1 | 18 |
| T1003 | OS Credential Dumping | 44 | 6 | 9 | 15 |
| T1547 | Boot or Logon Autostart Execution | 44 | 4 | 1 | 5 |
| T1546 | Event Triggered Execution | 42 | 7 | 0 | 7 |
| T1059 | Command and Scripting Interpreter | 37 | 6 | 4 | 10 |
| T1082 | System Information Discovery | 29 | 0 | 10 | 10 |
| T1105 | Ingress Tool Transfer | 29 | 4 | 3 | 7 |
| T1548 | Abuse Elevation Control Mechanism | 28 | 3 | 4 | 7 |
| T1055 | Process Injection | 26 | 1 | 2 | 3 |
| T1087 | Account Discovery | 26 | 0 | 1 | 1 |
| T1070 | Indicator Removal on Host | 25 | 6 | 0 | 6 |
| T1555 | Credentials from Password Stores | 25 | 3 | 7 | 10 |
| T1564 | Hide Artifacts | 23 | 2 | 1 | 3 |
| T1552 | Unsecured Credentials | 22 | 4 | 7 | 11 |
| T1027 | Obfuscated Files or Information | 19 | 4 | 0 | 4 |
| T1069 | Permission Groups Discovery | 19 | 0 | 0 | 0 |
| T1018 | Remote System Discovery | 16 | 2 | 0 | 2 |
| T1036 | Masquerading | 16 | 2 | 1 | 3 |
| T1021 | Remote Services | 15 | 4 | 0 | 4 |
| T1053 | Scheduled Task/Job | 15 | 1 | 7 | 7 |
| T1219 | Remote Access Software | 15 | 0 | 0 | 0 |
| T1137 | Office Application Startup | 14 | 7 | 0 | 7 |
| T1204 | User Execution | 14 | 2 | 0 | 2 |
| T1518 | Software Discovery | 14 | 1 | 3 | 4 |
| T1574 | Hijack Execution Flow | 14 | 3 | 0 | 3 |
| T1686 | Disable or Modify System Firewall | 14 | 4 | 0 | 4 |
| T1016 | System Network Configuration Discovery | 13 | 1 | 0 | 1 |
| T1134 | Access Token Manipulation | 13 | 1 | 2 | 3 |
| T1558 | Steal or Forge Kerberos Tickets | 13 | 5 | 5 | 10 |
| T1047 | Windows Management Instrumentation | 12 | 0 | 1 | 1 |
| T1110 | Brute Force | 12 | 3 | 1 | 4 |
| T1490 | Inhibit System Recovery | 12 | 0 | 4 | 4 |
| T1098 | Account Manipulation | 10 | 7 | 0 | 7 |
| T1046 | Network Service Discovery | 9 | 0 | 4 | 4 |
| T1057 | Process Discovery | 9 | 0 | 0 | 0 |
| T1135 | Network Share Discovery | 9 | 2 | 1 | 3 |
| T1222 | File and Directory Permissions Modification | 9 | 1 | 0 | 1 |
| T1553 | Subvert Trust Controls | 9 | 0 | 0 | 0 |
| … | 93 kỹ thuật ít bài thử hơn | | | | |

## Linux (Atomic Red Team) theo kỹ thuật (Wazuh cụ thể, theo bài thử)

Một bài thử được tính là bị bắt khi ít nhất 1 tiến trình của nó bị bắt.

| Kỹ thuật | Tên | Bài thử | Wazuh | Tự viết | Hợp |
|---|---|---|---|---|---|
| **Tổng** | 76 kỹ thuật | 414 | 0.7% | 2.9% | 3.6% |
| Kỹ thuật có ≥ 1 bài thử bị bắt | | | 3 | 7 | 10 |
| T1552 | Unsecured Credentials | 37 | 0 | 0 | 0 |
| T1685 | Disable or Modify Tools | 29 | 0 | 0 | 0 |
| T1059 | Command and Scripting Interpreter | 21 | 0 | 3 | 3 |
| T1070 | Indicator Removal on Host | 20 | 0 | 0 | 0 |
| T1548 | Abuse Elevation Control Mechanism | 16 | 0 | 0 | 0 |
| T1222 | File and Directory Permissions Modification | 13 | 0 | 0 | 0 |
| T1686 | Disable or Modify System Firewall | 13 | 0 | 0 | 0 |
| T1546 | Event Triggered Execution | 12 | 0 | 0 | 0 |
| T1529 | System Shutdown/Reboot | 10 | 0 | 0 | 0 |
| T1003 | OS Credential Dumping | 9 | 0 | 0 | 0 |
| T1027 | Obfuscated Files or Information | 9 | 0 | 0 | 0 |
| T1560 | Archive Collected Data | 9 | 0 | 0 | 0 |
| T1569 | System Services | 9 | 0 | 0 | 0 |
| T1690 | Prevent Command History Logging | 9 | 0 | 0 | 0 |
| T1040 | Network Sniffing | 8 | 0 | 0 | 0 |
| T1053 | Scheduled Task/Job | 8 | 0 | 2 | 2 |
| T1082 | System Information Discovery | 8 | 0 | 0 | 0 |
| T1087 | Account Discovery | 8 | 0 | 0 | 0 |
| T1105 | Ingress Tool Transfer | 8 | 0 | 1 | 1 |
| T1140 | Deobfuscate/Decode Files or Information | 8 | 0 | 0 | 0 |
| T1018 | Remote System Discovery | 7 | 0 | 0 | 0 |
| T1036 | Masquerading | 7 | 0 | 0 | 0 |
| T1048 | Exfiltration Over Alternative Protocol | 7 | 0 | 0 | 0 |
| T1055 | Process Injection | 6 | 0 | 0 | 0 |
| T1056 | Input Capture | 6 | 0 | 0 | 0 |
| T1136 | Create Account | 6 | 0 | 0 | 0 |
| T1078 | Valid Accounts | 5 | 0 | 0 | 0 |
| T1110 | Brute Force | 5 | 0 | 3 | 3 |
| T1201 | Password Policy Discovery | 5 | 0 | 0 | 0 |
| T1489 | Service Stop | 5 | 0 | 0 | 0 |
| T1572 | Protocol Tunneling | 5 | 0 | 0 | 0 |
| T1614 | System Location Discovery | 5 | 0 | 0 | 0 |
| T1014 | Rootkit | 4 | 0 | 0 | 0 |
| T1113 | Screen Capture | 4 | 0 | 0 | 0 |
| T1486 | Data Encrypted for Impact | 4 | 0 | 0 | 0 |
| T1543 | Create or Modify System Process | 4 | 0 | 0 | 0 |
| T1046 | Network Service Discovery | 3 | 0 | 0 | 0 |
| T1049 | System Network Connections Discovery | 3 | 0 | 0 | 0 |
| T1083 | File and Directory Discovery | 3 | 0 | 0 | 0 |
| T1497 | Virtualization/Sandbox Evasion | 3 | 0 | 0 | 0 |
| … | 36 kỹ thuật ít bài thử hơn | | | | |

## Báo nhầm của Wazuh cụ thể trên lệnh bình thường endpoint

| Lĩnh vực | Rule | Level | Mô tả | Lệnh bình thường bị bắt |
|---|---|---|---|---|
| windows | 92052 | 4 | Windows command prompt started by an abnormal process | `C:\Windows\system32\cmd.exe /c "C:\Scripts\backup.bat"` |
| windows | 92037 | 3 | A net.exe connection to a remote resource was started by C:\\Windows\\ | `net use Z: \\fileserver\share /persistent:yes` |
| windows | 92031 | 3 | Discovery activity executed | `net start` |
| windows | 92031 | 3 | Discovery activity executed | `net time \\dc01` |
| windows | 92043 | 10 | Netsh used to add firewall rule | `netsh advfirewall firewall add rule name="Allow MyApp 8080" dir=in action=allow protocol=TCP localport=8080` |
| windows | 92021 | 3 | Powershell was used to delete files or directories | `powershell.exe -Command "Get-ChildItem -Path C:\Logs -Filter *.log \| Where-Object LastWriteTime -lt (Get-Date` |
| windows | 92021 | 3 | Powershell was used to delete files or directories | `powershell.exe -Command "Invoke-WebRequest -Uri https://download.company.local/agent.msi -OutFile C:\Temp\agen` |
| windows | 92031 | 3 | Discovery activity executed | `net stop wuauserv` |
| windows | 92031 | 3 | Discovery activity executed | `net localgroup administrators` |
| windows | 92039 | 3 | A net.exe account discovery command was initiated | `net user lan /domain` |
| windows | 92052 | 4 | Windows command prompt started by an abnormal process | `cmd.exe /c del /q /s C:\Windows\Temp\*.tmp` |
| windows | 92052 | 4 | Windows command prompt started by an abnormal process | `"C:\Windows\system32\cmd.exe" /c "echo %DATE% %TIME% >> C:\Logs\login.log & net use"` |
| windows | 92052 | 4 | Windows command prompt started by an abnormal process | `cmd.exe /c reg add "HKCU\Software\MyApp\Settings" /v FirstRun /t REG_DWORD /d 0 /f` |
| windows | 92052 | 4 | Windows command prompt started by an abnormal process | `cmd.exe /c "timeout /t 2 & start "" "C:\Program Files\MyApp\MyApp.exe""` |
| linux | 92604 | 6 | Processes running for all users were queried with ps command. | `ps aux` |

## Rule Wazuh khớp theo cấu trúc chung chung (không tính vào cột Wazuh cụ thể)

| Rule | Vì sao không tính là phát hiện | Mẫu tấn công | Mẫu bình thường |
|---|---|---|---|
| 80792 | ghi nhận MỌI lệnh auditd có key audit-wazuh-c (89/94 lệnh bình thường cũng khớp) | 1,130 | 87 |
| 92032 | mọi tiến trình con có cha là `cmd.exe /c` (script, trình cài đặt cũng vậy) | 450 | 0 |
| 92036 | `net.exe` có cha là `cmd.exe /c` (con của 92032) | 55 | 0 |
| 92041 | regex `add.+\/d\s+(")?(?:[A-Za-z\d+\/]{4})*(...)?`: mọi nhóm sau `/d` đều tùy chọn nên khớp MỌI `reg add ... /d`, không riêng giá trị Base64 | 223 | 2 |

## Giới hạn của phép đo

- Event Windows là Sysmon EventID 1 dựng lại từ lệnh của bài thử Atomic Red Team: không có hash, OriginalFileName lấy theo tên file, Description / Company để trống, không có event khác (registry, file, network, PowerShell script block) — rule Wazuh dựa trên các trường / event đó không có cơ hội khớp. Rule tự viết cũng chịu cùng giới hạn.
- Linux dùng auditd với key `audit-wazuh-c` (Wazuh hướng dẫn cấu hình để ghi lệnh của root). Hệ thống hiện tại thu tiến trình Linux bằng script `siem-procs` (định dạng riêng) — ruleset gốc Wazuh không có rule nào cho định dạng đó.
- Tiến trình con trong tập lệnh bình thường Windows có dòng lệnh cha là đường dẫn chương trình (gõ tay), còn tiến trình con của bài thử Atomic có cha `cmd.exe /c ...` — rule 92032 / 92036 phân biệt hai bên chỉ nhờ điểm này.
- Mỗi event được xử lý độc lập; rule tần suất (nhiều lần trong khoảng thời gian) hầu như không kích hoạt vì mỗi request CSIC có IP riêng.
