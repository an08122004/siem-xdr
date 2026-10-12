# Case playbook: nguồn tham khảo và cách đưa vào hệ thống

Case playbook (`server/config/case_playbooks.yml`) là checklist xử lý sự cố mà SOAR gắn vào mỗi case. Tài liệu này ghi lại
các nguồn đã đọc (bản gốc, 12/10/2026), nguồn nào được đưa vào playbook nào, nguồn nào không và vì sao. Cách chọn playbook
và bảng phân quyền xem README mục 4.

## 1. Quy trình 5 bước của hệ thống

Hệ thống dùng vòng đời của **NIST SP 800-61r2** (bản cũ, 2012), tách bước "Containment, Eradication & Recovery" thành 3 bước
như SANS và CERT Société Générale, bỏ bước "Chuẩn bị" vì đó là việc làm trước sự cố, không nằm trong checklist của một case:

| Hệ thống | NIST SP 800-61r2 | CERT SG IRM / SANS PICERL | CISA Federal Playbook |
|---|---|---|---|
| (làm trước, xem README, DEPLOY-VM.md) | Preparation | Preparation | Preparation |
| Phát hiện & phân tích | Detection & Analysis | Identification | Detection & Analysis |
| Ngăn chặn | Containment, Eradication & Recovery | Containment | Containment |
| Loại bỏ | (cùng bước trên) | Remediation / Eradication | Eradication & Recovery |
| Khôi phục | (cùng bước trên) | Recovery | Eradication & Recovery |
| Rút kinh nghiệm | Post-Incident Activity | Lessons learned | Post-Incident Activities |

NIST SP 800-61 **Rev. 3** (4/2025) đã thay Rev. 2 bằng mô hình theo 6 chức năng của CSF 2.0 (Govern, Identify, Protect, Detect,
Respond, Recover); hệ thống vẫn giữ vòng đời 5 bước của Rev. 2 vì dễ dùng làm checklist cho từng case.

## 2. Nguồn đã rà soát

### CERT Société Générale — IRM (Incident Response Methodologies), 22 tài liệu

Repo `github.com/certsocietegenerale/IRM` (thư mục `EN/`, giấy phép CC BY 3.0, đồng tác giả CERT aDvens). Mỗi IRM là một cheat
sheet cho một loại sự cố, chia 6 bước như bảng trên.

| IRM | Đưa vào? | Playbook | Ghi chú |
|---|---|---|---|
| IRM-1 Worm Infection | Có | PB-16 | Dấu hiệu lây lan, ngăn chặn theo vùng, thử quy trình gỡ trước khi triển khai rộng, thứ tự nối mạng lại có phê duyệt |
| IRM-2 Windows Intrusion | Có | PB-03, PB-13, PB-17, PB-10 | Thu bộ nhớ trước tiên, 9 vị trí duy trì, 8 loại event log cần xem, "chỉ loại bỏ khi chắc đã khoanh vùng" |
| IRM-3 Unix/Linux Intrusion | Có | PB-03, PB-09, PB-13, PB-14, PB-08 | Tài khoản UID 0, file mồ côi / SUID / tên lạ, `lsof +L1`, PROMISC, cron, log, kiểm tra toàn vẹn gói làm sau cùng |
| IRM-4 DDoS | Có | PB-15 | Phân biệt lưu lượng, màn khói, tống tiền, chặn gần biên, ISP / scrubbing, gỡ dần biện pháp |
| IRM-5 Malicious Network Behaviour | Có | PB-18 (mới), PB-05, PB-06 | NET-004 (cảnh báo IDS) trước đây gắn nhầm vào "Tấn công Web" |
| IRM-6 Website Defacement | Có | PB-19 (mới), PB-12, PB-02 | Loại trừ nội dung bên thứ ba, quét CSDL, trang bảo trì tĩnh |
| IRM-7 Windows Malware Detection | Có | PB-03, PB-14 | Phân loại họ mã độc, gửi mẫu dạng zip có mật khẩu, xử lý máy quan trọng / không quan trọng khác nhau |
| IRM-12 Insider Abuse | Một phần | PB-04 | Trường hợp người trong nội bộ: yêu cầu bằng văn bản, pháp chế, nhân sự, không thao tác kỹ thuật khi đã xác nhận gian lận |
| IRM-16 Phishing | Có | PB-11 | Phân loại chiến dịch, lưu bằng chứng trang phishing, xóa email khỏi mọi hộp thư, theo dõi URL xuất hiện lại |
| IRM-17 Ransomware | Có | PB-07 | Giữ máy bật để thu RAM, backup 3-2-1, theo dõi trang công bố dữ liệu |
| IRM-18 Large scale compromise | Có | PB-07, PB-16, task chung | Nhóm xử lý khủng hoảng, ngăn chặn kín đáo khi chưa nắm hết điểm xâm nhập, thứ tự nối mạng lại |
| IRM-20 Red Team Detection | Một phần | Task chung | Đối chiếu với white team trước khi kết luận, không để lộ cho red team |
| IRM-21 Critical Vulnerability Prioritization | Một phần | PB-08 (SCA) | Xếp ưu tiên theo mức nghiêm trọng, khả năng khai thác, mức quan trọng tài sản; có phương án hoàn tác |
| IRM-8 Blackmail, IRM-9 Smartphone Malware, IRM-10 Social Engineering, IRM-11 Information Leakage, IRM-13 Customer Phishing, IRM-14 Scam, IRM-15 Trademark Infringement, IRM-19 3rd-party Compromise, IRM-22 Business Email Compromise | Không | — | Hệ thống không có nguồn log để phát hiện các loại này (mail server, DLP, proxy, thiết bị di động, giám sát thương hiệu). Đưa vào khi có thêm nguồn log tương ứng |

### Các nguồn khác

| Nguồn | Đưa vào playbook | Ghi chú |
|---|---|---|
| CISA — *Federal Government Cybersecurity Incident & Vulnerability Response Playbooks*, phụ lục B (checklist ~70 bước) | Task chung, PB-00 | Phân loại và chỉ định người điều phối, ghi chứng cứ (ai / khi nào / cách nào), timeline UTC, điều kiện xong từng bước, phân tích theo chiến thuật ATT&CK, họp rút kinh nghiệm |
| CISA — *#StopRansomware Guide*, Ransomware Response Checklist | PB-07 | 10 mục săn mối đe dọa (a–j), kênh liên lạc ngoài mạng, tìm máy đang ghi file trên file server, cơ chế duy trì ngoài vào / trong ra, tuyên bố kết thúc sự cố |
| CISA — Eviction Strategies CM0050 *Reset KRBTGT Password Twice* | PB-10 | Kiểm tra đồng bộ AD, đổi 2 lần cách nhau ít nhất 10 giờ, RODC làm riêng, ảnh hưởng phụ |
| Microsoft — *Password spray investigation* | PB-01, PB-09 | Phân biệt brute force / spraying, dấu hiệu "low and slow", thứ tự ưu tiên các lần đăng nhập thành công, cảnh báo IP đổi liên tục, kiểm tra người dùng chung mật khẩu. Phần riêng của Entra ID / AD FS không đưa vào |
| Microsoft — *Phishing investigation* | PB-11 | Checklist người nhận / mở / bấm / chạy payload, phân tích header (SPF / DKIM / DMARC, IP gốc), hộp thư bị chiếm (chuyển tiếp, ủy quyền, quy tắc). Phần riêng của Exchange Online không đưa vào |
| Microsoft — *App consent grant*, *Compromised and malicious applications* | Không | Chỉ áp dụng cho Microsoft 365 / Entra ID, hệ thống không giám sát các dịch vụ này |
| MITRE ATT&CK | Mọi playbook (cột `techniques`, tham khảo) | Mã kỹ thuật dùng để chọn playbook cho rule AI viết và cảnh báo ruleset Wazuh |
| Thông tư 20/2017/TT-BTTTT; Luật Bảo vệ dữ liệu cá nhân 91/2025/QH15 + Nghị định 356/2025/NĐ-CP | Task chung "nghĩa vụ báo cáo / thông báo" | Báo cáo sự cố cho cơ quan điều phối; thông báo khi lộ dữ liệu cá nhân. Kiểm tra hiệu lực văn bản với pháp chế |

## 3. Cách chuyển nội dung nguồn thành task

- Mỗi bước của nguồn thành một task ngắn (`title`) trong đúng giai đoạn ở bảng mục 1; chi tiết thực hiện (lệnh, event ID,
  vị trí trên console) đưa vào `detail`, hiện thu gọn dưới task ("Cách làm") trên console.
- Bước giống nhau ở mọi nguồn (ghi chứng cứ, timeline, xác định phạm vi, nghĩa vụ thông báo, chọn cách ngăn chặn, chỉ loại bỏ
  khi đã khoanh vùng, khôi phục từng bước, báo cáo, họp rút kinh nghiệm) đưa vào `common`, gắn vào mọi case một lần.
- Bước gắn với công cụ thương mại cụ thể (EDR, Defender XDR, Entra ID) được viết lại theo công cụ của hệ thống: Wazuh, SOAR
  (chặn IP, kill, cô lập), Điều tra thực thể, `config/intel`.
- Hành động nặng (cô lập máy, khóa tài khoản, cài lại máy, tắt dịch vụ) gắn `approval` theo bảng phân quyền.
- Mỗi playbook có `references` trỏ về nguồn gốc; case lưu kèm và console hiện ở mục "Tham khảo".

## 4. Danh sách playbook

| Playbook | Áp dụng (mã rule / MITRE / tag) | Nguồn chính |
|---|---|---|
| PB-00 Điều tra chung | còn lại | CISA phụ lục B |
| PB-01 Dò mật khẩu / password spraying | AUTH-001, AUTH-003, WIN-001, WEB-007; T1110 | Microsoft Password spray |
| PB-02 Tấn công ứng dụng Web | WEB-* còn lại; T1190, T1595.002 | IRM-6 |
| PB-03 Mã độc / hành vi độc hại trên endpoint | LNX-* còn lại, WIN-005/006/011/012; T1059, T1105, T1218, T1027, T1082; tag virustotal, yara | IRM-7, IRM-2, IRM-3 |
| PB-04 Thay đổi tài khoản / đặc quyền | WIN-003/004, AUTH-005/006; T1136, T1098, T1548 | IRM-12 |
| PB-05 Trinh sát / quét mạng | NET-001..003; T1046, T1595, T1590 | IRM-5 |
| PB-06 Kết nối tới IOC | TI-001; T1071, T1568, T1573 | IRM-5 |
| PB-07 Ransomware | WIN-010; T1486, T1490 | IRM-17, IRM-18, CISA #StopRansomware |
| PB-08 FIM / rootkit / SCA | tag syscheck, rootcheck, sca; T1565, T1014 | IRM-3, IRM-21 |
| PB-09 Tài khoản bị chiếm | AUTH-002, AUTH-004; T1078 | Microsoft Password spray, IRM-3 |
| PB-10 Đánh cắp thông tin đăng nhập | WIN-007; T1003, T1555, T1552, T1558 | CISA CM0050, Microsoft forest recovery, IRM-2 |
| PB-11 Phishing / tài liệu độc hại | WIN-008; T1566, T1204 | IRM-16, Microsoft Phishing |
| PB-12 Webshell | WEB-008, LNX-002, WZH-100100; T1505.003 | IRM-6, IRM-3 |
| PB-13 Cơ chế duy trì | LNX-006, WIN-009, WIN-013; T1053, T1543, T1547, T1546, T1098.004 | IRM-2, IRM-3 |
| PB-14 Đào tiền ảo | LNX-004; T1496 | IRM-3, IRM-7 |
| PB-15 DoS / DDoS | WEB-009; T1498, T1499 | IRM-4 |
| PB-16 Di chuyển ngang / sâu mạng | NET-005; T1021, T1570, T1210, T1550 | IRM-1, IRM-18 |
| PB-17 Xóa dấu vết / tắt phòng thủ | WIN-002; T1070, T1562 | IRM-2 |
| PB-18 Hành vi mạng độc hại / cảnh báo IDS (mới) | NET-004; tag suricata, ids | IRM-5 |
| PB-19 Thay đổi nội dung website (mới) | WZH-100101; T1491 | IRM-6 |

## 5. Nguồn

- CERT Société Générale, Incident Response Methodologies: https://github.com/certsocietegenerale/IRM
- CISA, Federal Government Cybersecurity Incident and Vulnerability Response Playbooks: https://www.cisa.gov/sites/default/files/2024-08/Federal_Government_Cybersecurity_Incident_and_Vulnerability_Response_Playbooks_508C.pdf
- CISA, #StopRansomware Guide: https://www.cisa.gov/stopransomware/ransomware-guide
- CISA, CM0050 Reset KRBTGT Password Twice: https://www.cisa.gov/eviction-strategies-tool/info-countermeasures/CM0050
- Microsoft, Reset the krbtgt password (AD forest recovery): https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password
- Microsoft, Incident response playbooks: https://learn.microsoft.com/en-us/security/operations/incident-response-playbooks
- NIST SP 800-61r3 (thông báo phát hành): https://www.nist.gov/news-events/news/2025/04/nist-revises-sp-800-61-incident-response-recommendations-and-considerations
- MITRE ATT&CK: https://attack.mitre.org/
