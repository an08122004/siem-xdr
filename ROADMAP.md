# Lộ trình hoàn thiện repo (16/10 → 16/11/2026)

Đích: ngày 16/11/2026, `main` là bản duy nhất, chạy được trên lab máy ảo, kiểm thử đầy đủ, tài liệu khớp code, gắn tag `v1.0`.
Gồm 4 tuần làm và 4 ngày dự phòng; đóng băng tính năng ngày 09/11. File này thay cho lộ trình 4 tuần (demo 10/11) trong Claude
Doc *Kế hoạch xây dựng hệ thống SOC chuyên nghiệp*.

## 1. Hiện trạng (16/10)

| Mảng | Đã có | Còn thiếu |
|---|---|---|
| Mã nguồn | `feature/soc-unified` đã gộp mọi việc: SOC Platform, agent Wazuh, tài khoản, cài một lệnh, sửa lỗi của `Test.md`; PR nháp #2 vào `main` | PR #2 chưa gộp; khoảng 10 nhánh cũ còn trên máy và GitHub (nội dung đã sang `soc-unified`) |
| Hệ thống đang chạy | Stack Docker chạy từ `D:\GSANM\BTL\siem-xdr` | Chạy code cũ của `feature/wazuh-auth-grafana`: chưa có FIM-001, RBA, KPI. Elasticsearch báo lỗi repository `siem-backup` còn sót từ soc-platform |
| Kiểm thử | Unit, E2E 44/44, UI 26/26 đạt trên máy demo (`Test.md`, 15/10) | Chưa chạy với agent thật; profile `ai` chưa thử; script Windows chặn IP / cô lập máy chưa chạy trên máy thật |
| Lab | VM firewall OPNsense (14/10), VM Windows 10 (16/10), image Ubuntu cloud, Kali | Ubuntu-01, Web-01, mạng 4 vùng, agent. Đĩa trống: C 28 GB, D 41 GB |
| Độ phủ | 10/12 kỹ thuật ưu tiên | T1547 (FIM-001 chưa chạy bóng trên hệ thống thật), T1486 |
| AI | Pipeline Sigma và kiểm định; 28 đề xuất chờ duyệt (11/10) | Chưa rule AI nào chạy thật |
| Tài liệu | README, DEPLOY-VM, LAB-VMWARE, SOC-OPERATIONS, RULES, AI-README, PLAYBOOKS, Test.md | Hai cách dựng lab chưa chốt; số liệu giữa các file lệch nhau |

## 2. Thế nào là "hoàn thiện" (nghiệm thu 16/11)

- [ ] `main` là bản duy nhất: PR #2 đã gộp, nhánh cũ đã xóa, CI GitHub Actions xanh
- [ ] Stack chạy code của `main` và vẫn giữ dữ liệu cũ
- [ ] 4/4 tài sản trong `BTL/asset.txt` gửi log; 9/9 bước kiểm thử (`DEPLOY-VM.md` mục 6) đạt trên lab, gồm chặn IP và cô lập máy Windows
- [ ] Unit, E2E, UI test đạt trên bản `main` cuối cùng; `Test.md` ghi kết quả mới
- [ ] 12/12 kỹ thuật ưu tiên có rule chạy chính thức; độ phủ dataset được đo lại và ghi vào `RULES.md` mục 4
- [ ] Luồng AI chạy trọn trên stack thật: đề xuất → duyệt → chạy bóng
- [ ] Tài liệu khớp code: một cách dựng lab chuẩn; số liệu thống nhất giữa README, RULES, AI-README, SOC-OPERATIONS
- [ ] Tag `v1.0` kèm ghi chú phát hành

## 3. Lịch

| Tuần | Thời gian | Việc | Mốc cuối tuần |
|---|---|---|---|
| 1. Hợp nhất | 16/10–22/10 | 1. Chạy lại unit test và `tools/rule_lint.py` trên `soc-unified`, gộp PR #2 vào `main`; commit kế hoạch độ phủ / AI (`RULES.md` mục 7, `AI-README.md` mục 15).<br>2. Chuyển stack sang code `main` mà giữ dữ liệu: snapshot Elasticsearch trước; `COMPOSE_PROJECT_NAME=siem-xdr` trong `.env` (hoặc `python tools/migrate_project.py --apply`), `python tools/init_secrets.py`, `docker compose up -d`; gỡ đăng ký repository `siem-backup` cũ.<br>3. Xóa nhánh và worktree cũ, thư mục rỗng `D:\GSANM\BTL\soc-platform`.<br>4. Lab: chốt cách dựng của `LAB-VMWARE.md` (SIEM chạy trên máy host), vì đĩa không đủ thêm VM `siem-server`; dựng mạng, Ubuntu-01 và Web-01 từ image cloud; cài agent cho PC-01 | PR #2 đã gộp; stack chạy code mới, FIM-001 bắt đầu chạy bóng; 4/4 tài sản có log |
| 2. Chạy thật trên lab | 23/10–29/10 | 1. Chạy 9 bước kiểm thử trên lab; thử script Windows chặn IP / cô lập máy (chụp snapshot trước).<br>2. Cho log OPNsense, Suricata thật đi qua parser, sửa nếu lệch định dạng.<br>3. Độ phủ đợt 1 (`RULES.md` mục 7): rule T1486 chạy bóng; cảnh báo web level 6 của Wazuh thành alert `low`.<br>4. Bắt đầu thu log hoạt động bình thường của lab.<br>5. Bật profile `ai`; Detection Engineer duyệt hoặc loại hết hàng chờ đề xuất | 9/9 bước đạt; T1486 chạy bóng; hàng chờ AI về 0 |
| 3. Độ phủ và AI | 30/10–05/11 | 1. Bật chính thức FIM-001 và T1486 khi đủ 7 ngày chạy bóng không báo nhầm → KPI 12/12.<br>2. Đo trước độ phủ nếu nhập SigmaHQ (việc 2.1); bộ biên dịch Sigma thêm 6 loại log (việc 2.2).<br>3. Nhập lô SigmaHQ đầu tiên, tối đa 30 rule, chạy bóng.<br>4. Một đề xuất AI đã duyệt vào chạy bóng trên stack thật | KPI 12/12; có số đo SigmaHQ; lô 1 chạy bóng |
| 4. Ổn định, tài liệu | 06/11–12/11 | 1. 09/11 đóng băng tính năng, từ đó chỉ sửa lỗi.<br>2. Bật các rule của lô 1 đạt tiêu chí chạy bóng (12/11).<br>3. Chạy lại toàn bộ unit / E2E / UI trên lab, cập nhật `Test.md`.<br>4. Rà tài liệu: README tổng quan, một cách dựng lab chuẩn, số liệu của RULES / AI-README / SOC-OPERATIONS | Mọi bộ test xanh trên lab; tài liệu rà xong |
| Nghiệm thu | 13/11–16/11 | Tổng duyệt kịch bản demo 8 bước và quay video; chỉ sửa lỗi chặn; viết ghi chú phát hành; gắn tag `v1.0` trên `main` | Đủ mọi mục ở phần 2 |

## 4. Không làm trong đợt này

- Phần lớn đợt 2–3 của kế hoạch độ phủ: nhập SigmaHQ quy mô lớn, Linux, 4 loại tấn công web, Collection / Exfiltration (`RULES.md` mục 7).
- Giai đoạn 1–4 của kế hoạch AI (`AI-README.md` mục 15).
- Đổi tên repo trên GitHub; các phần của SOC thật trong kế hoạch SOC: cụm HA, Velociraptor, Keycloak, MISP thật.

## 5. Rủi ro

| Rủi ro | Cách giảm |
|---|---|
| Chuyển stack sang code mới làm mất dữ liệu: `soc-unified` đặt tên project Compose là `soc-platform`, chạy thẳng sẽ tạo volume mới rỗng | Giữ `COMPOSE_PROJECT_NAME=siem-xdr` hoặc chạy `tools/migrate_project.py --apply`; snapshot Elasticsearch trước khi làm |
| Đĩa không đủ cho VM (C 28 GB, D 41 GB) | SIEM chạy trên máy host, không có VM `siem-server`; Ubuntu là linked clone từ image cloud; dọn snapshot của VM Kali nếu cần |
| Script Windows chặn IP / cô lập máy lỗi trên máy thật | Thử ngay tuần 2, có snapshot VM, mở màn hình VMware để tự gỡ |
| Nhiều phiên Claude cùng sửa repo | Mỗi việc một nhánh / worktree riêng, gộp qua PR, báo trước file sẽ sửa |
| Trễ tiến độ | Kiểm tra mốc mỗi cuối tuần; trễ thì cắt theo thứ tự: lô SigmaHQ, luồng AI trên stack thật, Suricata |
