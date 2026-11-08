# Lộ trình hoàn thiện repo (16/10 → 16/11/2026)

Đích: ngày 16/11/2026, `main` là bản duy nhất, chạy được trên lab máy ảo, kiểm thử đầy đủ, tài liệu khớp code, gắn tag `v1.0`.
Gồm 4 tuần làm và 4 ngày dự phòng; đóng băng tính năng ngày 09/11. File này thay cho lộ trình 4 tuần (demo 10/11) trong Claude
Doc *Kế hoạch xây dựng hệ thống SOC chuyên nghiệp*.

## 1. Hiện trạng (16/10)

| Mảng | Đã có | Còn thiếu |
|---|---|---|
| Mã nguồn | `feature/soc-unified` đã gộp mọi việc: quy trình SOC, agent Wazuh, tài khoản, cài một lệnh, sửa lỗi của `Test.md`; PR nháp #2 vào `main` | PR #2 chưa gộp; khoảng 10 nhánh cũ còn trên máy và GitHub (nội dung đã sang `soc-unified`) |
| Hệ thống đang chạy | Stack Docker chạy từ `D:\GSANM\BTL\siem-xdr` | Chạy code cũ của `feature/wazuh-auth-grafana`: chưa có FIM-001, RBA, KPI. Elasticsearch báo lỗi repository `siem-backup` còn sót từ stack cũ |
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
| 1. Hợp nhất | 16/10–22/10 | 1. Chạy lại unit test và `tools/rule_lint.py` trên `soc-unified`, gộp PR #2 vào `main`; commit kế hoạch độ phủ / AI (`RULES.md` mục 7, `AI-README.md` mục 15).<br>2. Chuyển stack sang code `main` mà giữ dữ liệu: snapshot Elasticsearch trước; `COMPOSE_PROJECT_NAME=siem-xdr` trong `.env`, `python tools/init_secrets.py`, `docker compose up -d`; gỡ đăng ký repository `siem-backup` cũ.<br>3. Xóa nhánh và worktree cũ, thư mục rỗng còn sót của repo tách riêng ngày 14/10.<br>4. Lab: chốt cách dựng của `LAB-VMWARE.md` (SIEM chạy trên máy host), vì đĩa không đủ thêm VM `siem-server`; dựng mạng, Ubuntu-01 và Web-01 từ image cloud; cài agent cho PC-01 | PR #2 đã gộp; stack chạy code mới, FIM-001 bắt đầu chạy bóng; 4/4 tài sản có log |
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
| Chuyển stack sang code mới làm mất dữ liệu: tên project Compose khác tên volume đang dùng sẽ tạo volume mới rỗng | Từ 19/10 `docker-compose.yml` đặt `name: siem-xdr`, trùng volume đang dùng; `.env` vẫn ghi `COMPOSE_PROJECT_NAME=siem-xdr`; snapshot Elasticsearch trước khi làm |
| Đĩa không đủ cho VM (C 28 GB, D 41 GB) | SIEM chạy trên máy host, không có VM `siem-server`; Ubuntu là linked clone từ image cloud; dọn snapshot của VM Kali nếu cần |
| Script Windows chặn IP / cô lập máy lỗi trên máy thật | Thử ngay tuần 2, có snapshot VM, mở màn hình VMware để tự gỡ |
| Nhiều phiên Claude cùng sửa repo | Mỗi việc một nhánh / worktree riêng, gộp qua PR, báo trước file sẽ sửa |
| Trễ tiến độ | Kiểm tra mốc mỗi cuối tuần; trễ thì cắt theo thứ tự: lô SigmaHQ, luồng AI trên stack thật, Suricata |

## 6. Kế hoạch thống nhất rule trên Wazuh (cập nhật 08/11/2026)

Kế hoạch: [docs/superpowers/plans/2026-10-31-wazuh-unified-ruleset.md](docs/superpowers/plans/2026-10-31-wazuh-unified-ruleset.md) (Task 0 đến 18) và
[docs/superpowers/plans/2026-11-06-p4-ai-wazuh-xml.md](docs/superpowers/plans/2026-11-06-p4-ai-wazuh-xml.md) (P4, Task 19 đến 26). Mô tả bộ rule:
[RULES.md](RULES.md) mục 2 và 9. Sổ quyết định: [docs/wazuh-ruleset-decisions.md](docs/wazuh-ruleset-decisions.md) (R1–R83).

| Phần | Trạng thái |
|---|---|
| Task 0 đến 17 (P0 đến P3: thử kỹ thuật, nền tảng, 10 file rule XML, tuning, báo cáo song song, thư viện rule, SOAR theo nhóm, ngoại lệ, KPI) | **Xong**, đã gộp `main`; CI xanh (603 unit test, 556 ca log gốc qua Wazuh thật lúc đó) |
| Task 18, cổng chuyển | **Đã chuyển hẳn (R65, 05/11/2026)**: engine YAML tắt, rule XML và rule gốc level 7–11 là alert thật, bỏ tiêu chí 7 ngày cho đợt chuyển; `main` 597cd5d chạy trên stack thật |
| P4, Task 19 đến 26 (Sigma → XML, sandbox Wazuh, cổng Wazuh cho rule AI, duyệt vào `ai.xml`, ngoại lệ AI, SigmaHQ lô 1 `0966-sigmahq.xml`, xóa engine YAML, tài liệu) | **Xong trên nhánh tích hợp `feature/p4-ai-xml`**, chưa gộp `main`, chưa triển khai lên stack thật. Unit test 660 đạt / 34 bỏ qua; lint 11 file 0 lỗi; E2E 43/43 trên project thử cách ly (08/11/2026). Triển khai: `DEPLOY-VM.md` mục 9.1, chỉ khi chủ dự án gộp PR và yêu cầu |
| Đổi mô hình AI | Chưa bắt đầu; `tools/bench_ai_models.py` chạy qua cổng Wazuh để so model ứng viên, chọn model là việc của chủ dự án |
| Lab (mạng 4 vùng, agent OPNsense, Ubuntu / Web-01) | Chưa dựng; rule Suricata XML cần agent OPNsense đọc `eve.json` |

Còn mở sau P4 (chi tiết ở [RULES.md](RULES.md) mục 9.10):

- Gỡ rule AI cuối cùng / ngoại lệ cuối cùng bị Wazuh từ chối (khối `<group>` rỗng), thấy khi thử trên project thử 08/11/2026.
- Thực thể XML (`&gt;`, `&lt;`, `&amp;`) trong trường Windows (Task 19c, R77); rule Linux SigmaHQ (`siem-proc`); bơm lại event thật vào sandbox (R74).
- Rule dự án `0965-windows.xml` dưới 61603 có thể bị rule gom level 0 che như ứng viên AI (R75): chưa kiểm.
- `tools/wazuh_coverage.run_wazuh`, `wazuh_noise.py`, `wazuh_rule_test.inject` vẫn dùng vòng gửi có thể mất event trên tập lớn (R80).
- Ca CI `0541-network`, `0271-web`, `0999-tuning` chưa xác nhận lại trên máy dev sau Task 24 (máy ngủ làm treo); CI GitHub phải xanh trước khi gộp.
- Đo lại độ ồn trên ≥ 24 giờ syslog và nhật ký console thật; đo lại 102505 (LNX-005) với dữ liệu giãn theo thời gian thật.
- SOAR: thêm IP proxy, relay, NAT nội bộ vào `SOAR_WHITELIST` trước khi dùng chặn IP theo rule gốc.
