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

## 6. Kế hoạch thống nhất rule trên Wazuh (cập nhật 05/11/2026)

Kế hoạch: [docs/superpowers/plans/2026-10-31-wazuh-unified-ruleset.md](docs/superpowers/plans/2026-10-31-wazuh-unified-ruleset.md). Mô tả bộ rule: [RULES.md](RULES.md) mục 9. Sổ quyết định: [docs/wazuh-ruleset-decisions.md](docs/wazuh-ruleset-decisions.md).

| Phần | Trạng thái |
|---|---|
| Task 0 đến 17 (P0 đến P3: thử kỹ thuật, nền tảng, 10 file rule XML chạy bóng, tuning, báo cáo song song, thư viện rule, SOAR theo nhóm, ngoại lệ, KPI) | **Xong trên nhánh `feature/wazuh-unified-ruleset`**; CI xanh (596 unit test, 539 ca log gốc qua Wazuh thật). Bốn bước cần stack thật còn hoãn (parity, E2E, ngoại lệ thật, đo độ ồn syslog + console) |
| Task 18, cổng chuyển (tắt engine YAML) | **Chờ người dùng quyết**: chưa triển khai nhánh lên stack thật, chưa tắt engine YAML. Nếu không đạt, giữ YAML bật + XML bóng cho demo 10/11 và chuyển sau 16/11 |
| Task 19 đến 24 (P4: Sigma → XML, kiểm định AI trên Wazuh, triển khai rule AI dạng XML, SigmaHQ → XML, xóa engine YAML, viết lại tài liệu) | Sau 17/11, **chưa lập kế hoạch chi tiết** |
| Đổi mô hình AI | Chưa bắt đầu |
| Lab (mạng 4 vùng, agent OPNsense, Ubuntu / Web-01) | Chưa dựng; rule Suricata XML cần agent OPNsense đọc `eve.json` |

Checklist Task 18 (tóm tắt, bản đầy đủ trong kế hoạch):

- Điều kiện đo: mọi mã `convert` có `only_yaml` = 0 trên ca test và 24 giờ log lab; độ ồn ≤ 1 alert / 100 event bình thường; E2E 44/44 với SOAR theo playbook mới.
- Người dùng quyết: TI-001 domain và hash chỉ có ở analyzer (Wazuh mới phủ IP).
- Đo lại 102505 (LNX-005) với dữ liệu giãn theo thời gian thật trước khi bật.
- Rule AI: pipeline AI vẫn ghi rule YAML vào `server/rules/ai`; tắt engine YAML thì rule AI không chạy, nên phải đổi đích sang `rules-dynamic/ai.xml` (dải 109000) trước, hoặc giữ engine cho rule AI.
- SOAR: hành động phá hủy chỉ theo id đã duyệt (sshd 5712, 5720, 5763; web 31152; 104095; bản XML của mã YAML từng chặn); thêm IP proxy, relay, NAT nội bộ vào `SOAR_WHITELIST` trước khi bật.
- Bỏ nhóm `shadow` ở các file 0101 đến 0106 và 0845 (trừ rule có `shadow_since` dưới 7 ngày); `RULE_ENGINE_ENABLED=false`; xóa playbook theo mã YAML.

