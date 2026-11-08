# Sổ quyết định: bộ rule Wazuh XML thống nhất

Bản cô đọng, lâu dài của các ruling R1 đến R65 và các phát hiện chính khi làm kế hoạch
[2026-10-31-wazuh-unified-ruleset.md](superpowers/plans/2026-10-31-wazuh-unified-ruleset.md) (Task 0 đến 18, nhánh `feature/wazuh-unified-ruleset`),
và R66 đến R83 của kế hoạch P4 [2026-11-06-p4-ai-wazuh-xml.md](superpowers/plans/2026-11-06-p4-ai-wazuh-xml.md) (Task 19 đến 26: rule AI và
SigmaHQ ra Wazuh XML, xóa engine YAML), ở mục 10.
Cách đọc: mỗi dòng là *quyết định, vì sao, nơi thấy trong code*. Ruling R1 đến R64 là tạm thời tới cổng chuyển (Task 18, R65).
Engine YAML đã bị xóa ở Task 25 (P4): dòng nào còn nhắc rule YAML là lịch sử.
Mô tả bộ rule và cách dùng: [RULES.md](../RULES.md) mục 9. Khi sổ này và mã nguồn lệch nhau, mã nguồn đúng.

## 1. Quy trình và phạm vi

| R | Quyết định | Vì sao | Thấy ở |
|---|---|---|---|
| R4 | Task 13 và 16 làm trọn code, test đơn vị và thử trên project thử; phần chạy trên stack thật hoãn tới cổng | Triển khai lên stack thật là tác dụng phụ ngoài worktree | kế hoạch Task 13, 16; docstring `wazuh_exceptions.py` |
| R5 | Task 18 là điểm dừng, hỏi người dùng; không tự tắt engine YAML | Đổi hành vi hệ thống thật | kế hoạch Task 18 |
| R6 | Lượt thực thi gồm Task 0 đến 17; Task 19 đến 24 (P4) cần kế hoạch riêng | Kế hoạch tự nói vậy | kế hoạch P4 |
| R7 | Mọi bước Docker chạy trên project thử riêng | Compose có `name: siem-xdr`, chạy nhầm sẽ đè stack thật | môi trường thử |
| R8 | Đẩy nhánh lên origin sau Task 3 để CI chạy, không tạo PR | CI có `push: feature/**` | `.github/workflows/ci.yml` |
| R9 | Giữ hai mặc định của kế hoạch: cổng 08/11; mã alert `WZH-<id>` + mã cũ ở đầu description | Người dùng không phản đối | `detection/alerts.py`, lint |
| R10 | Mạng `soc` của project thử đặt tên riêng | Compose đặt cứng `soc-lab`, trùng alias `wazuh-manager` với stack thật | môi trường thử |
| R19 | Không ghi đường dẫn workspace vào tài liệu repo | Tài liệu repo không phụ thuộc máy dev | |
| R46 | Chạy song song các task độc lập, mỗi task một worktree và nhánh, gộp bằng merge commit | Tăng tốc; không rebase nhánh đã push | lịch sử git |
| R39 | Gộp `main` vào nhánh bằng merge commit | Nhánh đã push, không force-push | lịch sử git |

## 2. Nạp rule, API và thư mục động

| R | Quyết định | Vì sao | Thấy ở |
|---|---|---|---|
| R1 | `write_dynamic` kiểm bằng `parse()` cục bộ, ghi file tạm rồi đổi tên nguyên tử, rồi `reload()`; reload lỗi thì khôi phục file cũ và reload lại, raise `WazuhRuleError` | Logtest không chắc nạp file tạm; cách này kiểm được và quay lui được | `server/siem/wazuh_rules.py` |
| R11 | `WazuhApi.reload()` xét `error`, `failed_items` và `msg`, không xét HTTP status; `msg` khác "Ruleset reload request sent successfully." là lỗi | Wazuh âm thầm bỏ rule trùng id hoặc sai `if_sid`, HTTP vẫn 200 (S1) | `wazuh_rules.py` |
| R12 | `10-siem-setup.sh` mỗi lần khởi động: tạo `rules-dynamic` cho user 10001, chạy `wazuh-analysisd -t`, lỗi thì chuyển file sang `rules-dynamic.quarantine/` | File AI hoặc ngoại lệ hỏng không được làm manager không khởi động (S1, S2) | `wazuh/manager/entrypoint/10-siem-setup.sh` |
| R13 | Bỏ mount `local_rules.xml`; file tạm đuôi `.xml.tmp`, cùng thư mục | Image chép `/wazuh-config-mount` vào `etc/rules` chỉ đọc sẽ lỗi; analysisd chỉ nạp `.xml` (S2) | `docker-compose.yml`, `wazuh_rules.py` |
| R17 | Thư viện rule đọc thêm file trong `DYNAMIC_DIR` bằng `wazuh_rules.parse` (**chưa có trong mã**, xem R83) | `GET /rules` không thấy `rules-dynamic` (S2) | `server/siem/rules_catalog.py` |
| R20 | Chown volume động làm trong `10-siem-setup.sh`, không làm ở `install.sh` | Volume có tên, `install.sh` không thấy đường dẫn host | entrypoint |
| R14 | Ca eventchannel chạy bằng bơm hàng đợi analysisd, định dạng khác qua logtest có token; xóa session sau mỗi ca; chờ rồi thử lại khi HTTP 429; CI nâng `max_request_per_minute` | Logtest không giải mã eventchannel; hạn mức 300 lời gọi / phút (S3) | `tools/wazuh_rule_test.py`, `wazuh/manager/tests/api-ci.yaml` |
| R45 | Tên file xếp sau file rule gốc mà rule con móc vào (`0271-web.xml` sau 0245) và khóa `ID_RANGES` theo tên đó | Rule con bị bỏ khi nạp nếu `if_sid` chưa tồn tại | `ID_RANGES` |

## 3. Cầu nối, chạy bóng và chống trùng

| R | Quyết định | Vì sao | Thấy ở |
|---|---|---|---|
| R2 | Alert từ Wazuh mang `rule.groups` | SOAR cần nhóm để chọn playbook | `detection/alerts.py:from_wazuh` |
| R22, R41 | Mặc định không chuyển nhóm `sca` (`WAZUH_ALERT_EXCLUDE_GROUPS`), ở mọi level | SCA là tư thế cấu hình (mỗi check CIS hỏng là level 7), sẽ làm lũ alert và case | `settings.py`, `detection/wazuh.py` |
| R38 | Rule gốc ngoài nhóm cũ (`syscheck`, `rootcheck`, `vulnerability-detector`, `virustotal`, `yara`) và dưới level 12 chỉ là alert bóng tới Task 18 | Giữ nguyên hành vi đang chạy, tránh lũ alert / case từ 87702, 5758, 2502 trên syslog | `WAZUH_ALERT_ACTIVE_GROUPS`, `alerts.py` |
| R40 | Khóa chống trùng có thêm `file.path` | Không gộp alert FIM của các file khác nhau trong 60 giây | `Suppressor` |
| R47 | Alert XML mang `rule.legacy_id` (nhóm `legacy_*` đầu) và `legacy_ids` nếu nhiều mã | Ghép với alert YAML cùng mã | `alerts.py` |
| R49 | Kỹ thuật ATT&CK tính là "phủ" khi có ít nhất một rule đang bật ở bất kỳ nguồn nào (YAML / AI, hoặc rule Wazuh không bóng). KPI ghi nguồn phủ. **Sửa ở Task 25 (R82):** chỉ còn rule Wazuh không bóng trong `siem-rules`; bỏ nguồn `lint-yaml` và `attack_coverage_source` | Nếu chỉ tính XML thì KPI tụt về gần 0 trước cổng vì rule XML đều bóng | `server/siem/manager/kpi.py` |
| R55 | Không dùng thuộc tính `ignore` ở bất kỳ rule nào; lint cấm; thêm ca "nguồn thứ hai vẫn báo" (`last: true`) | `ignore` tắt cả rule N giây; ràng buộc toàn cục 7 | `tools/wazuh_rule_lint.py`, `wazuh_rule_test.py` |

## 4. Quy ước rule, lint và ca test

| R | Quyết định | Vì sao | Thấy ở |
|---|---|---|---|
| R3 | Harness có `fired(case, api)`; `--report` dùng chung (`--report` đã xóa ở Task 25 cùng rule YAML; `legacy_map.yml` giữ làm lịch sử) | Tránh hai bộ chạy song song | `tools/wazuh_rule_test.py` |
| R23 | 100100 và 100101 mang mã `WEB-010` / `WEB-011` và nhóm `siem` | Ràng buộc toàn cục mã ở đầu description | `0100-platform.xml` |
| R24, R26 | "Nhóm chứa `siem`" xét nhóm hiệu lực, so khớp chính xác; file tuning miễn kiểm nhóm `siem`, dải id, mitre, mã, nhưng mọi rule phải có `overwrite="yes"` và id < 100000 | Thêm nhóm vào rule gốc làm đổi nhóm alert của nó | lint |
| R25 | Bắt buộc `type="pcre2"` cho `<regex>` và `<field>`; `<match>`, `<url>` mặc định OS_Match được phép | Mặc định của regex là OS_Regex | lint |
| R27 | File `rules-dynamic/*` miễn kiểm ca test trong lint | Console sinh lúc chạy, không có ca trong repo | lint |
| R21 | `wazuh_noise.py` nhận `--data` (mặc định `datasets/processed`); đo bằng manager tạm không nối mạng, image 4.14.8 cộng rule của nhánh | Số đo phải phản ánh rule của nhánh, không chạm stack thật | `tools/wazuh_noise.py` |
| R16 | Lint cảnh báo `frequency` + `if_matched_group` và `<field>` một từ không neo | Spike S4 | lint |
| R28 | Ca gốc của rule cũ ở `wazuh/manager/tests/legacy/` (chưa gán id); `tests/cases/` chỉ chứa ca đã có rule | Ca chưa gán id không được làm hỏng CI | `wazuh/manager/tests/` |
| R29 | "Rule gốc bắt được" = rule gốc level ≥ 7 (không thuộc `sca`) báo trên mọi ca dương và không báo ca âm | Level thấp hơn không thành alert | `wazuh_rule_test.py --report` (đã xóa ở Task 25), kết quả ở `legacy_map.yml` |
| R30 | `builtin` chỉ khi ca dương phủ mọi nhánh của điều kiện chính và ca âm đúng bản chất; thiếu nhánh thì `approx` kèm "chỉ chứng minh: ..." | Tránh nhận rule gốc quá hẹp | `legacy_map.yml` |
| R31 | `GENERIC_IDS` (rule chung như 80792, 31106, 86601) không tính là phủ; ca chỉ trúng rule chung là `convert` | Khớp chung chung không phải phát hiện | `wazuh_rule_test.py` |
| R32 | `convert` viết rule XML; `approx` thiếu nhánh thì viết rule cho nhánh thiếu; `approx` chỉ lệch level hoặc ngưỡng thì để file tuning | Chia việc giữa task lĩnh vực và Task 12 | `legacy_map.yml` |
| R15 | NET-001, NET-005, AUTH-003, LNX-005 dùng `different_*` với ca âm "hai giá trị xen kẽ, dưới 2N−2 dòng"; RULES.md ghi giới hạn | S4 | các file ca |
| R18 | `legacy_map` ghi cả 31106 lẫn id tấn công cụ thể; ca web thêm `%2527`, `+`, `%u0027`, `%55NION` | S5 | ca web |

## 5. Nguồn dữ liệu qua Wazuh

| R | Quyết định | Vì sao | Thấy ở |
|---|---|---|---|
| R33 | (đã **hết hiệu lực**) lo console không qua Wazuh nên mất AUTH-002 / 003 | Sau đó mọi nguồn được đưa qua `wazuh-manager`; console ghi audit JSON ra file, rule 101020 trở đi nhận | `0101-auth.xml` |
| R37 | (đã **thay bằng R43**) | | |
| R43 | Filterlog đến qua syslog RFC 3164 (agent 000, location = IP) hoặc agent OPNsense; Suricata chỉ qua agent OPNsense đọc `eve.json`; mọi bộ đếm có `same_source_ip` | S6 | `0541-network.xml` |
| R35 | Rule Linux phủ cả dòng `siem-proc:` và auditd EXECVE; LNX-002 chỉ làm được trên `siem-procs` | Auditd không có tên tiến trình cha | `0102-linux.xml`, `0851-linux-audit.xml` |
| R42 | Chấp nhận bộ đếm thất bại dùng chung giữa console và sshd; ghi rõ trường hợp lỗi bên này + thành công bên kia ra AUTH-002; thêm ca hỗn hợp | IP sai ở cả console và SSH vốn đáng ngờ | `0101-auth.xml` |
| R51 | Rule Windows là con của chuỗi rule gốc eventchannel (60000 / 61600 / 92000...), không dựa decoder json chung; ca âm: cùng JSON `win.*` qua syslog không kích hoạt | Chặn giả mạo qua syslog (tương tự F8) | `0965-windows.xml`, ID_RANGES giữ 105000–105999 |

## 6. Thứ tự anh em, danh sách IOC và rule gốc phải còn tới được

Quy luật đã đo (Task 8, 9, 11): rule **level cao hơn thắng**, bằng level thì **rule nạp trước thắng**; thắng ở tầng cha thì cả cây con của rule anh em thua bị bỏ.

| R | Quyết định | Vì sao | Thấy ở |
|---|---|---|---|
| R34 | Giữ bộ đếm chung 101000, chấp nhận mất 5763 / 5712 gốc | Không bù được (rule `frequency` tiêu sự kiện); phần mất (4 đến 5 lần sai / phút, không thành công) YAML cũ cũng không bắt | `0101-auth.xml` |
| R36 | Báo nhầm 102505 (1/36.871) chấp nhận ở chế độ bóng, ghi cho Task 12 | Không được ghi là đạt "0 alert" | `0999-tuning.xml`, checklist Task 18 |
| R44 | 103004 (NET-004) loại IP trong danh sách gốc bằng `not_match_key` trên `src_ip` / `dest_ip` | Để 99915 / 99916 giữ ngữ cảnh IOC; cách (b) theo thứ tự file không có tác dụng | `0541-network.xml` |
| R50 | Không ghi đè `etc/lists/malicious-ioc/malicious-ip`; IOC MISP vào danh sách riêng `siem-misp-ip`, đẩy bằng API rồi reload | 99915 / 99916 và loại trừ của 103004 dùng danh sách gốc | `0845-ti.xml`, `server/siem/pipeline/misp_cdb.py` |
| R52 | Rule IOC gốc (99903, 99904, 99905, 99906, 99919...) nạp sau và chiếm sự kiện từ IP độc hại; bộ đếm dự án không đếm sự kiện đó. Chấp nhận, ghi trong header, ca ghim hành vi | Rule IOC gốc báo từng event (level 14 là alert thật); không đổi thứ tự file để né | header các file, `0999-tuning.yml` |
| R53 | TI-001 làm ngay phần IP (MISP + nội bộ) cho pf, Suricata, sshd, web, Windows; domain và hash ghi trong `legacy_map` và checklist Task 18 | Rule cũ phủ IP / domain / hash trên mọi event | `0845-ti.xml` |
| R54 | (đã **thay bằng R56**) loại IP IOC khỏi rule web | Làm mất dòng chỉ rule WEB bắt | |
| R56 | Bỏ loại trừ; thêm 104095 (level 14, không bóng, `port_of_stock=99906`) làm con của các rule WEB payload / UA, khớp `malicious-ip` và mã `^200` | Rule WEB (L10–12) thắng rule gốc (L ≤ 7) ở tầng 31100 nên 99906 (alert thật) sẽ mất; 104095 là bản sao mở rộng | `0271-web.xml` |
| R57 | Con TI web (107009) loại IP có trong danh sách gốc (`not_match_key`) | Con TI (L10) thắng 31103 (L7) và chặn đường 31103 → 99905 → 99906 | `0845-ti.xml` |

## 7. Rule gốc: chỉnh và tuning

| R | Quyết định | Vì sao | Thấy ở |
|---|---|---|---|
| R58 | `overwrite` có hiệu lực ngay khi triển khai (không qua chạy bóng): (1) rule đè mà level mới ≥ 12 phải mang nhóm `shadow` tới cổng; (2) bản đè chép đủ định nghĩa gốc; (3) file tuning nạp sau mọi file chứa rule bị đè (đổi tên `0190` thành `0999-tuning.xml`); (4) phạm vi: 92041, 92021, rule ồn Windows, các rule `approx` chỉ lệch level / ngưỡng | Không sinh alert thật mới trước cổng | `0999-tuning.xml`, `TUNING_FILE`, lint |
| R61 | Bỏ 31151 khỏi danh sách chặn IP, giữ 31152 | Task 12 hạ 31151 xuống level 7; WEB-006 YAML cũ chỉ mức medium nên không chặn | `server/config/playbooks.yml` |
| R63 | `stock_reach` theo `if_group` (ca ghim HOẶC bảo đảm cấu trúc); 107008 / 107010 loại IP ở danh sách gốc như 107009; lint đòi `shadow` + `shadow_since` và cha dự án nạp trước; CI quét `ossec.log` | Review cuối: `if_group` vô hình với công cụ cũ, TI sshd / Windows thay ngữ cảnh IOC gốc (RULES.md 9.6 nói sai), thiếu chốt chặn bóng và thứ tự cha | `tools/wazuh_stock_reach.py`, `tools/wazuh_rule_lint.py`, `0845-ti.xml`, `.github/workflows/ci.yml` |
| R64 | TI-001 domain + hash bằng XML trước khi tắt YAML: danh sách riêng `siem-misp-domain` / `siem-misp-hash` (cùng nguồn MISP + `config/intel`, kiểm chặt, trần như IP), rule 107011-107016 (Suricata DNS / HTTP, Sysmon 22, FIM sha256 / sha1 / md5) loại danh sách gốc bằng `not_match_key`. Giới hạn nhận: subdomain không khớp (CDB chính xác), hash trong Sysmon 1 (`win.eventdata.hashes` là một chuỗi) chưa phủ | Chủ sở hữu quyết định phủ domain + hash trước khi tắt engine YAML | `0845-ti.xml`, `server/siem/pipeline/misp_cdb.py`, `siem_api_user.py`, `cases/0845-ti.yml`, RULES.md 9.9 |

## 8. SOAR và ngoại lệ

| R | Quyết định | Vì sao | Thấy ở |
|---|---|---|---|
| R48 | Ngoại lệ Wazuh cần hai người **khác nhau** duyệt mới ghi vào XML (người tạo là người duyệt thứ nhất); xóa một người đủ nhưng giữ lịch sử; ghi sổ trước, XML sau; rule cha kiểm qua API (503 khi API chết) | Ngoại lệ làm giảm cảnh báo; không để rule mồ côi | `server/siem/wazuh_exceptions.py`, `/api/v1/exceptions` |
| R59 | Playbook `block_ip` theo rule / nhóm Wazuh có `no_syslog: true`; alert bóng không chạy playbook | IP nguồn UDP syslog giả được, kẻ tấn công khiến hệ thống chặn nạn nhân | `soar/engine.py`, `playbooks.yml` |
| R60 | Hành động phá hủy (`block_ip`, `kill`, `isolate`) chỉ chọn theo id rõ ràng đã duyệt: bản XML của mã YAML từng chặn, 104095, và rule gốc 5712, 5720, 5763 (sshd), 31152 (web) với `scope: origin`; nhóm chỉ để thông báo, mở case và chọn case playbook. Case playbook chọn theo `legacy_id` trước kỹ thuật, nhóm, tag | Nhóm `authentication_failures` kéo 53 rule gốc (Postfix, Dovecot, WordPress, VPN...) mà `srcip` thường là proxy / NAT; `SOAR_WHITELIST` mặc định chỉ 127.0.0.0/8 | `playbooks.yml`, `soar/cases.py`, test hồi quy chặn `*` / `WZH-*` |
| R65 | **Chuyển hẳn (cổng T18, phương án A), 05/11/2026**, quyết định của chủ dự án: (1) tắt engine YAML (`RULE_ENGINE_ENABLED=false`, mặc định); (2) bỏ chạy bóng của mọi rule XML riêng ngay, **bỏ qua tiêu chí 7 ngày** của SOC-OPERATIONS mục 4 (trừ `0845-ti.xml`, controller bỏ khi gộp TI); (3) rule gốc Wazuh level 7 đến 11 cũng là alert thật (`WAZUH_STOCK_SHADOW=false`, thay R38); (4) xóa playbook theo mã YAML, đề xuất AI bị chặn 409 tới Task 19 đến 22; (5) lint bỏ yêu cầu "rule dự án level ≥ 3 phải chạy bóng" (R63) và "tuning level ≥ 12 phải shadow" (R58), giữ "có `shadow` thì phải có `shadow_since`" | Chủ dự án chọn chuyển hẳn thay vì giữ YAML bật + XML bóng tới demo 10/11 | Rủi ro: chưa đo ≥ 24 giờ syslog + console thật, báo nhầm chưa biết; alert medium / high từ rule gốc tăng, ngập case chứ không chặn nhầm (R60). Quay lui: `RULE_ENGINE_ENABLED=true` + `WAZUH_STOCK_SHADOW=true` + khôi phục playbook YAML từ git (hết hiệu lực từ Task 25: engine YAML và `RULE_ENGINE_ENABLED` đã xóa, quay lui chỉ còn bằng mã / image trước Task 25) | `settings.py`, `detection/wazuh.py`, `playbooks.yml`, `tools/wazuh_rule_lint.py` |

## 9. Phát hiện chính

- **F8 (bảo mật, đã vá trên `main`, PR #12):** syslog từ IP được phép giả được dòng `auditd` hoặc JSON `{"win":...}` và đi vào rule YAML LNX-001 / WIN-012. SOAR vốn bỏ qua agent `syslog-*` nên không tới kill / isolate, nhưng tạo được alert critical và case giả. Bài học áp cho mọi rule: ràng buộc `location` (R51, web `^\(`).
- **S6, RFC 5424:** `remoted` không tách được RFC 5424 (không có `program_name`) nên sshd và filterlog mất decoder; bắt buộc RFC 3164. Suricata qua syslog không có decoder ở cả hai dạng, nên rule Suricata cần agent OPNsense.
- **S7, location của agent:** analysisd so `<location>` với chuỗi có tiền tố agent (`(demo-web) any->siem-procs`); neo `(^|/)` ban đầu khiến cả họ LNX `siem-proc` chết với agent thật mà harness (location = IP) không thấy.
- **S4, `different_*`:** Wazuh đếm "N−1 event trước có giá trị khác", không đếm giá trị phân biệt; báo muộn khi chỉ vài giá trị xen kẽ.
- **Cổng 99906 / 104095 (R56):** rule dự án cấp 31100 thắng rule gốc; nếu không có bản sao, alert thật level 14 biến mất. Bản sao 104095 là rule không bóng duy nhất mới của dự án.
- **Shellshock:** nghi 104090 / 104005 che 31168 / 31169 (level 15) ở tầng 31100; đo thật cho thấy không (cả hai cùng là con của 31108 nên thua). Khẳng định bằng ca, không bằng suy luận.
- **Bỏ `ignore` (R55):** tám rule đã gộp và hai rule web dùng `ignore`; bỏ cả. Khi sửa thấy `ignore` so theo trường `same_*`, nên với rule có `same_source_ip` nó chặn theo nguồn chứ không theo cả rule như ràng buộc 7 giả định; vẫn bỏ vì dập trùng đã làm ở cầu nối, và lint giữ quy tắc.
- **R60, bán kính tác động SOAR:** map playbook theo nhóm Wazuh sẽ tác động cả alert thật của rule gốc ngay khi nhánh triển khai (53 rule `authentication_failures`; 31161 / 31163 chỉ là triệu chứng máy chủ). Chữa bằng danh sách id tường minh; `stock-groups-soar` là bản liệt kê đã đối chiếu với manager thật.
- **Ghi đè rule ồn Windows (Task 12):** độ ồn Windows 1,341 xuống 0,596 / 100 event. Sửa 92041 làm mất 221 khớp trong phép đo độ phủ dataset Windows (297 xuống 76), toàn bộ là khớp chung chung của một lỗi regex Wazuh (xem RULES.md mục 9.8).
- **Kiểm có hệ thống rule gốc còn tới được (05/11):** 22 hậu duệ gốc là alert thật dưới 43 rule cha dự án móc vào; 8 đã có ca, 14 chưa. Ca ghim và công cụ nằm ở nhánh `wzh/pin-real`.
- **Hoãn tới stack thật:** báo cáo song song, E2E, ngoại lệ Wazuh trên manager thật (ngoại lệ con level 0 so với rule anh em như 31106, che cây con, `pcre2` trên `<url>` / `<dstuser>`), đo độ ồn trên syslog và console.

## 10. P4: rule AI và SigmaHQ ra Wazuh XML, xóa engine YAML (06–08/11/2026)

Kế hoạch: [2026-11-06-p4-ai-wazuh-xml.md](superpowers/plans/2026-11-06-p4-ai-wazuh-xml.md); số đo ở mục *Kết quả đo P4* của kế hoạch.
Mô tả cho người dùng: [AI-README.md](../AI-README.md) mục 7, 8, 9.11 và [RULES.md](../RULES.md) mục 2.

| R | Quyết định | Vì sao | Thấy ở |
|---|---|---|---|
| R66 | Cây Python (`sigma.compile_rule`, bộ đánh giá `siem.ai.condition`) giữ làm bộ tìm. Wazuh sandbox là cổng quyết định: recall / báo nhầm / "che rule khác" tính trên alert Wazuh. Python với Wazuh lệch nhau thì chỉ ghi số liệu (check "khớp Python", không chặn) | Vòng tìm vế gọi replay hàng trăm lần, Wazuh mỗi lần mất hàng chục giây. Nhưng chỉ alert Wazuh mới là thật | `server/siem/ai/wazuh_gate.py`, `validate.py` |
| R67 | Sandbox là service compose `wazuh-sandbox` (profile `ai`, `network_mode: none`, cùng image với `wazuh-manager`). Worker giao việc qua thư mục job trên volume `ai_sandbox`, KHÔNG có docker socket | logtest không giải mã được eventchannel; bơm vào manager thật sẽ sinh alert giả | `docker-compose.yml`, `wazuh/sandbox/runner.py`, `server/siem/ai/sandbox.py` |
| R68 | Rule Linux (AI / SigmaHQ) chỉ nhắm decoder `siem-proc` (trường `cmd`, `exe`, `name`, `parent`, cha 102000), không nhắm auditd | auditd tách dòng lệnh thành `a0..aN`, có khi mã hóa hex, nên không có trường dòng lệnh để so | `ai/wazuh_xml.py` (`PARENTS`, `FIELDS`) |
| R69 | Mỗi vế (term) DNF thành một `<rule>` anh em. Trong một vế, mỗi trường Wazuh có đúng một phần tử pcre2 `(?i)^(?=…)(?!…)`: điều kiện dương là lookahead, phủ định là negative lookahead. IP thì `SigmaError`. User-Agent dùng regex chuỗi ngoặc kép cuối dòng như 104005 | Không phụ thuộc chuyện Wazuh có cho hai `<field>` trùng tên hay không. Rule chữ ký không viết theo IP | `ai/wazuh_xml.py` (`emit`) |
| R70 | Level: `low` 5, `medium` 7, `high` 10, `critical` 10. AI chỉ đặt `low` / `medium` (R-P8), nên rule AI là level 5 hoặc 7 | Rule sinh tự động không được thắng rule gốc level 11–12 cùng cha (thắng là cắt cây con, mất alert thật) | `wazuh_xml.LEVEL` |
| R71 | Rule AI / SigmaHQ mới luôn chạy bóng: nhóm `shadow` + `shadow_since`. Bật chính thức = bỏ đúng hai thứ đó (`unshadow`) | Dùng lại cơ chế có sẵn (alerts.py, SOAR, lint) | `wazuh_xml.unshadow`, `ai/deploy.py` (`promote`) |
| R72 | `ai.xml` dựng lại từ các đề xuất đã triển khai trong ES: mỗi đề xuất một khối `<group name="siem,ai,ai_<pid>,">`. XML đóng băng lúc duyệt (`wazuh.deployed_xml`). Mọi thay đổi (duyệt, bật chính thức, gỡ) đi qua một khóa và đọc lại đề xuất trong khóa | ES là nguồn sự thật, không sửa XML tại chỗ. Hai người duyệt cùng lúc không mất khối của nhau, cũng không ghi trùng | `ai/deploy.py` (`render_ai_file`, `_deploy_new`) |
| R73 | Đề xuất ngoại lệ AI: người bấm duyệt gọi `wazuh_exceptions.add` (tạo ngoại lệ chờ duyệt), người thứ hai duyệt ở trang ngoại lệ. Đề xuất AI loại ngoại lệ đặt `required_approvals: 1` | Một đường duyệt duy nhất (R48). Điều kiện ngoại lệ so chính xác, phân biệt hoa thường như `wazuh_fields.literal` | `ai/deploy.py`, `ai/validate.py` (`validate_exception_wazuh`) |
| R74 | Số alert/ngày trên event thật (`siem-events` 7 ngày) vẫn ước lượng bằng cây Python, ghi `replay_estimate="python"` | Wazuh không xử lý lại event cũ. Bơm lại `full_log` cần cả vị trí và header agent, ngoài phạm vi | `ai/validate.py` (`replay`) |
| R75 | Cha của rule Windows sinh tự động = 61603 + các rule gom level 0 của `0800-sysmon_id_1.xml` có con và móc vào sysmon_event1: 92025 (reg.exe), 92028 (PowerShell chạy script), 92042 (netsh), 92069 (cha WmiPrvSE). Đo trên 4.14.8, ghim bằng test | Rule gom level 0 nuốt event trước các anh em dưới 61603: chỉ treo dưới 61603 thì không ứng viên nào thấy event reg.exe. Đã đo: 92026 (level 14) vẫn thắng ứng viên level 10 | `wazuh_xml.PARENTS`, `test_windows_parents_pinned` |
| R76 | File SigmaHQ là `wazuh/manager/rules/0966-sigmahq.xml`, không phải `0108-sigmahq.xml` như kế hoạch ban đầu; dải id giữ 108000–108999, khóa `ID_RANGES` đổi theo tên | Wazuh nạp rule theo tên file: cha 61603 ở `0595-win-sysmon_rules.xml` và các cha gom nhóm ở `0800-sysmon_id_1.xml` phải nạp trước. File `0108` bị bỏ khi nạp (7617 / 7619) | `server/siem/wazuh_rules.py`, `tools/sigmahq_import.py` |
| R77 | Thực thể XML (`&gt;`, `&lt;`, `&amp;`) mà Wazuh giữ nguyên trong `win.eventdata.*` **chưa hỗ trợ** (Task 19c hoãn): vế rule AI Windows có ký tự `>`, `<`, `&` không bao giờ khớp trên Wazuh nên cổng không tính nó vào recall (rule chỉ dựa vào vế đó thì trượt check "bắt mẫu nghi vấn (Wazuh)"); `sigmahq_import` bỏ hẳn rule có ký tự đó (ghi lý do trong `skipped`) | `emit` viết các ký tự đó thành `\x3e`, `\x3c`, `\x26` nên không khớp chuỗi thực thể (đo ở 108017). Hỏng an toàn; sửa thì phải sinh lại lô và chạy lại CI | `ai/wazuh_gate.py`, `tools/sigmahq_import.py` |
| R78 | Bỏ nhánh 3 của worker (`gap-own`, event thật chưa có rule), tính năng so sánh đề xuất ↔ rule YAML (bản ghi `origin: comparison`, nút *So sánh với rule hiện có*, bảng trong dashboard Thư viện rule) và benchmark rule YAML (`ai/benchmark.py`; cột "Tự viết / Hợp" của `wazuh_coverage.py`, R-P6). So model bằng `tools/bench_ai_models.py`, chạy qua cổng Wazuh | Cả ba dựa vào engine YAML. `gap-own` không có log thô nên luôn trượt cổng; rule Wazuh không có tag / chuỗi mẫu để ghép cặp so sánh (thử thì gần như không ra cặp) | `ai/worker.py`, `rules_catalog.py`, `tools/gen_dashboard.py`, `console.html` |
| R79 | Cổng: "phát hiện" = alert level ≥ 7 của rule không thuộc `GENERIC`. Job ứng viên gửi mọi log thô cùng định dạng với lĩnh vực của rule (không chỉ train / kiểm tra / bình thường); "che rule khác" = mẫu có phát hiện ở job nền mà mất ở job ứng viên, bỏ qua alert `GENERIC` và level < 7. Doc không có log thô (Splunk, EVTX) không tính là khoảng trống | Nhóm khoảng trống theo định nghĩa không có alert, nên muốn bắt "mất alert thật" (Review Focus 1) phải gửi cả mẫu Wazuh đang bắt. Không có log thô thì không đo được trên Wazuh | `ai/wazuh_gate.py` (`detections`, `gaps`, `check`) |
| R80 | Sandbox gửi có chờ: cứ 500 event đọc file state, hàng đợi analysisd nào đầy quá 20% thì chờ. Job có `dropped > 0`, thiếu canary, `processed < sent + 1`, `alerts.json` xoay vòng giữa job, runner lỗi hay hết giờ đều thành `SandboxError`; chu kỳ AI ghi lỗi và bỏ nhánh khoảng trống, không coi là "rule không bắt" | Vòng gửi cũ làm tràn hàng đợi và mất âm thầm 7.591/50.000 event (15%): âm tính giả lặng lẽ. Có chờ: 50.000 event 73 giây, 0 rơi | `wazuh/sandbox/runner.py`, `ai/sandbox.py` |
| R81 | Id rule AI cấp `max + 1` trong 109000–109999 và **không bao giờ dùng lại**, kể cả của đề xuất đã gỡ. Bật chính thức giữ trạng thái `approved`, bỏ `wazuh.shadow_since`, ghi `promoted_at` / `promoted_by`. `generator_id` của đề xuất gồm `EMITTER_VERSION`: sửa bộ dịch thì mục tiêu từng bị cổng loại được thử lại ngay, không chờ 30 ngày | Alert cũ `WZH-<id>` không lẫn với rule mới. Lỗi bộ dịch (dấu `\` Windows) không được khóa mục tiêu oan | `ai/deploy.py` (`next_ids`, `promote`), `ai/worker.py` |
| R82 | Sau khi xóa engine (Task 25): KPI độ phủ ATT&CK chỉ đọc rule Wazuh trong `siem-rules`, ES lỗi thì để trống (không lùi về lint); mốc thời gian của danh mục rule = đầu ngày UTC (trước là mtime file YAML); đề xuất ngoại lệ trong danh mục lấy mức độ / tactic của rule Wazuh đích | Không còn file YAML để lấy mtime hay để lint; mốc 1970 làm mọi bản ghi biến khỏi dashboard | `manager/kpi.py`, `rules_catalog.py` |
| R83 | Danh mục rule (`siem-rules`) chỉ có rule mà Wazuh API liệt kê: đo lại 08/11/2026 trên 4.14.8, `GET /rules` (framework `wazuh.rule.get_rules`) không thấy `etc/rules-dynamic/` dù `ossec.conf` có `<rule_dir>`. R17 chưa được làm trong mã, nên rule AI đã duyệt và ngoại lệ không có bản ghi `wazuh_rule`. Dashboard Thư viện rule đếm rule AI theo đề xuất `approved`, bỏ ô ngoại lệ (Task 26) | Không đếm sai về 0 âm thầm; đọc thêm `rules-dynamic/` bằng `wazuh_rules.parse` là việc riêng (ngoài phạm vi Task 26) | `rules_catalog.py`, `tools/gen_dashboard.py` |

Phát hiện chính của P4:

- **Dấu `\` trong `win.eventdata.*` bị nhân đôi** (eventchannel): rule Windows có đường dẫn không bao giờ khớp (Task 21 đo T1548.002: Wazuh 0/16, Python 7/16). Sửa ở Task 19b: dấu `\` thành `(?:\x5c){1,2}`, `EMITTER_VERSION` 2; regex Windows có `\` trần thì `SigmaError`.
- **Rule gom level 0 nuốt event** (R75): ứng viên dưới 61603 không thấy event reg.exe. Rule dự án `0965-windows.xml` dưới 61603 có thể bị che cùng kiểu: **chưa kiểm**.
- **Vòng gửi cũ mất event** (R80): `tools/wazuh_coverage.run_wazuh`, `wazuh_noise`, `wazuh_rule_test.inject` vẫn dùng vòng gửi cũ, nên số độ phủ / độ ồn cũ trên tập lớn có thể thiếu.
- **Thực thể XML** (R77): Wazuh giữ `&gt;` / `&lt;` / `&amp;` nguyên văn trong trường Windows.
- **Sandbox** (đo S4): `wazuh-control restart` 11–14 giây; mỗi job tối thiểu khoảng 36 giây, nên cổng gom event thành ít job (một job nền, mỗi ứng viên một job). Header `(sbx-<ident>)` cho `agent.name = sbx-<ident>`, ghép alert với event không cần `full_log`.
