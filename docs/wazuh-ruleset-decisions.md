# Sổ quyết định: bộ rule Wazuh XML thống nhất

Bản cô đọng, lâu dài của 61 ruling (R1 đến R61) và các phát hiện chính khi làm kế hoạch
[2026-10-31-wazuh-unified-ruleset.md](superpowers/plans/2026-10-31-wazuh-unified-ruleset.md) (Task 0 đến 17, nhánh `feature/wazuh-unified-ruleset`).
Cách đọc: mỗi dòng là *quyết định, vì sao, nơi thấy trong code*. Mọi ruling là tạm thời: người dùng xem lại ở cổng chuyển (Task 18).
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
| R17 | Thư viện rule đọc thêm file trong `DYNAMIC_DIR` bằng `wazuh_rules.parse` | `GET /rules` không thấy `rules-dynamic` (S2) | `server/siem/rules_catalog.py` |
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
| R49 | Kỹ thuật ATT&CK tính là "phủ" khi có ít nhất một rule đang bật ở bất kỳ nguồn nào (YAML / AI, hoặc rule Wazuh không bóng). KPI ghi nguồn phủ | Nếu chỉ tính XML thì KPI tụt về gần 0 trước cổng vì rule XML đều bóng | `server/siem/manager/kpi.py` (`attack_coverage_source`: `siem-rules` hoặc `lint-yaml`) |
| R55 | Không dùng thuộc tính `ignore` ở bất kỳ rule nào; lint cấm; thêm ca "nguồn thứ hai vẫn báo" (`last: true`) | `ignore` tắt cả rule N giây; ràng buộc toàn cục 7 | `tools/wazuh_rule_lint.py`, `wazuh_rule_test.py` |

## 4. Quy ước rule, lint và ca test

| R | Quyết định | Vì sao | Thấy ở |
|---|---|---|---|
| R3 | Harness có `fired(case, api)`; `--report` dùng chung | Tránh hai bộ chạy song song | `tools/wazuh_rule_test.py` |
| R23 | 100100 và 100101 mang mã `WEB-010` / `WEB-011` và nhóm `siem` | Ràng buộc toàn cục mã ở đầu description | `0100-platform.xml` |
| R24, R26 | "Nhóm chứa `siem`" xét nhóm hiệu lực, so khớp chính xác; file tuning miễn kiểm nhóm `siem`, dải id, mitre, mã, nhưng mọi rule phải có `overwrite="yes"` và id < 100000 | Thêm nhóm vào rule gốc làm đổi nhóm alert của nó | lint |
| R25 | Bắt buộc `type="pcre2"` cho `<regex>` và `<field>`; `<match>`, `<url>` mặc định OS_Match được phép | Mặc định của regex là OS_Regex | lint |
| R27 | File `rules-dynamic/*` miễn kiểm ca test trong lint | Console sinh lúc chạy, không có ca trong repo | lint |
| R21 | `wazuh_noise.py` nhận `--data` (mặc định `datasets/processed`); đo bằng manager tạm không nối mạng, image 4.14.8 cộng rule của nhánh | Số đo phải phản ánh rule của nhánh, không chạm stack thật | `tools/wazuh_noise.py` |
| R16 | Lint cảnh báo `frequency` + `if_matched_group` và `<field>` một từ không neo | Spike S4 | lint |
| R28 | Ca gốc của rule cũ ở `wazuh/manager/tests/legacy/` (chưa gán id); `tests/cases/` chỉ chứa ca đã có rule | Ca chưa gán id không được làm hỏng CI | `wazuh/manager/tests/` |
| R29 | "Rule gốc bắt được" = rule gốc level ≥ 7 (không thuộc `sca`) báo trên mọi ca dương và không báo ca âm | Level thấp hơn không thành alert | `wazuh_rule_test.py --report` |
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

## 8. SOAR và ngoại lệ

| R | Quyết định | Vì sao | Thấy ở |
|---|---|---|---|
| R48 | Ngoại lệ Wazuh cần hai người **khác nhau** duyệt mới ghi vào XML (người tạo là người duyệt thứ nhất); xóa một người đủ nhưng giữ lịch sử; ghi sổ trước, XML sau; rule cha kiểm qua API (503 khi API chết) | Ngoại lệ làm giảm cảnh báo; không để rule mồ côi | `server/siem/wazuh_exceptions.py`, `/api/v1/exceptions` |
| R59 | Playbook `block_ip` theo rule / nhóm Wazuh có `no_syslog: true`; alert bóng không chạy playbook | IP nguồn UDP syslog giả được, kẻ tấn công khiến hệ thống chặn nạn nhân | `soar/engine.py`, `playbooks.yml` |
| R60 | Hành động phá hủy (`block_ip`, `kill`, `isolate`) chỉ chọn theo id rõ ràng đã duyệt: bản XML của mã YAML từng chặn, 104095, và rule gốc 5712, 5720, 5763 (sshd), 31152 (web) với `scope: origin`; nhóm chỉ để thông báo, mở case và chọn case playbook. Case playbook chọn theo `legacy_id` trước kỹ thuật, nhóm, tag | Nhóm `authentication_failures` kéo 53 rule gốc (Postfix, Dovecot, WordPress, VPN...) mà `srcip` thường là proxy / NAT; `SOAR_WHITELIST` mặc định chỉ 127.0.0.0/8 | `playbooks.yml`, `soar/cases.py`, test hồi quy chặn `*` / `WZH-*` |

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
