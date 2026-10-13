# Triển khai siem-xdr trên máy ảo

Hướng dẫn dựng toàn bộ hệ thống trên các máy ảo (VirtualBox / VMware / Hyper-V): một VM chạy backend bằng Docker và các
VM endpoint cài Wazuh agent theo đúng danh mục tài sản `BTL/asset.txt`. Kiến trúc, cấu hình chi tiết và giải thích từng
thành phần nằm ở [README.md](README.md); tài liệu này chỉ đi theo thứ tự các bước cài đặt.

> **Chỉ chạy trong mạng lab cô lập.** SOAR tự chặn IP, kill tiến trình trên máy thật; máy web có thể được cài trang CGI
> cố ý có lỗ hổng để thử. Chụp snapshot mọi VM trước khi thử tấn công.

## 0. Mô hình lab

```
                 Mạng host-only 192.168.56.0/24 (không ra Internet)
 ┌────────────────────┬───────────────────┬───────────────────┬───────────────────┬──────────────────┐
 │ siem-server .10    │ Web-01 .20        │ Ubuntu-01 .21     │ PC-01 .30         │ attacker .50     │
 │ Ubuntu 24.04       │ Ubuntu 24.04      │ Ubuntu 24.04      │ Windows 10/11     │ Kali (tùy chọn)  │
 │ Docker: toàn bộ    │ Apache + agent    │ agent             │ agent + Sysmon    │ công cụ thử      │
 │ backend            │ (S001)            │ (A003)            │ (A001)            │ tấn công         │
 └────────────────────┴───────────────────┴───────────────────┴───────────────────┴──────────────────┘
   + card NAT trên mỗi VM để cài gói (apt, docker pull). Máy host (Windows) là 192.168.56.1, mở console bằng trình duyệt.
```

| VM | Vai trò | Tên agent (bắt buộc) | CPU / RAM / Đĩa |
|---|---|---|---|
| `siem-server` | Elasticsearch, Kafka, Wazuh manager, Vector, analyzer, SOAR, console, Grafana | — | 4 vCPU / **8 GB** / 60 GB. Bật AI: 16 GB+ / 100 GB (xem mục 2.4) |
| `Web-01` | Máy chủ web S001 | `Web-01` | 2 vCPU / 2 GB / 20 GB |
| `Ubuntu-01` | Máy trạm Linux A003 | `Ubuntu-01` | 2 vCPU / 2 GB / 20 GB |
| `PC-01` | Máy trạm Windows A001 | `PC-01` | 2 vCPU / 4 GB / 50 GB |
| `attacker` | Thử tấn công (không cài agent) | — | 2 vCPU / 4 GB |

Đo thực tế (11/10/2026, stack chạy không tải): Elasticsearch ~1,8 GB, Kafka ~0,55 GB, Kafka UI ~0,3 GB, Wazuh manager
~0,36 GB, các service còn lại dưới 0,1 GB mỗi cái, tổng ~3,6 GB. 8 GB RAM cho VM là đủ chỗ cho hệ điều hành và lúc tải cao.

**Tên agent phải khớp `hostname` trong `server/config/assets.yml`** (`PC-01`, `Ubuntu-01`, `Web-01`): analyzer dựa vào tên
này để gắn tài sản và mức quan trọng (`risk_score`). Đổi mô hình thì sửa `assets.yml` trước (analyzer đọc khi khởi động).

## 1. Chuẩn bị mạng và VM

1. Tạo mạng host-only `192.168.56.0/24` (VirtualBox: *File → Tools → Network Manager*, tắt DHCP). Mỗi VM có 2 card:
   card 1 **NAT** (ra Internet để cài gói), card 2 **host-only**.
2. Đặt IP tĩnh cho card host-only. Ubuntu (tên card xem bằng `ip -br link`, ví dụ `enp0s8`):
   ```bash
   sudo tee /etc/netplan/60-lab.yaml >/dev/null <<'EOF'
   network:
     version: 2
     ethernets:
       enp0s8:
         addresses: [192.168.56.10/24]   # đổi theo bảng ở mục 0
   EOF
   sudo chmod 600 /etc/netplan/60-lab.yaml && sudo netplan apply
   ```
   Windows: *Settings → Network → Ethernet (card host-only) → IP assignment: Manual*, IP `192.168.56.30/24`, không cần gateway.
3. Đồng bộ giờ trên mọi VM (`sudo timedatectl set-ntp true`; Windows bật *Set time automatically*). Lệch giờ làm alert
   và kết quả lệnh phản ứng bị lệch thời điểm.
4. Đặt hostname trùng tên agent cho dễ đối chiếu: `sudo hostnamectl set-hostname Web-01` (tương tự cho các máy khác).
5. Chụp snapshot "sạch" cho mọi VM.

## 2. Máy chủ SIEM (`siem-server`, 192.168.56.10)

Cài bằng **một lệnh**. Script `install.sh` tự làm mọi bước (bảng ở 2.3); các bước làm tay để ở [phụ lục A](#phụ-lục-a-cài-máy-chủ-bằng-tay).

### 2.1 Cách nhanh nhất: một lệnh từ máy Windows

Chuẩn bị trên VM `siem-server`: Ubuntu 24.04 (hoặc 22.04 / Debian 12), đã đặt IP host-only ở mục 1, bật SSH:
```bash
sudo apt-get install -y openssh-server
```
Trên máy Windows, mở PowerShell trong thư mục mã nguồn `siem-xdr`:
```powershell
powershell -ExecutionPolicy Bypass -File .\tools\deploy-vm.ps1 <user>@192.168.56.10      # thêm -Demo: máy web demo, -AI: AI
```
(`-ExecutionPolicy Bypass` chỉ áp cho lần chạy này: Windows mặc định chặn chạy file `.ps1`. SSH khác cổng 22 hoặc dùng khóa:
thêm `-Port 2222`, `-SshOption '-i','C:\keys\vm'`.)
Nhập mật khẩu SSH, rồi mật khẩu sudo khi được hỏi. Script gửi **bản đã commit** của repo (`git archive`: đúng ký tự xuống dòng
cho Linux, không mang theo `.venv`, `datasets`, `secrets`, `.env`) sang VM và chạy `sudo ./install.sh`. IP của máy Windows
(nhìn từ VM) được thêm vào `SOAR_WHITELIST`, nên SOAR không bao giờ chặn máy quản trị. Lần đầu mất khoảng 5–20 phút
(cài Docker, tải image, build image Python).

Màn hình cuối in sẵn: địa chỉ console, mật khẩu `admin` tạm, đường dẫn file CA, lệnh cài agent Linux / Windows **đã điền IP
và mật khẩu enroll**. In lại lúc nào cũng được: `sudo ./install.sh info` (trong thư mục `~/siem-xdr` trên VM).

### 2.2 Hoặc chạy ngay trên VM

Nếu mã nguồn đã có trên VM (vd `git clone` bằng token GitHub, repo đang riêng tư):
```bash
cd siem-xdr
sudo ./install.sh                      # tự phát hiện IP; máy nhiều IP thì hỏi, hoặc chỉ định --ip 192.168.56.10
sudo ./install.sh --demo --admin-ip 192.168.56.1     # kèm máy web demo, khai IP máy quản trị
```

### 2.3 `install.sh` làm gì

| Bước | Việc |
|---|---|
| 1 | Kiểm tra: quyền root, Ubuntu / Debian, RAM (nên 8 GB), đĩa trống (nên ≥ 20 GB), file có bị đổi sang CRLF không |
| 2 | Cài Docker Engine + Compose từ `download.docker.com` nếu chưa có (cần Docker ≥ 26), thêm user vào nhóm `docker` |
| 3 | Tham số kernel `vm.max_map_count` (Elasticsearch), `net.core.rmem_max` (buffer UDP syslog), bật đồng bộ giờ |
| 4 | Sinh bí mật vào `secrets/` (thư mục chỉ root vào được); viết `.env`: IP máy chủ (chứng chỉ TLS), `GRAFANA_ROOT_URL`, `SOAR_WHITELIST` (127.0.0.0/8, IP máy chủ, IP máy quản trị), profile và file compose đang dùng |
| 5 | `docker compose up -d` |
| 6 | Chờ Elasticsearch + tài khoản RBAC, Wazuh manager, console; xuất CA nội bộ ra `ca.crt` |
| 7–8 | Kiểm tra nhanh trạng thái, in thông tin đăng nhập và lệnh cài agent |

Chạy lại bao nhiêu lần cũng được: bí mật, `.env` và dữ liệu giữ nguyên. Đổi IP máy chủ (`--ip` khác lần trước) thì script hỏi
rồi sinh lại chứng chỉ TLS (dữ liệu giữ nguyên).

Đã thử ngày 11/10/2026 trên Ubuntu 24.04 sạch (2 card mạng như mô hình lab): cài từ đầu kể cả Docker, phát hiện đúng IP
card lab; chạy lại và cập nhật qua `deploy-vm.ps1` giữ nguyên bí mật / `.env`; đổi IP rồi đổi lại, dữ liệu còn nguyên.
Sau cài: manager (uid 10001) và Grafana (uid 472) đọc được bí mật, analyzer ghi event vào Elasticsearch, SOAR đồng bộ agent
qua Wazuh API, đăng nhập console được, agent demo *Active*. Chưa thử: `--update` (build lại image) và `--ai`.

### 2.4 Lệnh thường dùng sau khi cài

| Việc | Lệnh (trên VM, thư mục `~/siem-xdr`) |
|---|---|
| Xem trạng thái | `sudo ./install.sh status` |
| In lại địa chỉ, mật khẩu tạm, lệnh cài agent | `sudo ./install.sh info` |
| Cập nhật mã nguồn mới | trên Windows: `powershell -ExecutionPolicy Bypass -File .\tools\deploy-vm.ps1 <user>@192.168.56.10 -Update` (gửi bản commit mới, build lại image; rule AI đã duyệt trên VM giữ nguyên) |
| Đổi IP máy chủ | `sudo ./install.sh --ip <IP mới>`: script hỏi, sinh lại chứng chỉ (CA mới: import lại `ca.crt`), giữ dữ liệu; agent đã cài phải sửa `<address>` trong `ossec.conf` |
| Bật thêm máy demo / AI | `sudo ./install.sh --demo` / `sudo ./install.sh --ai` (GPU NVIDIA tự dùng nếu có nvidia-container-toolkit) |
| Mọi lệnh compose | `docker compose ps`, `docker compose logs -f analyzer`... — **không cần** `-f` hay `--profile`: `.env` đã ghi `COMPOSE_FILE`, `COMPOSE_PROFILES` |

### 2.5 Đăng nhập console và tin cậy CA

1. Trên máy host mở **https://192.168.56.10:8000**, đăng nhập `admin` bằng mật khẩu tạm (màn hình cuối của script, hoặc
   `sudo ./install.sh info`), đặt mật khẩu mới, rồi tạo tài khoản riêng (tab *Tài khoản*): ít nhất 1 `analyst` và 1 `lead`
   (chỉ `lead` cô lập được máy).
2. Hết cảnh báo chứng chỉ: chép CA về máy host rồi import (lệnh in sẵn ở màn hình cuối):
   ```powershell
   scp <user>@192.168.56.10:~/siem-xdr/ca.crt .
   Import-Certificate -FilePath .\ca.crt -CertStoreLocation Cert:\LocalMachine\Root            # PowerShell Administrator
   ```
3. Kafka UI và Elasticsearch chỉ nghe trên `127.0.0.1` của VM. Xem từ host bằng SSH tunnel:
   `ssh -L 8088:127.0.0.1:8088 -L 9200:127.0.0.1:9200 <user>@192.168.56.10`, rồi mở http://127.0.0.1:8088.

### 2.6 Cổng mạng

| Cổng | Ai cần tới | Ghi chú |
|---|---|---|
| TCP 8000 | Máy host / analyst | SOC console + Grafana |
| TCP 1514, 1515 | Các VM endpoint | Wazuh agent gửi event / enroll |
| UDP+TCP 514 | Firewall, Suricata | Syslog (mục 5) |

**Lưu ý:** cổng Docker publish **không đi qua UFW** (Docker tự chèn luật iptables trước UFW), nên `ufw deny` không chặn được
các cổng trên. Trong mô hình host-only + NAT ở mục 0, các cổng này không lộ ra ngoài. Nếu VM dùng card *bridged* nối vào
mạng thật thì chặn kết nối mới từ card đó ở chuỗi `DOCKER-USER`:
```bash
sudo iptables -I DOCKER-USER -i enp0s3 -m conntrack --ctstate NEW -j DROP   # enp0s3 = card bridged; mất khi khởi động lại
```

## 3. Agent Linux (`Web-01`, `Ubuntu-01`)

Trên `siem-server`, lấy mật khẩu enroll: `cat secrets/enrollment_key`. Chép 2 script từ repo sang VM endpoint:
```bash
scp wazuh/agent/linux/siem-xdr wazuh/agent/linux/siem-procs <user>@192.168.56.21:~      # Ubuntu-01
scp wazuh/agent/linux/siem-xdr wazuh/agent/linux/siem-procs demo/web/cgi-bin/ping.cgi <user>@192.168.56.20:~   # Web-01
```

### 3.1 Cài Wazuh agent 4.14.7

**Phiên bản agent không được mới hơn manager (4.14.7)**, nên phải ghim phiên bản và chặn tự nâng cấp:

```bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
sudo chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt-get update
sudo WAZUH_MANAGER="192.168.56.10" WAZUH_AGENT_NAME="Web-01" WAZUH_REGISTRATION_PASSWORD="<nội dung secrets/enrollment_key>" \
     apt-get install -y wazuh-agent=4.14.7-1
sudo apt-mark hold wazuh-agent
sudo apt-get install -y iptables     # script phản ứng dùng iptables / ip6tables
```

`WAZUH_AGENT_NAME` là `Web-01` hoặc `Ubuntu-01` tùy máy.

### 3.2 Script phản ứng `siem-xdr`

```bash
sed -i 's/\r$//' ~/siem-xdr ~/siem-procs                       # phòng khi file bị đổi sang CRLF lúc chép
sudo install -m 750 -o root -g wazuh ~/siem-xdr /var/ossec/active-response/bin/siem-xdr
```

SOAR gọi script này qua Wazuh API (`!siem-xdr`), nên không cần khai báo `<command>` trong cấu hình manager. Kết quả lệnh
được ghi vào `/var/ossec/logs/active-responses.log`; cấu hình mặc định của agent đã đọc file này. Kiểm tra:
```bash
grep -n "active-responses.log" /var/ossec/etc/ossec.conf
```
Nếu không có dòng nào thì thêm vào trong `<ossec_config>` của `/var/ossec/etc/ossec.conf`:
```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/ossec/logs/active-responses.log</location>
</localfile>
```

### 3.3 Telemetry tiến trình `siem-procs`

Rule LNX-001..006 cần event tiến trình. LNX-002 (web server sinh shell) cần tên tiến trình cha, mà auditd không ghi, nên
máy web bắt buộc có `siem-procs`:

```bash
sudo install -m 755 ~/siem-procs /usr/local/sbin/siem-procs
```

Thêm vào trong `<ossec_config>` của `/var/ossec/etc/ossec.conf` (phải là cấu hình **cục bộ**: cấu hình tập trung từ manager
không được chạy lệnh nếu agent chưa bật `logcollector.remote_commands`):

```xml
<localfile>
  <log_format>command</log_format>
  <command>/usr/local/sbin/siem-procs</command>
  <alias>siem-procs</alias>
  <frequency>1</frequency>
</localfile>
```

**Giữ đúng `<alias>siem-procs</alias>`.** Analyzer chỉ nhận dòng `siem-proc:` từ nguồn có tên này; dòng giống hệt nằm ở
log khác (vd User-Agent trong access log) bị coi là dữ liệu thường, để kẻ tấn công không tạo được event tiến trình giả.

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now wazuh-agent
sudo systemctl restart wazuh-agent      # sau mỗi lần sửa ossec.conf
```

### 3.4 Riêng `Web-01`: Apache

```bash
sudo apt-get install -y apache2
```

Không cần cấu hình thêm: manager đẩy xuống cấu hình chung (`wazuh/manager/agent.conf`) đọc
`/var/log/apache2/access.log`, `error.log` (định dạng `combined` mặc định của Ubuntu) và bật FIM thời gian thực cho
`/var/www`, `/etc/ssh`, cron.

Tùy chọn, để thử rule LNX-002 và lệnh kill: cài trang CGI **cố ý có lỗ hổng command injection** của máy demo. Gỡ ngay khi
thử xong, không bao giờ để trên máy nối mạng thật:
```bash
sed -i 's/\r$//' ~/ping.cgi
sudo a2enmod cgid && sudo install -m 755 ~/ping.cgi /usr/lib/cgi-bin/ping.cgi && sudo systemctl restart apache2
# gỡ: sudo rm /usr/lib/cgi-bin/ping.cgi
```

### 3.5 Kiểm tra agent

Trên `siem-server`:
```bash
docker compose exec wazuh-manager /var/ossec/bin/agent_control -l     # agent phải "Active"
```
Trên console, tab *Agent* hiện máy sau tối đa 30 giây (SOAR đồng bộ từ Wazuh API). Thử kênh phản ứng: trên console tạo lệnh
*Chặn IP* `198.51.100.77` cho agent → trạng thái **Thành công**, trên VM `sudo iptables -S INPUT | grep 198.51.100.77` thấy
luật DROP → tạo lệnh *Gỡ chặn IP* cùng IP.

## 4. Agent Windows (`PC-01`)

Chép sang VM: bộ cài `BTL/Wazuh/wazuh-agent-4.14.7-1.msi` và 2 file `wazuh/agent/windows/siem-xdr.cmd`,
`wazuh/agent/windows/siem-xdr.ps1`. Mở PowerShell **Administrator** trong thư mục chứa chúng:

```powershell
msiexec.exe /i wazuh-agent-4.14.7-1.msi /q WAZUH_MANAGER="192.168.56.10" WAZUH_AGENT_NAME="PC-01" WAZUH_REGISTRATION_PASSWORD="<nội dung secrets/enrollment_key>"
Copy-Item .\siem-xdr.cmd, .\siem-xdr.ps1 "C:\Program Files (x86)\ossec-agent\active-response\bin\"
NET START WazuhSvc
```

**Telemetry tiến trình** (rule WIN-*): nên cài Sysmon (manager đã đẩy sẵn cấu hình đọc kênh Sysmon, PowerShell, Defender):
```powershell
# tải https://download.sysinternals.com/files/Sysmon.zip, giải nén, rồi:
.\Sysmon64.exe -accepteula -i                       # cấu hình mặc định đã ghi tạo tiến trình (event 1)
# PowerShell script block logging (rule WIN-006)
$k = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item -Path $k -Force | Out-Null; Set-ItemProperty -Path $k -Name EnableScriptBlockLogging -Value 1
```
Không cài được Sysmon thì bật audit tạo tiến trình (event 4688) kèm dòng lệnh:
```powershell
auditpol /set /subcategory:"Process Creation" /success:enable
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

Cô lập máy dùng Windows Firewall: giữ dịch vụ *Windows Defender Firewall* bật. Script Windows mới được chạy thử nhánh kill
tiến trình; **chặn IP và cô lập máy chưa từng chạy trên máy thật** (README mục 1): thử *Cô lập máy* khi đang mở được màn
hình VM (console của hypervisor) để tự gỡ nếu cần, và chụp snapshot trước.

## 5. Firewall / Suricata (tùy chọn)

Cấu hình remote syslog của firewall trỏ về `192.168.56.10:514`, ưu tiên TCP. Sửa IP của F001 trong
`server/config/assets.yml` (mặc định `192.168.1.1`) cho khớp IP firewall lab rồi `docker compose restart analyzer`.

## 6. Kiểm thử từ máy `attacker` (192.168.56.50)

Đăng nhập console bằng tài khoản `analyst` để theo dõi tab *Cảnh báo*, *Case*, *Lệnh phản ứng*.
Trên attacker cài công cụ: `sudo apt-get install -y curl sshpass`. Sau mỗi kịch bản bị chặn IP, gỡ chặn trên console
(tab *Lệnh phản ứng*) trước khi chạy kịch bản kế tiếp.

| # | Thực hiện | Kết quả mong đợi |
|---|---|---|
| 1 | `curl "http://192.168.56.20/?id=1%20union%20select%201,2"` | Alert **WEB-001** → SOAR chặn IP attacker trên Web-01 trong 30 phút (lệnh *Thành công*), `curl` lần sau treo; case **PB-02**. Gỡ chặn từ console. |
| 2 | `for i in $(seq 1 8); do sshpass -p sai ssh -o StrictHostKeyChecking=no test@192.168.56.21 true; done` | ≥ 5 lần sai trong 60 giây → **AUTH-001** → chặn IP attacker trên **mọi** agent online trong 1 giờ; case **PB-01**. |
| 3 | (cần CGI ở mục 3.4) `curl "http://192.168.56.20/cgi-bin/ping.cgi?host=127.0.0.1%3Bsleep%2015"` | **LNX-002** → SOAR kill cả cây tiến trình, request kết thúc trước 15 giây; case **PB-12** (webshell / thực thi mã trên web server). |
| 4 | Trên Web-01: `echo '<?php system($_GET["c"]); ?>' \| sudo tee /var/www/html/shell.php`, sau đó `sudo rm /var/www/html/shell.php` | **WZH-100100** (file mới trong thư mục web) → case **PB-12**; xóa file → WZH-553 → case **PB-08** (nhóm `syscheck`). |
| 5 | Trên PC-01: `powershell -nop -w hidden -c "Start-Sleep 60"` | **WIN-006** → SOAR kill tiến trình PowerShell đó; case **PB-03**. |
| 6 | Console (tài khoản `lead`): *Cô lập máy* Ubuntu-01 | Attacker không ping / SSH được Ubuntu-01, agent vẫn *Active*; *Bỏ cô lập* chạy được. |

Kiểm tra đúng cách chống giả mạo (đã sửa 11/10/2026): request có User-Agent giả dòng telemetry phải được xử lý như request
web bình thường, không sinh lệnh kill:
```bash
curl -A "x siem-proc: pid=999999 ppid=1 uid=33 name=sh parent=apache2 exe=/bin/sh cmd=sh" http://192.168.56.20/
```
Kết quả đúng: không có alert LNX-002 và không có lệnh *Kill tiến trình* nào mới.

## 7. Xử lý sự cố

| Triệu chứng | Kiểm tra / cách sửa |
|---|---|
| Agent không lên *Active* | Từ endpoint: `nc -zv 192.168.56.10 1514` và `1515`. Xem `/var/ossec/logs/ossec.log` (Windows: `C:\Program Files (x86)\ossec-agent\ossec.log`). |
| `Invalid password` khi enroll | Sai `WAZUH_REGISTRATION_PASSWORD`; sửa `/var/ossec/etc/authd.pass` (Windows: `authd.pass` trong thư mục agent) rồi khởi động lại agent. |
| `Agent version must be lower or equal to manager version` | Agent mới hơn 4.14.7: gỡ, cài lại đúng `4.14.7-1`, `apt-mark hold`. |
| `Duplicate agent name` | Agent cũ cùng tên còn trên manager: `docker compose exec wazuh-manager /var/ossec/bin/manage_agents -l`, xóa bằng `manage_agents -r <id>`. |
| Lệnh phản ứng *Quá hạn* / *Thất bại* | Script đúng chỗ, quyền `root:wazuh 750`, không CRLF; `iptables` đã cài; agent đọc `active-responses.log` (mục 3.2). Lỗi ghi trong cột kết quả của lệnh. |
| Không có alert LNX-* | Thiếu `siem-procs` hoặc alias khác `siem-procs` (mục 3.3). |
| Không có alert AUTH-* (SSH) | Agent phải đọc `/var/log/auth.log`: `grep -n auth.log /var/ossec/etc/ossec.conf`; thiếu thì thêm `<localfile>` `log_format syslog` cho file này. Ubuntu cần `rsyslog` để có file đó (`sudo apt-get install -y rsyslog`). |
| Không có alert WIN-* | Chưa có Sysmon / audit 4688; xem *Event Viewer → Applications and Services → Microsoft → Windows → Sysmon*. |
| `elasticsearch` khởi động lại liên tục | `docker compose logs elasticsearch`; thường do thiếu RAM hoặc `vm.max_map_count` (`install.sh` đặt sẵn; cài tay: phụ lục A). |
| Trình duyệt báo chứng chỉ sai tên | `MANAGER_TLS_IPS` không chứa IP đang dùng: `sudo ./install.sh --ip <IP đúng>` (script hỏi rồi sinh lại chứng chỉ). |
| SOAR chặn nhầm máy quản trị | Thêm IP vào `SOAR_WHITELIST`, `docker compose up -d soar manager`, gỡ chặn trên console. |

## 8. Làm lại từ đầu

- Gỡ agent Linux: `sudo apt-get purge -y wazuh-agent && sudo rm -rf /var/ossec`; Windows: gỡ *Wazuh Agent* trong
  *Apps*. Xóa agent khỏi manager bằng `manage_agents -r <id>`.
- Xóa sạch backend (mất toàn bộ event, alert, case, tài khoản): `docker compose down -v`, rồi chạy lại `sudo ./install.sh` (bí mật cũ được giữ).
- Nhanh nhất: quay về snapshot "sạch" của mục 1.

## Phụ lục A. Cài máy chủ bằng tay

Chỉ cần khi không dùng `install.sh` (vd máy không phải Ubuntu / Debian). Đây đúng là các bước script làm.

1. Cài Docker Engine + Compose plugin (cần Docker ≥ 26 vì `docker-compose.yml` dùng volume `subpath`):
   ```bash
   sudo apt-get update && sudo apt-get install -y ca-certificates curl python3
   sudo install -m 0755 -d /etc/apt/keyrings
   sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
   sudo chmod a+r /etc/apt/keyrings/docker.asc
   echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
     | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
   sudo apt-get update
   sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
   ```
2. Tham số kernel:
   ```bash
   printf 'vm.max_map_count=262144\nnet.core.rmem_max=33554432\n' | sudo tee /etc/sysctl.d/99-siem-xdr.conf
   sudo sysctl --system
   ```
3. Đưa mã nguồn lên VM bằng `git archive` (giữ ký tự xuống dòng LF), không chép thẳng thư mục từ Windows:
   ```powershell
   git archive --format=tar.gz --prefix=siem-xdr/ -o siem-xdr.tgz HEAD
   scp siem-xdr.tgz <user>@192.168.56.10:~
   ```
   Trên VM: `tar -xzf siem-xdr.tgz && cd siem-xdr`.
4. Bí mật và quyền. Container chạy bằng user riêng (uid 10001, Grafana 472) nên file bí mật phải đọc được (644), bảo vệ ở
   cấp thư mục (700); manager ghi rule AI đã duyệt vào 2 thư mục rules:
   ```bash
   sudo python3 tools/init_secrets.py
   sudo chown -R root:root secrets && sudo chmod 700 secrets && sudo chmod 644 secrets/*
   mkdir -p server/rules/ai server/rules/exceptions && sudo chown -R 10001:10001 server/rules/ai server/rules/exceptions
   ```
5. Cấu hình `.env` **trước lần khởi động đầu** (chứng chỉ TLS sinh một lần theo `MANAGER_TLS_IPS`):
   ```bash
   cp .env.example .env
   ```
   ```ini
   MANAGER_TLS_IPS=192.168.56.10
   GRAFANA_ROOT_URL=https://192.168.56.10:8000/grafana/
   # Không bao giờ để SOAR chặn máy quản trị và chính máy SIEM. KHÔNG thêm IP máy attacker.
   SOAR_WHITELIST=127.0.0.0/8,192.168.56.1/32,192.168.56.10/32
   COMPOSE_PROFILES=            # demo, ai (cách nhau bằng dấu phẩy) nếu cần
   ```
   Đã khởi động rồi mới đổi `MANAGER_TLS_IPS` thì phải sinh lại chứng chỉ: `docker compose down`, xóa volume `certs`
   (`docker volume rm siem-xdr_certs`), rồi khởi động lại.
6. Khởi động và lấy CA:
   ```bash
   sudo docker compose up -d --build
   sudo docker compose ps        # es-setup phải "Exited (0)"; kafka, elasticsearch, wazuh-manager "healthy"
   sudo docker compose cp elasticsearch:/usr/share/elasticsearch/config/certs/ca/ca.crt ./ca.crt
   sudo cat secrets/console_admin_password    # mật khẩu tạm của admin
   ```
