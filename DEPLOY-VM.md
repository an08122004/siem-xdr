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
| `siem-server` | Elasticsearch, Kafka, Wazuh manager, Vector, analyzer, SOAR, console, Grafana | — | 4 vCPU / **8 GB** / 60 GB. Bật AI: 16 GB+ / 100 GB (xem mục 2.5) |
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

### 2.1 Cài Docker Engine + Compose plugin

```bash
sudo apt-get update && sudo apt-get install -y ca-certificates curl python3
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker "$USER"     # đăng xuất / đăng nhập lại để có hiệu lực
```

### 2.2 Tham số kernel

```bash
sudo tee /etc/sysctl.d/99-siem.conf >/dev/null <<'EOF'
vm.max_map_count=262144          # Elasticsearch
net.core.rmem_max=33554432       # buffer UDP 32 MB cho syslog (vector/vector.yaml)
EOF
sudo sysctl --system
```

### 2.3 Đưa mã nguồn lên VM

Từ máy Windows đang có mã nguồn (PowerShell, `tar` có sẵn trên Windows 10+). Không mang theo môi trường Python, dữ liệu
AI, bí mật và `.env` của máy cũ:

```powershell
cd D:\GSANM\BTL
tar -czf siem-xdr.tgz --exclude=siem-xdr/server/.venv --exclude=siem-xdr/.claude --exclude=siem-xdr/datasets `
    --exclude=siem-xdr/ui-shots --exclude=siem-xdr/secrets --exclude=siem-xdr/.env siem-xdr
scp siem-xdr.tgz <user>@192.168.56.10:~
```

Trên `siem-server`:

```bash
tar -xzf siem-xdr.tgz && cd siem-xdr
mkdir -p secrets                  # thư mục bí mật mới cho máy này
```

Repo bắt buộc LF cho script (`.gitattributes`), nên script chạy được ngay trên Linux. Nếu đã chép bằng cách khác và gặp
lỗi `/bin/sh^M: bad interpreter` thì chạy `find . -name '*.sh' -o -path './wazuh/agent/linux/*' | xargs sed -i 's/\r$//'`.

### 2.4 Bí mật và cấu hình

```bash
python3 tools/init_secrets.py      # sinh mật khẩu / key ngẫu nhiên vào secrets/
cp .env.example .env
```

Sửa `.env` **trước lần khởi động đầu** (chứng chỉ TLS sinh một lần theo `MANAGER_TLS_IPS`):

```ini
MANAGER_TLS_IPS=192.168.56.10
GRAFANA_ROOT_URL=https://192.168.56.10:8000/grafana/
# Không bao giờ để SOAR chặn máy quản trị và chính máy SIEM. KHÔNG thêm IP máy attacker.
SOAR_WHITELIST=127.0.0.0/8,192.168.56.1/32,192.168.56.10/32
```

Đã khởi động rồi mới đổi `MANAGER_TLS_IPS` thì phải sinh lại chứng chỉ: `docker compose down`, xóa volume `certs`
(`docker volume rm siem-xdr_certs`), rồi khởi động lại.

### 2.5 Khởi động

```bash
docker compose up -d --build
docker compose ps        # es-setup phải "Exited (0)"; kafka, elasticsearch, wazuh-manager "healthy"
```

Lần đầu mất vài phút (tải image, build image Python). Tùy chọn:

- `--profile demo`: thêm container web demo (`demo-web`, chỉ mở `127.0.0.1:8081` trên VM). Không cần khi đã có VM `Web-01`.
- `--profile ai`: AI đề xuất rule (Ollama, model `qwen3.5:9b` 5–7 GB). Trên VM thường **không có GPU**, Ollama chạy CPU rất
  chậm; cần thêm ~8 GB RAM. Chỉ dùng `-f docker-compose.gpu.yml` khi VM có GPU NVIDIA và đã cài NVIDIA Container Toolkit.
  Mục 2.3 bỏ thư mục `datasets/`; dùng AI thì chép thêm thư mục này, hoặc tải lại bằng `tools/fetch_datasets.py` và
  `tools/convert_datasets.py` (xem AI-README.md).

### 2.6 Đăng nhập console và tin cậy CA

1. Lấy mật khẩu tạm của admin: `cat secrets/console_admin_password`.
2. Trên máy host mở **https://192.168.56.10:8000**, đăng nhập `admin`, đặt mật khẩu mới, rồi tạo tài khoản riêng
   (tab *Tài khoản*): ít nhất 1 `analyst` và 1 `lead` (chỉ `lead` cô lập được máy).
3. Hết cảnh báo chứng chỉ: lấy CA nội bộ rồi import vào *Trusted Root Certification Authorities* của máy host:
   ```bash
   docker compose cp elasticsearch:/usr/share/elasticsearch/config/certs/ca/ca.crt ./ca.crt   # trên VM
   ```
   ```powershell
   scp <user>@192.168.56.10:~/siem-xdr/ca.crt .                                                 # trên host
   Import-Certificate -FilePath .\ca.crt -CertStoreLocation Cert:\LocalMachine\Root            # PowerShell Administrator
   ```
4. Kafka UI và Elasticsearch chỉ nghe trên `127.0.0.1` của VM. Xem từ host bằng SSH tunnel:
   `ssh -L 8088:127.0.0.1:8088 -L 9200:127.0.0.1:9200 <user>@192.168.56.10`, rồi mở http://127.0.0.1:8088.

### 2.7 Cổng mạng

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

Cô lập máy dùng Windows Firewall: giữ dịch vụ *Windows Defender Firewall* bật. **Script Windows chưa từng được chạy thử
trên máy thật** (README mục 1): thử *Cô lập máy* khi đang mở được màn hình VM (console của hypervisor) để tự gỡ nếu cần,
và chụp snapshot trước.

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
| 3 | (cần CGI ở mục 3.4) `curl "http://192.168.56.20/cgi-bin/ping.cgi?host=127.0.0.1%3Bsleep%2015"` | **LNX-002** → SOAR kill cả cây tiến trình, request kết thúc trước 15 giây. |
| 4 | Trên Web-01: `echo '<?php system($_GET["c"]); ?>' \| sudo tee /var/www/html/shell.php`, sau đó `sudo rm /var/www/html/shell.php` | **WZH-100100** (file mới trong thư mục web) → case **PB-08**; xóa file → WZH-553. |
| 5 | Trên PC-01: `powershell -nop -w hidden -c "Start-Sleep 60"` | **WIN-006** → SOAR kill tiến trình PowerShell đó. |
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
| `elasticsearch` khởi động lại liên tục | `docker compose logs elasticsearch`; thường do thiếu RAM hoặc `vm.max_map_count` (mục 2.2). |
| Trình duyệt báo chứng chỉ sai tên | `MANAGER_TLS_IPS` không chứa IP đang dùng: sửa `.env`, xóa volume `certs`, khởi động lại (mục 2.4). |
| SOAR chặn nhầm máy quản trị | Thêm IP vào `SOAR_WHITELIST`, `docker compose up -d soar manager`, gỡ chặn trên console. |

## 8. Làm lại từ đầu

- Gỡ agent Linux: `sudo apt-get purge -y wazuh-agent && sudo rm -rf /var/ossec`; Windows: gỡ *Wazuh Agent* trong
  *Apps*. Xóa agent khỏi manager bằng `manage_agents -r <id>`.
- Xóa sạch backend (mất toàn bộ event, alert, case, tài khoản): `docker compose down -v`, rồi làm lại từ mục 2.4.
- Nhanh nhất: quay về snapshot "sạch" của mục 1.
