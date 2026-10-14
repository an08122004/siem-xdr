# Lab trên VMware Workstation: SIEM chạy trên máy host

Hướng dẫn dựng từng loại máy của lab khi **SIEM chạy trên Docker của máy host Windows** (không có VM `siem-server`). Máy
host nối vào vùng SOC với địa chỉ `10.10.40.1` và chính là SIEM. Mô hình mạng 4 vùng, bảng IP và các kịch bản kiểm thử giống
[DEPLOY-VM.md](DEPLOY-VM.md); chỗ nào DEPLOY-VM.md ghi `10.10.40.10` (VM `siem-server`) thì ở đây là `10.10.40.1`.

| Máy | Vùng · mạng VMware | IP | Mục |
|---|---|---|---|
| Firewall F001 (OPNsense) | 5 card: NAT, VMnet5, VMnet3, VMnet4, VMnet2 | 10.10.40.254, 10.10.20.254, 10.10.30.254, 203.0.113.1 | 1 |
| Web-01 (Linux server) | DMZ · VMnet3 | 10.10.20.20 | 2 |
| Ubuntu-01 (Linux workstation) | USERS · VMnet4 | 10.10.30.21 | 3 |
| PC-01 (Windows workstation) | USERS · VMnet4 | 10.10.30.30 | 4 |
| DC-01 (tùy chọn) | USERS · VMnet4 | 10.10.30.10 | 4 |
| Máy host = SIEM | SOC · VMnet5 | 10.10.40.1 | 0 |

## 0. Chuẩn bị chung (làm một lần)

1. **Mạng ảo:** *Edit → Virtual Network Editor → Change Settings* (cần quyền admin) → *Add Network*. Mỗi mạng chọn
   *Host-only*, **bỏ** *Use local DHCP service*:

   | Mạng | Vùng | Subnet / mask | *Connect a host virtual adapter* |
   |---|---|---|---|
   | VMnet2 | Internet giả | 203.0.113.0 / 255.255.255.0 | Bỏ |
   | VMnet3 | DMZ | 10.10.20.0 / 255.255.255.0 | Bỏ |
   | VMnet4 | USERS | 10.10.30.0 / 255.255.255.0 | Bỏ |
   | VMnet5 | SOC | 10.10.40.0 / 255.255.255.0 | **Chọn** (máy host nhận 10.10.40.1) |

2. **Route trên máy host** (PowerShell Administrator). Bắt buộc với phương án này: SIEM nằm trên máy host, không có route
   thì SIEM không trả lời được agent ở DMZ và USERS:
   ```powershell
   route -p add 10.10.20.0 mask 255.255.255.0 10.10.40.254
   route -p add 10.10.30.0 mask 255.255.255.0 10.10.40.254
   ```
3. **SIEM:** stack Docker chạy trong thư mục mã nguồn, cùng file `.env` của thư mục đó. Agent cần cổng 1514 và 1515, syslog
   cần 514, console ở 8000. `.env` nên có:
   ```ini
   SOAR_WHITELIST=127.0.0.0/8,10.10.40.1/32,10.10.40.254/32,10.10.20.254/32,10.10.30.254/32,203.0.113.1/32
   AGENT_DOWN_MINUTES=2
   WAZUH_AGENTS_DISCONNECTION_TIME=1m
   ```
   Sau khi sửa `.env`: `docker compose up -d soar manager analyzer wazuh-manager`.
4. **Mật khẩu enroll agent:** nội dung file `secrets\enrollment_key` trong thư mục mã nguồn.

## 1. Firewall F001 (OPNsense)

1. Tải [OPNsense-26.7-dvd-amd64.iso.bz2](https://pkg.opnsense.org/releases/26.7/OPNsense-26.7-dvd-amd64.iso.bz2), giải nén
   bằng 7-Zip. (Bản *nano* chỉ có console serial, cửa sổ VMware không hiện màn hình, nên dùng bản DVD.)
2. *New Virtual Machine → Custom*, Guest OS *Other → FreeBSD 14 64-bit*, 2 vCPU, 2 GB RAM, đĩa 16 GB. *VM Settings* thêm
   card cho đủ 5 card mạng, **đúng thứ tự**: 1 NAT, 2 VMnet5, 3 VMnet3, 4 VMnet4, 5 VMnet2.
3. Boot từ ISO, đăng nhập `installer` / `opnsense`, cài vào đĩa. Sau khi cài, tài khoản là `root` / `opnsense`.
4. Trên menu console:
   - *1) Assign interfaces*: không tạo VLAN; WAN = `em0`, LAN = `em1`, Optional = `em2`, `em3`, `em4`.
   - *2) Set interface IP address*: LAN `10.10.40.254/24`, không gateway, không bật DHCP.
5. Từ máy host mở `https://10.10.40.254` và chạy wizard: hostname `fw`, timezone `Asia/Ho_Chi_Minh`, WAN để DHCP,
   **đổi mật khẩu root**. Đổi Description của LAN thành `SOC`.
6. *Interfaces → OPT1 / OPT2 / OPT3*: bật cổng, đặt Description và IPv4 tĩnh: DMZ `10.10.20.254/24`, USERS `10.10.30.254/24`,
   INET_GIA `203.0.113.1/24`. Không đặt gateway cho ba cổng này.
7. **Luật** (*Firewall → Rules → <cổng>*). Tạo trước alias `PRIVATE` gồm `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`,
   `203.0.113.0/24`.

   | Cổng | Cho phép |
   |---|---|
   | DMZ, USERS | TCP tới `10.10.40.1` cổng 1514, 1515 (agent về SIEM) |
   | DMZ, USERS | UDP 53, 123 tới địa chỉ của chính cổng đó (DNS, NTP) |
   | DMZ, USERS | TCP 80, 443 tới đích **không** thuộc `PRIVATE` (cài gói; tắt trước buổi demo) |
   | SOC | Giữ luật mặc định cho phép tất cả |

   Luật riêng cho các kịch bản kiểm thử: DEPLOY-VM.md mục 1.2.
8. **Port forward web:** *Firewall → NAT → Port Forward*: cổng `INET_GIA`, TCP, đích là địa chỉ của INET_GIA cổng 80, chuyển
   tới `10.10.20.20:80`, chọn tự tạo luật đi kèm.
9. **Syslog về SIEM:** *System → Settings → Logging → Remote*: thêm đích UDP, `10.10.40.1`, cổng `514`, mọi ứng dụng và mọi
   mức.
10. **Suricata:** *Services → Intrusion Detection*:
    - *Administration*: bật *Enabled*, **không** bật IPS mode (chỉ phát hiện, để SOAR là bên phản ứng), Interfaces
      `INET_GIA` (thêm `DMZ` nếu đủ RAM), bật *Enable eve syslog output*.
    - *Download*: chọn bộ luật ET Open → *Download & Update Rules*.
11. **Kiểm tra:** mọi gói bị luật mặc định chặn đều được ghi log, ví dụ ping từ Web-01 sang `10.10.30.30`. Trong 1 phút,
    Grafana *Điều tra* có event `event.module:pfsense`.

## 2. Linux server: Web-01 (DMZ)

1. **Tạo VM:** ISO [Ubuntu Server 24.04](https://ubuntu.com/download/server) (bản Desktop cũng được nhưng nặng hơn), 1 vCPU,
   2 GB RAM, 20 GB, card *Custom: VMnet3*.
2. **Lúc cài:** hostname `Web-01`, mạng đặt tay `10.10.20.20/24`, gateway và DNS `10.10.20.254`, chọn cài *OpenSSH server*.
3. **Chép script từ máy host** (máy host đã có route ở mục 0), trong thư mục mã nguồn:
   ```powershell
   scp wazuh/agent/linux/siem-xdr wazuh/agent/linux/siem-procs <user>@10.10.20.20:~
   ```
4. **Wazuh agent 4.14.7** (bản agent không được mới hơn manager):
   ```bash
   curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
   sudo chmod 644 /usr/share/keyrings/wazuh.gpg
   echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list
   sudo apt-get update
   sudo WAZUH_MANAGER="10.10.40.1" WAZUH_AGENT_NAME="Web-01" WAZUH_REGISTRATION_PASSWORD="<nội dung secrets/enrollment_key>" \
        apt-get install -y wazuh-agent=4.14.7-1
   sudo apt-mark hold wazuh-agent
   sudo apt-get install -y iptables apache2
   ```
5. **Script phản ứng và telemetry tiến trình:**
   ```bash
   sed -i 's/\r$//' ~/siem-xdr ~/siem-procs
   sudo install -m 750 -o root -g wazuh ~/siem-xdr /var/ossec/active-response/bin/siem-xdr
   sudo install -m 755 ~/siem-procs /usr/local/sbin/siem-procs
   ```
   Thêm vào trong `<ossec_config>` của `/var/ossec/etc/ossec.conf` (giữ đúng `<alias>siem-procs</alias>`: analyzer chỉ nhận
   telemetry tiến trình từ nguồn có tên này):
   ```xml
   <localfile>
     <log_format>command</log_format>
     <command>/usr/local/sbin/siem-procs</command>
     <alias>siem-procs</alias>
     <frequency>1</frequency>
   </localfile>
   ```
   `grep active-responses.log /var/ossec/etc/ossec.conf` không ra dòng nào thì thêm một khối `<localfile>` đọc
   `/var/ossec/logs/active-responses.log` với `<log_format>syslog</log_format>`.
6. **Bật agent:**
   ```bash
   sudo systemctl daemon-reload && sudo systemctl enable --now wazuh-agent
   ```
   Log Apache và FIM của `/var/www` do manager tự đẩy cấu hình xuống (`wazuh/manager/agent.conf`).

## 3. Linux workstation: Ubuntu-01 (USERS)

Làm như mục 2, chỉ khác: card *VMnet4*; IP `10.10.30.21/24`, gateway và DNS `10.10.30.254`; `WAZUH_AGENT_NAME="Ubuntu-01"`;
không cài `apache2`.

## 4. Windows workstation: PC-01 (USERS)

1. **Tạo VM:** ISO `Windows10.iso`, Guest *Windows 10 x64*, 2 vCPU, 4 GB RAM, 50 GB, card *VMnet4*. Cài với tài khoản cục bộ,
   rồi *VM → Install VMware Tools* để kéo thả file.
2. **IP và tên máy** (PowerShell Administrator):
   ```powershell
   New-NetIPAddress -InterfaceAlias Ethernet0 -IPAddress 10.10.30.30 -PrefixLength 24 -DefaultGateway 10.10.30.254
   Set-DnsClientServerAddress -InterfaceAlias Ethernet0 -ServerAddresses 10.10.30.254
   Rename-Computer -NewName PC-01 -Restart
   ```
3. **Chép vào VM:** `BTL/Wazuh/wazuh-agent-4.14.7-1.msi`, `wazuh/agent/windows/siem-xdr.cmd`, `siem-xdr.ps1`.
4. **Cài agent** (PowerShell Administrator, trong thư mục chứa 3 file trên):
   ```powershell
   msiexec.exe /i wazuh-agent-4.14.7-1.msi /q WAZUH_MANAGER="10.10.40.1" WAZUH_AGENT_NAME="PC-01" WAZUH_REGISTRATION_PASSWORD="<nội dung secrets/enrollment_key>"
   Copy-Item .\siem-xdr.cmd, .\siem-xdr.ps1 "C:\Program Files (x86)\ossec-agent\active-response\bin\"
   NET START WazuhSvc
   ```
5. **Telemetry:** cài Sysmon (tải [Sysmon.zip](https://download.sysinternals.com/files/Sysmon.zip), giải nén,
   `.\Sysmon64.exe -accepteula -i`) và bật PowerShell script block logging:
   ```powershell
   $k = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
   New-Item -Path $k -Force | Out-Null; Set-ItemProperty -Path $k -Name EnableScriptBlockLogging -Value 1
   ```
6. **Giữ bật Windows Defender và Windows Firewall** (lệnh cô lập máy dùng Windows Firewall). Chụp snapshot trước khi thử cô
   lập máy.

**DC-01 (tùy chọn):** ISO Windows Server 2019 Evaluation, IP `10.10.30.10`, cài agent như PC-01 với
`WAZUH_AGENT_NAME="DC-01"`, rồi thêm role *Active Directory Domain Services* trong Server Manager.

## 5. Kiểm tra trên SIEM

Trong thư mục mã nguồn:
```powershell
docker compose exec wazuh-manager /var/ossec/bin/agent_control -l    # mọi agent phải "Active"
```
- Console `https://localhost:8000`, tab *Agent*: máy mới hiện sau tối đa 30 giây.
- Grafana *Điều tra*: `host.name:Web-01` (hoặc tên máy khác) có event.
- **Kênh phản ứng:** trên console tạo lệnh *Chặn IP* `198.51.100.77` cho một agent → *Thành công* (Linux:
  `sudo iptables -S INPUT`), rồi tạo lệnh gỡ chặn.
- **Báo mất kết nối:** dừng dịch vụ agent trên một máy → khoảng 2–3 phút sau có alert HLT-001; bật lại thì alert ghi
  "đã hồi phục".

Khi mọi máy đã chạy ổn, các kịch bản kiểm thử nằm ở DEPLOY-VM.md mục 6.
