# Triển khai SOC Platform trên máy ảo

Hướng dẫn dựng toàn bộ hệ thống trên các máy ảo VMware Workstation (VirtualBox / Hyper-V làm tương tự): một firewall chia
mạng thành 4 vùng, một VM chạy backend bằng Docker và các VM endpoint cài Wazuh agent theo đúng danh mục tài sản
`BTL/asset.txt`. Kiến trúc, cấu hình chi tiết và giải thích từng thành phần nằm ở [README.md](README.md); tài liệu này chỉ
đi theo thứ tự các bước cài đặt.

Chạy SIEM ngay trên Docker của máy host Windows, không có VM `siem-server`: xem [LAB-VMWARE.md](LAB-VMWARE.md) (hướng dẫn
theo từng loại máy, SIEM ở `10.10.40.1`).

> **Chỉ chạy trong mạng lab cô lập.** SOAR tự chặn IP, kill tiến trình trên máy thật; máy web có thể được cài trang CGI
> cố ý có lỗ hổng để thử. Chụp snapshot mọi VM trước khi thử tấn công.

## 0. Mô hình lab

Lab chia 4 vùng như mạng của một tổ chức thật, ngăn bởi firewall F001. Firewall vừa là gateway, DNS và NTP của mọi vùng,
vừa sinh log (filterlog, Suricata) gửi về SIEM. Attacker ở "Internet giả" chỉ thấy cổng 80 của Web-01; agent ở DMZ và LAN
chỉ được nói chuyện với `siem-server` qua cổng Wazuh.

```
                    Internet thật (VMnet8, NAT của VMware): chỉ để cài gói, cập nhật
                                         │ WAN (DHCP)
                    ┌────────────────────┴─────────────────────┐
 Internet giả       │ F001 firewall (pfSense CE hoặc OPNsense) │
 VMnet2 ────────────┤ + Suricata IDS                           │
 203.0.113.0/24  .1 │ cổng .254 trên mỗi vùng bên dưới         │
 attacker .50, .51  └───────┬───────────────┬──────────────┬───┘
 (chỉ được TCP 80           │               │              │
  tới Web-01)        DMZ · VMnet3     LAN · VMnet4     SOC · VMnet5
                     10.10.20.0/24    10.10.30.0/24    10.10.40.0/24
                     Web-01 .20       PC-01 .30        siem-server .10
                                      Ubuntu-01 .21    máy host Windows .1 (console)
                                      DC-01 .10 (tùy chọn)
```

| VM | Vùng · IP | Vai trò | Tên agent (bắt buộc) | vCPU / RAM / Đĩa |
|---|---|---|---|---|
| `fw` (F001) | WAN: DHCP từ VMnet8; 10.10.40.254, 10.10.20.254, 10.10.30.254, 203.0.113.1 | Firewall, NAT ra Internet, DNS, NTP, Suricata, gửi syslog | — | 2 / 2 GB / 16 GB |
| `siem-server` | SOC 10.10.40.10 | Elasticsearch, Kafka, Wazuh manager, Vector, analyzer, SOAR, console, Grafana | — | 4 / **8 GB** / 60 GB. Bật AI: 16 GB+ / 100 GB (mục 2.4) |
| `Web-01` | DMZ 10.10.20.20 | Máy chủ web S001 (Apache) | `Web-01` | 1 / 1,5 GB / 20 GB |
| `Ubuntu-01` | LAN 10.10.30.21 | Máy trạm Linux A003 | `Ubuntu-01` | 1 / 1,5 GB / 20 GB |
| `PC-01` | LAN 10.10.30.30 | Máy trạm Windows A001 | `PC-01` | 2 / 4 GB / 50 GB |
| `DC-01` (tùy chọn) | LAN 10.10.30.10 | Active Directory, S002 | `DC-01` | 2 / 4 GB / 50 GB |
| `attacker` | Internet giả 203.0.113.50 và .51 | Kali, thử tấn công (không cài agent) | — | 2 / 3 GB / 30 GB |
| máy host | SOC 10.10.40.1 | Trình duyệt mở console, SSH quản trị | — | — |

6 VM bắt buộc dùng khoảng 20 GB RAM (24 GB nếu thêm DC-01). Đĩa cấp phát mỏng (không chọn *Allocate all disk space now*);
3 VM Ubuntu nên là *linked clone* của cùng một template (mục 1.3) để tiết kiệm đĩa.

Đo thực tế (11/10/2026, stack chạy không tải): Elasticsearch ~1,8 GB, Kafka ~0,55 GB, Kafka UI ~0,3 GB, Wazuh manager
~0,36 GB, các service còn lại dưới 0,1 GB mỗi cái, tổng ~3,6 GB. 8 GB RAM cho VM là đủ chỗ cho hệ điều hành và lúc tải cao.

`203.0.113.0/24` là dải dành cho tài liệu (TEST-NET-3, RFC 5737): IP attacker trông như IP Internet mà không trùng máy thật
nào. Analyzer coi dải này là IP bên ngoài (`server/siem/pipeline/enrich.py` không dùng `ipaddress.is_private`, vốn xếp
TEST-NET vào nhóm private).

**Tên agent phải khớp `hostname` trong `server/config/assets.yml`** (`PC-01`, `Ubuntu-01`, `Web-01`, `DC-01`): analyzer dựa
vào tên này để gắn tài sản và mức quan trọng (ưu tiên P1–P4, `risk_score`). Firewall được nhận ra theo IP gửi syslog (`ips`
của F001). Đổi mô hình mạng thì sửa `assets.yml` trước (analyzer và SOAR đọc khi khởi động).

## 1. Chuẩn bị mạng và VM

### 1.1 Mạng ảo trong VMware

*Edit → Virtual Network Editor → Change Settings* (cần quyền admin) → *Add Network* lần lượt VMnet2–VMnet5. Mỗi mạng chọn
**Host-only**, **bỏ** *Use local DHCP service to distribute IP address to VMs*, đặt *Subnet IP* như bảng:

| Mạng | Vùng | Subnet IP / mask | *Connect a host virtual adapter to this network* |
|---|---|---|---|
| VMnet2 | Internet giả | 203.0.113.0 / 255.255.255.0 | **Bỏ** |
| VMnet3 | DMZ | 10.10.20.0 / 255.255.255.0 | **Bỏ** |
| VMnet4 | LAN | 10.10.30.0 / 255.255.255.0 | **Bỏ** |
| VMnet5 | SOC | 10.10.40.0 / 255.255.255.0 | **Chọn** (máy host nhận 10.10.40.1) |

VMnet8 (NAT) giữ nguyên, chỉ firewall nối vào. Máy host chỉ nối vào SOC: nếu nối cả DMZ hay LAN, lưu lượng từ host sẽ đi
thẳng, không qua firewall và không có log.

Mỗi VM chỉ có **một** card mạng, *Network connection: Custom* chọn VMnet của vùng mình (bảng mục 0). Riêng `fw` có 5 card,
thứ tự quyết định tên cổng trong firewall:

| Card | Mạng | Cổng firewall | Mô tả đặt trong firewall |
|---|---|---|---|
| 1 | VMnet8 (NAT) | WAN | WAN |
| 2 | VMnet5 | LAN | `SOC` |
| 3 | VMnet3 | OPT1 | `DMZ` |
| 4 | VMnet4 | OPT2 | `USERS` (vùng LAN người dùng) |
| 5 | VMnet2 | OPT3 | `INET_GIA` |

Cổng "LAN" của firewall được dùng cho vùng SOC vì firewall chỉ mở giao diện quản trị và luật "cho phép tất cả" trên cổng
LAN: máy host (10.10.40.1) vào được trang quản trị ngay sau khi cài, và vùng SOC quản trị được mọi vùng khác.

### 1.2 Firewall `fw` (F001)

Cài pfSense CE hoặc OPNsense (2 vCPU, 2 GB RAM, 16 GB đĩa, 5 card như trên). Hai sản phẩm có cùng nền FreeBSD/pf; các bước
dưới ghi menu pfSense, OPNsense có menu tương đương. Analyzer đọc được log `filterlog` của cả hai.

1. Trên màn hình console sau khi cài: *Assign Interfaces* theo bảng ở 1.1 (không dùng VLAN). *Set interface IP address*
   cho LAN: `10.10.40.254/24`, không bật DHCP server.
2. Từ máy host mở `https://10.10.40.254`, chạy *Setup Wizard*: hostname `fw`, DNS để trống (dùng DNS Resolver có sẵn),
   timezone `Asia/Ho_Chi_Minh`, WAN để DHCP. Đổi *Description* của cổng LAN thành `SOC`.
3. *Interfaces → OPT1/OPT2/OPT3*: bật, đặt Description và IPv4 tĩnh: DMZ `10.10.20.254/24`, USERS `10.10.30.254/24`,
   INET_GIA `203.0.113.1/24`. Không đặt gateway cho các cổng này.
4. *Services → DNS Resolver* và *Services → NTP*: để nghe trên mọi cổng (mặc định). Mọi VM dùng IP `.254` của vùng mình làm
   gateway, DNS và NTP; attacker dùng `203.0.113.1`.
5. *Firewall → Aliases*: tạo alias `PRIVATE` = `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `203.0.113.0/24`
   (đích "Internet thật" = không thuộc alias này).
6. *Firewall → NAT → Port Forward*: Interface `INET_GIA`, Protocol TCP, Destination *INET_GIA address* cổng 80 → Redirect
   target `10.10.20.20` cổng 80, *Filter rule association: Add associated filter rule*. Outbound NAT để *Automatic*: chỉ NAT
   khi ra WAN, nên Web-01 thấy đúng IP attacker (SOAR chặn đúng người).
7. *Firewall → Rules* (luật xét theo cổng mà gói tin **đi vào**; không khớp luật nào thì bị chặn và ghi log, đủ cho
   rule NET-001, NET-002):

   | Cổng | Cho phép | Mục đích |
   |---|---|---|
   | INET_GIA | TCP tới 10.10.20.20:80 (luật tự sinh ở bước 6) | Web public bị tấn công |
   | DMZ | TCP 10.10.20.0/24 → 10.10.40.10 cổng 1514, 1515 | Agent gửi log, enroll, nhận lệnh phản ứng |
   | DMZ | TCP 10.10.20.20 → 10.10.30.21 cổng 22 | **Cố ý mở** cho kịch bản đi ngang (mục 6, bước 4) |
   | USERS | TCP 10.10.30.0/24 → 10.10.40.10 cổng 1514, 1515 | Agent |
   | DMZ, USERS | UDP 53, 123 tới *address* của chính cổng đó | DNS, NTP qua firewall |
   | DMZ, USERS | TCP 80, 443 tới đích **không** thuộc `PRIVATE` | Cài gói, Windows Update. **Tắt trước buổi demo** |
   | SOC | Luật mặc định *Default allow LAN to any* (giữ nguyên) | Quản trị mọi vùng, ra Internet |
   | INET_GIA | (tùy chọn) TCP 80, 443 tới đích không thuộc `PRIVATE` | Cập nhật Kali; tắt trước demo |

   Giữ bật *Status → System Logs → Settings → Log packets matched from the default block rules* (mặc định đã bật).
   Firewall tự gửi syslog tới `siem-server` không cần luật riêng.
8. Gửi log và bật Suricata sau khi `siem-server` chạy xong: mục 5.

### 1.3 VM Ubuntu từ một template

1. Tạo VM template Ubuntu Server 24.04 (bản Server nhẹ hơn bản Desktop), cài `openssh-server`, `sudo apt-get upgrade`,
   tắt máy, chụp snapshot `base`. Trong lúc làm template, nối tạm card vào VMnet8 để có Internet.
2. *VM → Manage → Clone → An existing snapshot (base) → Create a linked clone* ra `siem-server`, `Web-01`, `Ubuntu-01`;
   chuyển card của từng máy sang VMnet của vùng (bảng mục 0). `siem-server` tăng lên 4 vCPU / 8 GB.
3. Trên mỗi bản clone, đổi danh tính để các máy không trùng nhau:
   ```bash
   sudo hostnamectl set-hostname Web-01                       # Web-01 / Ubuntu-01 / siem-server
   sudo rm -f /etc/machine-id && sudo systemd-machine-id-setup
   sudo rm -f /etc/ssh/ssh_host_* && sudo dpkg-reconfigure openssh-server
   ```

### 1.4 Đặt IP tĩnh

Ubuntu (tên card xem bằng `ip -br link`, trên VMware thường là `ens33`):
```bash
sudo tee /etc/netplan/60-lab.yaml >/dev/null <<'EOF'
network:
  version: 2
  ethernets:
    ens33:
      dhcp4: false
      addresses: [10.10.20.20/24]                 # đổi theo bảng ở mục 0
      routes: [{to: default, via: 10.10.20.254}]  # .254 của vùng
      nameservers: {addresses: [10.10.20.254]}
EOF
sudo chmod 600 /etc/netplan/60-lab.yaml && sudo netplan apply
```
| Máy | `addresses` | `via` và `nameservers` |
|---|---|---|
| `siem-server` | `10.10.40.10/24` | `10.10.40.254` |
| `Web-01` | `10.10.20.20/24` | `10.10.20.254` |
| `Ubuntu-01` | `10.10.30.21/24` | `10.10.30.254` |

Windows `PC-01` (PowerShell Administrator; tên card xem bằng `Get-NetAdapter`, thường là `Ethernet0`):
```powershell
New-NetIPAddress -InterfaceAlias Ethernet0 -IPAddress 10.10.30.30 -PrefixLength 24 -DefaultGateway 10.10.30.254
Set-DnsClientServerAddress -InterfaceAlias Ethernet0 -ServerAddresses 10.10.30.254
```
`DC-01` làm tương tự với `10.10.30.10`.

Kali `attacker` (bản VMware dựng sẵn: giảm còn 2 vCPU / 3 GB, chuyển card sang VMnet2, chụp snapshot trước khi đổi). Hai IP
để đổi IP sau khi bị chặn, như kẻ tấn công thật:
```bash
nmcli con show                                         # tên kết nối, thường là "Wired connection 1"
sudo nmcli con mod "Wired connection 1" ipv4.method manual \
     ipv4.addresses "203.0.113.50/24,203.0.113.51/24" ipv4.gateway 203.0.113.1 ipv4.dns 203.0.113.1
sudo nmcli con up "Wired connection 1"
```
Gửi request từ IP thứ hai: `curl --interface 203.0.113.51 ...`.

### 1.5 Đường đi từ máy host, giờ, snapshot

1. Máy host chỉ nối vào vùng SOC. Để SSH / `scp` tới Web-01, Ubuntu-01, PC-01 thì thêm route qua firewall (PowerShell
   Administrator, `-p` = giữ sau khi khởi động lại):
   ```powershell
   route -p add 10.10.20.0 mask 255.255.255.0 10.10.40.254
   route -p add 10.10.30.0 mask 255.255.255.0 10.10.40.254
   ```
   Attacker không cần route: thao tác qua màn hình VMware.
2. Đồng bộ giờ với firewall trên mọi VM. Lệch giờ làm alert và kết quả lệnh phản ứng bị lệch thời điểm, MTTD sai.
   ```bash
   sudo sed -i 's/^#\?NTP=.*/NTP=10.10.20.254/' /etc/systemd/timesyncd.conf    # .254 của vùng
   sudo systemctl restart systemd-timesyncd && timedatectl
   ```
   Windows: `w32tm /config /manualpeerlist:10.10.30.254 /syncfromflags:manual /update` rồi `w32tm /resync`.
3. Kiểm tra: từ mỗi VM `ping` được `.254` của vùng mình và ra Internet (`curl -I https://download.docker.com`); từ Web-01
   **không** ping được 10.10.30.30 (chỉ cổng 22 của Ubuntu-01 được mở).
4. Chụp snapshot "sạch" cho mọi VM.

## 2. Máy chủ SIEM (`siem-server`, 10.10.40.10)

Cài bằng **một lệnh**. Script `install.sh` tự làm mọi bước (bảng ở 2.3); các bước làm tay để ở [phụ lục A](#phụ-lục-a-cài-máy-chủ-bằng-tay).

### 2.1 Cách nhanh nhất: một lệnh từ máy Windows

Chuẩn bị trên VM `siem-server`: Ubuntu 24.04 (hoặc 22.04 / Debian 12), đã đặt IP ở mục 1.4, bật SSH:
```bash
sudo apt-get install -y openssh-server
```
Trên máy Windows, mở PowerShell trong thư mục mã nguồn (`soc-platform`, trước 14/10/2026 là `siem-xdr`):
```powershell
powershell -ExecutionPolicy Bypass -File .\tools\deploy-vm.ps1 <user>@10.10.40.10      # thêm -Demo: máy web demo, -AI: AI
```
(`-ExecutionPolicy Bypass` chỉ áp cho lần chạy này: Windows mặc định chặn chạy file `.ps1`. SSH khác cổng 22 hoặc dùng khóa:
thêm `-Port 2222`, `-SshOption '-i','C:\keys\vm'`.)
Nhập mật khẩu SSH, rồi mật khẩu sudo khi được hỏi. Script gửi **bản đã commit** của repo (`git archive`: đúng ký tự xuống dòng
cho Linux, không mang theo `.venv`, `datasets`, `secrets`, `.env`) sang VM và chạy `sudo ./install.sh`. IP của máy Windows
(nhìn từ VM, tức `10.10.40.1`) được thêm vào `SOAR_WHITELIST`, nên SOAR không bao giờ chặn máy quản trị. Lần đầu mất khoảng
5–20 phút (cài Docker, tải image, build image Python).

Màn hình cuối in sẵn: địa chỉ console, mật khẩu `admin` tạm, đường dẫn file CA, lệnh cài agent Linux / Windows **đã điền IP
và mật khẩu enroll**. In lại lúc nào cũng được: `sudo ./install.sh info` (trong thư mục `~/soc-platform` trên VM).

VM đã cài trước 14/10/2026 (mã nguồn ở `~/siem-xdr`): script cập nhật vào đúng thư mục đó, `install.sh` giữ tên project
Compose `siem-xdr` ghi trong `.env`, nên dữ liệu và agent đã enroll còn nguyên. Muốn chuyển sang tên mới, chạy trên VM:
`cd ~/siem-xdr && sudo python3 tools/migrate_project.py --apply && sudo ./install.sh --update` (xem README mục 2,
*Nâng cấp từ siem-xdr*). Các lệnh dưới đây ghi `~/soc-platform`; VM cũ thay bằng `~/siem-xdr`.

### 2.2 Hoặc chạy ngay trên VM (tự tải mã nguồn từ GitHub)

Không cần chép mã từ Windows: chỉ cần file `install.sh`, script tự tải repo (nhánh `main`) vào `~/siem-xdr` rồi cài. Repo
đang riêng tư nên cần token GitHub đọc được repo (fine-grained token, quyền *Contents: Read-only* trên `an08122004/siem-xdr`):
```bash
cd ~
read -rsp 'Token GitHub: ' GITHUB_TOKEN; echo; export GITHUB_TOKEN
curl -fsSL -H "Authorization: Bearer $GITHUB_TOKEN" -H 'Accept: application/vnd.github.raw' \
  https://api.github.com/repos/an08122004/siem-xdr/contents/install.sh -o install.sh
sudo --preserve-env=GITHUB_TOKEN bash install.sh --demo --admin-ip 10.10.40.1    # tham số như bên dưới
```
Không có `GITHUB_TOKEN` thì script hỏi token (không hiện ký tự). Các lần sau chạy trong `~/siem-xdr`.

Nếu mã nguồn đã có trên VM (vd `git clone` bằng token GitHub):
```bash
cd siem-xdr
sudo ./install.sh                      # tự phát hiện IP; máy nhiều IP thì hỏi, hoặc chỉ định --ip 10.10.40.10
sudo ./install.sh --demo --admin-ip 10.10.40.1       # kèm máy web demo, khai IP máy quản trị
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

Đã thử ngày 11/10/2026 trên Ubuntu 24.04 sạch (2 card mạng như mô hình lab cũ): cài từ đầu kể cả Docker, phát hiện đúng IP
card lab; chạy lại và cập nhật qua `deploy-vm.ps1` giữ nguyên bí mật / `.env`; đổi IP rồi đổi lại, dữ liệu còn nguyên.
Sau cài: manager (uid 10001) và Grafana (uid 472) đọc được bí mật, analyzer ghi event vào Elasticsearch, SOAR đồng bộ agent
qua Wazuh API, đăng nhập console được, agent demo *Active*. Chưa thử: `--update` (build lại image), `--ai`, và mô hình 4 vùng
sau firewall của tài liệu này.

### 2.4 Lệnh thường dùng sau khi cài

| Việc | Lệnh (trên VM, thư mục `~/soc-platform`) |
|---|---|
| Xem trạng thái | `sudo ./install.sh status` |
| In lại địa chỉ, mật khẩu tạm, lệnh cài agent | `sudo ./install.sh info` |
| Cập nhật mã nguồn mới | trên Windows: `powershell -ExecutionPolicy Bypass -File .\tools\deploy-vm.ps1 <user>@10.10.40.10 -Update` (gửi bản commit mới, build lại image; rule AI đã duyệt trên VM giữ nguyên); hoặc trên VM: `sudo --preserve-env=GITHUB_TOKEN ./install.sh --fetch` (tải nhánh `main` từ GitHub; file đã xóa trên GitHub không tự xóa trên VM) |
| Đổi IP máy chủ | `sudo ./install.sh --ip <IP mới>`: script hỏi, sinh lại chứng chỉ (CA mới: import lại `ca.crt`), giữ dữ liệu; agent đã cài phải sửa `<address>` trong `ossec.conf` |
| Bật thêm máy demo / AI | `sudo ./install.sh --demo` / `sudo ./install.sh --ai` (GPU NVIDIA tự dùng nếu có nvidia-container-toolkit) |
| Mọi lệnh compose | `docker compose ps`, `docker compose logs -f analyzer`... — **không cần** `-f` hay `--profile`: `.env` đã ghi `COMPOSE_FILE`, `COMPOSE_PROFILES` |

### 2.5 Cấu hình riêng cho lab 4 vùng

Sửa `.env` trên VM rồi `docker compose up -d soar manager analyzer`:

```ini
# Thêm IP các cổng firewall vào danh sách SOAR không bao giờ chặn (giữ nguyên các mục install.sh đã ghi).
# KHÔNG thêm IP attacker hay Web-01.
SOAR_WHITELIST=127.0.0.0/8,10.10.40.10/32,10.10.40.1/32,10.10.40.254/32,10.10.20.254/32,10.10.30.254/32,203.0.113.1/32
# Báo agent mất kết nối (HLT-001) sau 2 phút thay vì 15, để thấy được trong buổi demo.
AGENT_DOWN_MINUTES=2
```

Chặn nhầm cổng firewall làm máy mất DNS, NTP và đường ra Internet, nên firewall luôn nằm trong whitelist.

### 2.6 Đăng nhập console và tin cậy CA

1. Trên máy host mở **https://10.10.40.10:8000**, đăng nhập `admin` bằng mật khẩu tạm (màn hình cuối của script, hoặc
   `sudo ./install.sh info`), đặt mật khẩu mới, rồi tạo tài khoản riêng theo vai (tab *Tài khoản*, quyền từng vai ở
   [SOC-OPERATIONS.md](SOC-OPERATIONS.md) mục 1). Tối thiểu cho kịch bản thử: 1 `analyst` (Tier 1), 1 `lead` (Tier 2, cô lập
   được máy), 1 `detection` (duyệt rule và đề xuất AI).
2. Hết cảnh báo chứng chỉ: chép CA về máy host rồi import (lệnh in sẵn ở màn hình cuối):
   ```powershell
   scp <user>@10.10.40.10:~/soc-platform/ca.crt .
   Import-Certificate -FilePath .\ca.crt -CertStoreLocation Cert:\LocalMachine\Root            # PowerShell Administrator
   ```
3. Kafka UI và Elasticsearch chỉ nghe trên `127.0.0.1` của VM. Xem từ host bằng SSH tunnel:
   `ssh -L 8088:127.0.0.1:8088 -L 9200:127.0.0.1:9200 <user>@10.10.40.10`, rồi mở http://127.0.0.1:8088.

### 2.7 Cổng mạng

| Cổng | Ai cần tới | Ghi chú |
|---|---|---|
| TCP 8000 | Máy host / analyst (vùng SOC) | SOC console + Grafana |
| TCP 1514, 1515 | Agent ở DMZ, LAN (qua firewall, luật ở mục 1.2) | Wazuh agent gửi event / enroll |
| UDP+TCP 514 | Firewall F001 (cổng SOC 10.10.40.254) | Syslog: filterlog, Suricata (mục 5) |

**Lưu ý:** cổng Docker publish **không đi qua UFW** (Docker tự chèn luật iptables trước UFW), nên `ufw deny` không chặn được
các cổng trên. Trong mô hình mục 0, `siem-server` chỉ nằm ở vùng SOC sau firewall, nên chỉ những gì luật firewall cho phép
mới tới được. Nếu VM dùng card *bridged* nối vào mạng thật thì chặn kết nối mới từ card đó ở chuỗi `DOCKER-USER`:
```bash
sudo iptables -I DOCKER-USER -i ens34 -m conntrack --ctstate NEW -j DROP   # ens34 = card bridged; mất khi khởi động lại
```

## 3. Agent Linux (`Web-01`, `Ubuntu-01`)

Trên `siem-server`, lấy mật khẩu enroll: `cat secrets/enrollment_key`. Từ máy host (đã có route ở mục 1.5), chép 2 script từ
repo sang VM endpoint:
```bash
scp wazuh/agent/linux/siem-xdr wazuh/agent/linux/siem-procs <user>@10.10.30.21:~      # Ubuntu-01
scp wazuh/agent/linux/siem-xdr wazuh/agent/linux/siem-procs demo/web/cgi-bin/ping.cgi <user>@10.10.20.20:~   # Web-01
```

### 3.1 Cài Wazuh agent 4.14.7

**Phiên bản agent không được mới hơn manager (4.14.7)**, nên phải ghim phiên bản và chặn tự nâng cấp:

```bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
sudo chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt-get update
sudo WAZUH_MANAGER="10.10.40.10" WAZUH_AGENT_NAME="Web-01" WAZUH_REGISTRATION_PASSWORD="<nội dung secrets/enrollment_key>" \
     apt-get install -y wazuh-agent=4.14.7-1
sudo apt-mark hold wazuh-agent
sudo apt-get install -y iptables     # script phản ứng dùng iptables / ip6tables
```

`WAZUH_AGENT_NAME` là `Web-01` hoặc `Ubuntu-01` tùy máy.

### 3.2 Script phản ứng `siem-xdr` (tên lệnh giữ từ trước khi đổi tên project)

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

Kịch bản đi ngang (mục 6) chạy `sshpass` từ Web-01: `sudo apt-get install -y sshpass`.

### 3.5 Kiểm tra agent

Trên `siem-server`:
```bash
docker compose exec wazuh-manager /var/ossec/bin/agent_control -l     # agent phải "Active"
```
Trên console, tab *Agent* hiện máy sau tối đa 30 giây (SOAR đồng bộ từ Wazuh API). Thử kênh phản ứng: trên console tạo lệnh
*Chặn IP* `198.51.100.77` cho agent → trạng thái **Thành công**, trên VM `sudo iptables -S INPUT | grep 198.51.100.77` thấy
luật DROP → tạo lệnh *Gỡ chặn IP* cùng IP.

## 4. Agent Windows (`PC-01`, `DC-01`)

Chép sang VM: bộ cài `BTL/Wazuh/wazuh-agent-4.14.7-1.msi` và 2 file `wazuh/agent/windows/siem-xdr.cmd`,
`wazuh/agent/windows/siem-xdr.ps1`. Mở PowerShell **Administrator** trong thư mục chứa chúng:

```powershell
msiexec.exe /i wazuh-agent-4.14.7-1.msi /q WAZUH_MANAGER="10.10.40.10" WAZUH_AGENT_NAME="PC-01" WAZUH_REGISTRATION_PASSWORD="<nội dung secrets/enrollment_key>"
Copy-Item .\siem-xdr.cmd, .\siem-xdr.ps1 "C:\Program Files (x86)\ossec-agent\active-response\bin\"
NET START WazuhSvc
```
`DC-01` (nếu có) cài giống hệt, `WAZUH_AGENT_NAME="DC-01"`.

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

## 5. Firewall gửi log và Suricata

Làm sau khi `siem-server` chạy (mục 2). `assets.yml` đã khai IP các cổng của F001, nên log firewall được gắn tài sản F001
(mức `critical`) mà không phải sửa gì.

1. **Syslog**: *Status → System Logs → Settings → Remote Logging Options*: bật *Send log messages to remote syslog server*,
   *Source Address* `SOC` (để gói syslog đi ra từ 10.10.40.254), *Remote log servers* `10.10.40.10:514`, *Remote Syslog
   Contents* `Everything` (cần cả log Suricata ở bước 3). pfSense gửi UDP; Vector nghe cả UDP và TCP 514.
   OPNsense: *System → Settings → Logging → Remote*, thêm đích UDP `10.10.40.10:514`.
2. Kiểm tra: từ attacker `nmap -Pn -p 1-200 203.0.113.1`, trong 1 phút có event `event.module: pfsense` (tên dùng chung cho
   filterlog của pfSense và OPNsense) với `observer.ip` 10.10.40.254 trên Grafana *Điều tra*, và alert **NET-001** (một IP
   chạm ≥ 20 cổng trong 60 giây).
3. **Suricata** (pfSense: *System → Package Manager* cài gói `suricata`; OPNsense có sẵn ở *Services → Intrusion Detection*):
   - Tải bộ luật *ETOpen Emerging Threats* (pfSense: *Services → Suricata → Global Settings*; OPNsense: tab *Download*).
   - Bật Suricata trên cổng `INET_GIA` (và `DMZ` nếu đủ RAM), chế độ chỉ phát hiện (không chặn) để SOAR là bên phản ứng.
   - Gửi alert dạng EVE qua syslog: pfSense *Interface Settings → EVE Output Settings*: bật *EVE JSON Log*, *EVE Output
     Type* `SYSLOG`, tắt ghi payload (dòng syslog quá dài bị cắt thì analyzer không đọc được JSON); OPNsense *Settings →
     Enable eve syslog output*.
   - Analyzer chỉ đọc JSON EVE từ dòng syslog có tên chương trình `suricata` (mặc định của cả hai).
4. Kiểm tra: `nmap -sS -A 203.0.113.1` từ attacker sinh alert Suricata nhóm *ET SCAN*; mức 1–2 thành alert **NET-004**.

## 6. Kiểm thử từ máy `attacker` (203.0.113.50)

Đăng nhập console bằng tài khoản `analyst` để theo dõi tab *Cảnh báo*, *Case*, *Lệnh phản ứng*.
Trên attacker cài công cụ: `sudo apt-get install -y curl nmap`. Attacker chỉ tới được Web-01 qua địa chỉ của firewall
`203.0.113.1` (port forward). Bị chặn IP .50 thì chạy tiếp bằng .51 (`curl --interface 203.0.113.51`); muốn chạy lại từ
đầu thì gỡ chặn trên console (tab *Lệnh phản ứng*).

| # | Thực hiện | Kết quả mong đợi |
|---|---|---|
| 1 | Attacker: `nmap -Pn -p 1-200 203.0.113.1` | Firewall chặn và ghi log → **NET-001**; có Suricata thì thêm **NET-004** (mục 5). |
| 2 | Attacker: `curl "http://203.0.113.1/?id=1%20union%20select%201,2"` | Alert **WEB-001** với IP nguồn 203.0.113.50 → SOAR chặn IP đó trên Web-01 trong 30 phút (lệnh *Thành công*), `curl` lần sau treo; case **PB-02**. |
| 3 | (cần CGI ở mục 3.4) Attacker: `curl --interface 203.0.113.51 "http://203.0.113.1/cgi-bin/ping.cgi?host=127.0.0.1%3Bsleep%2015"` | **LNX-002** → SOAR kill cả cây tiến trình, request kết thúc trước 15 giây; case **PB-12** (webshell / thực thi mã trên web server). |
| 4 | Trên Web-01: `for i in $(seq 1 8); do sshpass -p sai ssh -o StrictHostKeyChecking=no test@10.10.30.21 true; done` | ≥ 5 lần sai trong 60 giây → **AUTH-001** → chặn IP 10.10.20.20 trên **mọi** agent online trong 1 giờ; case **PB-01**. Gỡ chặn sau khi thử. |
| 5 | Trên Web-01: `echo '<?php system($_GET["c"]); ?>' \| sudo tee /var/www/html/shell.php`, sau đó `sudo rm /var/www/html/shell.php` | **WZH-100100** (file mới trong thư mục web) → case **PB-12**; xóa file → WZH-553 → case **PB-08** (nhóm `syscheck`). |
| 6 | Trên PC-01: `powershell -nop -w hidden -c "Start-Sleep 60"` | **WIN-006** → SOAR kill tiến trình PowerShell đó; case **PB-03**. |
| 7 | Trên PC-01 (PowerShell Administrator, tắt *Real-time protection* của Defender trên VM lab): `rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).Id $env:TEMP\l.dmp full` | **WIN-007** (critical, dump LSASS). Tài khoản `lead` bấm *Cô lập máy* PC-01. Xóa `l.dmp` sau khi thử. |
| 8 | Trên Ubuntu-01: `sudo systemctl stop wazuh-agent`, đợi `AGENT_DOWN_MINUTES` (mục 2.5) | **HLT-001** (agent mất kết nối); `start` lại thì alert ghi "đã hồi phục". |
| 9 | Console (tài khoản `lead`): *Cô lập máy* Ubuntu-01 | Từ Web-01 không SSH được Ubuntu-01, agent vẫn *Active*; *Bỏ cô lập* chạy được. |

Kiểm tra đúng cách chống giả mạo (đã sửa 11/10/2026): request có User-Agent giả dòng telemetry phải được xử lý như request
web bình thường, không sinh lệnh kill:
```bash
curl -A "x siem-proc: pid=999999 ppid=1 uid=33 name=sh parent=apache2 exe=/bin/sh cmd=sh" http://203.0.113.1/
```
Kết quả đúng: không có alert LNX-002 và không có lệnh *Kill tiến trình* nào mới.

## 7. Xử lý sự cố

| Triệu chứng | Kiểm tra / cách sửa |
|---|---|
| Agent không lên *Active* | Từ endpoint: `nc -zv 10.10.40.10 1514` và `1515`. Không tới được: xem luật cổng DMZ / USERS trên firewall (mục 1.2) và *Status → System Logs → Firewall* tìm gói bị chặn. Xem `/var/ossec/logs/ossec.log` (Windows: `C:\Program Files (x86)\ossec-agent\ossec.log`). |
| VM không ra được Internet để cài gói | Gateway và DNS phải là `.254` của vùng (mục 1.4); luật TCP 80/443 ra đích ngoài `PRIVATE` còn bật; WAN của firewall có IP từ VMnet8. |
| Máy host không SSH được tới VM ở DMZ / LAN | Thiếu route qua 10.10.40.254 (mục 1.5), hoặc máy host đang nối thẳng vào VMnet3 / VMnet4 (phải bỏ *Connect a host virtual adapter*). |
| `Invalid password` khi enroll | Sai `WAZUH_REGISTRATION_PASSWORD`; sửa `/var/ossec/etc/authd.pass` (Windows: `authd.pass` trong thư mục agent) rồi khởi động lại agent. |
| `Agent version must be lower or equal to manager version` | Agent mới hơn 4.14.7: gỡ, cài lại đúng `4.14.7-1`, `apt-mark hold`. |
| `Duplicate agent name` | Agent cũ cùng tên còn trên manager: `docker compose exec wazuh-manager /var/ossec/bin/manage_agents -l`, xóa bằng `manage_agents -r <id>`. |
| Lệnh phản ứng *Quá hạn* / *Thất bại* | Script đúng chỗ, quyền `root:wazuh 750`, không CRLF; `iptables` đã cài; agent đọc `active-responses.log` (mục 3.2). Lỗi ghi trong cột kết quả của lệnh. |
| WEB-001 có IP nguồn là IP firewall, SOAR chặn nhầm | Outbound NAT của firewall đang NAT cả cổng DMZ: để *Automatic* (chỉ NAT khi ra WAN). Gỡ chặn, và kiểm tra IP firewall có trong `SOAR_WHITELIST` (mục 2.5). |
| Không có log firewall | `docker compose logs syslog` trên VM; *Source Address* của remote logging phải là cổng SOC; `observer.ip` khác các IP của F001 trong `assets.yml` thì log vẫn vào nhưng không gắn tài sản. |
| Alert Suricata chỉ hiện là event `host` / `info` | Dòng EVE bị cắt hoặc tên chương trình khác `suricata`: tắt ghi payload trong EVE Output (mục 5). |
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
- Nhanh nhất: quay về snapshot "sạch" của mục 1.5.

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
   printf 'vm.max_map_count=262144\nnet.core.rmem_max=33554432\n' | sudo tee /etc/sysctl.d/99-soc-platform.conf
   sudo sysctl --system
   ```
3. Đưa mã nguồn lên VM bằng `git archive` (giữ ký tự xuống dòng LF), không chép thẳng thư mục từ Windows:
   ```powershell
   git archive --format=tar.gz --prefix=soc-platform/ -o soc-platform.tgz HEAD
   scp soc-platform.tgz <user>@10.10.40.10:~
   ```
   Trên VM: `tar -xzf soc-platform.tgz && cd soc-platform`.
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
   MANAGER_TLS_IPS=10.10.40.10
   GRAFANA_ROOT_URL=https://10.10.40.10:8000/grafana/
   # Không bao giờ để SOAR chặn máy quản trị, chính máy SIEM và các cổng firewall. KHÔNG thêm IP máy attacker.
   SOAR_WHITELIST=127.0.0.0/8,10.10.40.1/32,10.10.40.10/32,10.10.40.254/32,10.10.20.254/32,10.10.30.254/32,203.0.113.1/32
   AGENT_DOWN_MINUTES=2         # lab: báo agent mất kết nối sau 2 phút
   COMPOSE_PROFILES=            # demo, ai (cách nhau bằng dấu phẩy) nếu cần
   ```
   Đã khởi động rồi mới đổi `MANAGER_TLS_IPS` thì phải sinh lại chứng chỉ: `docker compose down`, xóa volume `certs`
   (`docker volume rm soc-platform_certs`; hệ thống cũ chưa chuyển tên: `siem-xdr_certs`), rồi khởi động lại.
6. Khởi động và lấy CA:
   ```bash
   sudo docker compose up -d --build
   sudo docker compose ps        # es-setup phải "Exited (0)"; kafka, elasticsearch, wazuh-manager "healthy"
   sudo docker compose cp elasticsearch:/usr/share/elasticsearch/config/certs/ca/ca.crt ./ca.crt
   sudo cat secrets/console_admin_password    # mật khẩu tạm của admin
   ```
