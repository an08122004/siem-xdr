#!/usr/bin/env bash
# Cài SIEM/XDR (siem-xdr) trên máy chủ Ubuntu / Debian bằng MỘT lệnh:
#
#   sudo ./install.sh                 # cài / cập nhật cấu hình, khởi động toàn bộ hệ thống
#   sudo ./install.sh --demo          # thêm máy web demo (có lỗ hổng cố ý, chỉ dùng trong lab)
#   sudo ./install.sh --ai            # thêm AI đề xuất rule (Ollama, tự dùng GPU NVIDIA nếu có)
#   sudo ./install.sh --update        # sau khi chép mã mới: build lại image và khởi động lại
#   sudo ./install.sh --fetch         # tải mã mới nhất (nhánh main) từ GitHub, build lại và khởi động lại
#   sudo ./install.sh status          # trạng thái các service
#   sudo ./install.sh info            # in lại địa chỉ, mật khẩu tạm, lệnh cài agent
#
# Máy chưa có mã nguồn: chỉ cần file này, script tự tải repo vào ./siem-xdr (repo private: cần token GitHub đọc được repo):
#   read -rsp 'Token GitHub: ' GITHUB_TOKEN; echo; export GITHUB_TOKEN
#   curl -fsSL -H "Authorization: Bearer $GITHUB_TOKEN" -H 'Accept: application/vnd.github.raw' \
#     https://api.github.com/repos/an08122004/siem-xdr/contents/install.sh -o install.sh
#   sudo --preserve-env=GITHUB_TOKEN bash install.sh          # thêm --demo / --ai như trên
#
# Script tự làm: tải mã nguồn (nếu chưa có), kiểm tra máy, cài Docker, tham số kernel, phát hiện IP, sinh bí mật, viết .env,
# khởi động, chờ hệ thống sẵn sàng, xuất CA. Chạy lại bao nhiêu lần cũng được: giữ nguyên bí mật, .env và dữ liệu.
set -euo pipefail

cd "$(dirname "$(readlink -f "$0")")"
ROOT=$PWD
ARGV=("$@")
REPO=an08122004/siem-xdr            # GitHub: nơi tải mã nguồn khi máy chưa có / --fetch (nhánh main)
PROJECT=siem-xdr                    # tên project Compose; máy đang chạy bằng tên khác: xem pick_project
OLD_PROJECT=soc-platform            # tên cũ (bản cài từ 14/10/2026), chỉ để nhận ra hệ thống đang chạy
APP_UID=10001                       # user "siem" trong image server (server/Dockerfile)
WAZUH_VERSION=4.14.7
MIN_DOCKER=26                       # docker-compose.yml dùng volume subpath (Docker Engine >= 26)

IP=""; ADMIN_IP=""; DEMO=0; AI=0; GPU=auto; UPDATE=0; FETCH=0; ASSUME_YES=0; CMD=install

usage() { sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; cat <<'EOF'
Tùy chọn:
  --ip IP           IP của máy chủ mà agent / trình duyệt dùng (mặc định: tự phát hiện)
  --admin-ip IP     IP máy quản trị: thêm vào SOAR_WHITELIST để SOAR không bao giờ chặn nhầm
  --demo, --ai      bật thêm máy web demo / AI (được nhớ trong .env cho các lần chạy sau)
  --gpu, --no-gpu   ép bật / tắt GPU cho Ollama (mặc định: bật nếu có nvidia-container-toolkit)
  --update          build lại image (dùng sau khi chép mã nguồn mới)
  --fetch           tải mã mới nhất từ GitHub đè lên mã hiện có (giữ secrets/, .env, rule AI đã duyệt), rồi như --update
  -y, --yes         không hỏi lại (vd khi đổi IP phải sinh lại chứng chỉ)
EOF
}

say()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok()   { printf '    \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '    \033[33m!\033[0m %s\n' "$*"; }
die()  { printf '\033[31mLỖI:\033[0m %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --ip) IP=${2:?thiếu giá trị cho --ip}; shift 2 ;;
    --ip=*) IP=${1#*=}; shift ;;
    --admin-ip) ADMIN_IP=${2:?thiếu giá trị cho --admin-ip}; shift 2 ;;
    --admin-ip=*) ADMIN_IP=${1#*=}; shift ;;
    --demo) DEMO=1; shift ;;
    --ai) AI=1; shift ;;
    --gpu) GPU=1; shift ;;
    --no-gpu) GPU=0; shift ;;
    --update) UPDATE=1; shift ;;
    --fetch) FETCH=1; shift ;;
    -y|--yes) ASSUME_YES=1; shift ;;
    install|status|info) CMD=$1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "tham số lạ: $1 (xem ./install.sh --help)" ;;
  esac
done

valid_ipv4() { [[ $1 =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; }
confirm() {   # confirm "câu hỏi"  -> 0 nếu đồng ý
  [ "$ASSUME_YES" = 1 ] && return 0
  [ -t 0 ] || return 1
  local a; read -r -p "    $1 [y/N] " a; [[ $a =~ ^[yYcC] ]]
}
env_get() { [ -f .env ] && sed -n "s/^$1=//p" .env | tail -n1 || true; }
env_set() {   # env_set KHÓA GIÁ_TRỊ: sửa dòng có sẵn (kể cả dòng đang bị comment "# KHÓA=") hoặc thêm mới
  local k=$1 v=$2
  if grep -q "^$k=" .env; then sed -i "s|^$k=.*|$k=$v|" .env
  elif grep -q "^# *$k=" .env; then sed -i "0,/^# *$k=.*/s||$k=$v|" .env
  else printf '%s=%s\n' "$k" "$v" >> .env; fi
}
# COMPOSE_FILE / COMPOSE_PROFILES lấy từ .env. Tên project truyền thẳng (pick_project): lúc .env chưa ghi tên, compose
# dùng name: trong docker-compose.yml (chưa đổi tên) và thao tác nhầm sang hệ thống khác với hệ thống đang chạy.
compose() { docker compose -p "$PROJECT" "$@"; }

# ------------------------------------------------------------------------------------------------ mã nguồn
# Máy chỉ có install.sh: tải repo vào ./siem-xdr (đã có thì dùng luôn) rồi chạy install.sh trong đó, cùng tham số.
# --fetch: tải đè lên mã hiện có rồi chạy lại với --update; secrets/, .env, ca.crt không nằm trong repo nên giữ nguyên.
# shortcut: file đã xóa trên GitHub vẫn còn trên máy (như tools/deploy-vm.ps1); xóa rule thì xóa tay file trong server/rules.
fetch_source() {
  local dir=$ROOT token=${GITHUB_TOKEN:-} a
  if [ ! -f docker-compose.yml ]; then dir=$ROOT/siem-xdr
  elif [ "$FETCH" != 1 ]; then return 0; fi
  [ "$(id -u)" = 0 ] || die "cần quyền root: chạy lại bằng  sudo ./install.sh"
  if [ "$FETCH" = 1 ] || [ ! -f "$dir/docker-compose.yml" ]; then
    say "Tải mã nguồn $REPO (nhánh main) vào $dir"
    command -v curl >/dev/null 2>&1 || { apt-get update -qq && apt-get install -y -qq ca-certificates curl >/dev/null; }
    if [ -z "$token" ] && [ -t 0 ]; then read -rsp "    Token GitHub (đọc được $REPO): " token; echo; fi
    # tar chạy bằng user gọi sudo: mã nguồn thuộc user đó, như khi chép bằng tools/deploy-vm.ps1
    local -a as=(); [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ] && as=(sudo -u "$SUDO_USER")
    "${as[@]}" mkdir -p "$dir"
    # token qua stdin (-K -: cấu hình curl) thay vì tham số dòng lệnh: không lộ trong ps. Rule AI đã duyệt + ngoại lệ: không ghi đè
    { [ -z "$token" ] || printf 'header = "Authorization: Bearer %s"\n' "$token"; } \
      | curl -fsSL -K - "https://api.github.com/repos/$REPO/tarball/main" \
      | "${as[@]}" tar -xz -C "$dir" --strip-components=1 --exclude='*/server/rules/ai' --exclude='*/server/rules/exceptions' \
      || die "không tải được mã nguồn (lỗi ở trên). Repo private: cần token GitHub đọc được $REPO (GITHUB_TOKEN hoặc nhập khi được hỏi)"
    ok "đã tải vào $dir"
  fi
  local -a args=(); for a in "${ARGV[@]}"; do [ "$a" = --fetch ] || args+=("$a"); done
  [ "$FETCH" = 1 ] && args+=(--update)
  exec bash "$dir/install.sh" "${args[@]}"
}

# ------------------------------------------------------------------------------------------------ kiểm tra
check_system() {
  say "1/8 Kiểm tra máy"
  [ "$(id -u)" = 0 ] || die "cần quyền root: chạy lại bằng  sudo ./install.sh"
  [ -f docker-compose.yml ] && [ -f tools/init_secrets.py ] || die "không thấy mã nguồn siem-xdr trong $ROOT"
  # install.sh mà là CRLF thì hỏng ngay dòng đầu, không chạy tới đây: kiểm các script khác chép cùng đợt
  if grep -q $'\r' security/setup.sh wazuh/manager/entrypoint/*.sh 2>/dev/null; then
    die "file có ký tự xuống dòng Windows (CRLF). Chép mã bằng tools/deploy-vm.ps1 hoặc git, không chép thẳng thư mục từ Windows"
  fi
  # shellcheck disable=SC1091
  . /etc/os-release
  case " ${ID:-} ${ID_LIKE:-} " in
    *" ubuntu "*|*" debian "*) ok "hệ điều hành: ${PRETTY_NAME:-$ID}" ;;
    *) die "script chỉ hỗ trợ Ubuntu / Debian (máy này: ${PRETTY_NAME:-không rõ}); cài tay theo DEPLOY-VM.md" ;;
  esac
  [ "$(uname -m)" = x86_64 ] || warn "kiến trúc $(uname -m): mới thử trên x86_64"
  local mem_gb disk_gb
  mem_gb=$(awk '/^MemTotal/ {printf "%d", $2/1024/1024 + 0.5}' /proc/meminfo)
  disk_gb=$(df -Pk "$ROOT" | awk 'NR==2 {printf "%d", $4/1024/1024}')
  if [ "$mem_gb" -lt 7 ]; then warn "RAM ${mem_gb} GB: nên có 8 GB (Elasticsearch ~1,8 GB, cả hệ thống ~3,6 GB lúc rảnh)"
  else ok "RAM ${mem_gb} GB"; fi
  [ "$AI" = 1 ] && [ "$mem_gb" -lt 15 ] && warn "bật AI nên có 16 GB RAM (model ~6,6 GB)"
  if [ "$disk_gb" -lt 20 ]; then warn "đĩa trống ${disk_gb} GB: nên có ít nhất 20 GB (60 GB nếu chạy lâu, 100 GB nếu bật AI)"
  else ok "đĩa trống ${disk_gb} GB"; fi
}

install_docker() {
  say "2/8 Docker"
  export DEBIAN_FRONTEND=noninteractive
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    ok "đã có $(docker --version | cut -d, -f1), compose $(docker compose version --short)"
  else
    # shellcheck disable=SC1091
    . /etc/os-release
    local distro=ubuntu; case " ${ID:-} ${ID_LIKE:-} " in *" ubuntu "*) ;; *) distro=debian ;; esac
    local codename=${UBUNTU_CODENAME:-${VERSION_CODENAME:-}}
    ok "cài Docker Engine từ download.docker.com ($distro $codename)"
    apt-get update -qq
    apt-get install -y -qq ca-certificates curl gnupg >/dev/null
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL "https://download.docker.com/linux/$distro/gpg" -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/$distro $codename stable" \
      > /etc/apt/sources.list.d/docker.list
    apt-get update -qq
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin >/dev/null
  fi
  if ! docker info >/dev/null 2>&1; then
    if [ -d /run/systemd/system ]; then systemctl enable --now docker >/dev/null 2>&1 || true
    else
      service docker start >/dev/null 2>&1 || true
      sleep 3
      # không có systemd (WSL, container) và script init lỗi (vd ulimit): chạy thẳng dockerd
      if ! docker info >/dev/null 2>&1; then
        warn "không có systemd: chạy dockerd nền, log ở /var/log/dockerd.log (khởi động lại máy phải chạy lại script)"
        nohup dockerd >/var/log/dockerd.log 2>&1 &
      fi
    fi
    for _ in $(seq 30); do docker info >/dev/null 2>&1 && break; sleep 1; done
    docker info >/dev/null 2>&1 || die "Docker không chạy (xem: journalctl -u docker hoặc /var/log/dockerd.log)"
  fi
  local major
  major=$(docker version --format '{{.Server.Version}}' | cut -d. -f1)
  [ "$major" -ge "$MIN_DOCKER" ] || die "Docker Engine $major quá cũ (cần >= $MIN_DOCKER): gỡ gói docker.io của bản phân phối rồi chạy lại script"
  if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ] && ! id -nG "$SUDO_USER" | grep -qw docker; then
    usermod -aG docker "$SUDO_USER" && ok "thêm $SUDO_USER vào nhóm docker (đăng nhập lại để dùng docker không cần sudo)"
  fi
  command -v python3 >/dev/null 2>&1 || apt-get install -y -qq python3 >/dev/null
  command -v curl >/dev/null 2>&1 || apt-get install -y -qq curl >/dev/null
}

tune_kernel() {
  say "3/8 Tham số kernel"
  rm -f "/etc/sysctl.d/99-$OLD_PROJECT.conf"          # file của bản cài dùng tên cũ
  cat > /etc/sysctl.d/99-siem-xdr.conf <<'EOF'
# siem-xdr (install.sh)
vm.max_map_count=262144
net.core.rmem_max=33554432
EOF
  sysctl -q -p /etc/sysctl.d/99-siem-xdr.conf >/dev/null 2>&1 || warn "không đặt được sysctl (đang chạy trong container?)"
  ok "vm.max_map_count=$(sysctl -n vm.max_map_count) (Elasticsearch), net.core.rmem_max (buffer UDP syslog)"
  if command -v timedatectl >/dev/null 2>&1; then timedatectl set-ntp true >/dev/null 2>&1 || true; fi
}

# ------------------------------------------------------------------------------------------------ IP
detect_ip() {
  local def_if ifc addr
  local -a all=() lab=()
  def_if=$(ip -4 route show default 2>/dev/null | awk '{for (i=1;i<NF;i++) if ($i=="dev") {print $(i+1); exit}}')
  while read -r ifc addr; do
    case "$ifc" in lo|docker*|br-*|veth*|virbr*|cni*|flannel*|tailscale*|wg*) continue ;; esac
    all+=("${addr%/*}|$ifc")
    [ "$ifc" != "$def_if" ] && lab+=("${addr%/*}|$ifc")
  done < <(ip -4 -o addr show scope global | awk '{print $2, $4}')
  # Ưu tiên card KHÔNG phải đường ra Internet: mô hình lab có card NAT (ra Internet) + card host-only (lab).
  local -a pick=("${lab[@]}")
  [ ${#pick[@]} -eq 0 ] && pick=("${all[@]}")
  if [ ${#pick[@]} -eq 1 ]; then echo "${pick[0]%%|*}"; return; fi
  [ ${#pick[@]} -eq 0 ] && die "không tìm thấy IPv4 nào; chỉ định bằng --ip"
  if [ -t 0 ] && [ "$ASSUME_YES" != 1 ]; then
    echo "    Máy có nhiều IP. Chọn IP mà agent và trình duyệt sẽ dùng:" >&2
    local i=1; for c in "${pick[@]}"; do echo "      $i) ${c%%|*}  (${c##*|})" >&2; i=$((i+1)); done
    local n; read -r -p "    Số: " n
    [[ $n =~ ^[0-9]+$ ]] && [ "$n" -ge 1 ] && [ "$n" -le ${#pick[@]} ] || die "lựa chọn không hợp lệ"
    echo "${pick[$((n-1))]%%|*}"; return
  fi
  die "máy có nhiều IP (${pick[*]}): chỉ định bằng --ip"
}

# ------------------------------------------------------------------------------------------------ cấu hình
# Tên project Compose: giữ tên đang dùng, không tự đổi (đổi tên mà không chép volume = hệ thống mới rỗng). Bản cài từ
# 14/10/2026 có thể chạy bằng tên cũ: COMPOSE_PROJECT_NAME trong .env, hoặc có volume ${OLD_PROJECT}_*.
pick_project() {
  local cur; cur=$(env_get COMPOSE_PROJECT_NAME)
  if [ -n "$cur" ]; then PROJECT=$cur
  elif docker volume inspect "${OLD_PROJECT}_certs" >/dev/null 2>&1; then PROJECT=$OLD_PROJECT
  fi
}

configure() {
  say "4/8 Bí mật và cấu hình"
  local out; out=$(python3 tools/init_secrets.py) || die "không sinh được bí mật (tools/init_secrets.py, lỗi ở trên)"
  printf '%s\n' "$out" | grep "đã tạo" | sed 's/^/    /' || true
  chown -R root:root secrets
  chmod 700 secrets && chmod 644 secrets/*          # xem tools/init_secrets.py: container đọc qua bind mount
  ok "bí mật trong secrets/ (chỉ root vào được thư mục)"
  # manager (uid $APP_UID) ghi rule AI đã duyệt và ngoại lệ vào 2 thư mục này
  mkdir -p server/rules/ai server/rules/exceptions datasets/processed
  chown -R "$APP_UID:$APP_UID" server/rules/ai server/rules/exceptions
  # mọi file cấu hình được mount chỉ đọc vào container chạy bằng user khác: phải đọc được với mọi uid
  chmod -R a+rX server wazuh vector grafana security demo tools 2>/dev/null || true

  [ -f .env ] || { cp .env.example .env; ok "tạo .env từ .env.example"; }
  pick_project
  if [ "$PROJECT" = "$OLD_PROJECT" ]; then
    warn "hệ thống đang chạy bằng tên cũ: giữ tên project $OLD_PROJECT để không mất dữ liệu (volume ${OLD_PROJECT}_*)"
  fi
  local old_ip; old_ip=$(env_get MANAGER_TLS_IPS | cut -d, -f1)
  if [ -z "$IP" ]; then IP=${old_ip:-$(detect_ip)}; fi
  valid_ipv4 "$IP" || die "IP không hợp lệ: $IP"
  if [ -n "$old_ip" ] && [ "$old_ip" != "$IP" ] && docker volume inspect "${PROJECT}_certs" >/dev/null 2>&1; then
    warn "IP đổi từ $old_ip sang $IP: phải sinh lại chứng chỉ TLS (dữ liệu giữ nguyên)"
    confirm "Dừng hệ thống và sinh lại chứng chỉ?" || die "giữ IP cũ: chạy lại với --ip $old_ip"
    compose down >/dev/null 2>&1 || true
    docker volume rm "${PROJECT}_certs" >/dev/null
    warn "CA nội bộ được sinh MỚI: import lại ca.crt trên máy quản trị (lệnh ở cuối)"
    warn "agent đã cài vẫn trỏ $old_ip: sửa <address> trong ossec.conf của agent thành $IP rồi khởi động lại agent"
  fi
  env_set COMPOSE_PROJECT_NAME "$PROJECT"
  env_set MANAGER_TLS_IPS "$IP"
  env_set GRAFANA_ROOT_URL "https://$IP:8000/grafana/"

  # Không bao giờ để SOAR chặn chính máy SIEM / máy quản trị. Giữ mục người dùng đã thêm.
  if [ -z "$ADMIN_IP" ] && [ -n "${SSH_CLIENT:-}" ]; then ADMIN_IP=${SSH_CLIENT%% *}; fi
  # sudo xóa SSH_CLIENT: lấy IP của phiên SSH đang chạy lệnh này từ `who am i`
  if [ -z "$ADMIN_IP" ]; then ADMIN_IP=$(who am i 2>/dev/null | sed -n 's/.*(\([0-9.]*\)).*/\1/p' | head -n1); fi
  if [ -n "$ADMIN_IP" ] && ! valid_ipv4 "$ADMIN_IP"; then ADMIN_IP=""; fi
  local wl item; wl=$(env_get SOAR_WHITELIST)
  if [ -n "$old_ip" ] && [ "$old_ip" != "$IP" ]; then   # IP cũ của máy chủ có thể được cấp cho máy khác
    wl=$(printf '%s' "$wl" | tr ',' '\n' | grep -vxF "$old_ip/32" | paste -sd, -)
  fi
  for item in 127.0.0.0/8 "$IP/32" ${ADMIN_IP:+"$ADMIN_IP/32"}; do
    case ",$wl," in *",$item,"*) ;; *) wl=${wl:+$wl,}$item ;; esac
  done
  env_set SOAR_WHITELIST "$wl"

  # Profile và file compose ghi vào .env: sau này chỉ cần "docker compose ..." là đúng cấu hình.
  local profiles; profiles=$(env_get COMPOSE_PROFILES)
  [ "$DEMO" = 1 ] && case ",$profiles," in *,demo,*) ;; *) profiles=${profiles:+$profiles,}demo ;; esac
  [ "$AI" = 1 ] && case ",$profiles," in *,ai,*) ;; *) profiles=${profiles:+$profiles,}ai ;; esac
  env_set COMPOSE_PROFILES "$profiles"
  local files=docker-compose.yml
  case ",$profiles," in *,ai,*)
    if [ "$GPU" = 1 ] || { [ "$GPU" = auto ] && docker info --format '{{json .Runtimes}}' 2>/dev/null | grep -q nvidia; }; then
      files=docker-compose.yml:docker-compose.gpu.yml; ok "AI dùng GPU NVIDIA"
    else
      [ "$GPU" = 0 ] || warn "không thấy nvidia-container-toolkit: Ollama chạy CPU (rất chậm)"
    fi ;;
  esac
  env_set COMPOSE_FILE "$files"
  [ -n "${SUDO_USER:-}" ] && chown "$SUDO_USER:" .env
  ok "IP máy chủ $IP, profile: ${profiles:-mặc định}, whitelist SOAR: $wl"
  [ -n "$ADMIN_IP" ] || warn "chưa biết IP máy quản trị: thêm bằng --admin-ip để SOAR không chặn nhầm máy bạn"
}

start_stack() {
  say "5/8 Khởi động (lần đầu tải image và build mất 5–20 phút)"
  local -a args=(up -d --remove-orphans)
  [ "$UPDATE" = 1 ] && args+=(--build)
  compose "${args[@]}"
}

# ------------------------------------------------------------------------------------------------ chờ sẵn sàng
wait_until() {   # wait_until GIÂY lệnh...
  local limit=$1; shift
  local t=0
  until "$@" >/dev/null 2>&1; do
    t=$((t+5)); [ "$t" -ge "$limit" ] && return 1
    sleep 5
  done
}
service_state() { compose ps -a --format '{{.Service}} {{.State}} {{.ExitCode}}' | awk -v s="$1" '$1==s {print $2, $3}'; }
es_setup_exited() { [[ $(service_state es-setup) == exited* ]]; }
healthy() { [ "$(docker inspect -f '{{.State.Health.Status}}' "$(compose ps -q "$1")")" = healthy ]; }
console_up() { curl -sf --cacert ca.crt "https://127.0.0.1:8000/health" >/dev/null; }

wait_ready() {
  say "6/8 Chờ hệ thống sẵn sàng"
  # es-setup chạy một lần: thoát mã khác 0 thì báo ngay, không chờ hết 10 phút
  if ! wait_until 600 es_setup_exited || [ "$(service_state es-setup)" != "exited 0" ]; then
    compose logs --tail 30 es-setup elasticsearch >&2 || true
    die "es-setup lỗi hoặc chưa xong sau 10 phút (log ở trên). Thường do thiếu RAM hoặc vm.max_map_count"
  fi
  ok "Elasticsearch + tài khoản RBAC"
  compose cp elasticsearch:/usr/share/elasticsearch/config/certs/ca/ca.crt ./ca.crt >/dev/null
  chmod 644 ca.crt
  wait_until 300 healthy wazuh-manager || die "wazuh-manager chưa healthy (docker compose logs wazuh-manager)"
  ok "Wazuh manager (agent kết nối cổng 1514/1515)"
  wait_until 180 console_up || { compose logs --tail 30 manager >&2; die "console chưa trả lời trên cổng 8000 (log ở trên)"; }
  ok "SOC console + Grafana"
  local bad
  bad=$(compose ps -a --format '{{.Service}} {{.State}} {{.ExitCode}}' | awk '$2!="running" && !($1 ~ /^es-(certs|setup)$/ && $3==0) {print $1}')
  [ -z "$bad" ] || warn "service chưa chạy: $bad (xem: docker compose logs <tên>)"
}

# ------------------------------------------------------------------------------------------------ tóm tắt
info() {
  [ -f .env ] || die "chưa cài: chạy  sudo ./install.sh"
  local ip key pw
  ip=$(env_get MANAGER_TLS_IPS | cut -d, -f1)
  key=$(cat secrets/enrollment_key); pw=$(cat secrets/console_admin_password)
  cat <<EOF

$(say "8/8 Xong")
  Console + Grafana : https://$ip:8000
  Đăng nhập lần đầu : admin / $pw   (mật khẩu tạm, console buộc đổi ngay; đã đổi thì dùng mật khẩu mới)
  Tài khoản khác    : admin tạo ở tab Tài khoản > Thêm tài khoản, hoặc người dùng tự đăng ký ở
                      https://$ip:8000/register rồi admin duyệt (tab Tài khoản)
  CA nội bộ         : $ROOT/ca.crt  -> import vào máy quản trị để hết cảnh báo chứng chỉ:
                      scp ${SUDO_USER:-<user>}@$ip:$ROOT/ca.crt .
                      Import-Certificate -FilePath .\\ca.crt -CertStoreLocation Cert:\\LocalMachine\\Root   (PowerShell Admin)
  Trạng thái        : sudo ./install.sh status

  Cài agent (tên agent phải khớp server/config/assets.yml: Web-01, Ubuntu-01, PC-01). Chi tiết: DEPLOY-VM.md mục 3, 4.
  * Linux (Ubuntu/Debian):
      curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && sudo chmod 644 /usr/share/keyrings/wazuh.gpg
      echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list
      sudo apt-get update && sudo WAZUH_MANAGER="$ip" WAZUH_AGENT_NAME="Web-01" WAZUH_REGISTRATION_PASSWORD="$key" apt-get install -y wazuh-agent=$WAZUH_VERSION-1 && sudo apt-mark hold wazuh-agent
  * Windows (PowerShell Administrator, bộ cài BTL/Wazuh/wazuh-agent-$WAZUH_VERSION-1.msi):
      msiexec.exe /i wazuh-agent-$WAZUH_VERSION-1.msi /q WAZUH_MANAGER="$ip" WAZUH_AGENT_NAME="PC-01" WAZUH_REGISTRATION_PASSWORD="$key"

EOF
}

status() {
  [ -f .env ] || die "chưa cài: chạy  sudo ./install.sh"
  pick_project
  compose ps -a --format 'table {{.Service}}\t{{.State}}\t{{.Status}}'
  if [ -f ca.crt ] && console_up; then ok "console trả lời: https://$(env_get MANAGER_TLS_IPS | cut -d, -f1):8000"
  else warn "console chưa trả lời trên cổng 8000"; fi
  local n; n=$(compose exec -T wazuh-manager /var/ossec/bin/agent_control -l 2>/dev/null | grep -c "Active" || true)
  ok "agent Wazuh đang Active: ${n:-0} (kể cả manager)"
}

case "$CMD" in
  status) status ;;
  info) info ;;
  install)
    fetch_source
    check_system
    install_docker
    tune_kernel
    configure
    start_stack
    wait_ready
    say "7/8 Kiểm tra nhanh"
    status
    info
    ;;
esac
