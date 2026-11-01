#!/bin/bash
# Chạy bởi image wazuh-manager (/etc/cont-init.d/2-manager -> /entrypoint-scripts/*.sh) TRƯỚC `wazuh-control start`,
# mỗi lần container khởi động (idempotent). Đọc bí mật từ Docker secrets, không từ biến môi trường.
set -euo pipefail
S=/run/secrets

# 1. Không dùng Wazuh indexer -> không chạy filebeat (dịch vụ s6 của image). Sửa trong filesystem của container,
#    s6 chép /etc/services.d sang thư mục chạy SAU bước cont-init này, nên có hiệu lực ngay lần khởi động này.
printf '#!/bin/sh\n# filebeat bị tắt: siem-xdr đọc archives/alerts bằng Vector\nexec sleep infinity\n' > /etc/services.d/filebeat/run
echo "[siem-setup] đã tắt filebeat"

# 2. Mật khẩu enroll agent (auth/use_password=yes): cùng giá trị với secrets/enrollment_key
install -m 640 -o root -g wazuh "$S/enrollment_key" /var/ossec/etc/authd.pass
echo "[siem-setup] đã đặt mật khẩu enroll agent"

# 3. Chứng chỉ Wazuh API do CA nội bộ ký (es-certs sinh, volume certs) -> SOAR xác thực được bằng ca.crt
SSL=/var/ossec/api/configuration/ssl
install -m 600 -o wazuh -g wazuh /certs/wazuh/wazuh-manager.key "$SSL/server.key"
install -m 644 -o wazuh -g wazuh /certs/wazuh/wazuh-manager.crt "$SSL/server.crt"
echo "[siem-setup] đã cài chứng chỉ Wazuh API"

# 4. User Wazuh API quyền tối thiểu cho SOAR (siem-soar) và nạp rule (siem-rules) + vô hiệu hóa 2 user mặc định (wazuh / wazuh-wui)
/var/ossec/framework/python/bin/python3 /entrypoint-scripts/siem_api_user.py "$S/wazuh_api_password" "$S/wazuh_rules_api_password"

# 5. Bao lâu không có keepalive thì Wazuh đánh dấu agent "disconnected". HLT-001 (soar/health.py) chỉ báo khi agent đã ở
#    trạng thái này VÀ keepalive cũ hơn AGENT_DOWN_MINUTES, nên tổng thời gian ≈ giá trị lớn hơn trong hai mốc. Mặc định
#    10m như ossec.conf; lab đặt WAZUH_AGENTS_DISCONNECTION_TIME=1m + AGENT_DOWN_MINUTES=2 trong .env (kịch bản ~2-3 phút).
T=${WAZUH_AGENTS_DISCONNECTION_TIME:-10m}
if [[ "$T" =~ ^[1-9][0-9]*[smhd]?$ ]]; then
  sed -i "s|<agents_disconnection_time>[^<]*</agents_disconnection_time>|<agents_disconnection_time>$T</agents_disconnection_time>|" \
    /var/ossec/etc/ossec.conf
  echo "[siem-setup] agents_disconnection_time = $T"
else
  echo "[siem-setup] WAZUH_AGENTS_DISCONNECTION_TIME không hợp lệ ('$T', vd 1m, 10m): giữ giá trị trong ossec.conf"
fi

# 6. Syslog 514: chỉ nhận từ các IP/CIDR trong SYSLOG_ALLOWED_IPS (danh sách phân cách bằng dấu phẩy, mặc định IP firewall lab).
#    Xóa mọi <allowed-ips> cũ rồi ghi lại sau <connection>syslog</connection> của từng khối -> chạy lại không nhân đôi dòng.
A=${SYSLOG_ALLOWED_IPS:-10.10.40.254}
A=${A// /}
# Danh sách cho phép (allowlist) từng phần tử: IPv4 [/1-32 hoặc netmask dạng chấm khác 0.0.0.0] hoặc IPv6 [/1-128].
# Sai chính tả (10.0.0.0//8, 0.0.0.0/0:, prefix /0 cho cả Internet...) -> không hợp lệ, giữ cấu hình cũ: <allowed-ips> sai có
# thể làm Wazuh từ chối ossec.conf và remoted không chạy (mất luôn agent 1514).
O='(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])'
V4="^($O\.){3}$O"
siem_ip_ok() {
  local ip=${1%%/*} len=""
  [[ "$1" == */* ]] && len=${1#*/}
  if [[ "$ip" =~ $V4$ ]]; then
    [ -z "$len" ] && [[ "$1" != */* ]] && return 0
    [[ "$len" =~ ^(0?[1-9]|[12][0-9]|3[0-2])$ ]] && return 0
    [[ "$len" =~ $V4$ && "$len" != "0.0.0.0" ]]; return
  fi
  [[ "$ip" =~ ^([0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}$ && "$ip" != *:::* ]] || return 1
  [[ "$ip" == *::*::* ]] && return 1                       # tối đa một "::"
  [[ "$ip" == *::* ]] || [ "${ip//[^:]/}" = ":::::::" ] || return 1          # không có "::" thì phải đủ 8 nhóm
  [[ "$1" != */* ]] || [[ "$len" =~ ^([1-9]|[1-9][0-9]|1[01][0-9]|12[0-8])$ ]]
}
ok=1
[[ -n "$A" && ! "$A" =~ (^,|,,|,$) ]] || ok=0
IFS=, read -ra IPS <<< "$A"
for ip in "${IPS[@]}"; do siem_ip_ok "$ip" || ok=0; done
if [ "$ok" = 1 ]; then
  sed -i '/<allowed-ips>/d' /var/ossec/etc/ossec.conf
  for ip in "${IPS[@]}"; do
    sed -i "/<connection>syslog<\/connection>/a\    <allowed-ips>$ip</allowed-ips>" /var/ossec/etc/ossec.conf
  done
  echo "[siem-setup] syslog allowed-ips = $A"
else
  echo "[siem-setup] SYSLOG_ALLOWED_IPS không hợp lệ ('$A', vd 10.10.40.254,192.168.1.0/24; không nhận prefix /0): giữ giá trị trong ossec.conf"
fi

# 7. Nhật ký SOC console: manager (uid 10001, user của image siem-xdr-server) ghi /var/log/siem-console/console.json trên volume
#    console_audit, Wazuh đọc bằng <localfile>. Volume mới tạo thuộc root nên đặt lại chủ mỗi lần khởi động.
install -d -o 10001 -m 0755 /var/log/siem-console
# file có sẵn để logcollector không báo lỗi 1103 khi khởi động trước lần ghi đầu tiên của manager
[ -e /var/log/siem-console/console.json ] || install -m 0644 -o 10001 /dev/null /var/log/siem-console/console.json
echo "[siem-setup] đã chuẩn bị /var/log/siem-console"

# 8. Thư mục rule động (volume mới là root 0755): uid 10001 = user của container `manager` (siem-xdr-server) phải ghi
#    được, group wazuh để analysisd đọc. Làm mỗi lần khởi động, không làm ở install.sh (volume có tên, không phải thư mục host).
D=/var/ossec/etc/rules-dynamic
install -d -o 10001 -g wazuh -m 0755 "$D"
# 9. File rule hỏng còn trên đĩa thì wazuh-analysisd không lên, kéo theo remoted và apid. Kiểm tra cả ruleset trước khi
#    start; hỏng thì cách ly file động (AI / ngoại lệ) để manager vẫn khởi động được.
if ! /var/ossec/bin/wazuh-analysisd -t >/tmp/analysisd-test.log 2>&1; then
  if [ -n "$(ls -A "$D")" ]; then
    Q=/var/ossec/etc/rules-dynamic.quarantine/$(date +%Y%m%d-%H%M%S)
    mkdir -p "$Q"
    find "$D" -mindepth 1 -maxdepth 1 -exec mv -t "$Q" {} +
    echo "[siem-setup] CẢNH BÁO: ruleset lỗi (wazuh-analysisd -t), đã chuyển file rule động sang $Q:"
    tail -n 5 /tmp/analysisd-test.log | sed 's/^/[siem-setup]   /'
  fi
  # kiểm lại: lỗi có thể nằm ngoài rules-dynamic (vd file hỏng trong wazuh/manager/rules), cách ly không sửa được
  if /var/ossec/bin/wazuh-analysisd -t >/tmp/analysisd-test.log 2>&1; then
    echo "[siem-setup] ruleset hợp lệ sau khi cách ly rules-dynamic"
  else
    echo "[siem-setup] ruleset VẪN lỗi sau khi cách ly — lỗi nằm ngoài rules-dynamic: $(grep -m1 -iE 'error|critical' /tmp/analysisd-test.log || head -n 1 /tmp/analysisd-test.log)"
    # cách ly vô ích: chuyển file về chỗ cũ để không mất rule AI / ngoại lệ vì một lỗi không phải của chúng
    if [ -n "${Q:-}" ] && [ -n "$(ls -A "$Q")" ]; then
      find "$Q" -mindepth 1 -maxdepth 1 -exec mv -t "$D" {} + && rmdir "$Q"
      echo "[siem-setup] đã chuyển về $D các file rule động vừa cách ly"
    fi
  fi
else
  echo "[siem-setup] ruleset hợp lệ (wazuh-analysisd -t)"
fi
