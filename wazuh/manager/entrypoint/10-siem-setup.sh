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

# 4. User Wazuh API quyền tối thiểu cho SOAR + vô hiệu hóa 2 user mặc định (wazuh / wazuh-wui)
/var/ossec/framework/python/bin/python3 /entrypoint-scripts/siem_api_user.py "$S/wazuh_api_password"

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
# Prefix /0 (0.0.0.0/0, ::/0) cho cả Internet gửi syslog giả -> coi như không hợp lệ.
if [[ "$A" =~ ^[0-9A-Fa-f.:/]+(,[0-9A-Fa-f.:/]+)*$ && ! ",$A," =~ /0, ]]; then
  sed -i '/<allowed-ips>/d' /var/ossec/etc/ossec.conf
  IFS=, read -ra IPS <<< "$A"
  for ip in "${IPS[@]}"; do
    sed -i "/<connection>syslog<\/connection>/a\    <allowed-ips>$ip</allowed-ips>" /var/ossec/etc/ossec.conf
  done
  echo "[siem-setup] syslog allowed-ips = $A"
else
  echo "[siem-setup] SYSLOG_ALLOWED_IPS không hợp lệ ('$A', vd 10.10.40.254,192.168.1.0/24; không nhận prefix /0): giữ giá trị trong ossec.conf"
fi
