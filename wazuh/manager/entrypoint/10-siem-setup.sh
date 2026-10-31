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

# 6. Thư mục rule động (volume mới là root 0755): uid 10001 = user của container `manager` (siem-xdr-server) phải ghi
#    được, group wazuh để analysisd đọc. Làm mỗi lần khởi động, không làm ở install.sh (volume có tên, không phải thư mục host).
D=/var/ossec/etc/rules-dynamic
install -d -o 10001 -g wazuh -m 0755 "$D"
# 7. File rule hỏng còn trên đĩa thì wazuh-analysisd không lên, kéo theo remoted và apid. Kiểm tra cả ruleset trước khi
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
  fi
else
  echo "[siem-setup] ruleset hợp lệ (wazuh-analysisd -t)"
fi
