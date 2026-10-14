#!/bin/bash
# Chạy bởi image wazuh-manager (/etc/cont-init.d/2-manager -> /entrypoint-scripts/*.sh) TRƯỚC `wazuh-control start`,
# mỗi lần container khởi động (idempotent). Đọc bí mật từ Docker secrets, không từ biến môi trường.
set -euo pipefail
S=/run/secrets

# 1. Không dùng Wazuh indexer -> không chạy filebeat (dịch vụ s6 của image). Sửa trong filesystem của container,
#    s6 chép /etc/services.d sang thư mục chạy SAU bước cont-init này, nên có hiệu lực ngay lần khởi động này.
printf '#!/bin/sh\n# filebeat bị tắt: soc-platform đọc archives/alerts bằng Vector\nexec sleep infinity\n' > /etc/services.d/filebeat/run
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
