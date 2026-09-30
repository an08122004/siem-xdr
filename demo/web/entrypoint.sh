#!/bin/sh
set -e
touch /usr/local/apache2/logs/access_log /usr/local/apache2/logs/error_log
# socket cgid còn sót khi container restart -> cgid không bind được, mọi CGI trả 503
rm -f /usr/local/apache2/logs/cgisock.*

# /var/ossec/etc là volume (giữ client.keys: tạo lại container không phải enroll lại, không trùng tên agent).
# Cấu hình agent và mật khẩu enroll (Docker secret, giống wazuh-manager) chép lại mỗi lần khởi động.
install -m 640 -o root -g wazuh /opt/siem/ossec.conf /var/ossec/etc/ossec.conf
install -m 640 -o root -g wazuh /run/secrets/enrollment_key /var/ossec/etc/authd.pass
/var/ossec/bin/wazuh-control start

exec httpd-foreground
