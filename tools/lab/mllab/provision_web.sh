#!/bin/bash
# Dựng máy WEB của lab ML (Ubuntu 24.04): Apache phục vụ một website nội bộ có khu /portal (Basic Auth),
# SSH cho tài khoản người dùng mô phỏng, agent Wazuh gửi log về manager của SIEM. Chạy bằng root, chạy lại được.
#
#   MANAGER=10.10.1.1 KEY_FILE=/tmp/ek USERS_FILE=/tmp/users bash provision_web.sh
#
# USERS_FILE: mỗi dòng "tên | mật khẩu | vai trò" (secrets/lab-sim-users.txt). Dòng bắt đầu bằng # bị bỏ qua.
set -euo pipefail
: "${MANAGER:?cần MANAGER (IP manager Wazuh)}" "${KEY_FILE:?cần KEY_FILE (mật khẩu đăng ký agent)}" "${USERS_FILE:?cần USERS_FILE}"
AGENT_NAME=${AGENT_NAME:-lab-web}
AGENT_VERSION=${AGENT_VERSION:-4.14.8-1}
export DEBIAN_FRONTEND=noninteractive

if ss -ltnH 'sport = :80' | grep -q . && ! systemctl is-active -q apache2; then
  echo "cổng 80 đang bị chương trình khác dùng" >&2; exit 1
fi
apt-get update -qq
apt-get install -y -qq apache2 apache2-utils openssh-server >/dev/null

# ---- website: trang, css/js, ảnh, tài liệu tải về (kích thước khác nhau để đặc trưng bytes có nghĩa)
W=/var/www/html
mkdir -p $W/assets $W/docs $W/news $W/portal/reports
cat > $W/assets/site.css <<'CSS'
body{font-family:sans-serif;margin:2em;max-width:60em}nav a{margin-right:1em}
CSS
echo 'document.addEventListener("DOMContentLoaded",()=>{});' > $W/assets/site.js
for i in $(seq 1 6); do head -c $((4000 + i * 3000)) /dev/urandom > $W/assets/img$i.jpg; done
for i in $(seq 1 8); do head -c $((200000 * i)) /dev/urandom > $W/docs/tai-lieu-$i.pdf; done
page() {  # page <đường dẫn> <tiêu đề> <số ảnh>
  local imgs=""; for j in $(seq 1 "$3"); do imgs+="<img src=\"/assets/img$(( (j % 6) + 1 )).jpg\">"; done
  cat > "$1" <<HTML
<!doctype html><html><head><meta charset="utf-8"><title>$2</title><link rel="stylesheet" href="/assets/site.css">
<script src="/assets/site.js"></script></head><body><nav><a href="/">Trang chủ</a><a href="/news/">Tin</a>
<a href="/docs/">Tài liệu</a><a href="/portal/">Cổng nội bộ</a></nav><h1>$2</h1>$imgs</body></html>
HTML
}
page $W/index.html "Công ty Lab" 3
page $W/news/index.html "Tin tức" 1
for i in $(seq 1 30); do page $W/news/tin-$i.html "Tin số $i" $(( i % 3 )); done
page $W/docs/index.html "Tài liệu" 0
page $W/portal/index.html "Cổng nội bộ" 1
for i in $(seq 1 12); do page $W/portal/reports/bao-cao-$i.html "Báo cáo $i" 1; done
echo "User-agent: *" > $W/robots.txt
rm -f $W/index.nginx-debian.html

# ---- /portal: Basic Auth (đăng nhập sai -> 401 trong access.log, lỗi xác thực trong error.log)
: > /etc/apache2/lab-portal.htpasswd
getent group labsim >/dev/null || groupadd labsim
tr -d '\r' < "$USERS_FILE" | grep -vE '^\s*(#|$)' | while IFS='|' read -r name pass role; do
  name=$(echo "$name" | xargs); pass=$(echo "$pass" | xargs); role=$(echo "$role" | xargs)
  htpasswd -b -B /etc/apache2/lab-portal.htpasswd "$name" "$pass" >/dev/null 2>&1
  # tài khoản Linux cho SSH: chỉ vai trò admin, tên có tiền tố lab_ và thuộc nhóm labsim. KHÔNG BAO GIỜ đổi mật khẩu
  # của tài khoản không thuộc labsim (đã từng trùng tên với tài khoản thật của chủ máy).
  [ "$role" = admin ] || continue
  acct="lab_$name"
  if id "$acct" >/dev/null 2>&1; then
    id -nG "$acct" | grep -qw labsim || { echo "bỏ qua $acct: tài khoản có sẵn, không phải của lab" >&2; continue; }
  else
    useradd -m -s /bin/bash -G labsim "$acct"
  fi
  echo "$acct:$pass" | chpasswd
done
chmod 640 /etc/apache2/lab-portal.htpasswd; chgrp www-data /etc/apache2/lab-portal.htpasswd
cat > /etc/apache2/conf-available/lab-portal.conf <<'CONF'
<Directory /var/www/html/portal>
  AuthType Basic
  AuthName "Cong noi bo"
  AuthUserFile /etc/apache2/lab-portal.htpasswd
  Require valid-user
</Directory>
CONF
a2enconf -q lab-portal
systemctl enable -q --now apache2 ssh
systemctl reload apache2

# ---- agent Wazuh
if ! dpkg -s wazuh-agent >/dev/null 2>&1; then
  curl -fsS https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor --yes -o /usr/share/keyrings/wazuh.gpg
  echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list
  apt-get update -qq
  WAZUH_MANAGER="$MANAGER" WAZUH_AGENT_NAME="$AGENT_NAME" WAZUH_REGISTRATION_PASSWORD="$(cat "$KEY_FILE")" \
    apt-get install -y -qq "wazuh-agent=$AGENT_VERSION" >/dev/null
  apt-mark hold wazuh-agent >/dev/null
fi
systemctl enable -q --now wazuh-agent
sleep 5
grep -E "Connected to the server|Unable to connect" /var/ossec/logs/ossec.log | tail -1
echo "web: $(hostname) apache=$(systemctl is-active apache2) ssh=$(systemctl is-active ssh) agent=$(systemctl is-active wazuh-agent)"
