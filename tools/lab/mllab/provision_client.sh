#!/bin/bash
# Dựng máy CLIENT của lab ML (Ubuntu 24.04, đã có agent Wazuh): đăng ký lại agent về manager của SIEM, cài bộ mô phỏng
# người dùng (simulate_users.py) thành dịch vụ systemd `labsim`. Chạy bằng root, chạy lại được.
#
#   MANAGER=10.10.1.1 KEY_FILE=/tmp/ek USERS_FILE=/tmp/users SIM=/tmp/simulate_users.py \
#   WEB=10.10.1.132 IPS=10.10.1.40-59 DEV=ens37 bash provision_client.sh
set -euo pipefail
: "${MANAGER:?}" "${KEY_FILE:?}" "${USERS_FILE:?}" "${SIM:?}" "${WEB:?}" "${IPS:?}" "${DEV:?}"
AGENT_NAME=${AGENT_NAME:-lab-client}
export DEBIAN_FRONTEND=noninteractive

command -v python3 >/dev/null || { echo "thiếu python3" >&2; exit 1; }
if ! command -v sshpass >/dev/null; then
  # apt có thể đang kẹt vì gói khác (vd kernel cài dở): sshpass chỉ phụ thuộc libc nên tải .deb và cài thẳng, không
  # đụng tới các gói đang hỏng của máy
  (cd /tmp && apt-get download -qq sshpass && dpkg -i /tmp/sshpass_*.deb >/dev/null && rm -f /tmp/sshpass_*.deb) \
    || apt-get install -y -qq sshpass >/dev/null
fi

# ---- agent: trỏ về manager của SIEM và đăng ký lại (client.keys cũ của manager khác bị thay)
if ! grep -q " $AGENT_NAME " /var/ossec/etc/client.keys 2>/dev/null; then
  sed -i "s#<address>[^<]*</address>#<address>$MANAGER</address>#" /var/ossec/etc/ossec.conf
  /var/ossec/bin/agent-auth -m "$MANAGER" -A "$AGENT_NAME" -P "$(cat "$KEY_FILE")" >/dev/null
fi
systemctl restart wazuh-agent

# ---- bộ mô phỏng
install -d -m 0750 /opt/labsim /var/log/labsim
install -m 0640 "$SIM" /opt/labsim/simulate_users.py
tr -d '\r' < "$USERS_FILE" > /opt/labsim/users.txt; chmod 0600 /opt/labsim/users.txt
cat > /etc/systemd/system/labsim.service <<UNIT
[Unit]
Description=Lab ML: mô phỏng người dùng bình thường (siem-xdr)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/python3 /opt/labsim/simulate_users.py --web $WEB --users /opt/labsim/users.txt --ips $IPS --dev $DEV
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable -q labsim
systemctl restart labsim
sleep 8
echo "client: agent=$(systemctl is-active wazuh-agent) labsim=$(systemctl is-active labsim)"
grep -E "Connected to the server|Unable to connect" /var/ossec/logs/ossec.log | tail -1
journalctl -u labsim -n 2 --no-pager | tail -1
