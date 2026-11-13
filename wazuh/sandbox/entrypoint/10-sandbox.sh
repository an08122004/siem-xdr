#!/bin/bash
# Sandbox Wazuh của AI (R67). Chạy bởi image wazuh-manager (/etc/cont-init.d/2-manager -> /entrypoint-scripts/*.sh) TRƯỚC
# `wazuh-control start`, mỗi lần container khởi động (idempotent). Không secrets, không mạng: chỉ chuẩn bị đủ để
# wazuh-analysisd lên và chạy runner.py nhận job từ /sandbox/jobs.
set -euo pipefail
C=/var/ossec/etc/ossec.conf

# 1. Không chạy filebeat (như wazuh/manager/entrypoint/10-siem-setup.sh): sandbox không gửi alert đi đâu
printf '#!/bin/sh\n# filebeat bị tắt: sandbox không gửi alert đi đâu\nexec sleep infinity\n' > /etc/services.d/filebeat/run

# 2. Không ghi archives.json: mỗi job bơm hàng chục nghìn event, file chỉ phình mà không ai đọc
sed -i 's|<logall_json>yes</logall_json>|<logall_json>no</logall_json>|' "$C"

# 3. List CDB rỗng cho mọi <list> trong ossec.conf chưa có file (siem-misp-* do SOAR đẩy lên stack thật): thiếu file thì
#    analysisd không lên. Rule dùng list này không khớp gì trong sandbox.
grep -o '<list>[^<]*</list>' "$C" | sed 's|</\?list>||g' | while read -r L; do
  F=/var/ossec/$L
  if [ ! -e "$F" ]; then
    mkdir -p "$(dirname "$F")"
    install -m 0660 -o wazuh -g wazuh /dev/null "$F"
  fi
done

# 3b. File state của analysisd cập nhật mỗi giây (mặc định 5): runner đọc độ đầy hàng đợi để không gửi nhanh hơn
#     analysisd xử lý (đo S4: không chờ thì bỏ 15% event)
O=/var/ossec/etc/local_internal_options.conf
grep -q '^analysisd.state_interval=' "$O" || echo 'analysisd.state_interval=1' >> "$O"

# 4. Rule động của sandbox: runner chép /live-dynamic (bản thật, chỉ đọc) + ứng viên vào đây cho mỗi job
install -d -o root -g wazuh -m 0755 /var/ossec/etc/rules-dynamic

# 5. Thư mục job: uid 10001 = user của ai-worker (image siem-xdr-server) tạo job, runner (root) ghi kết quả
install -d -o 10001 -g 10001 -m 0775 /sandbox/jobs

# 6. Runner là dịch vụ s6, không phải tiến trình nền của script này: s6 giám sát và chạy lại khi nó chết, `wazuh-control
#    restart` của mỗi job không đụng tới nó. /var/run/s6/etc/services.d là symlink tới /etc/services.d và s6 đọc nó SAU
#    bước cont-init, nên dịch vụ thêm ở đây chạy ngay lần khởi động này (sau `wazuh-control start`).
mkdir -p /etc/services.d/sandbox-runner
printf '#!/bin/sh\nexec /var/ossec/framework/python/bin/python3 -u /sandbox-runner/runner.py watch /sandbox\n' \
  > /etc/services.d/sandbox-runner/run
chmod 0755 /etc/services.d/sandbox-runner/run
echo "[sandbox] đã chuẩn bị, runner chạy dưới s6"
