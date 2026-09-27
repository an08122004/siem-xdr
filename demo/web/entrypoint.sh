#!/bin/sh
set -e
mkdir -p /var/lib/siem-agent
touch /usr/local/apache2/logs/access_log /usr/local/apache2/logs/error_log
# socket cgid còn sót khi container restart -> cgid không bind được, mọi CGI trả 503
rm -f /usr/local/apache2/logs/cgisock.*
# agent chạy nền (root, để thực thi iptables khi nhận lệnh block_ip)
siem-agent -config /etc/siem-agent/config.yaml &
exec httpd-foreground
