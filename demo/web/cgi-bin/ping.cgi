#!/bin/bash
# !!! CỐ Ý CÓ LỖ HỔNG COMMAND INJECTION — CHỈ DÙNG ĐỂ DEMO XDR TRONG LAB !!!
# Tham số host được đưa thẳng vào shell -> kẻ tấn công chạy được lệnh tùy ý:
#   /cgi-bin/ping.cgi?host=127.0.0.1;id
# Dùng `exec sh -c` để tiến trình shell có cha là httpd -> agent phát hiện (rule LNX-002).
echo "Content-Type: text/plain"
echo
raw=$(printf '%s' "$QUERY_STRING" | sed -n 's/^.*host=\([^&]*\).*$/\1/p')
host=$(printf '%b' "$(printf '%s' "$raw" | sed 's/+/ /g; s/%\([0-9A-Fa-f][0-9A-Fa-f]\)/\\x\1/g')")
exec sh -c "ping -c 1 -W 1 $host 2>&1"
