#!/bin/sh
# Form đăng nhập giả: luôn từ chối (để demo brute-force web -> rule WEB-007)
read -r body 2>/dev/null || true
echo "Status: 401 Unauthorized"
echo "Content-Type: text/plain"
echo
echo "Sai tên đăng nhập hoặc mật khẩu"
