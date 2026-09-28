package main

import (
	"fmt"
	"strings"
)

// systemdUnit: agent cần root (đọc log hệ thống, iptables, kill tiến trình, proc connector),
// systemd tự khởi động lại khi agent chết và khi máy khởi động.
func systemdUnit(exe, configPath string) string {
	q := func(s string) string { return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"` }
	return fmt.Sprintf(`[Unit]
Description=SIEM/XDR agent
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=%s -config %s
Restart=always
RestartSec=5
User=root
# chỉ đọc /usr, /boot, /etc; agent chỉ ghi vào thư mục trạng thái và file log
ProtectSystem=full
PrivateTmp=true
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
`, q(exe), q(configPath))
}

// scCreateArgs: tham số cho `sc.exe create`. Service chạy bằng LocalSystem, tự khởi động cùng Windows.
func scCreateArgs(exe, configPath string) []string {
	bin := fmt.Sprintf(`"%s" -service -config "%s"`, exe, configPath)
	return []string{"create", serviceName, "binPath=", bin, "start=", "auto", "DisplayName=", "SIEM/XDR Agent"}
}

// scFailureArgs: SCM tự khởi động lại agent nếu tiến trình chết (5s, 5s, rồi 60s).
func scFailureArgs() []string {
	return []string{"failure", serviceName, "reset=", "86400", "actions=", "restart/5000/restart/5000/restart/60000"}
}
