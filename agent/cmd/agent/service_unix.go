//go:build !windows

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
)

const unitPath = "/etc/systemd/system/" + serviceName + ".service"

func installService(configPath string) error {
	if os.Geteuid() != 0 {
		return errors.New("cần chạy bằng root (sudo)")
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return errors.New("máy không dùng systemd: hãy tự cấu hình init system chạy `siem-agent -config " + configPath + "`")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if err := os.WriteFile(unitPath, []byte(systemdUnit(exe, configPath)), 0o644); err != nil {
		return fmt.Errorf("không ghi được %s: %w", unitPath, err)
	}
	if err := systemctl("daemon-reload"); err != nil {
		return err
	}
	return systemctl("enable", "--now", serviceName)
}

func uninstallService() error {
	if os.Geteuid() != 0 {
		return errors.New("cần chạy bằng root (sudo)")
	}
	_ = systemctl("disable", "--now", serviceName)
	if err := os.Remove(unitPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return systemctl("daemon-reload")
}

func systemctl(args ...string) error {
	out, err := exec.Command("systemctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %v: %v %s", args, err, out)
	}
	return nil
}

func runAsService(func(context.Context) error) error {
	return errors.New("-service chỉ dùng cho Windows; trên Linux service do systemd quản lý (siem-agent -install)")
}

// hardenStateDir: token, queue (log an ninh) và offset chỉ root được đọc.
func hardenStateDir(dir string) error {
	return os.Chmod(dir, 0o700)
}

// warnConfigPerms: file cấu hình chứa khóa enroll dùng chung; người khác đọc được thì họ có thể
// xin enroll (dù không còn giả mạo được agent đã có).
func warnConfigPerms(path string) {
	if info, err := os.Stat(path); err == nil && info.Mode().Perm()&0o044 != 0 {
		log.Printf("CẢNH BÁO: %s (chứa enrollment_key) đang cho user khác đọc — chạy: chmod 600 %s", path, path)
	}
}
