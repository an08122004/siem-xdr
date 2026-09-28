//go:build windows

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestServiceModeOutsideSCM(t *testing.T) {
	start := time.Now()
	err := runAsService(func(context.Context) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "Service Control Manager") || time.Since(start) > 5*time.Second {
		t.Fatalf("chạy -service ngoài SCM phải báo lỗi ngay, nhận %v", err)
	}
}

// Kiểm tra bằng SID (không phụ thuộc ngôn ngữ Windows): sau khi siết, Users / Everyone /
// Authenticated Users không còn quyền, người chạy agent vẫn đọc ghi được.
func TestHardenStateDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	os.MkdirAll(dir, 0o700)
	os.WriteFile(filepath.Join(dir, "agent.token"), []byte("bi-mat"), 0o600)
	if err := hardenStateDir(dir); err != nil {
		t.Fatal(err)
	}
	sids := func(p string) string {
		ps := `(Get-Acl -LiteralPath '` + p + `').Access | ForEach-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value }`
		out, err := exec.Command("powershell", "-NoProfile", "-Command", ps).CombinedOutput()
		if err != nil {
			t.Fatalf("Get-Acl: %v %s", err, out)
		}
		return string(out)
	}
	me, _ := currentUserSID()
	for _, p := range []string{dir, filepath.Join(dir, "agent.token")} {
		got := sids(p)
		for _, bad := range []string{"S-1-5-32-545", "S-1-1-0", "S-1-5-11"} {
			if strings.Contains(got, bad) {
				t.Fatalf("%s vẫn cho %s truy cập:\n%s", p, bad, got)
			}
		}
		if !strings.Contains(got, "S-1-5-18") || !strings.Contains(got, me) {
			t.Fatalf("%s phải giữ quyền cho SYSTEM và người chạy agent:\n%s", p, got)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "new"), []byte("x"), 0o600); err != nil {
		t.Fatalf("người chạy agent phải còn ghi được: %v", err)
	}
}
