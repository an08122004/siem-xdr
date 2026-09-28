package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadQuotedValuesWithComments(t *testing.T) {
	yaml := "agent_id: \"A001\"\n" +
		"server:\n" +
		"  url: \"https://10.0.0.5:8000\"     # IP manager\n" +
		`  ca_file: "C:\ProgramData\siem-agent\ca.crt"   # CA` + "\n" +
		"  enrollment_key: abc # comment\n" +
		"filetail:\n" +
		"  auth: \"/var/log/auth.log, /var/log/secure\"\n"
	p := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(p, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.URL != "https://10.0.0.5:8000" {
		t.Errorf("url = %q", cfg.Server.URL)
	}
	if cfg.Server.CAFile != `C:\ProgramData\siem-agent\ca.crt` {
		t.Errorf("ca_file = %q", cfg.Server.CAFile)
	}
	if cfg.Server.EnrollmentKey != "abc" {
		t.Errorf("enrollment_key = %q", cfg.Server.EnrollmentKey)
	}
	if got := cfg.FileTail["auth"]; len(got) != 2 || got[1] != "/var/log/secure" {
		t.Errorf("filetail.auth = %v", got)
	}
}

// Các file cấu hình mẫu đi kèm repo phải nạp được và có giá trị đúng.
func TestShippedSampleConfigs(t *testing.T) {
	t.Setenv("SIEM_ENROLLMENT_KEY", "k") // demo-web lấy khóa từ biến môi trường
	lin, err := Load(filepath.Join("..", "config.linux.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if lin.Queue.MaxMB != 512 || lin.Collectors.ProcessMode != "auto" || len(lin.FIM.Paths) < 5 || lin.FIM.Exclude[0] != "*.swp" {
		t.Errorf("config.linux.yaml: %+v %+v", lin.Queue, lin.FIM)
	}
	win, err := Load(filepath.Join("..", "config.windows.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if win.FIM.Paths[0] != `C:\Windows\System32\drivers\etc` || win.Queue.Dir != `C:\ProgramData\siem-agent` {
		t.Errorf("config.windows.yaml: %v %q", win.FIM.Paths, win.Queue.Dir)
	}
	demo, err := Load(filepath.Join("..", "..", "demo", "web", "agent.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if demo.Collectors.ProcessMode != "poll" || demo.FIM.IntervalSeconds != 30 {
		t.Errorf("demo agent.yaml: %+v %+v", demo.Collectors, demo.FIM)
	}
}

func TestEnrollmentKeyFromFile(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key")
	_ = os.WriteFile(keyFile, []byte("from-file\n"), 0o600)
	t.Setenv("SIEM_ENROLLMENT_KEY_FILE", keyFile)
	p := filepath.Join(dir, "c.yaml")
	_ = os.WriteFile(p, []byte("server:\n  url: https://m:8000\n  enrollment_key: from-config\n"), 0o600)
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.EnrollmentKey != "from-file" {
		t.Errorf("key = %q, muốn đọc từ file bí mật", cfg.Server.EnrollmentKey)
	}
}
