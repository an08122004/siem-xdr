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
