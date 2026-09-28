//go:build windows

package response

import (
	"os"
	"strings"
	"testing"
)

func TestProcessNameOfSelf(t *testing.T) {
	name, err := processName(os.Getpid())
	if err != nil || !strings.HasSuffix(strings.ToLower(name), ".exe") {
		t.Fatalf("tra tên tiến trình của chính test: %q, %v", name, err)
	}
	if _, err := processName(0x7ffffff0); err == nil {
		t.Fatal("pid không tồn tại phải báo lỗi")
	}
}

func TestParseTasklist(t *testing.T) {
	out := "\"svchost.exe\",\"1234\",\"Services\",\"0\",\"10,000 K\"\r\n"
	if n, err := parseTasklist(out, 1234); err != nil || n != "svchost.exe" {
		t.Fatalf("%q %v", n, err)
	}
	if _, err := parseTasklist("INFO: No tasks are running which match the specified criteria.\r\n", 5); err == nil {
		t.Fatal("không có tiến trình phải báo lỗi")
	}
}
