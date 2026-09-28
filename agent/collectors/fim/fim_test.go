package fim

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"siem-agent/core"
)

type sink struct {
	evs  []core.Event
	fail bool
}

func (s *sink) emit(evts []core.Event) error {
	if s.fail {
		return errors.New("đĩa lỗi giả lập")
	}
	s.evs = append(s.evs, evts...)
	return nil
}

func (s *sink) summary() string {
	var out []string
	for _, e := range s.evs {
		out = append(out, e.Data["action"].(string)+":"+filepath.Base(e.Data["path"].(string)))
	}
	sort.Strings(out)
	s.evs = nil
	return strings.Join(out, ",")
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestBaselineThenChanges(t *testing.T) {
	dir, state := t.TempDir(), t.TempDir()
	web := filepath.Join(dir, "htdocs")
	os.MkdirAll(filepath.Join(web, "cache"), 0o755)
	write(t, filepath.Join(web, "index.html"), "xin chao")
	write(t, filepath.Join(web, "old.txt"), "se bi xoa")
	write(t, filepath.Join(web, "cache", "x.tmp"), "bo qua")

	c := New([]string{web}, []string{"cache", "*.log"}, time.Minute, 1, state)
	s := &sink{}
	if err := c.Scan(s.emit); err != nil || len(s.evs) != 0 {
		t.Fatalf("lần đầu chỉ lập baseline, không báo: %v %d", err, len(s.evs))
	}

	write(t, filepath.Join(web, "index.html"), "bi sua noi dung!!")
	write(t, filepath.Join(web, "shell.php"), "<?php system($_GET['c']); ?>")
	os.Remove(filepath.Join(web, "old.txt"))
	write(t, filepath.Join(web, "access.log"), "loai tru")
	write(t, filepath.Join(web, "cache", "y.tmp"), "loai tru ca thu muc")
	if err := c.Scan(s.emit); err != nil {
		t.Fatal(err)
	}
	if got := s.summary(); got != "added:shell.php,deleted:old.txt,modified:index.html" {
		t.Fatalf("nhận %q", got)
	}

	// không đổi gì -> không báo
	c.Scan(s.emit)
	if got := s.summary(); got != "" {
		t.Fatalf("không thay đổi mà vẫn báo: %q", got)
	}
}

func TestHashesAndRestart(t *testing.T) {
	dir, state := t.TempDir(), t.TempDir()
	f := filepath.Join(dir, "passwd")
	write(t, f, "root:x:0:0")
	c := New([]string{f}, nil, time.Minute, 1, state) // đường dẫn là một file
	s := &sink{}
	c.Scan(s.emit)

	// khởi động lại agent: đọc baseline cũ, phát hiện thay đổi xảy ra lúc agent tắt
	write(t, f, "root:x:0:0\nhacker:x:0:0")
	c2 := New([]string{f}, nil, time.Minute, 1, state)
	c2.Scan(s.emit)
	if len(s.evs) != 1 {
		t.Fatalf("muốn 1 event, nhận %d", len(s.evs))
	}
	d := s.evs[0].Data
	if d["action"] != "modified" || d["sha256"] == d["old_sha256"] || len(d["sha256"].(string)) != 64 {
		t.Fatalf("event thiếu hash trước/sau: %v", d)
	}
}

func TestEmitFailureKeepsBaseline(t *testing.T) {
	dir, state := t.TempDir(), t.TempDir()
	c := New([]string{dir}, nil, time.Minute, 1, state)
	s := &sink{}
	c.Scan(s.emit)
	write(t, filepath.Join(dir, "new.sh"), "curl x | sh")
	s.fail = true
	if err := c.Scan(s.emit); err == nil {
		t.Fatal("emit lỗi phải trả lỗi")
	}
	s.fail = false
	c.Scan(s.emit)
	if got := s.summary(); got != "added:new.sh" {
		t.Fatalf("thay đổi chưa ghi được phải được báo lại ở vòng sau, nhận %q", got)
	}
}

func TestLargeFileComparedBySizeAndTime(t *testing.T) {
	dir, state := t.TempDir(), t.TempDir()
	big := filepath.Join(dir, "big.bin")
	write(t, big, strings.Repeat("a", 2<<20))
	c := New([]string{dir}, nil, time.Minute, 1, state) // giới hạn băm 1 MB
	s := &sink{}
	c.Scan(s.emit)
	if c.base[big].SHA256 != "" {
		t.Fatal("file quá lớn không được băm")
	}
	write(t, big, strings.Repeat("b", 3<<20))
	c.Scan(s.emit)
	if got := s.summary(); got != "modified:big.bin" {
		t.Fatalf("file lớn đổi kích thước phải được báo, nhận %q", got)
	}
}
