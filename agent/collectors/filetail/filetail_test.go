package filetail

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"siem-agent/core"
)

type sink struct {
	mu    sync.Mutex
	lines []string
	fail  int
}

func (s *sink) emit(evts []core.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail > 0 {
		s.fail--
		return errors.New("đĩa lỗi giả lập")
	}
	for _, e := range evts {
		s.lines = append(s.lines, e.Data["message"].(string))
	}
	return nil
}

func (s *sink) got() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Join(s.lines, ",")
}

func start(c *Collector, s *sink) func() {
	c.interval = 20 * time.Millisecond
	done := make(chan struct{})
	go func() { c.Start(s.emit); close(done) }()
	return func() { c.Stop(); <-done }
}

func waitFor(t *testing.T, s *sink, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if s.got() == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("muốn %q, nhận %q", want, s.got())
}

func appendLines(t *testing.T, path string, lines ...string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range lines {
		fmt.Fprintln(f, l)
	}
	f.Close()
}

// settle chờ collector chạy vài vòng quét.
func settle() { time.Sleep(120 * time.Millisecond) }

func setup(t *testing.T) (string, string) {
	dir := t.TempDir()
	return dir, filepath.Join(dir, "access.log")
}

func TestStartsAtEndThenFollows(t *testing.T) {
	dir, path := setup(t)
	appendLines(t, path, "cu1", "cu2")
	s := &sink{}
	stop := start(New(map[string][]string{"x": {path}}, dir), s)
	defer stop()
	settle()
	appendLines(t, path, "a", "b")
	waitFor(t, s, "a,b")
}

func TestRotationByRenameReadsOldTailThenNewFile(t *testing.T) {
	dir, path := setup(t)
	appendLines(t, path, "cu")
	s := &sink{}
	stop := start(New(map[string][]string{"x": {path}}, dir), s)
	defer stop()
	settle()
	appendLines(t, path, "1")
	waitFor(t, s, "1")

	appendLines(t, path, "2")
	if err := os.Rename(path, path+".1"); err != nil { // Windows: chỉ được khi agent mở với FILE_SHARE_DELETE
		t.Fatalf("agent cản việc xoay vòng log: %v", err)
	}
	appendLines(t, path+".1", "3") // ứng dụng ghi thêm vào file cũ trước khi mở file mới
	appendLines(t, path, "4", "5")
	waitFor(t, s, "1,2,3,4,5")
}

func TestCopyTruncate(t *testing.T) {
	dir, path := setup(t)
	appendLines(t, path)
	s := &sink{}
	stop := start(New(map[string][]string{"x": {path}}, dir), s)
	defer stop()
	settle()
	appendLines(t, path, "a", "b")
	waitFor(t, s, "a,b")
	os.Truncate(path, 0)
	appendLines(t, path, "dong-moi-dai-hon-offset-cu")
	waitFor(t, s, "a,b,dong-moi-dai-hon-offset-cu")
}

func TestRotationWhileAgentStopped(t *testing.T) {
	dir, path := setup(t)
	appendLines(t, path, "cu")
	s := &sink{}
	stop := start(New(map[string][]string{"x": {path}}, dir), s)
	settle()
	appendLines(t, path, "a")
	waitFor(t, s, "a")
	stop()

	// agent tắt: có thêm dòng chưa đọc, log xoay vòng, file mới đã dài hơn offset cũ
	appendLines(t, path, "b")
	os.Rename(path, path+".1")
	var fresh []string
	for i := 0; i < 20; i++ {
		fresh = append(fresh, fmt.Sprintf("moi%02d", i))
	}
	appendLines(t, path, fresh...)

	s2 := &sink{}
	stop2 := start(New(map[string][]string{"x": {path}}, dir), s2)
	defer stop2()
	waitFor(t, s2, "b,"+strings.Join(fresh, ","))
}

func TestEmitFailureDoesNotSkipLines(t *testing.T) {
	dir, path := setup(t)
	appendLines(t, path)
	s := &sink{}
	stop := start(New(map[string][]string{"x": {path}}, dir), s)
	defer stop()
	settle()
	s.mu.Lock()
	s.fail = 2
	s.mu.Unlock()
	appendLines(t, path, "x", "y")
	waitFor(t, s, "x,y")
}

func TestLegacyStateFormat(t *testing.T) {
	dir, path := setup(t)
	appendLines(t, path, "l1", "l2")
	os.WriteFile(filepath.Join(dir, "filetail.state.json"), []byte(fmt.Sprintf(`{%q: 3}`, path)), 0o640)
	s := &sink{}
	stop := start(New(map[string][]string{"x": {path}}, dir), s)
	defer stop()
	waitFor(t, s, "l2")
}

func TestGlobNewFileReadFromStart(t *testing.T) {
	dir := t.TempDir()
	appendLines(t, filepath.Join(dir, "a.log"), "cu")
	s := &sink{}
	stop := start(New(map[string][]string{"x": {filepath.Join(dir, "*.log")}}, dir), s)
	defer stop()
	settle()
	appendLines(t, filepath.Join(dir, "b.log"), "moi1", "moi2")
	waitFor(t, s, "moi1,moi2")
}
