package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeManager mô phỏng Manager API: enroll, nhận event, heartbeat, giao lệnh và nhận kết quả.
type fakeManager struct {
	mu      sync.Mutex
	failing bool
	lines   map[string]int // message -> số lần nhận
	agentID string
	results map[string]string
	gave    bool
}

func (m *fakeManager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch {
	case r.URL.Path == "/api/v1/agents/enroll":
		w.Write([]byte(`{"token":"tok"}`))
	case r.Header.Get("Authorization") != "Bearer tok":
		w.WriteHeader(http.StatusUnauthorized)
	case m.failing:
		w.WriteHeader(http.StatusInternalServerError)
	case r.URL.Path == "/api/v1/events":
		var evs []map[string]interface{}
		json.NewDecoder(r.Body).Decode(&evs)
		for _, e := range evs {
			m.agentID = fmt.Sprint(e["agent_id"])
			if d, ok := e["data"].(map[string]interface{}); ok {
				m.lines[fmt.Sprint(d["message"])]++
			}
		}
		w.Write([]byte(`{}`))
	case r.URL.Path == "/api/v1/agents/actions":
		if m.gave {
			w.Write([]byte(`[]`))
			return
		}
		m.gave = true
		w.Write([]byte(`[{"id":"a1","type":"kill_process","params":{"name":"xmrig"}}]`))
	case strings.HasPrefix(r.URL.Path, "/api/v1/actions/"):
		var res map[string]string
		json.NewDecoder(r.Body).Decode(&res)
		m.results[strings.Split(r.URL.Path, "/")[4]] = res["status"]
		w.Write([]byte(`{}`))
	default:
		w.Write([]byte(`{}`))
	}
}

func (m *fakeManager) set(failing bool) {
	m.mu.Lock()
	m.failing = failing
	m.mu.Unlock()
}

func (m *fakeManager) waitLines(t *testing.T, want int) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		m.mu.Lock()
		got := len(m.lines)
		m.mu.Unlock()
		if got >= want {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("manager chỉ nhận %d/%d dòng", len(m.lines), want)
}

func appendLog(t *testing.T, path string, from, to int) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	for i := from; i < to; i++ {
		fmt.Fprintf(f, "dong-%03d\n", i)
	}
	f.Close()
}

func TestAgentEndToEnd(t *testing.T) {
	m := &fakeManager{lines: map[string]int{}, results: map[string]string{}}
	srv := httptest.NewServer(m)
	defer srv.Close()

	dir := t.TempDir()
	logFile := filepath.Join(dir, "app.log")
	appendLog(t, logFile, 0, 0)
	cfgPath := filepath.Join(dir, "agent.yaml")
	cfg := fmt.Sprintf(`agent_id: "E2E-01"
server:
  url: %q
  enrollment_key: "k"
  retry_interval_seconds: 1
queue:
  dir: %q
filetail:
  app: %q
response:
  enabled: true
  dry_run: true
  poll_interval_seconds: 1
`, srv.URL, filepath.Join(dir, "state"), logFile)
	os.WriteFile(cfgPath, []byte(cfg), 0o600)

	start := func() (context.CancelFunc, chan error) {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- run(ctx, cfgPath, false) }()
		time.Sleep(1500 * time.Millisecond) // collector mở file, bắt đầu từ cuối
		return cancel, done
	}

	// 1. chạy bình thường
	stop, done := start()
	appendLog(t, logFile, 0, 50)
	m.waitLines(t, 50)

	// 2. manager lỗi: event dồn trong queue; dừng agent đúng lúc đó; ghi thêm log khi agent tắt
	m.set(true)
	appendLog(t, logFile, 50, 100)
	time.Sleep(2 * time.Second)
	stop()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	appendLog(t, logFile, 100, 150)

	// 3. khởi động lại, manager hồi phục: phải nhận đủ 150 dòng
	m.set(false)
	stop, done = start()
	m.waitLines(t, 150)
	time.Sleep(1500 * time.Millisecond)
	stop()
	<-done

	m.mu.Lock()
	defer m.mu.Unlock()
	for i := 0; i < 150; i++ {
		if m.lines[fmt.Sprintf("dong-%03d", i)] == 0 {
			t.Fatalf("mất dòng %d", i)
		}
	}
	if m.agentID != "E2E-01" {
		t.Fatalf("event thiếu agent_id: %q", m.agentID)
	}
	if m.results["a1"] != "success" {
		t.Fatalf("lệnh kill (dry-run) phải được báo kết quả về manager: %v", m.results)
	}
	// segment đã gửi xong phải bị xóa: không còn queue.log phình mãi
	segs, _ := filepath.Glob(filepath.Join(dir, "state", "*.seg"))
	if len(segs) > 1 {
		t.Fatalf("còn %d segment sau khi đã gửi hết", len(segs))
	}
}
