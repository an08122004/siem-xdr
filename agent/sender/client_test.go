package sender

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"siem-agent/core"
)

// fakeManager mô phỏng manager: cấp token, có thể thu hồi, ghi lại token agent trình khi enroll lại.
type fakeManager struct {
	mu        sync.Mutex
	valid     string
	next      []string
	conflict  bool
	enrolls   int
	presented []string
}

func (m *fakeManager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch r.URL.Path {
	case "/api/v1/agents/enroll":
		m.enrolls++
		m.presented = append(m.presented, r.Header.Get("Authorization"))
		if r.Header.Get("X-Enrollment-Key") != "k" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if m.conflict {
			w.WriteHeader(http.StatusConflict)
			return
		}
		m.valid, m.next = m.next[0], m.next[1:]
		w.Write([]byte(`{"token":"` + m.valid + `"}`))
	default:
		if r.Header.Get("Authorization") != "Bearer "+m.valid || m.valid == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Write([]byte(`{}`))
	}
}

func newTestClient(t *testing.T, url string) (*Client, string) {
	dir := t.TempDir()
	c, err := NewClient(url, "k", AgentInfo{AgentID: "a1"}, dir, 5*time.Second, "")
	if err != nil {
		t.Fatal(err)
	}
	return c, dir
}

func TestEnrollPresentsCurrentTokenAndPersists(t *testing.T) {
	m := &fakeManager{next: []string{"t1", "t2"}}
	srv := httptest.NewServer(m)
	defer srv.Close()
	c, dir := newTestClient(t, srv.URL)
	ctx := context.Background()

	if err := c.SendEvents(ctx, []core.Event{{Source: "mock"}}); err != nil {
		t.Fatal(err)
	}
	if raw, _ := os.ReadFile(filepath.Join(dir, "agent.token")); string(raw) != "t1" {
		t.Fatalf("token chưa được lưu: %q", raw)
	}
	// manager đổi token (vd: đổi sang token ngẫu nhiên) -> agent enroll lại, trình token cũ
	m.mu.Lock()
	m.valid = "khac"
	m.mu.Unlock()
	if err := c.SendEvents(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if got := m.presented[len(m.presented)-1]; got != "Bearer t1" {
		t.Fatalf("enroll lại phải trình token hiện tại, nhận %q", got)
	}
	// agent khởi động lại đọc token từ đĩa
	c2, _ := NewClient(srv.URL, "k", AgentInfo{AgentID: "a1"}, dir, 5*time.Second, "")
	if err := c2.Heartbeat(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestEnrollConflictBacksOff(t *testing.T) {
	m := &fakeManager{conflict: true}
	srv := httptest.NewServer(m)
	defer srv.Close()
	c, _ := newTestClient(t, srv.URL)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		if err := c.Heartbeat(ctx); !errors.Is(err, ErrEnrollConflict) {
			t.Fatalf("muốn ErrEnrollConflict, nhận %v", err)
		}
	}
	if m.enrolls != 1 {
		t.Fatalf("trong thời gian chờ không được gọi enroll lại, đã gọi %d lần", m.enrolls)
	}
}
