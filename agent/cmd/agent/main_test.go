package main

import (
	"context"
	"encoding/json"
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"

	"siem-agent/core"
	"siem-agent/queue"
)

func TestSystemdUnitAndScArgs(t *testing.T) {
	u := systemdUnit("/opt/siem agent/siem-agent", "/etc/siem-agent/config.yaml")
	if !strings.Contains(u, `ExecStart="/opt/siem agent/siem-agent" -config "/etc/siem-agent/config.yaml"`) ||
		!strings.Contains(u, "Restart=always") || !strings.Contains(u, "WantedBy=multi-user.target") {
		t.Fatalf("unit sai:\n%s", u)
	}
	args := strings.Join(scCreateArgs(`C:\siem\siem-agent.exe`, `C:\ProgramData\siem-agent\config.yaml`), " ")
	if !strings.Contains(args, `binPath= "C:\siem\siem-agent.exe" -service -config "C:\ProgramData\siem-agent\config.yaml"`) ||
		!strings.Contains(args, "start= auto") {
		t.Fatalf("tham số sc sai: %s", args)
	}
}

func TestEmitterStampsAndWaitsWhenQueueFull(t *testing.T) {
	big := func() []core.Event {
		return []core.Event{{Source: "test", Data: map[string]interface{}{"pad": strings.Repeat("x", 200)}}}
	}
	// đo kích thước 1 event đã gắn trường để queue chứa đúng 2 event
	sample := big()[0]
	sample.AgentID, sample.Hostname, sample.OS, sample.Timestamp = "A001", "PC-01", runtime.GOOS, time.Now().UTC()
	raw, _ := json.Marshal(sample)
	n := int64(len(raw) + 1)
	q, err := queue.New(t.TempDir(), queue.Options{SegmentBytes: n + 10, MaxBytes: 2*n + n/2})
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	emit := newEmitter(ctx, q, "A001", "PC-01", 1)
	for i := 0; i < 2; i++ {
		if err := emit(big()); err != nil {
			t.Fatal(err)
		}
	}
	e, pos, _ := q.Dequeue()
	if e.AgentID != "A001" || e.Hostname != "PC-01" || e.Timestamp.IsZero() {
		t.Fatalf("emit phải gắn agent_id/hostname/thời gian: %+v", e)
	}

	// queue đầy: emit chờ; gửi bớt (ack) thì emit tiếp tục được
	done := make(chan error, 1)
	go func() { done <- emit(big()) }()
	select {
	case err := <-done:
		t.Fatalf("queue đầy mà emit không chờ (err=%v)", err)
	case <-time.After(300 * time.Millisecond):
	}
	_, pos, _ = q.Dequeue() // event 2 (event 1 đã đọc ở trên)
	q.Ack(pos)
	if err := <-done; err != nil {
		t.Fatalf("sau khi gửi bớt emit phải ghi được: %v", err)
	}

	// đang chờ mà agent dừng -> ErrStopping (collector không lưu offset)
	go func() { done <- emit(big()) }()
	go func() { done <- emit(big()) }()
	time.Sleep(200 * time.Millisecond)
	cancel()
	for i := 0; i < 2; i++ {
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, core.ErrStopping) {
				t.Fatalf("muốn ErrStopping, nhận %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("emit không thoát khi agent dừng")
		}
	}
}
