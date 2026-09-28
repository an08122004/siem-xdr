//go:build linux

package process

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"siem-agent/core"
)

type collected struct {
	mu  sync.Mutex
	evs []core.Event
}

func (c *collected) emit(evts []core.Event) error {
	c.mu.Lock()
	c.evs = append(c.evs, evts...)
	c.mu.Unlock()
	return nil
}

// startNetlink chạy collector chỉ bằng netlink (chu kỳ quét 1 giờ: poll không thể bắt kịp).
// Cần root và network namespace gốc; trong container dùng --privileged --network host --pid host.
func startNetlink(t *testing.T, out *collected) *Collector {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("cần root để dùng proc connector")
	}
	c := New(time.Hour, "netlink")
	errCh := make(chan error, 1)
	go func() { errCh <- c.Start(out.emit) }()
	time.Sleep(300 * time.Millisecond)
	select {
	case err := <-errCh:
		t.Skipf("không dùng được netlink ở môi trường này: %v", err)
	default:
	}
	t.Cleanup(func() { c.Stop() })
	return c
}

// Kiểm tra giao thức với kernel: đăng ký được và nhận được event execve.
// Chạy được cả khi không ở PID namespace gốc (vd distro WSL).
func TestNetlinkReceivesExecEvents(t *testing.T) {
	requireInitPidNS = false
	defer func() { requireInitPidNS = true }()
	startNetlink(t, &collected{})
	before := execSeen.Load()
	if err := exec.Command("/bin/sh", "-c", "sleep 0.3").Run(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for execSeen.Load() == before {
		if time.Now().After(deadline) {
			t.Fatal("đăng ký proc connector nhưng không nhận được event execve nào")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Kiểm tra đầy đủ: bắt được tiến trình chỉ sống 0,3 giây, có command line.
func TestNetlinkCatchesShortLivedProcess(t *testing.T) {
	if !inInitPidNS() {
		t.Skip("không ở PID namespace gốc: collector sẽ tự lùi về quét /proc")
	}
	out := &collected{}
	startNetlink(t, out)
	marker := fmt.Sprintf("siem-test-%d", time.Now().UnixNano())
	if err := exec.Command("/bin/sh", "-c", "sleep 0.3", marker).Run(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		out.mu.Lock()
		for _, e := range out.evs {
			if strings.Contains(fmt.Sprint(e.Data["command_line"]), marker) {
				out.mu.Unlock()
				return
			}
		}
		out.mu.Unlock()
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("không bắt được tiến trình sống 0,3 giây")
}

func TestNetlinkRefusedOutsideInitPidNS(t *testing.T) {
	if inInitPidNS() {
		t.Skip("đang ở PID namespace gốc")
	}
	if err := New(time.Hour, "netlink").runNetlink(nil); err == nil || !strings.Contains(err.Error(), "PID namespace") {
		t.Fatalf("ngoài PID namespace gốc phải từ chối netlink, nhận %v", err)
	}
}
