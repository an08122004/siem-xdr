// Package process phát hiện tiến trình MỚI trên Linux. Mỗi tiến trình sinh 1 event
// "process_creation" gồm: pid, ppid, tên, command line, uid, exe và tên tiến trình cha.
//
// Hai cách thu:
//   - netlink (proc connector): kernel báo ngay mỗi lần execve, bắt được cả tiến trình chỉ sống
//     vài mili giây (vd `curl ... | sh`). Cần root (CAP_NET_ADMIN) và chạy ở network namespace gốc
//     của máy (không dùng được trong container có network riêng).
//   - poll: quét /proc định kỳ, dùng khi netlink không khả dụng; tiến trình sống ngắn hơn chu kỳ quét bị lọt.
//
// mode "auto" (mặc định) thử netlink trước rồi lùi về poll.
//
// Trên Windows, telemetry tiến trình lấy qua Sysmon (Event ID 1) hoặc Security 4688
// bằng collector winevent -> collector này chỉ chạy trên Linux.
package process

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"siem-agent/core"
)

type Collector struct {
	interval time.Duration
	mode     string // auto | netlink | poll
	stopCh   chan struct{}
	seen     map[int]bool
}

func New(interval time.Duration, mode string) *Collector {
	if mode == "" {
		mode = "auto"
	}
	return &Collector{interval: interval, mode: mode, stopCh: make(chan struct{}), seen: map[int]bool{}}
}

func (c *Collector) Name() string { return "process" }

func (c *Collector) Stop() error {
	close(c.stopCh)
	return nil
}

func (c *Collector) Start(emit core.Emit) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("process collector chỉ hỗ trợ Linux (Windows dùng Sysmon/4688 qua winevent)")
	}
	if c.mode != "poll" {
		err := c.runNetlink(emit)
		if err == nil || c.mode == "netlink" {
			return err
		}
		log.Printf("[process] không dùng được netlink (%v), chuyển sang quét /proc mỗi %s — tiến trình sống ngắn hơn có thể bị lọt", err, c.interval)
	}
	return c.runPoll(emit)
}

func (c *Collector) runPoll(emit core.Emit) error {
	// Ghi nhận các tiến trình đang chạy sẵn làm baseline, không báo là "mới".
	for _, pid := range listPIDs() {
		c.seen[pid] = true
	}
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		select {
		case <-c.stopCh:
			return nil
		case <-ticker.C:
		}
		current := map[int]bool{}
		var batch []core.Event
		for _, pid := range listPIDs() {
			current[pid] = true
			if c.seen[pid] {
				continue
			}
			if info, ok := readProc(pid); ok {
				batch = append(batch, newEvent(info))
			}
		}
		if err := emit(batch); errors.Is(err, core.ErrStopping) {
			return nil
		} else if err != nil {
			log.Printf("[process] không ghi được event: %v (quét lại vòng sau)", err)
			continue // giữ seen cũ -> vòng sau báo lại các tiến trình này
		}
		c.seen = current
	}
}

func newEvent(info map[string]interface{}) core.Event {
	return core.Event{Timestamp: time.Now().UTC(), Source: "process", EventType: "process_creation", Data: info}
}

func listPIDs() []int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var pids []int
	for _, e := range entries {
		if pid, err := strconv.Atoi(e.Name()); err == nil {
			pids = append(pids, pid)
		}
	}
	return pids
}

func readProc(pid int) (map[string]interface{}, bool) {
	base := filepath.Join("/proc", strconv.Itoa(pid))
	status, err := os.ReadFile(filepath.Join(base, "status"))
	if err != nil {
		return nil, false // tiến trình đã kết thúc
	}
	fields := parseStatus(string(status))
	cmdline, _ := os.ReadFile(filepath.Join(base, "cmdline"))
	exe, _ := os.Readlink(filepath.Join(base, "exe"))
	ppid, _ := strconv.Atoi(fields["PPid"])

	parentName := ""
	if ps, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(ppid), "status")); err == nil {
		parentName = parseStatus(string(ps))["Name"]
	}
	uid := strings.Fields(fields["Uid"])
	info := map[string]interface{}{
		"pid":          pid,
		"ppid":         ppid,
		"name":         fields["Name"],
		"command_line": strings.TrimSpace(strings.ReplaceAll(string(cmdline), "\x00", " ")),
		"executable":   exe,
		"parent_name":  parentName,
	}
	if len(uid) > 0 {
		info["uid"] = uid[0]
	}
	return info, true
}

func parseStatus(s string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		if i := strings.Index(line, ":"); i > 0 {
			m[line[:i]] = strings.TrimSpace(line[i+1:])
		}
	}
	return m
}
