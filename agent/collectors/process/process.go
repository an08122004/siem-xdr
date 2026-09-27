// Package process phát hiện tiến trình MỚI trên Linux bằng cách quét /proc định kỳ
// (không cần auditd/eBPF — đơn giản, đủ cho lab). Mỗi PID mới sinh 1 event
// "process_creation" gồm: pid, ppid, tên, command line, uid, exe và tên tiến trình cha.
//
// Trên Windows, telemetry tiến trình lấy qua Sysmon (Event ID 1) hoặc Security 4688
// bằng collector winevent -> collector này chỉ chạy trên Linux.
package process

import (
	"fmt"
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
	stopCh   chan struct{}
	seen     map[int]bool
}

func New(interval time.Duration) *Collector {
	return &Collector{interval: interval, stopCh: make(chan struct{}), seen: map[int]bool{}}
}

func (c *Collector) Name() string { return "process" }

func (c *Collector) Stop() error {
	close(c.stopCh)
	return nil
}

func (c *Collector) Start(out chan<- core.Event) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("process collector chỉ hỗ trợ Linux (Windows dùng Sysmon/4688 qua winevent)")
	}
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
			current := map[int]bool{}
			for _, pid := range listPIDs() {
				current[pid] = true
				if c.seen[pid] {
					continue
				}
				if info, ok := readProc(pid); ok {
					out <- core.Event{
						Timestamp: time.Now().UTC(),
						Source:    "process",
						EventType: "process_creation",
						Data:      info,
					}
				}
			}
			c.seen = current
		}
	}
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
