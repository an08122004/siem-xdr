// Package filetail theo dõi (tail) các file log văn bản — chạy được trên mọi OS.
// Dùng cho: Apache access/error log, /var/log/auth.log, Suricata eve.json,...
//
// Vị trí đọc (offset) của từng file được lưu ra đĩa để khi agent khởi động lại
// không đọc trùng / bỏ sót. Phát hiện log rotation đơn giản: nếu file nhỏ đi so
// với offset đã lưu -> file đã bị xoay vòng, đọc lại từ đầu.
package filetail

import (
	"bufio"
	"encoding/json"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"siem-agent/core"
)

type Collector struct {
	files     map[string]string // path -> log type (vd: "apache_access")
	statePath string
	interval  time.Duration
	stopCh    chan struct{}

	mu      sync.Mutex
	offsets map[string]int64
}

// New: files là map logType -> danh sách path (lấy từ section filetail của config).
func New(files map[string][]string, stateDir string) *Collector {
	c := &Collector{
		files:     map[string]string{},
		statePath: filepath.Join(stateDir, "filetail.state.json"),
		interval:  time.Second,
		stopCh:    make(chan struct{}),
		offsets:   map[string]int64{},
	}
	for logType, paths := range files {
		for _, p := range paths {
			c.files[p] = logType
		}
	}
	if raw, err := os.ReadFile(c.statePath); err == nil {
		_ = json.Unmarshal(raw, &c.offsets)
	}
	return c
}

func (c *Collector) Name() string { return "filetail" }

func (c *Collector) Start(out chan<- core.Event) error {
	for path, logType := range c.files {
		log.Printf("[filetail] theo dõi %s (type=%s)", path, logType)
	}
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		select {
		case <-c.stopCh:
			c.saveState()
			return nil
		case <-ticker.C:
			changed := false
			for path, logType := range c.files {
				if c.readNew(path, logType, out) {
					changed = true
				}
			}
			if changed {
				c.saveState()
			}
		}
	}
}

func (c *Collector) Stop() error {
	close(c.stopCh)
	return nil
}

// readNew đọc các dòng mới của 1 file; trả về true nếu offset thay đổi.
func (c *Collector) readNew(path, logType string, out chan<- core.Event) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false // file chưa tồn tại -> thử lại vòng sau
	}

	c.mu.Lock()
	offset, known := c.offsets[path]
	c.mu.Unlock()

	if !known {
		// Lần đầu gặp file: bắt đầu từ cuối file, tránh dồn toàn bộ log cũ lên server.
		c.setOffset(path, info.Size())
		return true
	}
	if info.Size() < offset {
		log.Printf("[filetail] %s bị rotate/truncate, đọc lại từ đầu", path)
		offset = 0
	}
	if info.Size() == offset {
		return false
	}

	f, err := os.Open(path)
	if err != nil {
		log.Printf("[filetail] không mở được %s: %v", path, err)
		return false
	}
	defer f.Close()
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return false
	}

	reader := bufio.NewReaderSize(f, 64*1024)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break // dòng cuối chưa ghi xong (không có '\n') -> để lần sau đọc trọn
		}
		offset += int64(len(line))
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}
		out <- core.Event{
			Timestamp: time.Now().UTC(),
			Source:    "file",
			EventType: logType,
			Data:      map[string]interface{}{"message": line, "path": path},
		}
	}
	c.setOffset(path, offset)
	return true
}

func (c *Collector) setOffset(path string, off int64) {
	c.mu.Lock()
	c.offsets[path] = off
	c.mu.Unlock()
}

func (c *Collector) saveState() {
	c.mu.Lock()
	raw, _ := json.Marshal(c.offsets)
	c.mu.Unlock()
	tmp := c.statePath + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o640); err == nil {
		_ = os.Rename(tmp, c.statePath)
	}
}
