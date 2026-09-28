// Package fim giám sát toàn vẹn file (File Integrity Monitoring) bằng cách quét định kỳ.
//
// Mỗi vòng quét các đường dẫn cấu hình (thư mục thì đệ quy), so với baseline lưu trên đĩa và sinh
// event "fim" cho file được THÊM / SỬA / XÓA kèm hash SHA-256 trước và sau.
//   - Lần chạy đầu chỉ lập baseline, không báo (tránh hàng nghìn event "file mới").
//   - File không đổi kích thước, thời gian sửa và quyền thì dùng lại hash cũ, nên vòng quét nhẹ.
//   - Baseline chỉ được cập nhật SAU khi event đã ghi bền vào queue.
//
// Hạn chế: quét định kỳ (không realtime như inotify/whodata của Wazuh), không biết AI sửa file;
// dùng kèm log tiến trình / Sysmon để truy ra tác nhân.
package fim

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"siem-agent/core"
)

const (
	maxFiles  = 200000 // chặn cấu hình nhầm kiểu quét cả "/"
	batchSize = 500
)

type entry struct {
	Size    int64  `json:"size"`
	ModTime int64  `json:"mtime"` // unix nano
	Mode    string `json:"mode"`
	SHA256  string `json:"sha256,omitempty"` // rỗng: file quá lớn, chỉ so kích thước / thời gian
	Link    string `json:"link,omitempty"`   // symlink: đích trỏ tới
}

type Collector struct {
	paths     []string
	exclude   []string
	interval  time.Duration
	maxBytes  int64
	statePath string
	stopCh    chan struct{}
	base      map[string]entry
	hasBase   bool
}

func New(paths, exclude []string, interval time.Duration, maxFileMB int, stateDir string) *Collector {
	c := &Collector{
		paths: paths, exclude: exclude, interval: interval, maxBytes: int64(maxFileMB) << 20,
		statePath: filepath.Join(stateDir, "fim.state.json"),
		stopCh:    make(chan struct{}),
		base:      map[string]entry{},
	}
	if raw, err := os.ReadFile(c.statePath); err == nil && json.Unmarshal(raw, &c.base) == nil {
		c.hasBase = true
	}
	return c
}

func (c *Collector) Name() string { return "fim" }

func (c *Collector) Stop() error {
	close(c.stopCh)
	return nil
}

func (c *Collector) Start(emit core.Emit) error {
	log.Printf("[fim] giám sát %v, quét mỗi %s", c.paths, c.interval)
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		if err := c.Scan(emit); errors.Is(err, core.ErrStopping) {
			return nil
		} else if err != nil {
			log.Printf("[fim] %v (quét lại vòng sau)", err)
		}
		select {
		case <-c.stopCh:
			return nil
		case <-ticker.C:
		}
	}
}

// Scan quét một vòng; lần đầu chỉ lập baseline.
func (c *Collector) Scan(emit core.Emit) error {
	cur, err := c.snapshot()
	if err != nil {
		return err
	}
	if !c.hasBase {
		c.base, c.hasBase = cur, true
		log.Printf("[fim] đã lập baseline %d file", len(cur))
		return c.save()
	}
	events := diff(c.base, cur)
	for i := 0; i < len(events); i += batchSize {
		end := i + batchSize
		if end > len(events) {
			end = len(events)
		}
		if err := emit(events[i:end]); err != nil {
			return err // baseline giữ nguyên -> vòng sau báo lại
		}
	}
	if len(events) > 0 {
		log.Printf("[fim] %d thay đổi", len(events))
	}
	c.base = cur
	return c.save()
}

func (c *Collector) excluded(path string) bool {
	name := filepath.Base(path)
	for _, p := range c.exclude {
		if ok, _ := filepath.Match(p, name); ok {
			return true
		}
		if ok, _ := filepath.Match(p, path); ok {
			return true
		}
	}
	return false
}

func (c *Collector) snapshot() (map[string]entry, error) {
	cur := map[string]entry{}
	for _, root := range c.paths {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			select {
			case <-c.stopCh:
				return core.ErrStopping
			default:
			}
			if err != nil {
				return nil // không đọc được (quyền, file vừa bị xóa): bỏ qua, không dừng cả vòng
			}
			if c.excluded(path) {
				if d.IsDir() && path != root {
					return filepath.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				return nil
			}
			if len(cur) >= maxFiles {
				return fmt.Errorf("quá %d file, hãy thu hẹp fim.paths", maxFiles)
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			e := entry{Size: info.Size(), ModTime: info.ModTime().UnixNano(), Mode: info.Mode().String()}
			if info.Mode()&fs.ModeSymlink != 0 {
				e.Link, _ = os.Readlink(path)
				cur[path] = e
				return nil
			}
			if !info.Mode().IsRegular() {
				return nil
			}
			if old, ok := c.base[path]; ok && old.Size == e.Size && old.ModTime == e.ModTime && old.Mode == e.Mode {
				e.SHA256 = old.SHA256 // không đổi gì: dùng lại hash, không đọc lại file
			} else if e.Size <= c.maxBytes {
				e.SHA256 = hashFile(path)
			}
			cur[path] = e
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return cur, nil
}

func hashFile(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

func diff(old, cur map[string]entry) []core.Event {
	var paths []string
	for p := range cur {
		paths = append(paths, p)
	}
	for p := range old {
		if _, ok := cur[p]; !ok {
			paths = append(paths, p)
		}
	}
	sort.Strings(paths)
	var out []core.Event
	for _, p := range paths {
		n, inNew := cur[p]
		o, inOld := old[p]
		var action string
		var changes []string
		switch {
		case !inOld:
			action = "added"
		case !inNew:
			action = "deleted"
		default:
			if o.SHA256 != n.SHA256 || (n.SHA256 == "" && (o.Size != n.Size || o.ModTime != n.ModTime)) {
				changes = append(changes, "content")
			}
			if o.Mode != n.Mode {
				changes = append(changes, "permissions")
			}
			if o.Link != n.Link {
				changes = append(changes, "link_target")
			}
			if len(changes) == 0 {
				continue
			}
			action = "modified"
		}
		data := map[string]interface{}{"action": action, "path": p}
		if inNew {
			data["size"], data["mode"], data["sha256"] = n.Size, n.Mode, n.SHA256
			data["mtime"] = time.Unix(0, n.ModTime).UTC().Format(time.RFC3339)
			if n.Link != "" {
				data["link_target"] = n.Link
			}
		}
		if inOld {
			data["old_size"], data["old_mode"], data["old_sha256"] = o.Size, o.Mode, o.SHA256
		}
		if len(changes) > 0 {
			data["changes"] = changes
		}
		data["message"] = fmt.Sprintf("FIM: %s %s", action, p)
		if len(changes) > 0 {
			data["message"] = fmt.Sprintf("FIM: %s %s (%s)", action, p, strings.Join(changes, ", "))
		}
		out = append(out, core.Event{Timestamp: time.Now().UTC(), Source: "fim", EventType: "fim", Data: data})
	}
	return out
}

func (c *Collector) save() error {
	raw, err := json.Marshal(c.base)
	if err != nil {
		return err
	}
	tmp := c.statePath + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.statePath)
}
