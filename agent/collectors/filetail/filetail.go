// Package filetail theo dõi (tail) các file log văn bản — chạy được trên mọi OS.
// Dùng cho: Apache access/error log, /var/log/auth.log, Suricata eve.json,...
//
// Độ tin cậy:
//   - Offset chỉ được lưu SAU khi event đã ghi bền vào queue (core.Emit) -> crash không mất dòng.
//   - Giữ handle file đang mở: khi log bị xoay vòng (rename), agent vẫn đọc nốt file cũ qua handle
//     trong vài giây rồi mới chuyển sang file mới ở cùng đường dẫn và đọc file mới TỪ ĐẦU.
//     Trên Windows handle được mở với FILE_SHARE_DELETE nên không cản ứng dụng xoay vòng log.
//   - Nhận diện file bằng fingerprint (SHA-256 của tối đa 1 KB đầu file) lưu cùng offset: agent tắt
//     đúng lúc log xoay vòng thì khi chạy lại vẫn biết đó là file khác, đọc nốt phần còn lại ở
//     "<file>.1" (nếu có) và đọc file mới từ đầu, không đọc lệch.
//   - copytruncate (file bị cắt về 0): phát hiện qua kích thước nhỏ hơn offset -> đọc lại từ đầu.
//   - Đường dẫn có thể là wildcard (vd /var/log/nginx/*.log); file khớp sau khi agent chạy được đọc từ đầu.
package filetail

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"siem-agent/core"
)

const (
	fpMax       = 1024      // số byte đầu file dùng làm fingerprint
	maxLine     = 256 << 10 // dòng dài hơn bị cắt (tránh file nhị phân làm phình bộ nhớ)
	batchSize   = 500
	rotateGrace = 5 * time.Second // thời gian đọc nốt file cũ sau khi bị xoay vòng
)

type fileState struct {
	Offset int64  `json:"offset"`
	FPLen  int    `json:"fp_len,omitempty"`
	FP     string `json:"fp,omitempty"`
}

type tracked struct {
	path    string
	logType string
	f       *os.File   // file hiện tại ở path
	st      fileState  // vị trí đã ghi bền vào queue + fingerprint của f
	saved   *fileState // trạng thái lần chạy trước, chưa đối chiếu với file thật
	fresh   bool       // file ở path là file mới (sau rotate / xuất hiện sau khi agent chạy) -> đọc từ đầu
	old     *os.File   // file vừa bị xoay vòng, đọc nốt trong rotateGrace
	oldOff  int64
	oldTill time.Time
}

type Collector struct {
	patterns  map[string]string // đường dẫn / wildcard -> loại log (vd "apache_access")
	statePath string
	interval  time.Duration
	stopCh    chan struct{}
	files     map[string]*tracked
	saved     map[string]fileState
}

// New: files là map logType -> danh sách đường dẫn (lấy từ section filetail của config).
func New(files map[string][]string, stateDir string) *Collector {
	c := &Collector{
		patterns:  map[string]string{},
		statePath: filepath.Join(stateDir, "filetail.state.json"),
		interval:  time.Second,
		stopCh:    make(chan struct{}),
		files:     map[string]*tracked{},
	}
	for logType, paths := range files {
		for _, p := range paths {
			c.patterns[p] = logType
		}
	}
	return c
}

func (c *Collector) Name() string { return "filetail" }

func (c *Collector) Stop() error {
	close(c.stopCh)
	return nil
}

func (c *Collector) Start(emit core.Emit) error {
	c.saved = loadState(c.statePath)
	for p, logType := range c.patterns {
		log.Printf("[filetail] theo dõi %s (type=%s)", p, logType)
	}
	c.scan(true)
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	defer c.closeAll()
	for {
		changed := false
		for _, t := range c.files {
			ch, err := c.poll(t, emit)
			changed = changed || ch
			if errors.Is(err, core.ErrStopping) {
				c.saveState()
				return nil
			}
			if err != nil {
				log.Printf("[filetail] %s: %v (sẽ thử lại)", t.path, err)
			}
		}
		if changed {
			c.saveState()
		}
		select {
		case <-c.stopCh:
			c.saveState()
			return nil
		case <-ticker.C:
			c.scan(false)
		}
	}
}

// scan tìm các file cần theo dõi. Đường dẫn cố định luôn được theo dõi (kể cả khi chưa tồn tại);
// wildcard chỉ theo dõi file đang khớp.
func (c *Collector) scan(first bool) {
	for pattern, logType := range c.patterns {
		var paths []string
		if strings.ContainsAny(pattern, "*?[") {
			paths, _ = filepath.Glob(pattern)
		} else {
			paths = []string{pattern}
		}
		for _, p := range paths {
			if _, ok := c.files[p]; ok {
				continue
			}
			_, statErr := os.Stat(p)
			t := &tracked{path: p, logType: logType, fresh: !first || statErr != nil}
			if s, ok := c.saved[p]; ok {
				t.saved = &s
				delete(c.saved, p)
			}
			c.files[p] = t
		}
	}
}

// poll đọc dòng mới của một file; trả về true nếu trạng thái cần lưu thay đổi.
func (c *Collector) poll(t *tracked, emit core.Emit) (bool, error) {
	changed := false
	if t.old != nil {
		off, _, err := readLines(t.old, t.oldOff, t.path, t.logType, emit)
		t.oldOff = off
		if err != nil {
			return false, err
		}
		if time.Now().After(t.oldTill) {
			t.old.Close()
			t.old = nil
		}
	}
	if t.f == nil {
		opened, ch, err := c.open(t, emit)
		if !opened || err != nil {
			return ch, err
		}
		changed = true
	}

	cur, serr := os.Stat(t.path)
	fi, ferr := t.f.Stat()
	same := serr == nil && ferr == nil && os.SameFile(cur, fi)
	// copytruncate: cùng file nhưng bị cắt (nhỏ hơn offset) hoặc đã bị cắt rồi ghi lại (đầu file khác)
	if ferr == nil && (fi.Size() < t.st.Offset || (same && !matchesFP(t.f, t.st))) {
		log.Printf("[filetail] %s bị cắt ngắn (copytruncate), đọc lại từ đầu", t.path)
		t.st = fileState{}
		changed = true
	}
	off, n, err := readLines(t.f, t.st.Offset, t.path, t.logType, emit)
	if off != t.st.Offset {
		t.st.Offset = off
		changed = true
	}
	if err != nil {
		return changed, err
	}
	if n > 0 || t.st.FPLen < fpMax {
		changed = updateFP(t.f, &t.st) || changed
	}
	if !same {
		// path đã trỏ sang file khác hoặc bị xóa: đọc nốt file cũ trong rotateGrace, file mới đọc từ đầu
		log.Printf("[filetail] %s đã bị xoay vòng / xóa, chuyển sang file mới", t.path)
		if t.old != nil {
			t.old.Close()
		}
		t.old, t.oldOff, t.oldTill = t.f, t.st.Offset, time.Now().Add(rotateGrace)
		t.f, t.st, t.fresh = nil, fileState{}, true
		changed = true
		if serr == nil { // file mới đã có sẵn -> mở và đọc luôn
			if _, err := c.poll(t, emit); err != nil {
				return true, err
			}
		}
	}
	return changed, nil
}

// open mở file ở path và quyết định đọc từ đâu.
func (c *Collector) open(t *tracked, emit core.Emit) (opened, changed bool, err error) {
	f, err := openShared(t.path)
	if err != nil {
		if !os.IsNotExist(err) {
			return false, false, err
		}
		return false, false, nil // chưa có file -> thử lại vòng sau
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return false, false, err
	}
	switch {
	case t.saved != nil:
		s := *t.saved
		if matchesFP(f, s) && fi.Size() >= s.Offset {
			t.st = fileState{Offset: s.Offset, FPLen: s.FPLen, FP: s.FP}
		} else {
			// File đã đổi trong lúc agent tắt: đọc nốt phần chưa đọc ở file vừa bị xoay vòng.
			if s.FPLen > 0 {
				if err := drainRotated(t, s, emit); err != nil {
					f.Close()
					return false, false, err
				}
			}
			log.Printf("[filetail] %s là file mới so với lần chạy trước, đọc từ đầu", t.path)
			t.st = fileState{}
		}
		t.saved = nil
	case t.fresh:
		t.st = fileState{}
	default:
		// File có sẵn trước khi agent chạy lần đầu: bắt đầu từ cuối, tránh dồn toàn bộ log cũ lên server.
		t.st = fileState{Offset: fi.Size()}
	}
	t.f, t.fresh = f, false
	updateFP(f, &t.st)
	return true, true, nil
}

// drainRotated đọc phần còn lại (từ offset đã lưu) của file cũ nay mang tên "<path>.1".
func drainRotated(t *tracked, s fileState, emit core.Emit) error {
	f, err := openShared(t.path + ".1")
	if err != nil {
		return nil
	}
	defer f.Close()
	if !matchesFP(f, s) {
		return nil
	}
	_, n, err := readLines(f, s.Offset, t.path, t.logType, emit)
	if n > 0 {
		log.Printf("[filetail] đọc nốt %d dòng của %s.1 (xoay vòng trong lúc agent tắt)", n, t.path)
	}
	return err
}

// readLines đọc các dòng trọn vẹn từ off và ghi theo lô qua emit.
// Trả về offset đã ghi bền (lỗi giữa chừng thì chỉ tính các lô đã ghi xong).
func readLines(f *os.File, off int64, path, logType string, emit core.Emit) (int64, int, error) {
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return off, 0, err
	}
	r := bufio.NewReaderSize(f, 64<<10)
	committed, pos, sent := off, off, 0
	var batch []core.Event
	flush := func() error {
		if len(batch) > 0 {
			if err := emit(batch); err != nil {
				return err
			}
			sent += len(batch)
			batch = nil
		}
		committed = pos
		return nil
	}
	for {
		line, n, ok := readLine(r)
		if !ok {
			break // dòng cuối chưa ghi xong (không có '\n') -> để lần sau đọc trọn
		}
		pos += n
		if line = strings.TrimRight(line, "\r\n"); line != "" {
			batch = append(batch, core.Event{
				Timestamp: time.Now().UTC(),
				Source:    "file",
				EventType: logType,
				Data:      map[string]interface{}{"message": line, "path": path},
			})
		}
		if len(batch) >= batchSize {
			if err := flush(); err != nil {
				return committed, sent, err
			}
		}
	}
	if err := flush(); err != nil {
		return committed, sent, err
	}
	return committed, sent, nil
}

// readLine đọc một dòng kết thúc bằng '\n'. Dòng quá maxLine bị cắt phần thừa (vẫn tính đủ byte đã đọc).
func readLine(r *bufio.Reader) (string, int64, bool) {
	var buf []byte
	var n int64
	for {
		chunk, err := r.ReadSlice('\n')
		n += int64(len(chunk))
		if room := maxLine - len(buf); room > 0 {
			if len(chunk) > room {
				buf = append(buf, chunk[:room]...)
			} else {
				buf = append(buf, chunk...)
			}
		}
		switch {
		case err == nil:
			return string(buf), n, true
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		default:
			return "", 0, false
		}
	}
}

func fingerprint(f *os.File, n int) (string, int) {
	buf := make([]byte, n)
	got, _ := f.ReadAt(buf, 0)
	sum := sha256.Sum256(buf[:got])
	return hex.EncodeToString(sum[:]), got
}

// updateFP mở rộng fingerprint khi file còn nhỏ hơn fpMax lúc lấy lần trước.
func updateFP(f *os.File, st *fileState) bool {
	if st.FPLen >= fpMax {
		return false
	}
	fp, n := fingerprint(f, fpMax)
	if n <= st.FPLen {
		return false
	}
	st.FP, st.FPLen = fp, n
	return true
}

// matchesFP: file có cùng fingerprint với trạng thái đã lưu không. Trạng thái kiểu cũ (không có
// fingerprint) coi như khớp, khi đó chỉ còn dựa vào kích thước file.
func matchesFP(f *os.File, s fileState) bool {
	if s.FPLen == 0 {
		return true
	}
	fp, n := fingerprint(f, s.FPLen)
	return n == s.FPLen && fp == s.FP
}

func loadState(path string) map[string]fileState {
	out := map[string]fileState{}
	raw, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	if json.Unmarshal(raw, &out) == nil {
		return out
	}
	// định dạng của bản cũ: {"path": offset}
	var legacy map[string]int64
	if json.Unmarshal(raw, &legacy) == nil {
		for p, off := range legacy {
			out[p] = fileState{Offset: off}
		}
	}
	return out
}

func (c *Collector) saveState() {
	state := map[string]fileState{}
	for p, s := range c.saved { // file của lần trước hiện không còn khớp pattern nào: giữ lại
		state[p] = s
	}
	for p, t := range c.files {
		switch {
		case t.f != nil:
			state[p] = t.st
		case t.saved != nil:
			state[p] = *t.saved
		}
	}
	raw, _ := json.Marshal(state)
	tmp := c.statePath + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o640); err == nil {
		_ = os.Rename(tmp, c.statePath)
	}
}

func (c *Collector) closeAll() {
	for _, t := range c.files {
		if t.f != nil {
			t.f.Close()
		}
		if t.old != nil {
			t.old.Close()
		}
	}
}
