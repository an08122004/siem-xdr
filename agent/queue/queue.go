// Package queue cài đặt một hàng đợi bền vững (persistent) trên đĩa.
//
// Thiết kế: log chỉ ghi nối (append-only) chia thành nhiều SEGMENT + con trỏ ack
// (giống Kafka ở quy mô rất nhỏ, chạy local). Mỗi dòng trong 00000000000000000001.seg,
// 00000000000000000002.seg, ... là 1 event (JSON); queue.ack chứa "<segment> <byte offset>"
// đã gửi thành công.
//
// Ghi: nối vào segment cuối, đầy SegmentBytes thì mở segment mới; mỗi lô fsync một lần.
// Đọc: từ vị trí ack trở đi, hết segment thì sang segment kế.
// Ack: ghi con trỏ (write-tmp-then-rename) rồi XÓA các segment đã gửi xong, nên queue không phình mãi.
// Tổng dung lượng vượt MaxBytes thì Enqueue trả ErrFull: bên ghi phải chờ (đẩy ngược áp lực về
// collector; collector chưa lưu offset nên không mất dữ liệu nguồn), không vứt event.
//
// Crash giữa lúc gửi thành công và ghi ack -> gửi lại lô đó (at-least-once, chấp nhận trùng).
// Crash giữa lúc ghi một lô -> dòng dở dang cuối segment bị cắt khi mở lại.
package queue

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"siem-agent/core"
)

const (
	ackFileName = "queue.ack"
	segSuffix   = ".seg"

	// định dạng cũ (một file duy nhất), chỉ đọc để chuyển đổi
	legacyLogName    = "queue.log"
	legacyOffsetName = "queue.offset"

	DefaultSegmentBytes = 16 << 20
	DefaultMaxBytes     = 512 << 20
)

// ErrFull: queue đã đạt MaxBytes, bên ghi cần chờ sender gửi bớt.
var ErrFull = errors.New("queue đầy")

// Position là vị trí trong queue: segment và byte offset ngay SAU event.
type Position struct {
	Seg uint64
	Off int64
}

type Options struct {
	SegmentBytes int64 // kích thước để chuyển sang segment mới
	MaxBytes     int64 // tổng dung lượng tối đa trên đĩa (0 = không giới hạn)
}

// Queue là hàng đợi bền vững trên đĩa, an toàn khi dùng đồng thời.
type Queue struct {
	mu   sync.Mutex
	dir  string
	opts Options

	sizes map[uint64]int64 // kích thước từng segment còn trên đĩa
	total int64

	wSeg  uint64
	wFile *os.File

	rSeg    uint64
	rOff    int64
	rFile   *os.File
	rReader *bufio.Reader

	ack Position
}

func segPath(dir string, id uint64) string {
	return filepath.Join(dir, fmt.Sprintf("%020d%s", id, segSuffix))
}

// New mở (hoặc tạo mới) queue tại thư mục dir.
func New(dir string, opts Options) (*Queue, error) {
	if opts.SegmentBytes <= 0 {
		opts.SegmentBytes = DefaultSegmentBytes
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("không tạo được thư mục queue '%s': %w", dir, err)
	}
	q := &Queue{dir: dir, opts: opts, sizes: map[uint64]int64{}}
	if err := q.migrateLegacy(); err != nil {
		return nil, err
	}
	ids, err := q.listSegments()
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		ids = []uint64{1}
		if err := os.WriteFile(segPath(dir, 1), nil, 0o640); err != nil {
			return nil, fmt.Errorf("không tạo được segment đầu tiên: %w", err)
		}
	}
	for _, id := range ids {
		info, err := os.Stat(segPath(dir, id))
		if err != nil {
			return nil, err
		}
		q.sizes[id] = info.Size()
	}
	last := ids[len(ids)-1]
	if err := q.repairTail(last); err != nil {
		return nil, err
	}
	for _, size := range q.sizes {
		q.total += size
	}

	q.ack = q.readAck(ids[0])
	// Con trỏ ack nằm ngoài dải segment hiện có (file ack cũ/hỏng) -> kẹp lại, ưu tiên gửi lại hơn bỏ sót.
	if _, ok := q.sizes[q.ack.Seg]; !ok || q.ack.Seg < ids[0] {
		q.ack = Position{Seg: ids[0]}
	}
	if q.ack.Off > q.sizes[q.ack.Seg] {
		q.ack.Off = q.sizes[q.ack.Seg]
	}
	q.dropBefore(q.ack.Seg) // crash giữa lúc ack và xóa segment cũ

	q.wSeg = last
	if q.wFile, err = os.OpenFile(segPath(dir, last), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640); err != nil {
		return nil, fmt.Errorf("không mở được segment để ghi: %w", err)
	}
	if err := q.openReader(q.ack.Seg, q.ack.Off); err != nil {
		return nil, err
	}
	return q, nil
}

func (q *Queue) listSegments() ([]uint64, error) {
	entries, err := os.ReadDir(q.dir)
	if err != nil {
		return nil, fmt.Errorf("không đọc được thư mục queue: %w", err)
	}
	var ids []uint64
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, segSuffix) {
			continue
		}
		if id, err := strconv.ParseUint(strings.TrimSuffix(name, segSuffix), 10, 64); err == nil && id > 0 {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids, nil
}

// migrateLegacy chuyển queue.log + queue.offset của bản cũ thành segment 1, giữ nguyên event chưa gửi.
func (q *Queue) migrateLegacy() error {
	legacy := filepath.Join(q.dir, legacyLogName)
	if _, err := os.Stat(legacy); err != nil {
		return nil
	}
	if ids, _ := q.listSegments(); len(ids) > 0 {
		return nil // đã chuyển rồi
	}
	var off int64
	if raw, err := os.ReadFile(filepath.Join(q.dir, legacyOffsetName)); err == nil {
		fmt.Sscanf(strings.TrimSpace(string(raw)), "%d", &off)
	}
	if err := os.Rename(legacy, segPath(q.dir, 1)); err != nil {
		return fmt.Errorf("không chuyển được queue.log cũ: %w", err)
	}
	if err := q.writeAck(Position{Seg: 1, Off: off}); err != nil {
		return err
	}
	os.Remove(filepath.Join(q.dir, legacyOffsetName))
	return nil
}

// repairTail cắt phần dòng ghi dở ở cuối segment (agent chết giữa lúc ghi).
func (q *Queue) repairTail(id uint64) error {
	size := q.sizes[id]
	if size == 0 {
		return nil
	}
	f, err := os.OpenFile(segPath(q.dir, id), os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("không mở được segment %d: %w", id, err)
	}
	defer f.Close()
	buf := make([]byte, 64<<10)
	end := size
	for end > 0 {
		start := end - int64(len(buf))
		if start < 0 {
			start = 0
		}
		chunk := buf[:end-start]
		if _, err := f.ReadAt(chunk, start); err != nil && err != io.EOF {
			return err
		}
		if i := bytes.LastIndexByte(chunk, '\n'); i >= 0 {
			end = start + int64(i) + 1
			break
		}
		end = start
	}
	if end == size {
		return nil
	}
	if err := f.Truncate(end); err != nil {
		return fmt.Errorf("không cắt được dòng dở ở segment %d: %w", id, err)
	}
	q.sizes[id] = end
	return f.Sync()
}

func (q *Queue) readAck(first uint64) Position {
	raw, err := os.ReadFile(filepath.Join(q.dir, ackFileName))
	if err != nil {
		return Position{Seg: first}
	}
	var p Position
	if _, err := fmt.Sscanf(strings.TrimSpace(string(raw)), "%d %d", &p.Seg, &p.Off); err != nil || p.Off < 0 {
		return Position{Seg: first} // file ack hỏng -> gửi lại từ đầu còn hơn bỏ sót
	}
	return p
}

func (q *Queue) writeAck(p Position) error {
	path := filepath.Join(q.dir, ackFileName)
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return fmt.Errorf("không ghi được ack tạm: %w", err)
	}
	_, err = fmt.Fprintf(f, "%d %d", p.Seg, p.Off)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("không ghi được ack tạm: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("không rename được file ack: %w", err)
	}
	return nil
}

// dropBefore xóa các segment có id < seg (đã gửi xong toàn bộ).
func (q *Queue) dropBefore(seg uint64) {
	for id, size := range q.sizes {
		if id >= seg {
			continue
		}
		if err := os.Remove(segPath(q.dir, id)); err != nil && !os.IsNotExist(err) {
			continue // thử lại ở lần ack sau
		}
		q.total -= size
		delete(q.sizes, id)
	}
}

func (q *Queue) openReader(seg uint64, off int64) error {
	if q.rFile != nil {
		q.rFile.Close()
	}
	f, err := os.Open(segPath(q.dir, seg))
	if err != nil {
		return fmt.Errorf("không mở được segment %d để đọc: %w", seg, err)
	}
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		f.Close()
		return fmt.Errorf("không seek được tới vị trí đã lưu: %w", err)
	}
	q.rFile, q.rSeg, q.rOff = f, seg, off
	q.rReader = bufio.NewReaderSize(f, 64<<10)
	return nil
}

// Enqueue ghi một lô event vào cuối queue và fsync MỘT lần cho cả lô. Khi hàm trả về nil,
// các event đã nằm bền trên đĩa -> collector mới được phép lưu offset/bookmark của mình.
func (q *Queue) Enqueue(evts ...core.Event) error {
	if len(evts) == 0 {
		return nil
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf) // Encode tự thêm '\n' sau mỗi event
	enc.SetEscapeHTML(false)
	for i := range evts {
		if err := enc.Encode(&evts[i]); err != nil {
			return fmt.Errorf("không serialize được event: %w", err)
		}
	}

	q.mu.Lock()
	defer q.mu.Unlock()
	n := int64(buf.Len())
	if q.opts.MaxBytes > 0 && q.total > 0 && q.total+n > q.opts.MaxBytes {
		return ErrFull
	}
	if q.sizes[q.wSeg] > 0 && q.sizes[q.wSeg]+n > q.opts.SegmentBytes {
		if err := q.rotate(); err != nil {
			return err
		}
	}
	if _, err := q.wFile.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("không ghi được event vào queue: %w", err)
	}
	if err := q.wFile.Sync(); err != nil {
		return fmt.Errorf("không fsync được queue: %w", err)
	}
	q.sizes[q.wSeg] += n
	q.total += n
	return nil
}

func (q *Queue) rotate() error {
	if err := q.wFile.Close(); err != nil {
		return fmt.Errorf("không đóng được segment %d: %w", q.wSeg, err)
	}
	next := q.wSeg + 1
	f, err := os.OpenFile(segPath(q.dir, next), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return fmt.Errorf("không tạo được segment %d: %w", next, err)
	}
	q.wFile, q.wSeg = f, next
	q.sizes[next] = 0
	return nil
}

// Dequeue đọc event tiếp theo chưa gửi. Trả về (nil, _, nil) nếu hiện không có gì mới.
// Position trả về dùng để Ack sau khi gửi thành công.
func (q *Queue) Dequeue() (*core.Event, Position, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for {
		line, err := q.rReader.ReadBytes('\n')
		if err == nil {
			q.rOff += int64(len(line))
			pos := Position{Seg: q.rSeg, Off: q.rOff}
			var evt core.Event
			if jerr := json.Unmarshal(line, &evt); jerr != nil {
				// Dòng hỏng: vẫn phải tiến lên để không kẹt queue mãi
				return nil, pos, fmt.Errorf("event hỏng trong queue, đã bỏ qua: %w", jerr)
			}
			return &evt, pos, nil
		}
		// Chưa đủ một dòng: bufio đã nuốt phần đầu dòng, seek lại để lần sau đọc trọn.
		if _, serr := q.rFile.Seek(q.rOff, io.SeekStart); serr != nil {
			return nil, Position{}, fmt.Errorf("không seek lại được queue: %w", serr)
		}
		q.rReader.Reset(q.rFile)
		if q.rSeg >= q.wSeg || q.rOff < q.sizes[q.rSeg] {
			return nil, Position{}, nil
		}
		// Đọc hết một segment đã đóng -> sang segment kế
		if err := q.openReader(q.rSeg+1, 0); err != nil {
			return nil, Position{}, err
		}
	}
}

// Ack xác nhận server đã nhận tới vị trí p, rồi xóa các segment đã gửi xong.
func (q *Queue) Ack(p Position) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if p.Seg == 0 {
		return nil
	}
	if err := q.writeAck(p); err != nil {
		return err
	}
	q.ack = p
	q.dropBefore(p.Seg)
	return nil
}

// Pending trả về số byte chưa được ack.
func (q *Queue) Pending() int64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	if p := q.total - q.ack.Off; p > 0 {
		return p
	}
	return 0
}

// DiskBytes trả về tổng dung lượng các segment đang nằm trên đĩa.
func (q *Queue) DiskBytes() int64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.total
}

// Close đóng các file handle. Nên gọi khi agent tắt.
func (q *Queue) Close() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	var firstErr error
	if err := q.wFile.Close(); err != nil {
		firstErr = err
	}
	if q.rFile != nil {
		if err := q.rFile.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
