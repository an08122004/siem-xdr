// Package queue cài đặt một hàng đợi bền vững (persistent) trên đĩa.
//
// Thiết kế: theo mô hình "append-only log + offset con trỏ" (giống ý tưởng
// của Kafka ở quy mô rất nhỏ, chạy local trên 1 file):
//
//	queue.log     -> mỗi dòng là 1 event (JSON), chỉ được APPEND, không bao giờ sửa giữa file
//	queue.offset  -> con trỏ byte offset của event cuối cùng đã gửi thành công (đã "ack")
//
// Nhờ vậy: nếu agent bị kill/crash giữa chừng, khi khởi động lại, agent đọc
// lại queue.offset để biết đã gửi tới đâu, rồi tiếp tục đọc queue.log từ đó
// -> KHÔNG mất event, và không gửi trùng (trừ trường hợp crash đúng lúc giữa
// gửi thành công và ghi offset - đây là đánh đổi "at-least-once" chấp nhận được
// cho một agent giám sát).
package queue

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"siem-agent/core"
)

const (
	logFileName    = "queue.log"
	offsetFileName = "queue.offset"
	offsetTmpFile  = "queue.offset.tmp"
)

// Queue là hàng đợi bền vững trên đĩa, an toàn khi dùng đồng thời (concurrent-safe).
type Queue struct {
	mu         sync.Mutex
	dir        string
	logPath    string
	offsetPath string

	writeFile *os.File // file handle mở ở chế độ append, dùng để Enqueue
	readFile  *os.File // file handle riêng dùng để Dequeue tuần tự
	reader    *bufio.Reader

	readOffset int64 // vị trí byte đã ĐỌC (đã gửi cho sender, chưa chắc đã ack)
	ackOffset  int64 // vị trí byte đã ACK (server xác nhận nhận thành công), persist ra đĩa
}

// New mở (hoặc tạo mới) queue tại thư mục dir.
func New(dir string) (*Queue, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("không tạo được thư mục queue '%s': %w", dir, err)
	}

	q := &Queue{
		dir:        dir,
		logPath:    filepath.Join(dir, logFileName),
		offsetPath: filepath.Join(dir, offsetFileName),
	}

	if err := q.restoreOffset(); err != nil {
		return nil, err
	}

	wf, err := os.OpenFile(q.logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, fmt.Errorf("không mở được queue log để ghi: %w", err)
	}
	q.writeFile = wf

	rf, err := os.Open(q.logPath)
	if err != nil {
		return nil, fmt.Errorf("không mở được queue log để đọc: %w", err)
	}
	q.readFile = rf

	// Con trỏ đọc bắt đầu từ vị trí đã ack (những gì chưa ack coi như chưa gửi,
	// sẽ được gửi lại - an toàn hơn là mất dữ liệu).
	q.readOffset = q.ackOffset
	if _, err := q.readFile.Seek(q.readOffset, 0); err != nil {
		return nil, fmt.Errorf("không seek được tới offset đã lưu: %w", err)
	}
	q.reader = bufio.NewReader(q.readFile)

	return q, nil
}

// restoreOffset đọc offset đã lưu từ lần chạy trước, nếu chưa có thì offset = 0.
func (q *Queue) restoreOffset() error {
	raw, err := os.ReadFile(q.offsetPath)
	if os.IsNotExist(err) {
		q.ackOffset = 0
		return nil
	}
	if err != nil {
		return fmt.Errorf("không đọc được offset file: %w", err)
	}
	var offset int64
	if _, err := fmt.Sscanf(string(raw), "%d", &offset); err != nil {
		// File offset hỏng (ví dụ crash giữa lúc ghi) -> an toàn nhất là về 0,
		// chấp nhận gửi lại từ đầu còn hơn bỏ sót dữ liệu.
		q.ackOffset = 0
		return nil
	}
	q.ackOffset = offset
	return nil
}

// Enqueue ghi một event mới vào cuối queue log, fsync ngay để đảm bảo bền vững
// (chấp nhận đánh đổi hiệu năng lấy độ an toàn - phù hợp với agent giám sát
// nơi mất event log an ninh là không chấp nhận được).
func (q *Queue) Enqueue(evt core.Event) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	data, err := json.Marshal(evt)
	if err != nil {
		return fmt.Errorf("không serialize được event: %w", err)
	}

	line := append(data, '\n')
	if _, err := q.writeFile.Write(line); err != nil {
		return fmt.Errorf("không ghi được event vào queue: %w", err)
	}
	if err := q.writeFile.Sync(); err != nil {
		return fmt.Errorf("không fsync được queue log: %w", err)
	}
	return nil
}

// Dequeue đọc event tiếp theo chưa được gửi. Trả về (nil, nil) nếu queue rỗng
// (không phải lỗi - đây là trạng thái bình thường khi không có gì mới).
func (q *Queue) Dequeue() (*core.Event, int64, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	line, err := q.reader.ReadBytes('\n')
	if err != nil {
		if len(line) == 0 {
			return nil, 0, nil // chưa có dữ liệu mới, không phải lỗi
		}
		// Dòng cuối đang được ghi dở -> bufio đã "nuốt" phần đầu dòng, phải seek
		// lại về readOffset để lần sau đọc trọn vẹn cả dòng, không làm lệch offset.
		if _, serr := q.readFile.Seek(q.readOffset, 0); serr != nil {
			return nil, 0, fmt.Errorf("không seek lại được queue: %w", serr)
		}
		q.reader.Reset(q.readFile)
		return nil, 0, nil
	}

	var evt core.Event
	if err := json.Unmarshal(line, &evt); err != nil {
		// Dòng hỏng -> log lỗi ở tầng gọi, nhưng vẫn phải tiến offset để không kẹt queue mãi
		q.readOffset += int64(len(line))
		return nil, q.readOffset, fmt.Errorf("event hỏng trong queue, đã bỏ qua: %w", err)
	}

	q.readOffset += int64(len(line))
	return &evt, q.readOffset, nil
}

// Ack xác nhận đã gửi thành công tới server, tới vị trí offset cho trước.
// Ghi offset ra đĩa theo kiểu "write-tmp-then-rename" để đảm bảo atomic,
// tránh trường hợp crash giữa lúc ghi làm hỏng file offset.
func (q *Queue) Ack(offset int64) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	tmpPath := filepath.Join(q.dir, offsetTmpFile)
	if err := os.WriteFile(tmpPath, []byte(fmt.Sprintf("%d", offset)), 0o640); err != nil {
		return fmt.Errorf("không ghi được offset tạm: %w", err)
	}
	if err := os.Rename(tmpPath, q.offsetPath); err != nil {
		return fmt.Errorf("không rename được offset file: %w", err)
	}

	q.ackOffset = offset
	return nil
}

// Pending trả về số byte chưa được ack - dùng để giám sát/log độ trễ của queue.
func (q *Queue) Pending() int64 {
	q.mu.Lock()
	defer q.mu.Unlock()

	info, err := os.Stat(q.logPath)
	if err != nil {
		return 0
	}
	pending := info.Size() - q.ackOffset
	if pending < 0 {
		return 0
	}
	return pending
}

// Close đóng các file handle. Nên gọi khi agent tắt (graceful shutdown).
func (q *Queue) Close() error {
	q.mu.Lock()
	defer q.mu.Unlock()

	var firstErr error
	if err := q.writeFile.Close(); err != nil {
		firstErr = err
	}
	if err := q.readFile.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}
