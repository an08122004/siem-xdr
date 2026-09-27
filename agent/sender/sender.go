package sender

import (
	"context"
	"log"
	"time"

	"siem-agent/core"
	"siem-agent/queue"
)

// Sender lấy event từ Queue theo lô (batch) và đẩy lên manager.
// Nguyên tắc: CHỈ ack sau khi server xác nhận nhận thành công -> at-least-once,
// không mất event khi mất mạng/server lỗi.
type Sender struct {
	client        *Client
	q             *queue.Queue
	batchSize     int
	retryInterval time.Duration
}

func New(client *Client, q *queue.Queue, batchSize int, retryInterval time.Duration) *Sender {
	return &Sender{client: client, q: q, batchSize: batchSize, retryInterval: retryInterval}
}

func (s *Sender) Run(ctx context.Context) {
	log.Printf("[sender] bắt đầu gửi dữ liệu (batch=%d)", s.batchSize)
	for {
		if ctx.Err() != nil {
			return
		}

		batch, lastOffset := s.collectBatch()
		if len(batch) == 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(500 * time.Millisecond):
			}
			continue
		}

		if err := s.sendWithRetry(ctx, batch); err != nil {
			log.Printf("[sender] dừng gửi do context bị hủy: %v", err)
			return
		}
		if err := s.q.Ack(lastOffset); err != nil {
			log.Printf("[sender] LỖI: gửi thành công nhưng không ghi được ack offset: %v", err)
		}
	}
}

// collectBatch đọc tối đa batchSize event đang có sẵn trong queue.
func (s *Sender) collectBatch() ([]core.Event, int64) {
	var batch []core.Event
	var last int64
	for len(batch) < s.batchSize {
		evt, offset, err := s.q.Dequeue()
		if err != nil {
			log.Printf("[sender] cảnh báo: %v", err)
			last = offset
			continue
		}
		if evt == nil {
			break
		}
		batch = append(batch, *evt)
		last = offset
	}
	return batch, last
}

func (s *Sender) sendWithRetry(ctx context.Context, batch []core.Event) error {
	for attempt := 1; ; attempt++ {
		err := s.client.SendEvents(ctx, batch)
		if err == nil {
			return nil
		}
		log.Printf("[sender] gửi %d event thất bại (lần %d): %v - thử lại sau %s", len(batch), attempt, err, s.retryInterval)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(s.retryInterval):
		}
	}
}
