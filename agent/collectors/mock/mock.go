// Package mock cung cấp một collector GIẢ LẬP, sinh sự kiện định kỳ.
// Mục đích: kiểm thử toàn bộ luồng core (queue -> sender -> server) mà KHÔNG
// cần chờ collector thật của Windows/Linux (sẽ làm ở bước 2, 3 theo lộ trình).
// Đây chính là collector implement interface core.Collector đã định nghĩa,
// chứng minh thiết kế "core không biết gì về OS" hoạt động đúng.
package mock

import (
	"errors"
	"fmt"
	"log"
	"time"

	"siem-agent/core"
)

// Collector sinh 1 event giả mỗi Interval, mô phỏng như một sự kiện đăng nhập.
type Collector struct {
	AgentID  string
	Interval time.Duration
	stopCh   chan struct{}
}

// New tạo mock collector mới.
func New(agentID string, interval time.Duration) *Collector {
	return &Collector{
		AgentID:  agentID,
		Interval: interval,
		stopCh:   make(chan struct{}),
	}
}

func (c *Collector) Name() string { return "mock_collector" }

// Start sinh event định kỳ, ghi qua emit cho tới khi Stop() được gọi.
func (c *Collector) Start(emit core.Emit) error {
	ticker := time.NewTicker(c.Interval)
	defer ticker.Stop()

	counter := 0
	for {
		select {
		case <-c.stopCh:
			log.Println("[mock] collector đã dừng")
			return nil
		case <-ticker.C:
			counter++
			evt := core.Event{
				Timestamp: time.Now(),
				AgentID:   c.AgentID,
				Source:    "mock",
				EventType: "fake_logon",
				Data: map[string]interface{}{
					"seq":     counter,
					"user":    fmt.Sprintf("user%d", counter%5),
					"src_ip":  "10.0.0.1",
					"success": counter%7 != 0, // thỉnh thoảng giả lập đăng nhập fail
					"message": "Đây là sự kiện giả lập dùng để kiểm thử pipeline core",
				},
			}
			if err := emit([]core.Event{evt}); errors.Is(err, core.ErrStopping) {
				return nil
			} else if err != nil {
				log.Printf("[mock] không ghi được event: %v", err)
			}
		}
	}
}

// Stop dừng việc sinh sự kiện.
func (c *Collector) Stop() error {
	close(c.stopCh)
	return nil
}
