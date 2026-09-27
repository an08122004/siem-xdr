// Package core định nghĩa các kiểu dữ liệu và interface DÙNG CHUNG cho toàn agent.
// Package này không import gì phụ thuộc hệ điều hành cụ thể — đây là "hợp đồng"
// mà mọi collector (Windows/Linux) và response executor phải tuân theo.
package core

import "time"

// Event là định dạng CHUẨN HÓA cho mọi sự kiện agent thu thập được.
// Server (analyzer) sẽ dựa vào Source + EventType để chọn parser phù hợp.
type Event struct {
	Timestamp time.Time              `json:"timestamp"`
	AgentID   string                 `json:"agent_id"`
	Hostname  string                 `json:"hostname,omitempty"`
	OS        string                 `json:"os,omitempty"`
	Source    string                 `json:"source"`     // vd: "file", "eventlog", "process", "mock"
	EventType string                 `json:"event_type"` // vd: "apache_access", "auth", "suricata", "windows_event", "process_creation"
	Data      map[string]interface{} `json:"data"`
}

// Collector là interface mà MỌI collector phải implement.
type Collector interface {
	Name() string
	// Start chạy thu thập (blocking), đẩy Event vào out cho tới khi Stop() được gọi.
	Start(out chan<- Event) error
	Stop() error
}

// Action là lệnh phản ứng (XDR response) do server gửi xuống agent.
type Action struct {
	ID        string                 `json:"id"`
	AgentID   string                 `json:"agent_id"`
	Type      string                 `json:"type"` // block_ip, unblock_ip, kill_process, isolate_host, unisolate_host
	Params    map[string]interface{} `json:"params"`
	AlertID   string                 `json:"alert_id,omitempty"`
	CreatedAt string                 `json:"created_at,omitempty"`
}

// ActionResult là kết quả thực thi Action, agent gửi ngược lên server.
type ActionResult struct {
	Status string `json:"status"` // success | failed
	Output string `json:"output"`
}
