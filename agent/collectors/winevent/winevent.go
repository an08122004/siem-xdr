// Package winevent thu thập Windows Event Log bằng công cụ có sẵn `wevtutil`
// (không cần cgo / thư viện ngoài). Mỗi channel được poll định kỳ, truy vấn các
// bản ghi có EventRecordID lớn hơn bookmark đã lưu.
//
// Channel gợi ý: Security (4624/4625/4688/4720/4732/1102...), System,
// Microsoft-Windows-Sysmon/Operational, Microsoft-Windows-PowerShell/Operational.
// Đọc channel Security cần chạy agent với quyền Administrator/SYSTEM.
package winevent

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"siem-agent/core"
)

const maxPerPoll = 500

type Collector struct {
	channels  []string
	interval  time.Duration
	statePath string
	bookmarks map[string]uint64
	stopCh    chan struct{}
}

func New(channels []string, interval time.Duration, stateDir string) *Collector {
	c := &Collector{
		channels:  channels,
		interval:  interval,
		statePath: filepath.Join(stateDir, "winevent.state.json"),
		bookmarks: map[string]uint64{},
		stopCh:    make(chan struct{}),
	}
	if raw, err := os.ReadFile(c.statePath); err == nil {
		_ = json.Unmarshal(raw, &c.bookmarks)
	}
	return c
}

func (c *Collector) Name() string { return "windows_eventlog" }

func (c *Collector) Stop() error {
	close(c.stopCh)
	return nil
}

func (c *Collector) Start(out chan<- core.Event) error {
	for _, ch := range c.channels {
		if _, ok := c.bookmarks[ch]; !ok {
			// Lần đầu: bắt đầu từ bản ghi mới nhất, không đẩy toàn bộ lịch sử.
			last, err := latestRecordID(ch)
			if err != nil {
				log.Printf("[winevent] bỏ qua channel %q: %v", ch, err)
				continue
			}
			c.bookmarks[ch] = last
		}
		log.Printf("[winevent] theo dõi channel %q từ record %d", ch, c.bookmarks[ch])
	}
	c.save()

	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		select {
		case <-c.stopCh:
			return nil
		case <-ticker.C:
			for _, ch := range c.channels {
				if _, ok := c.bookmarks[ch]; !ok {
					continue
				}
				c.poll(ch, out)
			}
			c.save()
		}
	}
}

func (c *Collector) poll(channel string, out chan<- core.Event) {
	query := fmt.Sprintf("*[System[(EventRecordID>%d)]]", c.bookmarks[channel])
	raw, err := exec.Command("wevtutil", "qe", channel, "/q:"+query, "/f:xml", "/c:"+strconv.Itoa(maxPerPoll)).Output()
	if err != nil {
		log.Printf("[winevent] lỗi truy vấn %q: %v", channel, err)
		return
	}
	events, err := ParseEvents(raw)
	if err != nil {
		log.Printf("[winevent] lỗi parse XML %q: %v", channel, err)
	}
	for _, e := range events {
		if e.RecordID > c.bookmarks[channel] {
			c.bookmarks[channel] = e.RecordID
		}
		out <- e.ToCoreEvent()
	}
}

func latestRecordID(channel string) (uint64, error) {
	raw, err := exec.Command("wevtutil", "qe", channel, "/rd:true", "/c:1", "/f:xml").Output()
	if err != nil {
		return 0, err
	}
	events, err := ParseEvents(raw)
	if err != nil {
		return 0, err
	}
	if len(events) == 0 {
		return 0, nil
	}
	return events[0].RecordID, nil
}

func (c *Collector) save() {
	raw, _ := json.Marshal(c.bookmarks)
	tmp := c.statePath + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o640); err == nil {
		_ = os.Rename(tmp, c.statePath)
	}
}

// ---------------------------------------------------------------------------
// Parse XML của wevtutil
// ---------------------------------------------------------------------------

type xmlEvent struct {
	System struct {
		Provider struct {
			Name string `xml:"Name,attr"`
		} `xml:"Provider"`
		EventID     string `xml:"EventID"`
		Level       string `xml:"Level"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
		EventRecordID uint64 `xml:"EventRecordID"`
		Channel       string `xml:"Channel"`
		Computer      string `xml:"Computer"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
}

// WinEvent là một bản ghi Event Log đã parse.
type WinEvent struct {
	RecordID uint64
	EventID  int
	Channel  string
	Provider string
	Computer string
	Level    string
	Time     time.Time
	Fields   map[string]string
}

func (w WinEvent) ToCoreEvent() core.Event {
	data := map[string]interface{}{
		"event_id":  w.EventID,
		"channel":   w.Channel,
		"provider":  w.Provider,
		"computer":  w.Computer,
		"record_id": w.RecordID,
		"level":     w.Level,
	}
	fields := map[string]interface{}{}
	for k, v := range w.Fields {
		fields[k] = v
	}
	data["fields"] = fields
	ts := w.Time
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	return core.Event{Timestamp: ts, Source: "eventlog", EventType: "windows_event", Data: data}
}

// ParseEvents parse chuỗi các phần tử <Event> liên tiếp (không có root) do wevtutil in ra.
func ParseEvents(raw []byte) ([]WinEvent, error) {
	raw = decodeUTF16IfNeeded(raw)
	dec := xml.NewDecoder(bytes.NewReader(raw))
	var result []WinEvent
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return result, nil
		}
		if err != nil {
			return result, err
		}
		start, ok := tok.(xml.StartElement)
		if !ok || start.Name.Local != "Event" {
			continue
		}
		var xe xmlEvent
		if err := dec.DecodeElement(&xe, &start); err != nil {
			return result, err
		}
		id, _ := strconv.Atoi(strings.TrimSpace(xe.System.EventID))
		ts, _ := time.Parse(time.RFC3339Nano, xe.System.TimeCreated.SystemTime)
		ev := WinEvent{
			RecordID: xe.System.EventRecordID,
			EventID:  id,
			Channel:  xe.System.Channel,
			Provider: xe.System.Provider.Name,
			Computer: xe.System.Computer,
			Level:    xe.System.Level,
			Time:     ts.UTC(),
			Fields:   map[string]string{},
		}
		for i, d := range xe.EventData.Data {
			name := d.Name
			if name == "" {
				name = fmt.Sprintf("param%d", i+1)
			}
			ev.Fields[name] = strings.TrimSpace(d.Value)
		}
		result = append(result, ev)
	}
}

// wevtutil có thể xuất UTF-16LE (có BOM) khi chuyển hướng output.
func decodeUTF16IfNeeded(b []byte) []byte {
	if len(b) >= 2 && b[0] == 0xFF && b[1] == 0xFE {
		u16 := make([]uint16, 0, len(b)/2)
		for i := 2; i+1 < len(b); i += 2 {
			u16 = append(u16, uint16(b[i])|uint16(b[i+1])<<8)
		}
		return []byte(string(utf16.Decode(u16)))
	}
	return b
}
