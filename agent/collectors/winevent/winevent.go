// Package winevent thu thập Windows Event Log bằng công cụ có sẵn `wevtutil`
// (không cần cgo / thư viện ngoài). Mỗi channel được poll định kỳ, truy vấn các
// bản ghi có EventRecordID lớn hơn bookmark đã lưu.
//
// Độ tin cậy:
//   - Mỗi vòng đọc liên tục từng lô maxPerPoll bản ghi cho tới khi hết tồn đọng (tối đa
//     maxChunks lô), nên log nhiều không bị tụt lại sau tốc độ ghi của Windows.
//   - Bookmark chỉ lưu SAU khi lô event đã ghi bền vào queue.
//   - Log bị xóa (EventRecordID bắt đầu lại) -> đặt lại bookmark để không bỏ lỡ event 1102.
//   - Bản ghi bị ghi đè trước khi kịp đọc (khoảng trống EventRecordID) -> báo event agent_health.
//
// Channel gợi ý: Security (4624/4625/4688/4720/4732/1102...), System,
// Microsoft-Windows-Sysmon/Operational, Microsoft-Windows-PowerShell/Operational.
// Đọc channel Security cần chạy agent với quyền Administrator/SYSTEM.
package winevent

import (
	"bufio"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
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

const (
	maxPerPoll     = 500
	maxChunks      = 20 // tối đa 10.000 bản ghi / channel / vòng
	resetCheckIdle = 6  // cứ 6 vòng không có gì mới thì kiểm tra log có bị xóa không
)

// wevtutil chạy công cụ wevtutil; test thay bằng hàm giả.
var wevtutil = func(args ...string) ([]byte, error) {
	return exec.Command("wevtutil", args...).Output()
}

type Collector struct {
	channels  []string
	interval  time.Duration
	statePath string
	bookmarks map[string]uint64
	idle      map[string]int
	stopCh    chan struct{}
}

func New(channels []string, interval time.Duration, stateDir string) *Collector {
	c := &Collector{
		channels:  channels,
		interval:  interval,
		statePath: filepath.Join(stateDir, "winevent.state.json"),
		bookmarks: map[string]uint64{},
		idle:      map[string]int{},
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

func (c *Collector) Start(emit core.Emit) error {
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
		}
		for _, ch := range c.channels {
			if _, ok := c.bookmarks[ch]; !ok {
				continue
			}
			if err := c.poll(ch, emit); errors.Is(err, core.ErrStopping) {
				return nil
			} else if err != nil {
				log.Printf("[winevent] %q: %v (sẽ thử lại)", ch, err)
			}
		}
	}
}

// poll đọc hết bản ghi mới của một channel theo từng lô.
func (c *Collector) poll(channel string, emit core.Emit) error {
	for chunk := 0; chunk < maxChunks; chunk++ {
		bm := c.bookmarks[channel]
		query := fmt.Sprintf("*[System[(EventRecordID>%d)]]", bm)
		raw, err := wevtutil("qe", channel, "/q:"+query, "/f:xml", "/c:"+strconv.Itoa(maxPerPoll))
		if err != nil {
			return fmt.Errorf("lỗi truy vấn: %w", err)
		}
		events, perr := ParseEvents(raw)
		if perr != nil {
			log.Printf("[winevent] lỗi parse XML %q: %v", channel, perr)
		}
		if len(events) == 0 {
			if chunk == 0 {
				c.checkReset(channel)
			}
			return nil
		}
		c.idle[channel] = 0

		batch := make([]core.Event, 0, len(events)+1)
		if first := events[0].RecordID; bm > 0 && first > bm+1 {
			lost := first - bm - 1
			log.Printf("[winevent] %q: %d bản ghi đã bị ghi đè trước khi kịp đọc", channel, lost)
			batch = append(batch, core.Event{Timestamp: time.Now().UTC(), Source: "agent", EventType: "agent_health",
				Data: map[string]interface{}{"kind": "eventlog_gap", "channel": channel, "lost": lost,
					"message": fmt.Sprintf("Windows Event Log %s: mất %d bản ghi (bị ghi đè trước khi agent đọc)", channel, lost)}})
		}
		next := bm
		for _, e := range events {
			batch = append(batch, e.ToCoreEvent())
			if e.RecordID > next {
				next = e.RecordID
			}
		}
		if err := emit(batch); err != nil {
			return err // bookmark giữ nguyên -> vòng sau đọc lại
		}
		c.bookmarks[channel] = next
		c.save()
		if len(events) < maxPerPoll {
			return nil
		}
	}
	return nil
}

// checkReset: log bị xóa thì EventRecordID có thể bắt đầu lại từ 1, khi đó truy vấn
// "> bookmark" không bao giờ trả kết quả. Phát hiện bằng số bản ghi mới nhất < bookmark.
func (c *Collector) checkReset(channel string) {
	c.idle[channel]++
	if c.idle[channel] < resetCheckIdle {
		return
	}
	c.idle[channel] = 0
	oldest, count, err := logInfo(channel)
	if err != nil || count == 0 {
		return
	}
	if newest := oldest + count - 1; newest < c.bookmarks[channel] {
		log.Printf("[winevent] %q: log đã bị xóa (record mới nhất %d < bookmark %d), đọc lại từ đầu",
			channel, newest, c.bookmarks[channel])
		c.bookmarks[channel] = oldest - 1
		c.save()
	}
}

// logInfo đọc oldestRecordNumber và numberOfLogRecords qua `wevtutil gli`.
func logInfo(channel string) (oldest, count uint64, err error) {
	raw, err := wevtutil("gli", channel)
	if err != nil {
		return 0, 0, err
	}
	sc := bufio.NewScanner(bytes.NewReader(decodeUTF16IfNeeded(raw)))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		n, perr := strconv.ParseUint(strings.TrimSpace(v), 10, 64)
		if perr != nil {
			continue
		}
		switch strings.TrimSpace(k) {
		case "oldestRecordNumber":
			oldest = n
		case "numberOfLogRecords":
			count = n
		}
	}
	return oldest, count, nil
}

func latestRecordID(channel string) (uint64, error) {
	raw, err := wevtutil("qe", channel, "/rd:true", "/c:1", "/f:xml")
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

type xmlField struct {
	XMLName xml.Name
	Name    string `xml:"Name,attr"`
	Value   string `xml:",chardata"`
}

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
		Data []xmlField `xml:"Data"`
	} `xml:"EventData"`
	// UserData: một phần tử con tùy loại event, vd event 1102 (xóa audit log) là
	// <LogFileCleared><SubjectUserName>...</SubjectUserName>...</LogFileCleared>
	UserData struct {
		Inner []struct {
			Fields []xmlField `xml:",any"`
		} `xml:",any"`
	} `xml:"UserData"`
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
		for _, inner := range xe.UserData.Inner {
			for _, f := range inner.Fields {
				if _, dup := ev.Fields[f.XMLName.Local]; !dup {
					ev.Fields[f.XMLName.Local] = strings.TrimSpace(f.Value)
				}
			}
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
