package winevent

import (
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"siem-agent/core"
)

// fakeLog giả lập một channel có các bản ghi first..last; bản ghi 1 là event 1102.
type fakeLog struct{ first, last uint64 }

func (f *fakeLog) run(args ...string) ([]byte, error) {
	switch args[0] {
	case "gli":
		return []byte(fmt.Sprintf("logFileName: x\r\noldestRecordNumber: %d\r\nnumberOfLogRecords: %d\r\n", f.first, f.last-f.first+1)), nil
	case "qe":
		var after uint64
		limit := 1 << 30
		for _, a := range args {
			if strings.HasPrefix(a, "/q:") {
				fmt.Sscanf(a, "/q:*[System[(EventRecordID>%d)]]", &after)
			}
			if strings.HasPrefix(a, "/c:") {
				limit, _ = strconv.Atoi(a[3:])
			}
		}
		var b strings.Builder
		for id, n := f.first, 0; id <= f.last && n < limit; id++ {
			if id <= after {
				continue
			}
			eid := 4624
			if id == 1 {
				eid = 1102
			}
			fmt.Fprintf(&b, `<Event><System><EventID>%d</EventID><EventRecordID>%d</EventRecordID><Channel>Security</Channel></System></Event>`, eid, id)
			n++
		}
		return []byte(b.String()), nil
	}
	return nil, errors.New("lệnh lạ")
}

type sink struct {
	events []core.Event
	fail   int
}

func (s *sink) emit(evts []core.Event) error {
	if s.fail > 0 {
		s.fail--
		return errors.New("đĩa lỗi giả lập")
	}
	s.events = append(s.events, evts...)
	return nil
}

func newTest(t *testing.T, fl *fakeLog, bookmark uint64) *Collector {
	old := wevtutil
	wevtutil = fl.run
	t.Cleanup(func() { wevtutil = old })
	c := New([]string{"Security"}, time.Second, t.TempDir())
	c.bookmarks["Security"] = bookmark
	return c
}

func TestPollDrainsBacklogAndCommitsOnlyAfterEmit(t *testing.T) {
	c := newTest(t, &fakeLog{first: 1, last: 1234}, 0)
	s := &sink{fail: 1}
	if err := c.poll("Security", s.emit); err == nil || c.bookmarks["Security"] != 0 {
		t.Fatalf("emit lỗi thì không được tiến bookmark (bookmark=%d)", c.bookmarks["Security"])
	}
	if err := c.poll("Security", s.emit); err != nil {
		t.Fatal(err)
	}
	if len(s.events) != 1234 || c.bookmarks["Security"] != 1234 {
		t.Fatalf("một vòng phải đọc hết tồn đọng: %d event, bookmark %d", len(s.events), c.bookmarks["Security"])
	}
	// bookmark được lưu xuống đĩa
	c2 := New([]string{"Security"}, time.Second, filepath.Dir(c.statePath))
	if c2.bookmarks["Security"] != 1234 {
		t.Fatalf("bookmark chưa được lưu: %d", c2.bookmarks["Security"])
	}
}

func TestClearedLogIsDetected(t *testing.T) {
	fl := &fakeLog{first: 1, last: 3} // log vừa bị xóa: đánh số lại từ 1, bản ghi 1 là 1102
	c := newTest(t, fl, 5000)
	s := &sink{}
	for i := 0; i < resetCheckIdle; i++ {
		c.poll("Security", s.emit)
	}
	c.poll("Security", s.emit)
	if len(s.events) != 3 || s.events[0].Data["event_id"] != 1102 {
		t.Fatalf("phải đọc lại log sau khi bị xóa, nhận %d event", len(s.events))
	}
}

func TestOverwrittenRecordsAreReported(t *testing.T) {
	c := newTest(t, &fakeLog{first: 50, last: 60}, 10)
	s := &sink{}
	c.poll("Security", s.emit)
	if len(s.events) != 12 || s.events[0].EventType != "agent_health" || s.events[0].Data["lost"] != uint64(39) {
		t.Fatalf("phải báo 39 bản ghi bị mất rồi mới tới 11 event: %+v", s.events[0])
	}
}

func TestUserDataFields(t *testing.T) {
	raw := `<Event><System><EventID>1102</EventID><EventRecordID>7</EventRecordID><Channel>Security</Channel></System>` +
		`<UserData><LogFileCleared xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'>` +
		`<SubjectUserSid>S-1-5-21-1</SubjectUserSid><SubjectUserName>attacker</SubjectUserName></LogFileCleared></UserData></Event>`
	evs, err := ParseEvents([]byte(raw))
	if err != nil || len(evs) != 1 {
		t.Fatal(err)
	}
	if evs[0].Fields["SubjectUserName"] != "attacker" {
		t.Fatalf("UserData phải được đọc: %+v", evs[0].Fields)
	}
}

const sample = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4625</EventID><Level>0</Level><TimeCreated SystemTime='2026-09-24T15:53:08.6187319Z'/><EventRecordID>101</EventRecordID><Channel>Security</Channel><Computer>PC-01</Computer></System><EventData><Data Name='TargetUserName'>admin</Data><Data Name='IpAddress'>10.0.0.66</Data><Data Name='LogonType'>3</Data></EventData></Event>
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='x'/><EventID>4624</EventID><EventRecordID>102</EventRecordID><Channel>Security</Channel></System><EventData><Data>unnamed</Data></EventData></Event>`

func TestParseEvents(t *testing.T) {
	evs, err := ParseEvents([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 2 {
		t.Fatalf("want 2 events, got %d", len(evs))
	}
	e := evs[0]
	if e.EventID != 4625 || e.RecordID != 101 || e.Fields["IpAddress"] != "10.0.0.66" || e.Computer != "PC-01" {
		t.Fatalf("parse sai: %+v", e)
	}
	if evs[1].Fields["param1"] != "unnamed" {
		t.Fatalf("Data không tên phải thành param1: %+v", evs[1].Fields)
	}
}
