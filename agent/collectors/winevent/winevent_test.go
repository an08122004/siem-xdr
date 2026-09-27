package winevent

import "testing"

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
