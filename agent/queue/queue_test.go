package queue

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"siem-agent/core"
)

func ev(i int) core.Event {
	return core.Event{Source: "test", EventType: "t", Data: map[string]interface{}{"i": i, "pad": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}}
}

// drain đọc hết những gì đang có, trả về chỉ số event và vị trí cuối.
func drain(t *testing.T, q *Queue) ([]int, Position) {
	t.Helper()
	var got []int
	var last Position
	for {
		e, pos, err := q.Dequeue()
		if err != nil {
			t.Fatal(err)
		}
		if e == nil {
			return got, last
		}
		got = append(got, int(e.Data["i"].(float64)))
		last = pos
	}
}

func segCount(t *testing.T, dir string) int {
	t.Helper()
	m, _ := filepath.Glob(filepath.Join(dir, "*"+segSuffix))
	return len(m)
}

func TestSegmentsAreDeletedAfterAck(t *testing.T) {
	dir := t.TempDir()
	q, err := New(dir, Options{SegmentBytes: 1000})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		if err := q.Enqueue(ev(i)); err != nil {
			t.Fatal(err)
		}
	}
	if n := segCount(t, dir); n < 5 {
		t.Fatalf("muốn nhiều segment, có %d", n)
	}
	got, last := drain(t, q)
	if len(got) != 100 || got[0] != 0 || got[99] != 99 {
		t.Fatalf("đọc sai thứ tự/thiếu: %d event", len(got))
	}
	if err := q.Ack(last); err != nil {
		t.Fatal(err)
	}
	if n := segCount(t, dir); n != 1 {
		t.Fatalf("sau ack chỉ còn segment đang ghi, còn %d", n)
	}
	if q.Pending() != 0 || q.DiskBytes() > 1000+200 {
		t.Fatalf("pending=%d disk=%d", q.Pending(), q.DiskBytes())
	}
	q.Close()
}

func TestResumeFromAckAfterRestart(t *testing.T) {
	dir := t.TempDir()
	q, _ := New(dir, Options{SegmentBytes: 500})
	for i := 0; i < 30; i++ {
		q.Enqueue(ev(i))
	}
	// gửi được 10 event đầu rồi agent chết (không Close)
	var pos Position
	for i := 0; i < 10; i++ {
		_, pos, _ = q.Dequeue()
	}
	q.Ack(pos)
	q.Dequeue() // đọc thêm nhưng chưa ack -> phải được gửi lại
	q.wFile.Close()
	q.rFile.Close()

	q2, err := New(dir, Options{SegmentBytes: 500})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := drain(t, q2)
	if len(got) != 20 || got[0] != 10 || got[19] != 29 {
		t.Fatalf("muốn event 10..29, nhận %v", got)
	}
	q2.Close()
}

func TestFullQueueRejectsInsteadOfGrowing(t *testing.T) {
	dir := t.TempDir()
	q, _ := New(dir, Options{SegmentBytes: 400, MaxBytes: 1200})
	var err error
	n := 0
	for ; n < 1000; n++ {
		if err = q.Enqueue(ev(n)); err != nil {
			break
		}
	}
	if !errors.Is(err, ErrFull) || q.DiskBytes() > 1200 {
		t.Fatalf("muốn ErrFull trước khi vượt MaxBytes, err=%v disk=%d", err, q.DiskBytes())
	}
	// gửi bớt -> ghi tiếp được
	got, last := drain(t, q)
	q.Ack(last)
	if len(got) != n {
		t.Fatalf("mất event: ghi %d, đọc %d", n, len(got))
	}
	if err := q.Enqueue(ev(n)); err != nil {
		t.Fatalf("sau khi gửi bớt phải ghi được: %v", err)
	}
	q.Close()
}

func TestTornWriteIsTruncated(t *testing.T) {
	dir := t.TempDir()
	q, _ := New(dir, Options{})
	q.Enqueue(ev(1), ev(2))
	q.Close()
	// agent chết giữa lúc ghi: dòng cuối dở dang
	f, _ := os.OpenFile(segPath(dir, 1), os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString(`{"source":"test","data":{"i":3`)
	f.Close()

	q2, err := New(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	q2.Enqueue(ev(4))
	got, _ := drain(t, q2)
	if fmt.Sprint(got) != "[1 2 4]" {
		t.Fatalf("dòng dở phải bị cắt, event sau vẫn đọc được; nhận %v", got)
	}
	q2.Close()
}

func TestMigrateLegacySingleFileQueue(t *testing.T) {
	dir := t.TempDir()
	line1 := `{"timestamp":"0001-01-01T00:00:00Z","agent_id":"","source":"old","event_type":"t","data":{"i":1}}` + "\n"
	line2 := `{"timestamp":"0001-01-01T00:00:00Z","agent_id":"","source":"old","event_type":"t","data":{"i":2}}` + "\n"
	os.WriteFile(filepath.Join(dir, legacyLogName), []byte(line1+line2), 0o640)
	os.WriteFile(filepath.Join(dir, legacyOffsetName), []byte(fmt.Sprint(len(line1))), 0o640)

	q, err := New(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := drain(t, q)
	if fmt.Sprint(got) != "[2]" {
		t.Fatalf("phải giữ đúng phần chưa gửi của queue cũ, nhận %v", got)
	}
	if _, err := os.Stat(filepath.Join(dir, legacyLogName)); !os.IsNotExist(err) {
		t.Fatal("queue.log cũ phải được chuyển thành segment")
	}
	q.Close()
}
