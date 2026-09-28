package process

import (
	"encoding/binary"
	"testing"
)

func TestBuildMcastMsg(t *testing.T) {
	b := buildMcastMsg(procCnMcastListen, 42)
	ne := binary.NativeEndian
	if len(b) != 40 || ne.Uint32(b[0:]) != 40 || ne.Uint32(b[16:]) != cnIdxProc || ne.Uint16(b[32:]) != 4 || ne.Uint32(b[36:]) != procCnMcastListen {
		t.Fatalf("message đăng ký sai: %v", b)
	}
}

func procMsg(what uint32, a, b uint32) []byte {
	ne := binary.NativeEndian
	d := make([]byte, cnMsgLen+16+8)
	ne.PutUint32(d[0:], cnIdxProc)
	ne.PutUint32(d[4:], cnValProc)
	ne.PutUint32(d[cnMsgLen:], what)
	ne.PutUint32(d[cnMsgLen+16:], a)
	ne.PutUint32(d[cnMsgLen+20:], b)
	return d
}

func TestParseProcEvent(t *testing.T) {
	if what, tgid, _, ok := parseProcEvent(procMsg(procEventExec, 1235, 1234)); !ok || what != procEventExec || tgid != 1234 {
		t.Fatalf("exec: what=%d tgid=%d ok=%v", what, tgid, ok)
	}
	if what, _, ackErr, ok := parseProcEvent(procMsg(procEventNone, 1, 0)); !ok || what != procEventNone || ackErr != 1 {
		t.Fatalf("ack lỗi phải đọc được err: what=%d err=%d", what, ackErr)
	}
	if _, _, _, ok := parseProcEvent([]byte{1, 2, 3}); ok {
		t.Fatal("message ngắn phải bị bỏ")
	}
	other := procMsg(procEventExec, 1, 1)
	other[0] = 9 // không phải proc connector
	if _, _, _, ok := parseProcEvent(other); ok {
		t.Fatal("message của connector khác phải bị bỏ")
	}
}
