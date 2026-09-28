package process

import "encoding/binary"

// Định dạng message của proc connector (linux/connector.h, linux/cn_proc.h).
// Tách riêng khỏi phần socket để test được trên mọi OS.
const (
	cnIdxProc         = 0x1
	cnValProc         = 0x1
	procCnMcastListen = 1
	procCnMcastIgnore = 2

	procEventNone = 0x00000000 // ack của lệnh đăng ký
	procEventExec = 0x00000002

	nlmsgHdrLen = 16
	cnMsgLen    = 20 // cb_id{idx,val} + seq + ack + len(u16) + flags(u16)
	nlmsgDone   = 0x3
)

// buildMcastMsg tạo message netlink đăng ký (op = listen) / hủy (op = ignore) nhận event tiến trình.
func buildMcastMsg(op uint32, pid uint32) []byte {
	ne := binary.NativeEndian
	buf := make([]byte, nlmsgHdrLen+cnMsgLen+4)
	ne.PutUint32(buf[0:], uint32(len(buf))) // nlmsg_len
	ne.PutUint16(buf[4:], nlmsgDone)        // nlmsg_type
	ne.PutUint32(buf[12:], pid)             // nlmsg_pid
	ne.PutUint32(buf[16:], cnIdxProc)       // cn_msg.id.idx
	ne.PutUint32(buf[20:], cnValProc)       // cn_msg.id.val
	ne.PutUint16(buf[32:], 4)               // cn_msg.len
	ne.PutUint32(buf[36:], op)              // dữ liệu: enum proc_cn_mcast_op
	return buf
}

// parseProcEvent đọc phần dữ liệu (sau nlmsghdr) của một message proc connector.
// proc_event: what(u32) cpu(u32) timestamp_ns(u64) rồi union event_data ở offset 16:
// exec = {process_pid, process_tgid}, ack = {err}.
func parseProcEvent(data []byte) (what uint32, tgid int, ackErr uint32, ok bool) {
	if len(data) < cnMsgLen+16+8 {
		return 0, 0, 0, false
	}
	ne := binary.NativeEndian
	if ne.Uint32(data[0:]) != cnIdxProc || ne.Uint32(data[4:]) != cnValProc {
		return 0, 0, 0, false
	}
	ev := data[cnMsgLen:]
	what = ne.Uint32(ev[0:])
	switch what {
	case procEventExec:
		return what, int(ne.Uint32(ev[20:])), 0, true
	case procEventNone:
		return what, 0, ne.Uint32(ev[16:]), true
	}
	return what, 0, 0, true
}
