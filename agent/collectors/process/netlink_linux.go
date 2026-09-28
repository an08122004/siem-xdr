//go:build linux

package process

import (
	"errors"
	"fmt"
	"log"
	"os"
	"sync/atomic"
	"syscall"
	"time"

	"siem-agent/core"
)

const (
	flushEvery = 200 * time.Millisecond
	flushSize  = 200
	maxPending = 10000 // queue lỗi kéo dài thì giữ tối đa chừng này event trong RAM

	initPidNS = "pid:[4026531836]" // PROC_PID_INIT_INO: PID namespace gốc của máy
)

var (
	// execSeen đếm mọi event execve nhận được từ kernel (kể cả tiến trình đã kết thúc trước khi đọc /proc).
	execSeen atomic.Uint64
	// requireInitPidNS: kernel báo PID theo namespace gốc; ở namespace khác thì không tra được /proc.
	requireInitPidNS = true
)

func inInitPidNS() bool {
	link, err := os.Readlink("/proc/self/ns/pid")
	return err == nil && link == initPidNS
}

// runNetlink nhận event execve từ kernel qua proc connector. Trả lỗi ngay nếu không dùng được
// (thiếu quyền, network hoặc PID namespace riêng như trong container) để Start lùi về quét /proc.
func (c *Collector) runNetlink(emit core.Emit) error {
	if requireInitPidNS && !inInitPidNS() {
		return errors.New("agent không chạy trong PID namespace gốc (container?), PID do kernel báo không tra được /proc")
	}
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_DGRAM, syscall.NETLINK_CONNECTOR)
	if err != nil {
		return fmt.Errorf("mở socket netlink: %w", err)
	}
	defer syscall.Close(fd)
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK, Groups: cnIdxProc}); err != nil {
		return fmt.Errorf("bind proc connector: %w", err)
	}
	_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4<<20)
	tv := syscall.NsecToTimeval(int64(flushEvery))
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		return fmt.Errorf("đặt timeout netlink: %w", err)
	}
	send := func(op uint32) error {
		return syscall.Sendto(fd, buildMcastMsg(op, uint32(os.Getpid())), 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK})
	}
	if err := send(procCnMcastListen); err != nil {
		return fmt.Errorf("đăng ký proc connector: %w", err)
	}
	defer send(procCnMcastIgnore)

	buf := make([]byte, 64<<10)
	var batch []core.Event
	lastFlush, lastReport := time.Now(), time.Now()
	ackDeadline := time.Now().Add(2 * time.Second)
	acked, missed, overflow := false, 0, 0
	for {
		select {
		case <-c.stopCh:
			_ = emit(batch)
			return nil
		default:
		}
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		switch {
		case err == nil:
			msgs, _ := syscall.ParseNetlinkMessage(buf[:n])
			for _, m := range msgs {
				what, pid, ackErr, ok := parseProcEvent(m.Data)
				if !ok {
					continue
				}
				switch what {
				case procEventNone:
					if ackErr != 0 {
						return fmt.Errorf("kernel từ chối đăng ký proc connector: %w", syscall.Errno(ackErr))
					}
					if !acked {
						log.Printf("[process] nhận event tiến trình trực tiếp từ kernel (netlink proc connector)")
					}
					acked = true
				case procEventExec:
					acked = true
					execSeen.Add(1)
					if info, ok := readProc(pid); ok {
						batch = append(batch, newEvent(info))
					} else {
						missed++ // kết thúc trước khi kịp đọc /proc
					}
				}
			}
		case errors.Is(err, syscall.EAGAIN), errors.Is(err, syscall.EINTR):
			// hết timeout nhận -> tới lượt flush / kiểm tra dừng
		case errors.Is(err, syscall.ENOBUFS):
			overflow++ // kernel bỏ bớt event vì buffer nhận đầy
		default:
			return fmt.Errorf("đọc netlink: %w", err)
		}
		if !acked && time.Now().After(ackDeadline) {
			return errors.New("kernel không phản hồi đăng ký proc connector")
		}
		if len(batch) >= flushSize || (len(batch) > 0 && time.Since(lastFlush) >= flushEvery) {
			lastFlush = time.Now()
			if err := emit(batch); errors.Is(err, core.ErrStopping) {
				return nil
			} else if err != nil {
				log.Printf("[process] không ghi được event: %v (giữ lại để thử lại)", err)
				if len(batch) > maxPending {
					overflow += len(batch) - maxPending
					batch = batch[len(batch)-maxPending:]
				}
			} else {
				batch = nil
			}
		}
		if (missed > 0 || overflow > 0) && time.Since(lastReport) > time.Minute {
			log.Printf("[process] 1 phút qua: %d tiến trình kết thúc trước khi đọc được /proc, %d event bị bỏ do quá tải", missed, overflow)
			missed, overflow, lastReport = 0, 0, time.Now()
		}
	}
}
