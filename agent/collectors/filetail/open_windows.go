//go:build windows

package filetail

import (
	"os"
	"syscall"
)

// openShared mở file chỉ đọc với FILE_SHARE_DELETE: ứng dụng ghi log vẫn đổi tên / xóa được file
// trong lúc agent giữ handle (os.Open của Go không bật cờ này nên sẽ cản việc xoay vòng log).
func openShared(path string) (*os.File, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	h, err := syscall.CreateFile(p, syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil, syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(h), path), nil
}
