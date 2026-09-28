//go:build !windows

package filetail

import "os"

// openShared: trên Unix handle đang mở không cản việc đổi tên / xóa file.
func openShared(path string) (*os.File, error) {
	return os.Open(path)
}
