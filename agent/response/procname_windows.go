//go:build windows

package response

import (
	"encoding/csv"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// processName tra tên tiến trình theo PID bằng tasklist (không cần thư viện ngoài).
func processName(pid int) (string, error) {
	out, err := exec.Command("tasklist", "/FI", "PID eq "+strconv.Itoa(pid), "/FO", "CSV", "/NH").Output()
	if err != nil {
		return "", err
	}
	return parseTasklist(string(out), pid)
}

func parseTasklist(out string, pid int) (string, error) {
	r := csv.NewReader(strings.NewReader(out))
	r.FieldsPerRecord = -1
	for {
		rec, err := r.Read()
		if err != nil {
			break
		}
		if len(rec) >= 2 && strings.TrimSpace(rec[1]) == strconv.Itoa(pid) {
			return strings.TrimSpace(rec[0]), nil
		}
	}
	return "", fmt.Errorf("không có tiến trình pid %d", pid)
}
