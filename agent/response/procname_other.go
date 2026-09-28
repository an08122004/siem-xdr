//go:build !linux && !windows

package response

import (
	"os/exec"
	"strconv"
	"strings"
)

func processName(pid int) (string, error) {
	out, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "comm=").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}
