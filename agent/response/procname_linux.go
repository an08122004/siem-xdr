//go:build linux

package response

import (
	"os"
	"strconv"
	"strings"
)

func processName(pid int) (string, error) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/comm")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}
