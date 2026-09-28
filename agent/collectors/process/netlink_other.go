//go:build !linux

package process

import (
	"errors"

	"siem-agent/core"
)

func (c *Collector) runNetlink(core.Emit) error {
	return errors.New("proc connector chỉ có trên Linux")
}
