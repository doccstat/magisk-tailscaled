// SPDX-License-Identifier: BSD-3-Clause
//go:build linux

package resolver

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

// Separate from Android/Tailscale routing marks and the capture bit (0x40000000).
const moduleDNSBypassMark = 0x20000000

func init() {
	if runtime.GOOS == "android" && os.Getenv("TS_MODULE_DNS") == "true" {
		moduleDNSListenConfig = &net.ListenConfig{Control: moduleDNSControl}
	}
}

func moduleDNSControl(_, _ string, c syscall.RawConn) error {
	var sockErr error
	err := c.Control(func(fd uintptr) {
		mark, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK)
		if err != nil {
			sockErr = err
			return
		}
		sockErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, mark|moduleDNSBypassMark)
	})
	if err != nil {
		return err
	}
	if sockErr != nil {
		return fmt.Errorf("mark DNS upstream socket: %w", sockErr)
	}
	return nil
}
