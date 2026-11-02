// SPDX-License-Identifier: MIT
//go:build linux

package tun

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/rwcancel"
	"golang.org/x/sys/unix"
)

func TestAndroidNetlinkOverflowKeepsListener(t *testing.T) {
	for _, cancel := range []bool{false, true} {
		t.Run(fmt.Sprint("cancel=", cancel), func(t *testing.T) {
			// An ordinary local socket supplies a valid fd for cleanup. Receive
			// itself is injected: no real netlink/TUN/route operations run here.
			fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			rw, err := rwcancel.NewRWCancel(fd)
			if err != nil {
				unix.Close(fd)
				t.Fatal(err)
			}
			tun := &NativeTun{netlinkSock: fd, netlinkCancel: rw, errors: make(chan error, 4), events: make(chan Event, 4), statusListenersShutdown: make(chan struct{})}
			if cancel {
				close(tun.statusListenersShutdown)
			}
			calls := 0
			done := make(chan struct{})
			go func() {
				defer close(done)
				tun.listenNetlink(func(int, []byte, []byte, int) (int, int, int, unix.Sockaddr, error) {
					calls++
					if calls <= 2 {
						return 0, 0, 0, nil, fmt.Errorf("receive: %w", unix.ENOBUFS)
					}
					return 0, 0, 0, nil, unix.EBADF
				})
			}()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("listener failed to stop")
			}
			if cancel {
				if calls != 1 || len(tun.errors) != 0 || len(tun.events) != 0 {
					t.Fatal("shutdown lost to overflow recovery")
				}
				return
			}
			if calls != 3 || len(tun.errors) != 1 {
				t.Fatalf("overflow closed listener: calls=%d errors=%d", calls, len(tun.errors))
			}
			if err := <-tun.errors; !errors.Is(err, unix.EBADF) {
				t.Fatalf("wrong fatal error: %v", err)
			}
			if len(tun.events) != 2 {
				t.Fatalf("MTU was not refreshed: %d", len(tun.events))
			}
			for event := range tun.events {
				if event != EventMTUUpdate {
					t.Fatalf("unexpected event %v", event)
				}
			}
		})
	}
}
