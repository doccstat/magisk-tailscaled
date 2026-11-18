// SPDX-License-Identifier: BSD-3-Clause
//go:build linux

package resolver

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	dns "golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/unix"
	"tailscale.com/net/tsdial"
	"tailscale.com/tstest"
	"tailscale.com/types/dnstype"
)

func TestAndroidDNSUpstreamUsesSocketControl(t *testing.T) {
	calls := map[string]*atomic.Int32{"udp": {}, "tcp": {}}
	lc := &net.ListenConfig{Control: func(network, _ string, c syscall.RawConn) error {
		calls[network[:3]].Add(1)
		return c.Control(func(uintptr) {})
	}}
	tstest.Replace(t, &moduleDNSListenConfig, lc)
	request := makeTestRequest(t, "service.example.", dns.TypeA, 0)
	response := makeTestResponse(t, "service.example.", dns.RCodeSuccess, netip.MustParseAddr("192.0.2.1"))
	f := &forwarder{logf: t.Logf, dialer: &tsdial.Dialer{}}
	defer f.dialer.Close()
	f.dialer.SetSystemDialerForTest(func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("module DNS must use marked kernel routes, not SystemDial")
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	fq := &forwardQuery{packet: request, txid: getTxID(request), closeOnCtxDone: new(closePool)}
	stop := context.AfterFunc(ctx, func() { fq.closeOnCtxDone.Close() })
	defer stop()
	// Exercise each transport synchronously so fallback goroutines cannot outlive the override.
	for _, family := range []string{"udp", "tcp"} {
		port := runDNSServer(t, &testDNSServerOptions{SkipUDP: family == "tcp", SkipTCP: family == "udp"}, response, func(bool, []byte) {})
		before := calls[family].Load()
		send := f.sendUDP
		if family == "tcp" {
			send = f.sendTCP
		}
		got, err := send(ctx, fq, resolverAndDelay{name: &dnstype.Resolver{Addr: fmt.Sprintf("127.0.0.1:%d", port)}})
		if err != nil || !bytes.Equal(got, response) || calls[family].Load() <= before {
			t.Fatalf("%s: response %x err %v control calls %d", family, got, err, calls[family].Load()-before)
		}
	}
	lc.Control = func(_, _ string, _ syscall.RawConn) error { return errors.New("mark denied") }
	listener, err := (&forwarder{}).packetListener(netip.MustParseAddr("127.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	if conn, err := listener.ListenPacket(context.Background(), "udp4", "127.0.0.1:0"); err == nil {
		conn.Close()
		t.Fatal("sent unmarked upstream traffic after Control failed")
	}
}

func TestAndroidDNSUpstreamSocketMark(t *testing.T) {
	// Run on a rooted Android device to verify the real kernel mark, not a mock.
	if os.Geteuid() != 0 {
		t.Skip("SO_MARK needs root or CAP_NET_ADMIN")
	}
	lc := net.ListenConfig{Control: func(network, address string, c syscall.RawConn) error {
		var sockErr error
		if err := c.Control(func(fd uintptr) {
			sockErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, 0x10064)
		}); err != nil {
			return err
		}
		if sockErr != nil {
			return sockErr
		}
		return moduleDNSControl(network, address, c)
	}}
	for _, network := range []string{"udp4", "udp6"} {
		addr := "127.0.0.1:0"
		if network == "udp6" {
			addr = "[::1]:0"
		}
		conn, err := lc.ListenPacket(context.Background(), network, addr)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := conn.(*net.UDPConn).SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		var mark int
		var sockErr error
		if err := raw.Control(func(fd uintptr) {
			mark, sockErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK)
		}); err != nil {
			t.Fatal(err)
		}
		conn.Close()
		if sockErr != nil || mark != 0x10064|moduleDNSBypassMark {
			t.Fatalf("%s: mark %#x err %v", network, mark, sockErr)
		}
	}
}
