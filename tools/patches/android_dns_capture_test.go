// SPDX-License-Identifier: BSD-3-Clause
package netstack

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"tailscale.com/ipn"
	"tailscale.com/net/dns/resolver"
	"tailscale.com/net/packet"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/ipproto"
	"tailscale.com/util/dnsname"
	"tailscale.com/wgengine/filter"
)

func TestAndroidUpstreamDNSNotRecaptured(t *testing.T) {
	ns := makeNetstack(t, nil)
	if _, err := ns.lb.EditPrefs(&ipn.MaskedPrefs{Prefs: ipn.Prefs{CorpDNS: true}, CorpDNSSet: true}); err != nil {
		t.Fatal(err)
	}
	for _, dst := range []string{"100.64.0.53:53", "[fd7a:115c:a1e0::123]:53", "192.0.2.53:53", "[2001:db8::53]:53"} {
		for _, protocol := range []ipproto.Proto{ipproto.UDP, ipproto.TCP} {
			p := &packet.Parsed{IPVersion: 4, IPProto: protocol, Src: netip.MustParseAddrPort("100.64.0.1:45678"), Dst: netip.MustParseAddrPort(dst), TCPFlags: packet.TCPSyn}
			if p.Dst.Addr().Is6() {
				p.IPVersion = 6
				p.Src = netip.MustParseAddrPort("[fd7a:115c:a1e0::1]:45678")
			}
			if got, _ := ns.handleLocalPackets(p, ns.tundev, nil); got != filter.Accept {
				t.Fatalf("upstream %s %v intercepted: %v", dst, protocol, got)
			}
		}
	}
}

// Exercise real TCP framing/handshakes and UDP replies through two in-memory
// network stacks; no host firewall, network namespace, or TUN privileges needed.
func TestAndroidDNSCaptureDualStack(t *testing.T) {
	ns := makeNetstack(t, nil)
	upstream, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	go func() {
		b := make([]byte, 4096)
		for {
			n, addr, err := upstream.ReadFrom(b)
			if err != nil {
				return
			}
			var m dnsmessage.Message
			if m.Unpack(b[:n]) != nil || len(m.Questions) != 1 {
				continue
			}
			m.Response = true
			m.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: m.Questions[0].Name, Class: dnsmessage.ClassINET}, Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 80}}}}
			out, _ := m.Pack()
			upstream.WriteTo(out, addr)
		}
	}()
	if err := ns.dns.Resolver().SetConfig(resolver.Config{
		Hosts:  map[dnsname.FQDN][]netip.Addr{"host.private.example.": {netip.MustParseAddr("192.0.2.80"), netip.MustParseAddr("2001:db8::80")}},
		Routes: map[dnsname.FQDN][]*dnstype.Resolver{".": {{Addr: upstream.LocalAddr().String()}}},
	}); err != nil {
		t.Fatal(err)
	}
	server, err := newModuleDNSStack(ns.dns, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := newModuleDNSStack(ns.dns, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pump := func(from, to *moduleDNSCapture) {
		for {
			p := from.link.ReadContext(ctx)
			if p == nil {
				return
			}
			b := p.ToBuffer()
			protocol := p.NetworkProtocolNumber
			p.DecRef()
			p = stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: b})
			to.link.InjectInbound(protocol, p)
			p.DecRef()
		}
	}
	go pump(client, server)
	go pump(server, client)
	for _, address := range []string{"192.0.2.100", "2001:db8:1::100"} {
		ip := netip.MustParseAddr(address)
		protocol := ipv4.ProtocolNumber
		dst := netip.MustParseAddr("198.51.100.53")
		if ip.Is6() {
			protocol = ipv6.ProtocolNumber
			dst = netip.MustParseAddr("2001:db8:2::53")
		}
		if err := client.stack.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: protocol, AddressWithPrefix: tcpip.AddrFromSlice(ip.AsSlice()).WithPrefix()}, stack.AddressProperties{}); err != nil {
			t.Fatal(err)
		}
		for _, network := range []string{"udp", "tcp"} {
			t.Run(address+"/"+network, func(t *testing.T) {
				endpoint := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(dst.AsSlice()), Port: 53}
				var conn net.Conn
				var err error
				queryCtx, stop := context.WithTimeout(ctx, 3*time.Second)
				defer stop()
				if network == "tcp" {
					conn, err = gonet.DialContextTCP(queryCtx, client.stack, endpoint, protocol)
				} else {
					conn, err = gonet.DialUDP(client.stack, nil, &endpoint, protocol)
				}
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				for _, q := range []struct {
					name string
					kind dnsmessage.Type
				}{{"host.private.example.", dnsmessage.TypeA}, {"host.private.example.", dnsmessage.TypeAAAA}, {"upstream.example.", dnsmessage.TypeA}} {
					m := dnsmessage.Message{Header: dnsmessage.Header{ID: 1234, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(q.name), Type: q.kind, Class: dnsmessage.ClassINET}}}
					wire, _ := m.Pack()
					if network == "tcp" {
						wire = append(binary.BigEndian.AppendUint16(nil, uint16(len(wire))), wire...)
					}
					if _, err = conn.Write(wire); err != nil {
						t.Fatal(err)
					}
					buf := make([]byte, 4096)
					var n int
					if network == "tcp" {
						var size uint16
						if err = binary.Read(conn, binary.BigEndian, &size); err != nil {
							t.Fatal(err)
						}
						buf = make([]byte, size)
						n, err = io.ReadFull(conn, buf)
					} else {
						n, err = conn.Read(buf)
					}
					if err != nil {
						t.Fatal(err)
					}
					if err = m.Unpack(buf[:n]); err != nil {
						t.Fatal(err)
					}
					if !m.Response || m.ID != 1234 || m.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 1 {
						t.Fatalf("invalid response: %+v", m)
					}
					if m.Answers[0].Header.Type != q.kind {
						t.Fatalf("wrong answer: %+v", m.Answers)
					}
				}
			})
		}
	}
}
