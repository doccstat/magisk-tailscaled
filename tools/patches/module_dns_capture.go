// SPDX-License-Identifier: BSD-3-Clause
package netstack

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"sync"
	"time"

	"github.com/tailscale/wireguard-go/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
	"tailscale.com/net/dns"
	"tailscale.com/types/logger"
)

// A separate TUN distinguishes captured queries from the resolver's upstream
// traffic without relying on NAT, socket UIDs inside netstack, or packet tags.
const moduleDNSInterface = "tsdns0"

type moduleDNSCapture struct {
	stack  *stack.Stack
	link   *channel.Endpoint
	device tun.Device
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func newModuleDNSStack(manager *dns.Manager, logf logger.Logf) (*moduleDNSCapture, error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	link := channel.New(128, 1280, "")
	c := &moduleDNSCapture{stack: s, link: link}
	if err := s.CreateNIC(1, link); err != nil {
		c.Close()
		return nil, fmt.Errorf("DNS capture NIC: %v", err)
	}
	s.SetPromiscuousMode(1, true)
	s.SetSpoofing(1, true)
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}, {Destination: header.IPv6EmptySubnet, NIC: 1}})
	tcpForwarder := tcp.NewForwarder(s, 0, 64, func(r *tcp.ForwarderRequest) {
		id := r.ID()
		if id.LocalPort != 53 {
			r.Complete(true)
			return
		}
		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			r.Complete(true)
			return
		}
		r.Complete(false)
		from := netip.AddrPortFrom(netip.MustParseAddr(id.RemoteAddress.String()), id.RemotePort)
		go manager.HandleTCPConn(gonet.NewTCPConn(&wq, ep), from)
	})
	udpForwarder := udp.NewForwarder(s, func(r *udp.ForwarderRequest) bool {
		id := r.ID()
		if id.LocalPort != 53 {
			return true
		}
		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			return true
		}
		conn := gonet.NewUDPConn(&wq, ep)
		from := netip.AddrPortFrom(netip.MustParseAddr(id.RemoteAddress.String()), id.RemotePort)
		go func() {
			defer conn.Close()
			buf := make([]byte, 65535)
			for {
				conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
				n, err := conn.Read(buf)
				if err != nil {
					return
				}
				response, err := manager.Query(context.Background(), buf[:n], "udp", from)
				if err != nil {
					logf("DNS capture query: %v", err)
					return
				}
				if _, err := conn.Write(response); err != nil {
					return
				}
			}
		}()
		return true
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)
	return c, nil
}

func (ns *Impl) startModuleDNSCapture() error {
	if _, err := net.InterfaceByName(moduleDNSInterface); err == nil {
		return fmt.Errorf("DNS capture interface %s already exists", moduleDNSInterface)
	}
	c, err := newModuleDNSStack(ns.dns, ns.logf)
	if err != nil {
		return err
	}
	c.device, err = tun.CreateTUN(moduleDNSInterface, 1280)
	if err != nil {
		c.Close()
		return fmt.Errorf("DNS capture TUN: %w", err)
	}
	ctx, cancel := context.WithCancel(ns.ctx)
	c.cancel = cancel
	commandCtx, commandCancel := context.WithTimeout(ctx, 3*time.Second)
	defer commandCancel()
	if out, err := exec.CommandContext(commandCtx, "/system/bin/ip", "link", "set", "dev", moduleDNSInterface, "up").CombinedOutput(); err != nil {
		c.Close()
		return fmt.Errorf("DNS capture link: %w: %s", err, out)
	}
	c.wg.Add(3)
	go func() {
		defer c.wg.Done()
		for range c.device.Events() {
		}
	}()
	go func() {
		defer c.wg.Done()
		defer c.device.Close() // Remove the route if either packet pump fails.
		defer cancel()
		const offset = 16
		bufs := make([][]byte, c.device.BatchSize())
		sizes := make([]int, len(bufs))
		for i := range bufs {
			bufs[i] = make([]byte, offset+65535)
		}
		for {
			n, err := c.device.Read(bufs, sizes, offset)
			if err != nil {
				if ctx.Err() == nil {
					ns.logf("DNS capture read: %v", err)
				}
				return
			}
			for i := range n {
				b := bufs[i][offset : offset+sizes[i]]
				var protocol tcpip.NetworkProtocolNumber
				if len(b) == 0 {
					continue
				}
				switch b[0] >> 4 {
				case 4:
					protocol = ipv4.ProtocolNumber
				case 6:
					protocol = ipv6.ProtocolNumber
				default:
					continue
				}
				pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), b...))})
				c.link.InjectInbound(protocol, pkt)
				pkt.DecRef()
			}
		}
	}()
	go func() {
		defer c.wg.Done()
		defer c.device.Close()
		defer cancel()
		for {
			pkt := c.link.ReadContext(ctx)
			if pkt == nil {
				return
			}
			b := pkt.ToBuffer()
			data := append(make([]byte, 16), b.Flatten()...)
			b.Release()
			pkt.DecRef()
			if _, err := c.device.Write([][]byte{data}, 16); err != nil {
				if ctx.Err() == nil {
					ns.logf("DNS capture write: %v", err)
				}
				return
			}
		}
	}()
	ns.moduleDNS = c
	return nil
}

func (c *moduleDNSCapture) Close() {
	if c.cancel != nil {
		c.cancel()
	}
	if c.device != nil {
		c.device.Close()
	}
	c.stack.Close()
	c.stack.Wait()
	c.link.Close()
	c.wg.Wait()
	c.link.Drain()
}
