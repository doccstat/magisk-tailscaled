// SPDX-License-Identifier: BSD-3-Clause
//go:build linux

package netmon

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/jsimonetti/rtnetlink"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nltest"
	"golang.org/x/sys/unix"
)

func TestAndroidNetlinkRuleABI(t *testing.T) {
	for _, family := range []uint8{unix.AF_INET, unix.AF_INET6} {
		for _, table := range []uint32{52, 254, 1029, 1000000031} {
			priority := uint32(5210)
			msg := rtnetlink.RuleMessage{Family: family, Table: 252, Attributes: &rtnetlink.RuleAttributes{
				Table: &table, Priority: &priority,
				UIDRange: &rtnetlink.RuleUIDRange{Start: 10000, End: 60000},
			}}
			data, err := msg.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			got, relevant, err := decodeRuleDeleted(data)
			if err != nil || relevant != (table <= 255) {
				t.Fatalf("table %d: %+v %v %v", table, got, relevant, err)
			}
			if relevant && (uint32(got.Table) != table || got.Priority != priority) {
				t.Fatalf("wrong event: %+v", got)
			}
		}
	}
	// Old kernels can supply only the fib_rule_hdr table. Priority is optional.
	data, err := (&rtnetlink.RuleMessage{Family: unix.AF_INET, Table: 52}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	got, relevant, err := decodeRuleDeleted(data)
	if err != nil || !relevant || got != (RuleDeleted{Table: 52}) {
		t.Fatalf("header-only: %+v %v %v", got, relevant, err)
	}
	if _, relevant, err := decodeRuleDeleted([]byte{1}); err == nil || relevant {
		t.Fatal("malformed rule accepted")
	}
	// Malformed input must trigger a poll, not publish a zero/partial rule event.
	c := nlConn{logf: t.Logf, buffered: []netlink.Message{{Header: netlink.Header{Type: unix.RTM_DELRULE}, Data: []byte{1}}}}
	if m, err := c.Receive(); err != nil || m.ignore() {
		t.Fatalf("malformed event: %v %v", m, err)
	}
}

func TestAndroidNetlinkOverflowResync(t *testing.T) {
	for _, receiveErr := range []error{unix.ENOBUFS, unix.EBADF} {
		conn := nltest.Dial(func([]netlink.Message) ([]netlink.Message, error) { return nil, receiveErr })
		defer conn.Close()
		c := nlConn{conn: conn, logf: t.Logf, addrCache: map[uint32]map[netip.Addr]bool{
			1: {netip.MustParseAddr("192.0.2.1"): true},
		}}
		m, err := c.Receive()
		if receiveErr == unix.ENOBUFS {
			if err != nil || m.ignore() || len(c.addrCache) != 0 {
				t.Fatalf("overflow did not force fresh poll: %v %v %v", m, err, c.addrCache)
			}
		} else if !errors.Is(err, receiveErr) || len(c.addrCache) != 1 {
			t.Fatalf("unrelated error suppressed: %v", err)
		}
	}
}
