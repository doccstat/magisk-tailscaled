package main

import (
	"errors"
	"strings"
	"testing"
)

func TestDNSRoutesRepairAndMigration(t *testing.T) {
	a, f := dnsTestApp(t)
	f.rules["iptables/nat"] = []string{"-p udp --dport 53 -j DNAT --to-destination 100.100.100.100:53"}
	f.jumps["iptables/nat"] = true
	_ = a.saveDNSJournal(dnsBridge{Active: true, Families: []string{"ipv4"}, Scope: a.options()})
	for _, drift := range []string{"legacy", "route", "rule", "chain"} {
		switch drift {
		case "route":
			delete(f.routes, "-6")
		case "rule":
			delete(f.policy, "-4")
		case "chain":
			f.rules["ip6tables"] = []string{"unexpected rule"}
		}
		if err := a.reconcileDNSLocked(runningDNSStatus(), prefs{CorpDNS: true}); err != nil {
			t.Fatal(err)
		}
		if f.jumps["iptables/nat"] || len(f.rules["iptables/nat"]) != 0 || f.routes["-6"] == "" || f.policy["-4"] == "" || a.dnsJournal().Mode != "routed" {
			t.Fatalf("failed repair for %s: %+v", drift, f)
		}
	}
}

func TestDNSRoutesRejectForeignState(t *testing.T) {
	for _, collision := range []string{"route", "rule", "extra-route", "extra-rule"} {
		t.Run(collision, func(t *testing.T) {
			a, f := dnsTestApp(t)
			switch collision {
			case "route":
				f.routes["-6"] = "default dev another0 proto static metric 1"
			case "extra-route":
				f.routes["-6"] = "default dev tsdns0 proto static metric 1\n2001:db8::/64 dev other0"
			case "rule":
				f.policy["-6"] = "12400: from all lookup 100"
			case "extra-rule":
				f.policy["-6"] = "12400: from all fwmark 0x40000000/0x40000000 lookup 5300\n12400: from all lookup 100"
			}
			beforeRoutes, beforePolicy := f.routes["-6"], f.policy["-6"]
			if err := a.reconcileDNSLocked(runningDNSStatus(), prefs{CorpDNS: true}); err == nil || !strings.Contains(err.Error(), "occupied") {
				t.Fatalf("accepted foreign routing: %v", err)
			}
			if f.routes["-6"] != beforeRoutes || f.policy["-6"] != beforePolicy || f.mutations != 0 {
				t.Fatalf("modified foreign state: %+v", f)
			}
		})
	}
}

func TestDNSRoutesRollbackEveryStage(t *testing.T) {
	for _, stage := range []string{"route", "rule", "chain", "hook"} {
		t.Run(stage, func(t *testing.T) {
			a, f := dnsTestApp(t)
			f.fail = func(tool string, args []string) bool {
				if tool == "ip" {
					return len(args) > 2 && args[0] == "-6" && args[1] == stage && args[2] == "add"
				}
				return tool == "ip6tables" && ((stage == "chain" && args[0] == "-A") || (stage == "hook" && args[0] == "-I"))
			}
			if err := a.installDNSLocked([]string{"ipv4", "ipv6"}); err == nil {
				t.Fatal("injected failure ignored")
			}
			if len(f.routes) != 0 || len(f.policy) != 0 || len(f.rules) != 0 || f.jumps["iptables"] || f.jumps["ip6tables"] || exists(a.file("dns-redirect-active")) {
				t.Fatalf("partial capture survived: %+v", f)
			}
		})
	}
}

func TestDNSMissingTunnelDoesNotCapture(t *testing.T) {
	a, f := dnsTestApp(t)
	original := a.android
	a.android = func(tool string, args ...string) ([]byte, error) {
		if tool == "ip" && args[0] == "link" {
			return nil, errors.New("Device tsdns0 does not exist")
		}
		return original(tool, args...)
	}
	if err := a.reconcileDNSLocked(runningDNSStatus(), prefs{CorpDNS: true}); err == nil || !strings.Contains(err.Error(), "tunnel unavailable") {
		t.Fatal(err)
	}
	if f.mutations != 0 || exists(a.file("dns-redirect-active")) {
		t.Fatalf("captured without tunnel: %+v", f)
	}
}

func TestDNSRoutesAcceptMissingFIBTable(t *testing.T) {
	a, f := dnsTestApp(t)
	original := a.android
	a.android = func(tool string, args ...string) ([]byte, error) {
		if tool == "ip" && len(args) > 2 && args[1] == "route" && args[2] == "show" && f.routes[args[0]] == "" {
			return []byte("Error: ipv6: FIB table does not exist.\nDump terminated"), errors.New("exit status 2")
		}
		return original(tool, args...)
	}
	if err := a.installDNSLocked([]string{"ipv4", "ipv6"}); err != nil {
		t.Fatal(err)
	}
	if err := a.clearDNSRedirect(); err != nil {
		t.Fatal(err)
	}
}

func TestDNSRouteCleanupRetriesWithoutBroadDeletes(t *testing.T) {
	a, f := dnsTestApp(t)
	if err := a.installDNSLocked([]string{"ipv4", "ipv6"}); err != nil {
		t.Fatal(err)
	}
	f.fail = func(tool string, args []string) bool {
		return tool == "ip" && len(args) > 2 && args[0] == "-6" && args[1] == "rule" && args[2] == "del"
	}
	if err := a.clearDNSRedirect(); err == nil || !exists(a.file("dns-redirect-active")) {
		t.Fatal("lost cleanup journal", err)
	}
	f.fail = nil
	if err := a.clearDNSRedirect(); err != nil {
		t.Fatal(err)
	}
	if len(f.routes) != 0 || len(f.policy) != 0 || exists(a.file("dns-redirect-active")) {
		t.Fatalf("cleanup incomplete: %+v", f)
	}
}
