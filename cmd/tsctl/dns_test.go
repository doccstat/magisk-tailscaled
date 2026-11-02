package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
)

// Model only our NAT chain and OUTPUT jump. No test executes a firewall tool.
type fakeDNSFirewall struct {
	rules     map[string][]string
	jumps     map[string]bool
	mutations int
	fail      func(string, []string) bool
}

func dnsTestApp(t *testing.T) (app, *fakeDNSFirewall) {
	t.Helper()
	f := &fakeDNSFirewall{rules: map[string][]string{}, jumps: map[string]bool{}}
	a := app{base: t.TempDir(), module: t.TempDir(), tunPresent: func() bool { return true }}
	_ = a.write("module-options.json", []byte(`{"captureDNS":true}`))
	a.android = func(tool string, args ...string) ([]byte, error) {
		if !slices.Equal(args[:4], []string{"-w", "1", "-t", "nat"}) {
			t.Fatalf("unexpected firewall scope: %v", args)
		}
		args = args[4:]
		if f.fail != nil && f.fail(tool, args) {
			return nil, errors.New("injected firewall failure")
		}
		_, exists := f.rules[tool]
		switch args[0] {
		case "-S":
			if len(args) == 2 && !exists {
				return nil, errors.New("missing chain")
			}
			lines := []string{}
			if len(args) == 1 {
				lines = append(lines, "-P OUTPUT ACCEPT", "-N FOREIGN", "-A OUTPUT -j FOREIGN")
				if f.jumps[tool] {
					lines = append(lines, "-A OUTPUT -j "+dnsRedirectChain)
				}
			}
			if exists {
				lines = append(lines, "-N "+dnsRedirectChain)
				for _, rule := range f.rules[tool] {
					lines = append(lines, "-A "+dnsRedirectChain+" "+rule)
				}
			}
			return []byte(strings.Join(lines, "\n")), nil
		case "-C":
			if !f.jumps[tool] {
				return nil, errors.New("missing jump")
			}
			return nil, nil
		case "-N", "-A", "-F", "-X":
			if args[1] != dnsRedirectChain {
				t.Fatalf("modified another chain: %v", args)
			}
			switch args[0] {
			case "-N", "-F":
				f.rules[tool] = nil
			case "-A":
				f.rules[tool] = append(f.rules[tool], strings.Join(args[2:], " "))
			case "-X":
				delete(f.rules, tool)
			}
		case "-I", "-D":
			if args[1] != "OUTPUT" || args[len(args)-1] != dnsRedirectChain {
				t.Fatalf("unexpected jump: %v", args)
			}
			f.jumps[tool] = args[0] == "-I"
		default:
			t.Fatalf("unexpected command: %s %v", tool, args)
		}
		f.mutations++
		return nil, nil
	}
	return a, f
}

func runningDNSStatus() tailStatus {
	return tailStatus{BackendState: "Running", TailscaleIPs: []string{"100.64.0.1", "fd7a:115c:a1e0::1"}}
}

func TestDNSBridgeReconcileAndRepair(t *testing.T) {
	a, f := dnsTestApp(t)
	ts := runningDNSStatus()
	p := prefs{CorpDNS: true, ExitNodeID: "selected-exit"}
	if err := a.reconcileDNSLocked(ts, p); err != nil {
		t.Fatal(err)
	}
	for tool, target := range map[string]string{"iptables": "100.100.100.100:53", "ip6tables": "[fd7a:115c:a1e0::53]:53"} {
		rules := f.rules[tool]
		if !f.jumps[tool] || len(rules) != 4 || rules[0] != "-m owner --uid-owner 0 -j RETURN" {
			t.Fatalf("missing loop exemption or jump: %s %v", tool, rules)
		}
		for i, proto := range []string{"udp", "tcp"} {
			if rules[i+2] != fmt.Sprintf("-p %s --dport 53 -j DNAT --to-destination %s", proto, target) {
				t.Fatalf("unexpected DNS capture: %v", rules)
			}
		}
	}
	count := f.mutations
	if err := a.reconcileDNSLocked(ts, p); err != nil || f.mutations != count {
		t.Fatalf("intact rules churned: %v", err)
	}
	// An Android firewall reload removed the IPv6 chain and jump.
	delete(f.rules, "ip6tables")
	f.jumps["ip6tables"] = false
	if err := a.reconcileDNSLocked(ts, p); err != nil || !f.jumps["ip6tables"] {
		t.Fatalf("did not repair rules: %v", err)
	}
	// Changing exit nodes does not select a DNS server in the controller.
	count = f.mutations
	p.ExitNodeID = "different-exit"
	if err := a.reconcileDNSLocked(ts, p); err != nil || f.mutations != count {
		t.Fatalf("exit-node switch unnecessarily rebuilt the bridge: %v", err)
	}
	// Drop IPv6 when Tailscale no longer owns an IPv6 address.
	ts.TailscaleIPs = ts.TailscaleIPs[:1]
	if err := a.reconcileDNSLocked(ts, p); err != nil || f.jumps["ip6tables"] || !f.jumps["iptables"] {
		t.Fatalf("address-family change was not applied: %v", err)
	}
}

func TestDNSBridgeInactiveCleanup(t *testing.T) {
	for _, why := range []string{"opt-out", "disconnected", "saved-disconnect", "paused", "disabled", "no-addresses", "no-tun", "backend-error"} {
		t.Run(why, func(t *testing.T) {
			a, f := dnsTestApp(t)
			ts, p := runningDNSStatus(), prefs{CorpDNS: true}
			if err := a.reconcileDNSLocked(ts, p); err != nil {
				t.Fatal(err)
			}
			switch why {
			case "opt-out":
				p.CorpDNS = false
			case "disconnected":
				ts.BackendState = "Stopped"
			case "paused":
				if err := a.write("paused", nil); err != nil {
					t.Fatal(err)
				}
			case "disabled":
				if err := os.WriteFile(a.module+"/disable", nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "no-addresses":
				ts.TailscaleIPs = nil
			case "no-tun":
				a.tunPresent = func() bool { return false }
			case "saved-disconnect":
				if err := a.write("disconnected", nil); err != nil {
					t.Fatal(err)
				}
			}
			a.dnsBackend = func() (tailStatus, prefs, error) {
				if why == "backend-error" {
					return ts, p, errors.New("backend unavailable")
				}
				return ts, p, nil
			}
			err := a.reconcileDNSRedirect()
			wantError := why == "no-addresses" || why == "backend-error" || why == "no-tun"
			if (err != nil) != wantError {
				t.Fatalf("unexpected error: %v", err)
			}
			if f.jumps["iptables"] || f.jumps["ip6tables"] || len(f.rules) != 0 || exists(a.file("dns-redirect-active")) {
				t.Fatalf("capture survived %s: %+v", why, f)
			}
		})
	}
}

func TestDNSBridgeRollbackAndRetry(t *testing.T) {
	a, f := dnsTestApp(t)
	f.fail = func(tool string, args []string) bool { return tool == "ip6tables" && args[0] == "-I" }
	if err := a.installDNSLocked([]string{"ipv4", "ipv6"}); err == nil {
		t.Fatal("partial failure ignored")
	}
	if len(f.rules) != 0 || f.jumps["iptables"] || f.jumps["ip6tables"] || exists(a.file("dns-redirect-active")) {
		t.Fatal("partial install was not rolled back")
	}
	f.fail = nil
	if err := a.installDNSLocked([]string{"ipv4", "ipv6"}); err != nil {
		t.Fatal(err)
	}
	f.fail = func(tool string, args []string) bool { return tool == "ip6tables" && args[0] == "-D" }
	if err := a.clearDNSRedirect(); err == nil || !exists(a.file("dns-redirect-active")) {
		t.Fatal("cleanup failure lost recovery journal")
	}
	f.fail = nil
	if err := a.clearDNSRedirect(); err != nil || exists(a.file("dns-redirect-active")) {
		t.Fatal(err)
	}
}

func TestDNSBridgeAllowsMissingIPv6NAT(t *testing.T) {
	a, f := dnsTestApp(t)
	failIPv6 := true
	original := a.android
	a.android = func(tool string, args ...string) ([]byte, error) {
		if tool == "ip6tables" && failIPv6 && len(args) >= 4 && args[3] == "nat" {
			return []byte("ip6tables v1.8.11 (legacy): can't initialize ip6tables table `nat': Table does not exist (do you need to insmod?) Perhaps ip6tables or your kernel needs to be upgraded."), errors.New("exit status 3")
		}
		return original(tool, args...)
	}
	// Recover an incomplete journal when IPv6 NAT has become unavailable.
	if err := a.saveDNSJournal(dnsBridge{Families: []string{"ipv4", "ipv6"}}); err != nil {
		t.Fatal(err)
	}
	if err := a.reconcileDNSLocked(runningDNSStatus(), prefs{CorpDNS: true}); err != nil {
		t.Fatal(err)
	}
	if !f.jumps["iptables"] || f.jumps["ip6tables"] {
		t.Fatalf("IPv4 bridge was not retained: %+v", f)
	}
	journal := a.dnsJournal()
	if !slices.Equal(journal.Families, []string{"ipv4"}) || !slices.Equal(journal.Skipped, []string{"ipv6"}) {
		t.Fatalf("missing capability was not journaled: %+v", journal)
	}
	if err := a.clearDNSRedirect(); err != nil {
		t.Fatal(err)
	}
}

func TestMissingNATTableRecognizesAndroidQuoteVariant(t *testing.T) {
	for _, tt := range []struct {
		message string
		want    bool
	}{
		{"ip6tables v1.8.11 (legacy): can't initialize ip6tables table `nat': Table does not exist (do you need to insmod?)", true},
		{"can't initialize ip6tables table `nat`: Table does not exist", true},
		{"can't initialize ip6tables table `nat': Permission denied (you must be root)", false},
		{"can't initialize ip6tables table `filter': Table does not exist", false},
	} {
		if got := missingNATTable(errors.New(tt.message)); got != tt.want {
			t.Errorf("missingNATTable(%q) = %v, want %v", tt.message, got, tt.want)
		}
	}
}

func TestDNSBridgeLegacyCleanup(t *testing.T) {
	a, f := dnsTestApp(t)
	if err := a.write("dns-redirect-active", []byte("1\n")); err != nil {
		t.Fatal(err)
	}
	f.rules["iptables"] = []string{"legacy fixed destination rule"}
	f.jumps["iptables"] = true
	if err := a.clearDNSRedirect(); err != nil || len(f.rules) != 0 || f.jumps["iptables"] {
		t.Fatalf("legacy rules survived cleanup: %v", err)
	}
}

func TestDNSBackendTypedProjection(t *testing.T) {
	a := app{base: t.TempDir()}
	l, err := net.Listen("unix", a.file("tailscaled.sock"))
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/localapi/v0/status":
			io.WriteString(w, `{"BackendState":"Running","TailscaleIPs":["100.64.0.1"],"PrivateKey":"secret","Peer":{"p":{"ID":"exit","ExitNodeOption":true}}}`)
		case "/localapi/v0/prefs":
			io.WriteString(w, `{"CorpDNS":true,"ExitNodeID":"exit","Persist":{"PrivateNodeKey":"secret"}}`)
		default:
			t.Errorf("unexpected endpoint: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	ts, p, err := a.readDNSBackend()
	if err != nil || !p.CorpDNS || p.ExitNodeID != "exit" || !ts.Peer["p"].ExitNodeOption {
		t.Fatalf("projection: %+v %+v %v", ts, p, err)
	}
	b, _ := json.Marshal([]any{ts, p})
	if strings.Contains(string(b), "secret") || strings.Contains(string(b), "Persist") {
		t.Fatal("secret escaped typed projection")
	}
}

func TestDNSPreferenceToggle(t *testing.T) {
	a := testApp(t)
	_ = a.write("module-options.json", []byte(`{"captureDNS":true}`))
	fake, f := dnsTestApp(t)
	a.android, a.tunPresent = fake.android, fake.tunPresent
	a.self, _ = os.Executable()
	if err := a.saveRecord("supervisor.json", os.Getpid()); err != nil {
		t.Fatal(err)
	}
	if err := a.write("ready", nil); err != nil {
		t.Fatal(err)
	}
	for _, enabled := range []bool{true, false} {
		a.dnsBackend = func() (tailStatus, prefs, error) {
			return runningDNSStatus(), prefs{CorpDNS: enabled, ExitNodeID: "kept-exit"}, nil
		}
		if err := a.setDNSRedirect(fmt.Sprint(enabled)); err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(a.file("last-ts-args"))
		if string(b) != fmt.Sprintf("set --accept-dns=%v", enabled) {
			t.Fatalf("changed preferences other than accept-dns: %s", b)
		}
		status := a.status()
		dns := status["dns"].(map[string]any)
		if dns["enabled"] != enabled || dns["active"] != enabled || status["prefs"].(prefs).ExitNodeID != "kept-exit" || f.jumps["iptables"] != enabled {
			t.Fatalf("toggle/status mismatch: %+v", status)
		}
	}
}
