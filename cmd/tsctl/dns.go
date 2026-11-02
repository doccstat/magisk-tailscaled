// SPDX-License-Identifier: MIT
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"time"
)

// Tailscale owns DNS policy: global/split resolvers, MagicDNS and exit-node
// overrides. This bridge only steers ordinary app port-53 traffic to its local
// service addresses. These chain names belong only to this controller.
const dnsRedirectChain = "MAGISK_TS_DNS"
const hotspotChain = "MAGISK_TS_HOTSPOT"
const dnsIPv4 = "100.100.100.100"
const dnsIPv6 = "fd7a:115c:a1e0::53"

type dnsBridge struct {
	Active   bool              `json:"active"`
	Families []string          `json:"families"`
	Skipped  []string          `json:"skipped,omitempty"`
	Rules    map[string]string `json:"rules,omitempty"`
	Scope    moduleOptions     `json:"scope"`
}

// A number of Android kernels ship iptables with IPv4 nat but omit the IPv6
// nat table entirely. That is a capability limitation, not a bridge failure:
// keep IPv4 DNS working and leave IPv6 DNS to the device's normal resolver.
func missingNATTable(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	// Legacy iptables opens with a backtick and closes with an apostrophe.
	// Match the table name and diagnostic without depending on quote style.
	return strings.Contains(s, "table `nat") && strings.Contains(s, "does not exist")
}

func (a app) availableDNSFamilies(families []string) (available, skipped []string, err error) {
	for _, family := range families {
		if _, e := a.dnsFirewall(family, "-S"); e != nil {
			if family == "ipv6" && missingNATTable(e) {
				skipped = append(skipped, family)
				continue
			}
			return nil, nil, e
		}
		available = append(available, family)
	}
	return available, skipped, nil
}

func (a app) dnsJournal() dnsBridge {
	var s dnsBridge
	b, _ := os.ReadFile(a.file("dns-redirect-active"))
	_ = json.Unmarshal(b, &s) // A malformed or older marker is an incomplete journal.
	return s
}

func (a app) saveDNSJournal(s dnsBridge) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return a.write("dns-redirect-active", b)
}

func (a app) dnsError(message string) {
	if message == "" {
		_ = os.Remove(a.file("dns-redirect-error"))
		return
	}
	b, _ := os.ReadFile(a.file("dns-redirect-error"))
	if string(b) != message {
		_ = a.write("dns-redirect-error", []byte(message))
	}
}

func (a app) dnsFirewall(family string, args ...string) (string, error) {
	tool := "iptables"
	if family == "ipv6" {
		tool = "ip6tables"
	}
	argv := append([]string{"-w", "1", "-t", "nat"}, args...)
	var b []byte
	var err error
	if a.android != nil {
		b, err = a.android(tool, argv...)
	} else {
		// Even accidentally running a unit test must never touch host rules.
		if runtime.GOOS != "android" {
			return "", errors.New("DNS firewall requires Android")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		b, err = exec.CommandContext(ctx, "/system/bin/"+tool, argv...).CombinedOutput()
	}
	if err != nil {
		return "", fmt.Errorf("%s %s: %w: %s", tool, strings.Join(args, " "), err, strings.TrimSpace(string(b)))
	}
	return strings.TrimSpace(string(b)), nil
}

// All DNS rule changes (including the supervisor's) use a separate lock. Never
// take control.lock from the supervisor: start/stop wait for that process.
func (a app) clearDNSRedirect() error {
	l, err := lock(a.file("dns.lock"))
	if err != nil {
		return err
	}
	defer l.Close()
	err = a.clearDNSLocked(true)
	if err != nil {
		a.dnsError(err.Error())
	}
	return err
}

func (a app) clearDNSLocked(force bool) error {
	recorded := exists(a.file("dns-redirect-active"))
	if !force && !recorded {
		return nil
	}
	families := []string{"ipv4", "ipv6"}
	var errs []error
	for _, family := range families {
		rules, err := a.dnsFirewall(family, "-S")
		if err != nil {
			if family == "ipv6" && missingNATTable(err) {
				continue
			}
			if recorded {
				errs = append(errs, err)
			}
			continue
		}
		for _, line := range strings.Split(rules, "\n") {
			args := strings.Fields(line)
			owned := line == "-A OUTPUT -j "+dnsRedirectChain
			owned = owned || (len(args) == 6 && args[0] == "-A" && args[1] == "PREROUTING" && args[2] == "-i" && interfaceRE.MatchString(args[3]) && args[4] == "-j" && args[5] == hotspotChain)
			if owned {
				args[0] = "-D"
				if _, err := a.dnsFirewall(family, args...); err != nil {
					errs = append(errs, err)
				}
			}
		}
		for _, chain := range []string{dnsRedirectChain, hotspotChain} {
			if !slices.Contains(strings.Split(rules, "\n"), "-N "+chain) {
				continue
			}
			// Never flush a built-in or foreign chain.
			if _, err := a.dnsFirewall(family, "-F", chain); err != nil {
				errs = append(errs, err)
				continue
			}
			if _, err := a.dnsFirewall(family, "-X", chain); err != nil {
				errs = append(errs, err)
			}
		}
	}
	if err := errors.Join(errs...); err != nil {
		return err
	} // Retain journal for retry.
	for _, file := range []string{"dns-redirect-active", "dns-redirect-target"} {
		if err := os.Remove(a.file(file)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func dnsHooks(o moduleOptions) map[string][]string {
	hooks := map[string][]string{}
	if o.CaptureDNS {
		hooks[dnsRedirectChain] = []string{"OUTPUT", "-j", dnsRedirectChain}
	}
	if o.HotspotDNS {
		hooks[hotspotChain] = []string{"PREROUTING", "-i", o.HotspotInterface, "-j", hotspotChain}
	}
	return hooks
}

func dnsRules(family string) [][]string {
	addr, destination := dnsIPv4, dnsIPv4+":53"
	if family == "ipv6" {
		addr, destination = dnsIPv6, "["+dnsIPv6+"]:53"
	}
	return [][]string{
		// tailscaled runs as root; its upstream queries must not loop back to
		// itself, including unmarked sockets used for subnet DNS resolvers.
		{"-m", "owner", "--uid-owner", "0", "-j", "RETURN"},
		{"-d", addr, "-j", "RETURN"},
		{"-p", "udp", "--dport", "53", "-j", "DNAT", "--to-destination", destination},
		{"-p", "tcp", "--dport", "53", "-j", "DNAT", "--to-destination", destination},
	}
}

func (a app) installDNSLocked(families []string) error {
	return a.installDNSLockedWithSkipped(families, nil)
}

func (a app) installDNSLockedWithSkipped(families, skipped []string) (err error) {
	if err = a.clearDNSLocked(true); err != nil {
		return err
	}
	opts, e := a.loadOptions()
	if e != nil {
		return e
	}
	s := dnsBridge{Families: families, Skipped: skipped, Rules: make(map[string]string), Scope: opts}
	// Journal BEFORE any mutation so partial installs and hard kills recover.
	if err = a.saveDNSJournal(s); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, a.clearDNSLocked(false))
		}
	}()
	for _, family := range families {
		for chain := range dnsHooks(opts) {
			if _, err = a.dnsFirewall(family, "-N", chain); err != nil {
				return err
			}
			rules := dnsRules(family)
			if chain == hotspotChain {
				rules = rules[1:]
			} // owner match is OUTPUT-only.
			for _, rule := range rules {
				if _, err = a.dnsFirewall(family, append([]string{"-A", chain}, rule...)...); err != nil {
					return err
				}
			}
			if s.Rules[family+chain], err = a.dnsFirewall(family, "-S", chain); err != nil {
				return err
			}
		}
	}
	// Attach only after both families are prepared; rollback on either failure.
	for _, family := range families {
		for _, hook := range dnsHooks(opts) {
			if _, err = a.dnsFirewall(family, append([]string{"-I"}, hook...)...); err != nil {
				return err
			}
		}
	}
	s.Active = true
	return a.saveDNSJournal(s)
}

func (a app) readDNSBackend() (ts tailStatus, p prefs, err error) {
	if a.dnsBackend != nil {
		return a.dnsBackend()
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", a.file("tailscaled.sock"))
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	// Decode ONLY typed fields. Raw prefs and network maps contain secrets and
	// must not be logged or sent to WebUI, even when a request fails.
	for _, endpoint := range []struct {
		name string
		out  any
	}{{"status", &ts}, {"prefs", &p}} {
		resp, e := client.Get("http://local-tailscaled.sock/localapi/v0/" + endpoint.name)
		if e != nil {
			return ts, p, fmt.Errorf("read Tailscale %s: %w", endpoint.name, e)
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return ts, p, fmt.Errorf("read Tailscale %s: HTTP %d", endpoint.name, resp.StatusCode)
		}
		e = json.NewDecoder(resp.Body).Decode(endpoint.out)
		resp.Body.Close()
		if e != nil {
			return ts, p, fmt.Errorf("invalid Tailscale %s response", endpoint.name)
		}
	}
	return ts, p, nil
}

func (a app) reconcileDNSRedirect() error {
	l, err := lock(a.file("dns.lock"))
	if err != nil {
		return nil
	} // A control operation owns DNS; retry next tick.
	defer l.Close()
	ts, p, err := a.readDNSBackend()
	if err == nil {
		err = a.reconcileDNSLocked(ts, p)
	} else {
		err = errors.Join(err, a.clearDNSLocked(false))
	}
	if err != nil {
		a.dnsError(err.Error())
	} else {
		a.dnsError("")
	}
	return err
}

func (a app) reconcileDNSLocked(ts tailStatus, p prefs) error {
	opts, err := a.loadOptions()
	if err != nil {
		return errors.Join(err, a.clearDNSLocked(false))
	}
	if (!opts.CaptureDNS && !opts.HotspotDNS) || !p.CorpDNS || ts.BackendState != "Running" || a.disabled() || exists(a.file("paused")) || exists(a.file("disconnected")) {
		return a.clearDNSLocked(false)
	}
	if !a.hasTUN() {
		return errors.Join(errors.New("DNS capture requires native TUN; userspace networking cannot route captured queries"), a.clearDNSLocked(false))
	}
	var families []string
	for _, family := range []string{"ipv4", "ipv6"} {
		for _, value := range ts.TailscaleIPs {
			ip, err := netip.ParseAddr(value)
			if err == nil && ((family == "ipv4" && ip.Is4()) || (family == "ipv6" && ip.Is6())) {
				families = append(families, family)
				break
			}
		}
	}
	if len(families) == 0 {
		return errors.Join(errors.New("waiting for Tailscale addresses"), a.clearDNSLocked(false))
	}
	available, skipped, err := a.availableDNSFamilies(families)
	if err != nil {
		return errors.Join(err, a.clearDNSLocked(false))
	}
	if len(available) == 0 {
		return errors.Join(errors.New("Android has no usable DNS NAT table"), a.clearDNSLocked(false))
	}
	families = available
	s := a.dnsJournal()
	intact := s.Active && slices.Equal(s.Families, families) && s.Scope == opts
	if intact {
		for _, family := range families {
			for chain, hook := range dnsHooks(opts) {
				rules, err := a.dnsFirewall(family, "-S", chain)
				_, jumpErr := a.dnsFirewall(family, append([]string{"-C"}, hook...)...)
				if err != nil || jumpErr != nil || rules != s.Rules[family+chain] {
					intact = false
				}
			}
		}
	}
	if intact {
		return nil
	}
	return a.installDNSLockedWithSkipped(families, skipped)
}

func (a app) setDNSRedirect(value string) error {
	if !a.running() {
		return errors.New("start the service first")
	}
	l, err := lock(a.file("dns.lock"))
	if err != nil {
		return err
	}
	defer l.Close()
	// Remove capture before disabling the resolver. Only CorpDNS is changed;
	// the exit-node choice and other Tailscale preferences are preserved.
	if value == "false" {
		if err = a.clearDNSLocked(true); err != nil {
			a.dnsError(err.Error())
			return err
		}
	}
	if _, err = a.ts(4*time.Second, "set", "--accept-dns="+value); err != nil {
		return err
	}
	ts, p, err := a.readDNSBackend()
	if err == nil {
		err = a.reconcileDNSLocked(ts, p)
	}
	if err != nil {
		a.dnsError(err.Error())
	} else {
		a.dnsError("")
	}
	return err
}
