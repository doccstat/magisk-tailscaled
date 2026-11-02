// SPDX-License-Identifier: BSD-3-Clause
package dns

import (
	"net/netip"
	"slices"
	"testing"

	"tailscale.com/types/dnstype"
	"tailscale.com/util/dnsname"
)

func TestAndroidQuad100Defaults(t *testing.T) {
	t.Setenv("TS_MODULE_SEARCH", "true")
	for _, addr := range []string{"192.0.2.53", "2001:db8::53", "https://resolver.example/dns-query"} {
		t.Run(addr, func(t *testing.T) {
			m := &Manager{goos: "android", os: noopManager{}}
			cfg := Config{DefaultResolvers: []*dnstype.Resolver{{Addr: addr, UseWithExitNode: true}},
				Routes:        map[dnsname.FQDN][]*dnstype.Resolver{"private.example.": {{Addr: "192.0.2.54"}}, "tail.example.": nil},
				SearchDomains: []dnsname.FQDN{"tail.example."},
				Hosts:         map[dnsname.FQDN][]netip.Addr{"peer.tail.example.": {netip.MustParseAddr("100.64.0.1")}}}
			r, osCfg, err := m.compileConfig(cfg)
			if err != nil || len(r.Routes["."]) != 1 || r.Routes["."][0] != cfg.DefaultResolvers[0] || !slices.Equal(r.SearchDomains, cfg.SearchDomains) {
				t.Fatalf("default not forwarded unchanged: %+v, %v", r, err)
			}
			if len(r.Routes["private.example."]) != 1 || r.Routes["private.example."][0].Addr != "192.0.2.54" || !slices.Contains(r.LocalDomains, "tail.example.") || !slices.Equal(r.Hosts["peer.tail.example."], cfg.Hosts["peer.tail.example."]) {
				t.Fatalf("split/MagicDNS lost: %+v", r)
			}
			if !slices.Contains(osCfg.Nameservers, netip.MustParseAddr("100.100.100.100")) {
				t.Fatalf("OS config does not use quad-100: %+v", osCfg)
			}
			cfg.Routes = nil // Reproduces the trivial global-IP/no-MagicDNS case.
			cfg.Hosts = nil
			r, _, err = m.compileConfig(cfg)
			if err != nil || len(r.Routes["."]) != 1 || r.Routes["."][0].Addr != addr {
				t.Fatalf("trivial default lost: %+v, %v", r, err)
			}
			cfg.OnlyIPv6 = true
			_, osCfg, err = m.compileConfig(cfg)
			if err != nil || !slices.Equal(osCfg.Nameservers, []netip.Addr{netip.MustParseAddr("fd7a:115c:a1e0::53")}) {
				t.Fatalf("IPv6-only service address lost: %+v, %v", osCfg, err)
			}
		})
	}
}

func TestAndroidQuad100Disabled(t *testing.T) {
	t.Setenv("TS_MODULE_SEARCH", "false")
	m := &Manager{goos: "android", os: noopManager{}}
	r, osCfg, err := m.compileConfig(Config{})
	if err != nil || len(r.Routes) != 0 || len(osCfg.Nameservers) != 0 {
		t.Fatalf("disabled DNS acquired a default resolver: %+v, %+v, %v", r, osCfg, err)
	}
	r, _, err = m.compileConfig(Config{SearchDomains: []dnsname.FQDN{"tail.example."}})
	if err != nil || len(r.SearchDomains) != 0 {
		t.Fatalf("search expansion silently enabled: %+v, %v", r, err)
	}
}
