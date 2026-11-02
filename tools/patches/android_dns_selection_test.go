// SPDX-License-Identifier: BSD-3-Clause
package ipnlocal

import (
	"strings"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/netmap"
)

// Exercise the native policy selection; the module must not duplicate it.
func TestAndroidDNSSelection(t *testing.T) {
	nm := &netmap.NetworkMap{
		SelfNode: (&tailcfg.Node{Addresses: ipps("100.64.0.1")}).View(),
		DNS: tailcfg.DNSConfig{
			Resolvers: []*dnstype.Resolver{{Addr: "192.0.2.53", UseWithExitNode: true}, {Addr: "192.0.2.54"}},
			Routes: map[string][]*dnstype.Resolver{
				"private.example.": {{Addr: "192.0.2.55", UseWithExitNode: true}},
				"local.example.":   {{Addr: "192.0.2.56"}},
			},
		},
	}
	peer := (&tailcfg.Node{ID: 1, StableID: "exit", Cap: 26, Addresses: ipps("100.64.0.2"),
		Hostinfo: (&tailcfg.Hostinfo{Services: []tailcfg.Service{{Proto: tailcfg.PeerAPI4, Port: 8080}}}).View()}).View()
	peers := map[tailcfg.NodeID]tailcfg.NodeView{1: peer}
	p := &ipn.Prefs{CorpDNS: true}
	for _, useExit := range []bool{false, true} {
		p.ExitNodeID = ""
		if useExit {
			p.ExitNodeID = "exit"
		}
		cfg := dnsConfigForNetmap(nm, peers, p.View(), false, t.Logf, "android")
		wantDefaults := 2
		if useExit {
			wantDefaults = 1
		}
		if len(cfg.DefaultResolvers) != wantDefaults || cfg.DefaultResolvers[0].Addr != "192.0.2.53" {
			t.Fatalf("exit=%v: incorrect defaults: %+v", useExit, cfg.DefaultResolvers)
		}
		if len(cfg.Routes["private.example."]) != 1 || (len(cfg.Routes["local.example."]) > 0) == useExit {
			t.Fatalf("exit=%v: incorrect split DNS selection: %+v", useExit, cfg.Routes)
		}
	}
	// Without the override flag, a modern exit node supplies its own DNS proxy.
	nm.DNS.Resolvers[0].UseWithExitNode = false
	cfg := dnsConfigForNetmap(nm, peers, p.View(), false, t.Logf, "android")
	if len(cfg.DefaultResolvers) != 1 || !strings.HasSuffix(cfg.DefaultResolvers[0].Addr, "/dns-query") {
		t.Fatalf("exit-node DNS proxy not selected: %+v", cfg.DefaultResolvers)
	}
	p.CorpDNS = false
	cfg = dnsConfigForNetmap(nm, peers, p.View(), false, t.Logf, "android")
	if len(cfg.DefaultResolvers) != 0 || len(cfg.Routes) != 0 {
		t.Fatalf("accept-dns=false was ignored: %+v", cfg)
	}
}
