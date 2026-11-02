// SPDX-License-Identifier: BSD-3-Clause
package resolver

import (
	"net/netip"
	"testing"

	dns "golang.org/x/net/dns/dnsmessage"
	"tailscale.com/types/dnstype"
	"tailscale.com/util/dnsname"
)

func TestAndroidSearchDomains(t *testing.T) {
	server := serveDNS(t, "127.0.0.1:0",
		"homepage.private.example.", resolveToIP(testipv4, testipv6, ""),
		"homepage.example.", resolveToIP(testipv4, testipv6, ""),
	)
	defer server.Shutdown()
	r := newResolver(t)
	defer r.Close()
	cfg := Config{
		Routes:        map[dnsname.FQDN][]*dnstype.Resolver{".": {{Addr: server.PacketConn.LocalAddr().String()}}},
		Hosts:         map[dnsname.FQDN][]netip.Addr{"peer.tail.example.": {testipv4}},
		LocalDomains:  []dnsname.FQDN{"tail.example."},
		SearchDomains: []dnsname.FQDN{"tail.example.", "tail.example.", "private.example."},
	}
	r.SetConfig(cfg)
	for _, tt := range []struct{ query, target string }{
		{"peer.", "peer.tail.example."},
		{"homepage.", "homepage.private.example."},
		{"homepage.example.", "homepage.example."},
	} {
		t.Run(tt.query, func(t *testing.T) {
			payload, err := syncRespond(r, dnspacket(dnsname.FQDN(tt.query), dns.TypeA, noEdns))
			if err != nil {
				t.Fatal(err)
			}
			var message dns.Message
			if err := message.Unpack(payload); err != nil {
				t.Fatal(err)
			}
			if message.RCode != dns.RCodeSuccess || message.Questions[0].Name.String() != tt.query {
				t.Fatal(message)
			}
			owner := tt.query
			found := false
			for _, answer := range message.Answers {
				if answer.Header.Name.String() != owner {
					t.Fatalf("answer %s does not follow %s", answer.Header.Name, owner)
				}
				switch body := answer.Body.(type) {
				case *dns.CNAMEResource:
					owner = body.CNAME.String()
					if message.AuthenticData || message.Authoritative {
						t.Fatal("synthesized alias claims authority")
					}
				case *dns.AResource:
					found = netip.AddrFrom4(body.A) == testipv4 && owner == tt.target
				}
			}
			if !found {
				t.Fatal("no reachable A answer", message)
			}
		})
	}
	cfg.SearchDomains = nil
	r.SetConfig(cfg)
	payload, err := syncRespond(r, dnspacket("peer.", dns.TypeA, noEdns))
	if err != nil {
		t.Fatal(err)
	}
	var message dns.Message
	if err = message.Unpack(payload); err != nil {
		t.Fatal(err)
	}
	if len(message.Answers) != 0 {
		t.Fatal("search expansion ignored opt-out", message)
	}
}
