// SPDX-License-Identifier: BSD-3-Clause
//go:build linux && !android

package osrouter

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/tailscale/netlink"
	"golang.org/x/time/rate"
	"tailscale.com/tstest"
	"tailscale.com/types/logger"
	"tailscale.com/util/eventbus"
	"tailscale.com/version/distro"
)

// This runner records the real restoration path without changing host routes.
type ruleRecoveryCommands chan string

func (c ruleRecoveryCommands) run(args ...string) error {
	c <- strings.Join(args, " ")
	return nil
}

func (c ruleRecoveryCommands) output(args ...string) ([]byte, error) {
	return nil, fmt.Errorf("unexpected command output request: %v", args)
}

func TestAndroidIPRuleRecovery(t *testing.T) {
	for _, tc := range []struct {
		name     string
		base     int
		rules    []netlink.Rule
		accepted []uint32
		rejected []uint32
	}{
		{"linux", 5200, baseIPRules, []uint32{5210, 5230, 5250, 5270}, []uint32{5200, 5299, 12500}},
		{"shifted", 1300, baseIPRules, []uint32{1310, 1330, 1350, 1370}, []uint32{1300, 1399, 5210}},
		{"ubnt", 5200, ubntIPRules, []uint32{5270}, []uint32{5210, 5250, 13001}},
		{"android", 5200, getAndroidIPRules(), []uint32{12500, 13001}, []uint32{5210, 5299, 12400, 13000, 13002, ^uint32(0)}},
		{"other-layout", 9000, []netlink.Rule{{Priority: 31337, Table: 52}}, []uint32{40337}, []uint32{9000, 9099, 12500}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Feed each platform's actual rules through the Linux host selector.
			tstest.Replace(t, &getDistroFunc, func() distro.Distro { return "" })
			tstest.Replace(t, &baseIPRules, tc.rules)
			bus := eventbus.New()
			client := bus.Client("rule-recovery-test")
			defer client.Close()
			newRouter := func(t *testing.T) (*linuxRouter, ruleRecoveryCommands) {
				commands := make(ruleRecoveryCommands, 64)
				r := &linuxRouter{
					logf:             logger.Discard,
					cmd:              commands,
					nfr:              newIPTablesRunner(t),
					ipRuleAvailable:  true,
					ipPolicyPrefBase: tc.base,
					ipRuleFixLimiter: rate.NewLimiter(rate.Every(time.Hour), 1),
					rulesAddedPub:    eventbus.Publish[AddIPRules](client),
				}
				r.fwmaskWorksLazy.Set(true)
				t.Cleanup(func() { r.closed.Store(true) })
				return r, commands
			}
			for _, priority := range tc.rejected {
				t.Run(fmt.Sprintf("ignore-%d", priority), func(t *testing.T) {
					r, _ := newRouter(t)
					r.onIPRuleDeleted(52, priority)
					if r.ruleRestorePending.Load() {
						t.Fatalf("foreign priority %d scheduled restoration", priority)
					}
				})
			}
			for _, priority := range tc.accepted {
				t.Run(fmt.Sprintf("restore-%d", priority), func(t *testing.T) {
					r, commands := newRouter(t)
					r.onIPRuleDeleted(52, priority)
					if !r.ruleRestorePending.Load() {
						t.Fatalf("owned priority %d did not schedule restoration", priority)
					}
					r.onIPRuleDeleted(52, priority) // A deletion batch must use one timer.
					if r.ipRuleFixLimiter.Tokens() < 0 {
						t.Fatal("duplicate event consumed another recovery reservation")
					}
					deadline := time.NewTimer(3 * time.Second)
					defer deadline.Stop()
					for _, family := range []string{"-4", "-6"} {
						for _, rule := range tc.rules {
							want := fmt.Sprintf("ip %s rule add pref %d ", family, tc.base+rule.Priority)
							select {
							case got := <-commands:
								if !strings.HasPrefix(got, want) {
									t.Fatalf("restoration = %q; want prefix %q", got, want)
								}
							case <-deadline.C:
								t.Fatalf("no restoration for %s", want)
							}
						}
					}
				})
			}
		})
	}
}
