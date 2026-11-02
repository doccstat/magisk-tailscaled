package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFirstRunRequiresExplicitPolicy(t *testing.T) {
	a := testApp(t)
	_ = os.Remove(a.file("initialized"))
	_ = os.Remove(a.file("tailscaled.state"))
	if _, err := a.dispatch([]string{"start"}); err == nil {
		t.Fatal("started without policy choice")
	}
	if _, err := a.dispatch([]string{"boot"}); err != nil || a.running() {
		t.Fatal("boot started uninitialized module", err)
	}
	if _, err := a.dispatch([]string{"initialize", "preserve"}); err == nil {
		t.Fatal("preserved nonexistent identity")
	}
	if _, err := a.dispatch([]string{"initialize", "conservative"}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.dispatch([]string{"initialize", "preserve"}); err == nil {
		t.Fatal("overwrote policy")
	}
}

func TestPreserveRequiresIdentityAndNewPolicyIsAppliedOnce(t *testing.T) {
	a := testApp(t)
	_ = os.Remove(a.file("tailscaled.state"))
	if err := a.preflight(); err == nil {
		t.Fatal("missing preserved identity silently replaced")
	}
	_ = a.write("initialized", []byte("conservative\n"))
	t.Cleanup(func() { _ = a.stop(false) })
	if _, err := a.dispatch([]string{"start"}); err != nil {
		t.Fatal(err)
	}
	args, _ := os.ReadFile(a.file("last-ts-args"))
	if string(args) != "set --accept-dns=false --accept-routes=false --shields-up=true --ssh=false --exit-node= --exit-node-allow-lan-access=false" {
		t.Fatal("unexpected first-run settings", string(args))
	}
	_ = os.Remove(a.file("last-ts-args"))
	if _, err := a.dispatch([]string{"restart"}); err != nil {
		t.Fatal(err)
	}
	if exists(a.file("last-ts-args")) {
		t.Fatal("preferences reapplied after initialization")
	}
}

func TestIdentityMissingEmptyOrRedirected(t *testing.T) {
	a := testApp(t)
	_ = os.Remove(a.file("tailscaled.state"))
	_ = a.write("initialized", []byte("conservative\n"))
	_ = a.write("policy-applied", []byte("1\n"))
	if err := a.preflight(); err == nil {
		t.Fatal("lost initialized identity replaced")
	}
	_ = a.write("tailscaled.state", nil)
	if err := a.preflight(); err == nil {
		t.Fatal("empty identity accepted")
	}
	_ = os.Remove(a.file("tailscaled.state"))
	_ = os.Symlink(a.file("outside-state"), a.file("tailscaled.state"))
	if err := a.preflight(); err == nil {
		t.Fatal("redirected identity accepted")
	}
}

func TestOptionsAreExplicitAndNoNormalization(t *testing.T) {
	a, _ := dnsTestApp(t)
	_ = os.Remove(a.file("module-options.json"))
	if a.options() != (moduleOptions{}) {
		t.Fatal("capture or fallback silently enabled")
	}
	if err := a.setOption("hotspot-dns", "true"); err == nil {
		t.Fatal("accepted unscoped hotspot")
	}
	for _, value := range []string{"wlan+", " wlan0", "wlan0;id"} {
		if _, err := settingArgs("hotspot-interface", value); err == nil {
			t.Fatal("accepted invalid interface", value)
		}
	}
	if _, err := settingArgs("hostname", " phone "); err == nil {
		t.Fatal("normalized hostname")
	}
	if err := a.setOption("hotspot-interface", "wlan1"); err != nil {
		t.Fatal(err)
	}
	if err := a.setOption("hotspot-dns", "true"); err != nil {
		t.Fatal(err)
	}
	hooks := dnsHooks(a.options())
	if strings.Join(hooks[hotspotChain], " ") != "PREROUTING -i wlan1 -j MAGISK_TS_HOTSPOT" || len(hooks) != 1 {
		t.Fatal(hooks)
	}
	if err := a.setOption("hotspot-interface", ""); err == nil {
		t.Fatal("cleared live capture scope")
	}
	l, err := lock(a.file("dns.lock"))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.setOption("hotspot-interface", "wlan2"); err == nil || a.options().HotspotInterface != "wlan1" {
		t.Fatal("option changed during DNS reconciliation")
	}
	l.Close()
	_ = a.write("module-options.json", []byte("corrupted"))
	if err := a.preflight(); err == nil {
		t.Fatal("ignored corrupted options")
	}
}

func TestPurgeRequiresConfirmationAndPreservesLocks(t *testing.T) {
	a := testApp(t)
	_ = a.write("tailscaled.state", []byte("identity"))
	if _, err := a.dispatch([]string{"purge"}); err == nil {
		t.Fatal("purged without confirmation")
	}
	if !exists(a.file("tailscaled.state")) {
		t.Fatal("lost identity")
	}
	_ = os.MkdirAll(a.file("backups"), 0700)
	_ = os.WriteFile(a.file("backups/old"), []byte("old identity"), 0600)
	external := filepath.Join(t.TempDir(), "keep")
	_ = os.WriteFile(external, []byte("external"), 0600)
	_ = os.Symlink(external, a.file("external-link"))
	if _, err := a.dispatch([]string{"purge", "erase-identity"}); err != nil {
		t.Fatal(err)
	}
	if exists(a.file("tailscaled.state")) || exists(a.file("backups")) || exists(a.file("initialized")) {
		t.Fatal("state not erased")
	}
	if !exists(a.file("paused")) || !exists(a.file("control.lock")) || !exists(external) {
		t.Fatal("purge removed lock, pause or external file")
	}
}

func TestHotspotRulesJournalAndCleanup(t *testing.T) {
	a := app{base: t.TempDir(), module: t.TempDir()}
	_ = a.write("module-options.json", []byte(`{"hotspotDNS":true,"hotspotInterface":"wlan1"}`))
	var calls []string
	active := false
	a.android = func(tool string, args ...string) ([]byte, error) {
		c := strings.Join(args[4:], " ")
		calls = append(calls, c)
		if c == "-N "+hotspotChain {
			active = true
		}
		if c == "-S" && active {
			return []byte("-N " + hotspotChain + "\n-A PREROUTING -i wlan1 -j " + hotspotChain + "\n-A PREROUTING -i wlan2 -j FOREIGN"), nil
		}
		return nil, nil
	}
	if err := a.installDNSLocked([]string{"ipv4"}); err != nil {
		t.Fatal(err)
	}
	if !a.dnsJournal().Active {
		t.Fatal("lost journal")
	}
	if err := a.clearDNSRedirect(); err != nil {
		t.Fatal(err)
	}
	text := strings.Join(calls, "\n")
	if strings.Contains(text, "--uid-owner") || strings.Contains(text, "-F FOREIGN") || !strings.Contains(text, "-D PREROUTING -i wlan1 -j "+hotspotChain) {
		t.Fatal(text)
	}
	for _, proto := range []string{"udp", "tcp"} {
		if !strings.Contains(text, "-p "+proto+" --dport 53") {
			t.Fatal(text)
		}
	}
}
