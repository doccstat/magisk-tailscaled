package main

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Real subprocess integration, with fake Tailscale binaries and no host routing.
func TestMain(m *testing.M) {
	base := os.Getenv("TSM_TEST_BASE")
	if base != "" {
		exe, _ := os.Executable()
		switch filepath.Base(exe) {
		case "tsctl":
			a := app{module: filepath.Dir(filepath.Dir(exe)), base: base, self: exe,
				checkSystem: func() error { return nil }, setupTUN: func() error { return nil }}
			if len(os.Args) != 2 || (os.Args[1] != "supervise" && os.Args[1] != "supervise-loop") {
				os.Exit(2)
			}
			if err := a.superviseLoop(); err != nil {
				_ = a.write("startup-error", []byte(err.Error()))
				os.Exit(1)
			}
			os.Exit(0)
		case "tailscaled":
			state := filepath.Join(base, "tailscaled.state")
			if !exists(state) {
				if err := os.WriteFile(state, []byte("fake new identity"), 0600); err != nil {
					os.Exit(6)
				}
			}
			if os.Getenv("TSM_TEST_CRASH") == "1" {
				os.Exit(42)
			}
			listener, err := net.Listen("unix", filepath.Join(base, "tailscaled.sock"))
			if err != nil {
				os.Exit(3)
			}
			server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/localapi/v0/status":
					io.WriteString(w, `{"BackendState":"Stopped","PrivateKey":"do-not-expose"}`)
				case "/localapi/v0/prefs":
					io.WriteString(w, `{"CorpDNS":false,"ShieldsUp":true,"Persist":{"PrivateNodeKey":"do-not-expose"}}`)
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			})}
			go server.Serve(listener)
			ch := make(chan os.Signal, 1)
			signal.Notify(ch, syscall.SIGTERM)
			<-ch
			server.Close()
			_ = os.WriteFile(filepath.Join(base, "daemon-exited"), []byte("graceful"), 0600)
			os.Exit(0)
		case "tailscale":
			if len(os.Args) < 3 {
				os.Exit(4)
			}
			if err := os.WriteFile(filepath.Join(base, "last-ts-args"), []byte(strings.Join(os.Args[2:], " ")), 0600); err != nil {
				os.Exit(5)
			}
			switch os.Args[2] {
			case "status":
				b, err := os.ReadFile(filepath.Join(base, "mock-status"))
				if err != nil {
					b = []byte(`{"BackendState":"Stopped"}`)
				}
				os.Stdout.Write(b)
			case "debug":
				os.Stdout.WriteString(`{"CorpDNS":false,"ShieldsUp":true,"Persist":{"PrivateNodeKey":"do-not-expose"}}`)
			}
			os.Exit(0)
		}
	}
	os.Exit(m.Run())
}

func testApp(t *testing.T) app {
	t.Helper()
	// Unix socket paths have a 108-byte limit; don't include long test names.
	root, err := os.MkdirTemp("", "tsctl-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	base := filepath.Join(root, "state")
	bin := filepath.Join(root, "module", "bin")
	if err := os.MkdirAll(base, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(bin, 0700); err != nil {
		t.Fatal(err)
	}
	exe, _ := os.Executable()
	b, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"tsctl", "tailscale", "tailscaled"} {
		if err := os.WriteFile(filepath.Join(bin, name), b, 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("TSM_TEST_BASE", base)
	if err := os.WriteFile(filepath.Join(base, "initialized"), []byte("preserve\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "tailscaled.state"), []byte("saved-identity"), 0600); err != nil {
		t.Fatal(err)
	}
	return app{module: filepath.Dir(bin), base: base, self: filepath.Join(bin, "tsctl"),
		checkSystem: func() error { return nil }, setupTUN: func() error { return nil }}
}

func TestLifecyclePreservesIdentityAndPause(t *testing.T) {
	a := testApp(t)
	if err := a.write("tailscaled.state", []byte("saved-identity")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.stop(false) })
	if _, err := a.dispatch([]string{"start"}); err != nil {
		t.Fatal(err)
	}
	if !a.running() {
		t.Fatal("service did not start")
	}
	first := a.record("supervisor.json")
	if _, err := a.dispatch([]string{"start"}); err != nil {
		t.Fatal(err)
	}
	if first != a.record("supervisor.json") {
		t.Fatal("duplicate supervisor")
	}
	status := a.status()
	if status["error"] != nil || status["prefs"].(prefs).ShieldsUp != true {
		t.Fatalf("status did not reach fake LocalAPI: %+v", status)
	}
	encoded, _ := json.Marshal(status)
	if strings.Contains(string(encoded), "do-not-expose") {
		t.Fatal("private prefs leaked")
	}
	if _, err := a.dispatch([]string{"stop"}); err != nil {
		t.Fatal(err)
	}
	if a.running() || !exists(a.file("daemon-exited")) {
		t.Fatal("daemon did not shut down gracefully")
	}
	if _, err := a.dispatch([]string{"boot"}); err != nil || a.running() {
		t.Fatal("boot ignored pause", err)
	}
	if _, err := a.dispatch([]string{"start"}); err != nil {
		t.Fatal(err)
	}
	if exists(a.file("paused")) {
		t.Fatal("manual start did not clear pause")
	}
	if _, err := a.dispatch([]string{"restart"}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(a.file("tailscaled.state"))
	if string(b) != "saved-identity" {
		t.Fatal("identity changed")
	}
	if err := os.WriteFile(filepath.Join(a.module, "disable"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	for range 40 {
		if !a.record("supervisor.json").alive() {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if a.record("supervisor.json").alive() {
		t.Fatal("disabled module is still running")
	}
	if _, err := a.dispatch([]string{"start"}); err == nil {
		t.Fatal("disabled module started")
	}
}

func TestConnectUsesMaskedPrefsAndReusesLogin(t *testing.T) {
	a := testApp(t)
	listener, err := net.Listen("unix", a.file("tailscaled.sock"))
	if err != nil {
		t.Fatal(err)
	}
	var calls []string
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		calls = append(calls, r.Method+" "+r.URL.Path+" "+string(b))
		w.WriteHeader(204)
	})}
	go server.Serve(listener)
	defer server.Close()
	_ = a.write("mock-status", []byte(`{"BackendState":"NeedsLogin"}`))
	if err := a.connect(); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || calls[0] != `PATCH /localapi/v0/prefs {"WantRunning":true,"WantRunningSet":true}` || !strings.Contains(calls[1], "login-interactive") {
		t.Fatalf("unexpected API calls %v", calls)
	}
	_ = a.write("mock-status", []byte(`{"BackendState":"NeedsLogin","AuthURL":"https://login.tailscale.com/a/existing"}`))
	if err := a.connect(); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 3 {
		t.Fatal("pending login was regenerated")
	}
}

func TestProcessIdentityAndLock(t *testing.T) {
	r, err := readProcess(os.Getpid())
	if err != nil || !r.alive() {
		t.Fatal("cannot identify current process", err)
	}
	r.Start += "0"
	if r.alive() {
		t.Fatal("recycled PID accepted")
	}
	cmd := exec.Command("sleep", "30")
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	other, err := readProcess(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	a := app{base: t.TempDir(), module: "/not-this-module", self: "/not-this-module/bin/tsctl"}
	b, _ := json.Marshal(other)
	_ = a.write("supervisor.json", b)
	if err := a.stop(false); err != nil {
		t.Fatal(err)
	}
	if !other.alive() {
		t.Fatal("unrelated process was stopped")
	}
	l, err := lock(a.file("control.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if l2, err := lock(a.file("control.lock")); err == nil {
		l2.Close()
		t.Fatal("concurrent lock admitted")
	}
}

func TestSettingValidation(t *testing.T) {
	for _, pair := range [][2]string{{"accept-dns", "yes"}, {"shields-up", "yes"}, {"hostname", "a;id"}, {"hostname", "-bad"}, {"hostname", strings.Repeat("a", 64)}, {"exit-node", "--reset"}, {"exit-node", "1.2.3.999"}} {
		if _, err := settingArgs(pair[0], pair[1]); err == nil {
			t.Fatalf("accepted %q", pair)
		}
	}
	for _, pair := range [][2]string{{"accept-dns", "true"}, {"accept-dns", "false"}, {"shields-up", "false"}, {"ssh", "true"}, {"capture-dns", "false"}, {"hostname", "my-phone"}, {"exit-node", "100.100.1.2"}, {"exit-node", "fd7a:115c:a1e0::1"}} {
		if _, err := settingArgs(pair[0], pair[1]); err != nil {
			t.Fatal(err)
		}
	}
	args, _ := settingArgs("exit-node", "")
	if strings.Join(args, " ") != "set --exit-node=" {
		t.Fatal(args)
	}
}

func TestDNSRedirectUsesPrivateOwnedChain(t *testing.T) {
	a := app{base: t.TempDir(), module: "/module", self: "/module/bin/tsctl"}
	_ = a.write("module-options.json", []byte(`{"captureDNS":true}`))
	var calls [][]string
	a.android = func(name string, args ...string) ([]byte, error) {
		call := append([]string{name}, args...)
		calls = append(calls, call)
		if len(args) > 1 && args[len(args)-2] == "-S" {
			return []byte("-N MAGISK_TS_DNS\n-A OUTPUT -j MAGISK_TS_DNS\n"), nil
		}
		return nil, nil
	}
	if err := a.installDNSLocked([]string{"ipv4"}); err != nil {
		t.Fatal(err)
	}
	if !a.dnsJournal().Active {
		t.Fatal("DNS redirect was not marked active")
	}
	joined := ""
	for _, call := range calls {
		joined += strings.Join(call, " ") + "\n"
	}
	if !strings.Contains(joined, "-N MAGISK_TS_DNS") || !strings.Contains(joined, "-j DNAT --to-destination 100.100.100.100:53") {
		t.Fatalf("unexpected firewall commands:\n%s", joined)
	}
	if err := a.clearDNSRedirect(); err != nil {
		t.Fatal(err)
	}
	if exists(a.file("dns-redirect-active")) {
		t.Fatal("DNS redirect marker survived cleanup")
	}
}

func TestPreflightFailureAndLogRotation(t *testing.T) {
	a := testApp(t)
	a.checkSystem = func() error { return errors.New("TUN unavailable") }
	if _, err := a.dispatch([]string{"start"}); err == nil || !strings.Contains(err.Error(), "TUN") {
		t.Fatal(err)
	}
	if a.running() {
		t.Fatal("started without TUN")
	}
	w := rollingLog{name: a.file("test.log")}
	for range 12 {
		if _, err := w.Write([]byte(strings.Repeat("a", 100000))); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []string{w.name, w.name + ".1"} {
		info, err := os.Stat(p)
		if err != nil || info.Size() > 512*1024 || info.Mode().Perm() != 0600 {
			t.Fatal("invalid log", info, err)
		}
	}
}

func TestRecoveryBudgetBackoffAndReset(t *testing.T) {
	b := recoveryBudget{}
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 32 * time.Second, 60 * time.Second}
	for i, delay := range want {
		got, retry := b.failed(time.Second)
		if !retry || got != delay || b.failures != i+1 {
			t.Fatalf("failure %d: delay=%v retry=%v count=%d", i+1, got, retry, b.failures)
		}
	}
	if _, retry := b.failed(time.Second); retry {
		t.Fatal("recovery budget did not stop after eight failures")
	}
	if delay, retry := b.failed(5 * time.Minute); !retry || delay != time.Second || b.failures != 1 {
		t.Fatalf("long healthy run did not reset: %v %v %d", delay, retry, b.failures)
	}
}

func TestDisconnectedDoesNotReconnectOnBootOrStart(t *testing.T) {
	a := testApp(t)
	if _, err := a.dispatch([]string{"disconnect"}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.dispatch([]string{"boot"}); err != nil || a.running() {
		t.Fatal("boot ignored disconnect", err)
	}
	if _, err := a.dispatch([]string{"start"}); err == nil || a.record("supervisor.json").alive() {
		t.Fatal("start launched a disconnected identity", err)
	}
}

func TestRecoveryWaitHonorsIntentionalStop(t *testing.T) {
	a := app{base: t.TempDir()}
	signals := make(chan os.Signal, 1)
	if err := a.write("paused", []byte("stop")); err != nil {
		t.Fatal(err)
	}
	if a.waitRecovery(signals, time.Second) {
		t.Fatal("paused recovery kept waiting")
	}
	_ = os.Remove(a.file("paused"))
	if err := a.write("disconnected", []byte("down")); err != nil {
		t.Fatal(err)
	}
	if a.waitRecovery(signals, time.Second) {
		t.Fatal("disconnect recovery kept waiting")
	}
}
