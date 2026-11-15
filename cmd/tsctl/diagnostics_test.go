package main

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func diagnosticTestApp(t *testing.T) app {
	t.Helper()
	a := testApp(t)
	a.self, _ = os.Executable()
	if err := a.saveRecord("supervisor.json", os.Getpid()); err != nil {
		t.Fatal(err)
	}
	_ = a.write("ready", nil)
	_ = a.write("module-options.json", []byte(`{"captureDNS":true}`))
	_ = a.saveDNSJournal(dnsBridge{Mode: "routed", Active: true, Families: []string{"ipv4", "ipv6"}})
	a.tunPresent = func() bool { return true }
	a.dnsBackend = func() (tailStatus, prefs, error) {
		return runningDNSStatus(), prefs{CorpDNS: true, RouteAll: true, Hostname: "my-phone"}, nil
	}
	a.android = func(tool string, args ...string) ([]byte, error) {
		s := strings.Join(args, " ")
		switch tool {
		case "ip":
			if !strings.Contains(s, " show") && !strings.Contains(s, "route get") {
				t.Fatalf("mutating network probe: %s", s)
			}
			if strings.Contains(s, "route get") {
				return []byte(args[len(args)-1] + " dev tailscale0 src 100.64.0.1"), nil
			}
			return []byte("100.64.0.53 dev tailscale0 src 100.64.0.1"), nil
		case "iptables":
			if !strings.Contains(s, " -L ") && !strings.Contains(s, " -S ") {
				t.Fatalf("mutating firewall probe: %s", s)
			}
			return []byte("12 480 MARK udp -- 0.0.0.0/0 0.0.0.0/0 udp dpt:53 MARK or 0x40000000"), nil
		case "ip6tables":
			if strings.Contains(s, "-t mangle") {
				return []byte("14 980 MARK udp -- ::/0 ::/0 udp dpt:53 MARK or 0x40000000"), nil
			}
			return []byte("can't initialize ip6tables table `nat': Table does not exist"), errors.New("exit status 3")
		case "settings":
			if s == "get global private_dns_mode" {
				return []byte("hostname"), nil
			}
			if s == "get global private_dns_specifier" {
				return []byte("dns.private.example"), nil
			}
		case "dumpsys":
			if s == "dnsresolver" {
				return []byte("netId=100 server=192.0.2.53 TLS=validated"), nil
			}
		case "getprop", "uname":
			return []byte("17"), nil
		}
		t.Fatalf("unexpected probe %s %s", tool, s)
		return nil, nil
	}
	l, err := net.Listen("unix", a.file("tailscaled.sock"))
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != "GET" || req.URL.Path != "/localapi/v0/dns-config" {
			t.Errorf("unexpected LocalAPI operation: %s %s", req.Method, req.URL.Path)
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `{"Resolvers":[{"Addr":"100.64.0.53","UseWithExitNode":false}],"Routes":{"private.example.":[{"Addr":"192.0.2.53"}]},"Domains":["tail.example."],"Proxied":true,"PrivateNodeKey":"must-not-export"}`)
	})}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	_ = a.write("tailscaled.log", []byte("dns: my-phone query service.private.example. to 100.64.0.53 timed out\nlogin https://login.tailscale.com/a/LEAKME123 alice@example.com tskey-auth-LEAKME123\n"))
	_ = os.WriteFile(filepath.Join(a.module, "build-info.json"), []byte(`{"source_commit":"test-commit","go":"go1.26.10"}`), 0600)
	return a
}

func TestDiagnosticsWithoutExitNode(t *testing.T) {
	a := diagnosticTestApp(t)
	result, err := a.dispatch([]string{"diagnostics", "Service.Private.Example."})
	if err != nil {
		t.Fatal(err)
	}
	report := result.(map[string]any)
	status := report["status"].(map[string]any)
	p := status["prefs"].(map[string]any)
	if p["ExitNodeID"] != "" || p["ExitNodeIP"] != "" || p["CorpDNS"] != true || p["RouteAll"] != true {
		t.Fatalf("unexpected preferences: %v", p)
	}
	if status["dns"].(map[string]any)["active"] != true {
		t.Fatal("DNS incorrectly requires an exit node")
	}
	dns := report["dns"].(map[string]any)
	if dns["privateDNSMode"].(map[string]any)["output"] != "hostname" {
		t.Fatal("Private DNS mode not recorded")
	}
	query := dns["query"].(map[string]any)["results"].(map[string]any)
	for _, kind := range []string{"A", "AAAA"} {
		if !strings.Contains(query[kind].(map[string]any)["output"].(string), "RCodeSuccess") {
			t.Fatal("missing DNS result", query)
		}
	}
	args, _ := os.ReadFile(a.file("last-ts-args"))
	if string(args) != "dns query --json Service.Private.Example. AAAA" {
		t.Fatalf("hostname was changed or command incorrect: %s", args)
	}
	network := report["network"].(map[string]any)
	if network[dnsRedirectChain+"6"].(map[string]any)["error"] == nil || !strings.Contains(network["mangle"+dnsRedirectChain+"4"].(map[string]any)["output"].(string), "12 480 MARK") || !strings.Contains(network["mangle"+dnsRedirectChain+"6"].(map[string]any)["output"].(string), "14 980 MARK") {
		t.Fatal("missing legacy NAT failure or dual-stack capture counters")
	}
	if network["captureInterface"] == nil || network["captureRoutes6"] == nil {
		t.Fatal("missing capture tunnel or policy routes")
	}
	encoded, _ := json.Marshal(report)
	for _, private := range []string{"my-phone", "100.64.0.53", "100.64.0.1", "192.0.2.53", "private.example", "LEAKME123", "alice@example.com", "must-not-export"} {
		if strings.Contains(strings.ToLower(string(encoded)), strings.ToLower(private)) {
			t.Fatalf("private data leaked: %s in %s", private, encoded)
		}
	}
	for _, want := range []string{"100.100.100.100", "test-commit", "go1.26.10", "timed out", "UseWithExitNode"} {
		if !strings.Contains(string(encoded), want) {
			t.Fatalf("lost diagnostic evidence: %s", want)
		}
	}
}

func TestDiagnosticExportIsExplicitAndExclusive(t *testing.T) {
	a := diagnosticTestApp(t)
	path := filepath.Join(t.TempDir(), "报告 with spaces.json")
	result, err := a.dispatch([]string{"export-diagnostics", path})
	if err != nil || result.(map[string]string)["path"] != path {
		t.Fatalf("export: %v %v", result, err)
	}
	b, err := os.ReadFile(path)
	if err != nil || !json.Valid(b) {
		t.Fatalf("invalid file: %s %v", b, err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("report not private", info.Mode())
	}
	var report map[string]any
	_ = json.Unmarshal(b, &report)
	if report["redacted"] != true || report["dns"].(map[string]any)["query"] != nil || exists(a.file("last-ts-args")) {
		t.Fatal("unrequested query or unredacted export")
	}
	if _, err := a.dispatch([]string{"export-diagnostics", path}); err == nil {
		t.Fatal("overwrote existing report")
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(b) {
		t.Fatal("existing file changed")
	}
	link := path + ".link"
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := a.exportDiagnostics(link, ""); err == nil {
		t.Fatal("followed destination symlink")
	}
	for _, args := range [][]string{{"export-diagnostics"}, {"export-diagnostics", "relative.json"}, {"diagnostics", "https://private.example"}, {"diagnostics", " --help"}, {"diagnostics", "name", "extra"}} {
		if _, err := a.dispatch(args); err == nil {
			t.Fatal("accepted invalid arguments", args)
		}
	}
	for _, name := range []string{"", "service", "Service.Private.Example.", "xn--bcher-kva.example"} {
		if err := validateDiagnosticName(name); err != nil {
			t.Fatal(name, err)
		}
	}
}

func TestDiagnosticsRetainsFailuresWhenStopped(t *testing.T) {
	a := app{base: t.TempDir(), module: t.TempDir(), tunPresent: func() bool { return false },
		android: func(string, ...string) ([]byte, error) { return nil, errors.New("permission denied") }}
	report, err := a.diagnostics("")
	if err != nil {
		t.Fatal(err)
	}
	if report["status"].(map[string]any)["running"] != false || report["dns"].(map[string]any)["configurationError"] == nil {
		t.Fatal("stopped/backend failure not recorded")
	}
	if report["network"].(map[string]any)["routes4"].(map[string]any)["error"] != "permission denied" || report["logs"].(map[string]any)["current"].(map[string]any)["error"] == nil {
		t.Fatal("probe or missing-log failure lost")
	}
}

func TestDiagnosticRedactionAndBounds(t *testing.T) {
	r := diagnosticRedactor{aliases: map[string]string{}}
	data := map[string]any{
		"version": "v2.0.0.1", "HostName": "Alice's Phone", "AuthURL": "secret-login",
		"Peer": map[string]any{"nodekey:abcdef": map[string]any{"HostName": "测试手机"}},
		"logs": "Alice's Phone 测试手机 alice@private.example 10.1.2.3 [fd7a:115c:a1e0::1234]:53 01:23:45:67:89:ab password=hunter2 Authorization: Bearer BEARERCREDENTIAL nodekey:abcdef https://user:pass@private.example/dns-query?token=secret",
	}
	r.identifiers(data)
	result := r.scrub(data).(map[string]any)
	encoded, _ := json.Marshal(result)
	for _, secret := range []string{"Alice", "测试手机", "secret-login", "private.example", "10.1.2.3", "::1234", "01:23:45:67:89:ab", "hunter2", "abcdef", "user:pass", "Bearer", "BEARERCREDENTIAL"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("leaked %s: %s", secret, encoded)
		}
	}
	if result["version"] != "v2.0.0.1" {
		t.Fatal("module version mistaken for an IP")
	}
	var buffer diagnosticBuffer
	n, err := buffer.Write([]byte(strings.Repeat("x", diagnosticLimit+200)))
	if err != nil || n != diagnosticLimit+200 || len(buffer.data) != diagnosticLimit || !buffer.truncated {
		t.Fatal("command output is not bounded")
	}
	path := filepath.Join(t.TempDir(), "large.log")
	_ = os.WriteFile(path, []byte("secret="+strings.Repeat("x", diagnosticLimit+200)+"\ndns: timeout\n"), 0600)
	file := diagnosticFile(path, true)
	if !file.Truncated || file.Output != "dns: timeout\n" {
		t.Fatal("partial log line exposed", file)
	}
	link := path + ".link"
	_ = os.Symlink(path, link)
	if result := diagnosticFile(link, true); result.Error == "" || result.Output != "" {
		t.Fatal("read a redirected log", result)
	}
	a := app{}
	probe := a.diagnosticCommand(20*time.Millisecond, "/bin/sleep", "5")
	if !strings.Contains(probe.Error, "deadline exceeded") {
		t.Fatal("probe did not time out", probe)
	}
}
