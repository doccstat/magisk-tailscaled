// SPDX-License-Identifier: MIT
// tsctl owns only this module's daemon and files. No TCP control listener.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var version = "development"

const stateDir = "/data/adb/tailscale"

type app struct {
	module, base, self string
	// Test seams for Android kernel probes; never populated by the shipped CLI.
	checkSystem, setupTUN func() error
	// Only tests inject these; Android tools are otherwise absolute paths.
	android    func(string, ...string) ([]byte, error)
	dnsBackend func() (tailStatus, prefs, error)
	tunPresent func() bool
}
type processRecord struct {
	PID        int
	Start, Exe string
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "version" {
		fmt.Println(version)
		return
	}
	if runtime.GOOS != "android" || os.Geteuid() != 0 {
		fatal(errors.New("tsctl requires a root shell on Android"))
	}
	syscall.Umask(0077)
	exe, err := os.Executable()
	if err != nil {
		fatal(err)
	}
	a := app{module: filepath.Dir(filepath.Dir(exe)), base: stateDir, self: exe}
	if info, e := os.Lstat(a.base); e == nil && (!info.IsDir() || info.Mode()&os.ModeSymlink != 0) {
		fatal(errors.New("state directory must not be a symlink"))
	}
	if err = os.MkdirAll(a.base, 0700); err != nil {
		fatal(err)
	}
	if err = os.Chmod(a.base, 0700); err != nil {
		fatal(err)
	}
	if len(os.Args) < 2 {
		fatal(errors.New("usage: tsctl status|initialize conservative|initialize preserve|start|stop|restart|connect|disconnect|logout|set <name> <value>|logs|diagnostics|purge erase-identity"))
	}
	if os.Args[1] == "supervise-loop" {
		if err = a.superviseLoop(); err != nil {
			_ = a.write("startup-error", []byte(err.Error()))
			fatal(err)
		}
		return
	}
	if os.Args[1] == "supervise" {
		if err = a.superviseLoop(); err != nil {
			_ = a.write("startup-error", []byte(err.Error()))
			fatal(err)
		}
		return
	}
	out, err := a.dispatch(os.Args[1:])
	if err != nil {
		fatal(err)
	}
	if err = json.NewEncoder(os.Stdout).Encode(out); err != nil {
		fatal(err)
	}
}

func fatal(err error)                 { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
func (a app) file(name string) string { return filepath.Join(a.base, name) }
func exists(p string) bool            { _, err := os.Stat(p); return err == nil }
func (a app) disabled() bool {
	return exists(filepath.Join(a.module, "disable")) || exists(filepath.Join(a.module, "remove"))
}
func (a app) write(name string, b []byte) error {
	tmp := a.file(name + ".tmp")
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, a.file(name))
}

func lock(p string) (*os.File, error) {
	f, err := os.OpenFile(p, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.New("another module operation is running; try again shortly")
	}
	return f, nil
}

// Start time prevents a stale PID file from identifying an unrelated process.
func readProcess(pid int) (processRecord, error) {
	p := fmt.Sprintf("/proc/%d", pid)
	b, err := os.ReadFile(p + "/stat")
	if err != nil {
		return processRecord{}, err
	}
	end := strings.LastIndexByte(string(b), ')')
	if end < 0 {
		return processRecord{}, errors.New("invalid process stat")
	}
	fields := strings.Fields(string(b[end+1:]))
	if len(fields) < 20 || fields[0] == "Z" {
		return processRecord{}, errors.New("process has exited")
	}
	exe, err := os.Readlink(p + "/exe")
	return processRecord{pid, fields[19], exe}, err
}
func (r processRecord) alive() bool {
	if r.PID <= 1 || r.Start == "" || r.Exe == "" {
		return false
	}
	current, err := readProcess(r.PID)
	return err == nil && current == r
}
func (a app) record(name string) processRecord {
	b, _ := os.ReadFile(a.file(name))
	var r processRecord
	_ = json.Unmarshal(b, &r)
	// Records may only refer to this module's two executable paths.
	if r.Exe != a.self && r.Exe != filepath.Join(a.module, "bin/tailscaled") {
		return processRecord{}
	}
	return r
}
func (a app) saveRecord(name string, pid int) error {
	r, err := readProcess(pid)
	if err != nil {
		return err
	}
	b, _ := json.Marshal(r)
	return a.write(name, b)
}
func (a app) running() bool { return a.record("supervisor.json").alive() && exists(a.file("ready")) }

func (a app) ts(timeout time.Duration, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	argv := append([]string{"--socket=" + a.file("tailscaled.sock")}, args...)
	out, err := exec.CommandContext(ctx, filepath.Join(a.module, "bin/tailscale"), argv...).CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("tailscale %s: %w: %s", args[0], err, strings.TrimSpace(string(out)))
	}
	return out, nil
}
func command(timeout time.Duration, name string, args ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	b, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return strings.TrimSpace(string(b)) + " (" + err.Error() + ")"
	}
	return strings.TrimSpace(string(b))
}

func (a app) preflight() error {
	if _, err := a.loadOptions(); err != nil {
		return fmt.Errorf("invalid module options: %w", err)
	}
	if a.disabled() {
		return errors.New("module is disabled or pending removal")
	}
	policy, err := os.ReadFile(a.file("initialized"))
	if err != nil || (string(policy) != "conservative\n" && string(policy) != "preserve\n") {
		return errors.New("choose a valid first-run policy before starting")
	}
	if err := a.validateIdentity(string(policy) == "preserve\n" || exists(a.file("policy-applied"))); err != nil {
		return err
	}
	if a.checkSystem != nil {
		return a.checkSystem()
	}
	if exists("/data/adb/service.d/tailscaled_service.sh") {
		return errors.New("retire the legacy tailscaled_service.sh launcher before starting this controller")
	}
	if !a.options().UserspaceFallback && !charDevice("/dev/net/tun") && !charDevice("/dev/tun") {
		return errors.New("kernel TUN device /dev/tun or /dev/net/tun is unavailable")
	}
	if _, err = net.InterfaceByName("tailscale0"); err == nil {
		return errors.New("tailscale0 already exists; stop the other Tailscale instance or reboot")
	}
	if err := foreignDaemon(); err != nil {
		return err
	}
	connectivity := command(4*time.Second, "/system/bin/dumpsys", "connectivity")
	if strings.Contains(connectivity, "VPN:com.tailscale.ipn") {
		return errors.New("disconnect the official Tailscale Android app first")
	}
	return nil
}

func (a app) start() error {
	if a.disabled() {
		return errors.New("enable the module and reboot first")
	}
	if !exists(a.file("initialized")) {
		return errors.New("choose a first-run policy in WebUI or run tsctl initialize conservative|preserve")
	}
	if a.running() {
		_ = os.Remove(a.file("paused"))
		return nil
	}
	if a.record("supervisor.json").alive() {
		return errors.New("daemon is still starting or stopping")
	}
	if exists(a.file("disconnected")) {
		return errors.New("intentionally disconnected; use Connect to resume")
	}
	if err := a.preflight(); err != nil {
		return err
	}
	_ = os.Remove(a.file("ready"))
	_ = os.Remove(a.file("startup-error"))
	_ = os.Remove(a.file("paused"))
	null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer null.Close()
	cmd := exec.Command(a.self, "supervise-loop")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = null, null, null
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err = cmd.Start(); err != nil {
		return err
	}
	defer cmd.Process.Release()
	for range 150 {
		if a.running() {
			return nil
		}
		if b, err := os.ReadFile(a.file("startup-error")); err == nil {
			return errors.New(string(b))
		}
		time.Sleep(200 * time.Millisecond)
	}
	_ = a.stop(false)
	return errors.New("startup timed out; inspect logs")
}

// superviseLoop distinguishes an intentional clean shutdown from an
// unexpected daemon/engine exit. The latter is retried with bounded backoff;
// The lifetime lock and process record remain owned throughout backoff.
func (a app) superviseLoop() error {
	lifetime, err := lock(a.file("supervisor.lock"))
	if err != nil {
		return err
	}
	defer lifetime.Close()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(signals)
	if err := a.saveRecord("supervisor.json", os.Getpid()); err != nil {
		return err
	}
	defer os.Remove(a.file("supervisor.json"))
	defer os.Remove(a.file("recovery"))
	budget := recoveryBudget{}
	var last error
	for {
		if a.disabled() || exists(a.file("paused")) {
			return nil
		}
		select {
		case <-signals:
			return nil
		default:
		}
		started := time.Now()
		last = a.runDaemon(signals)
		if last == nil || a.disabled() || exists(a.file("paused")) || exists(a.file("disconnected")) {
			return nil
		}
		backoff, retry := budget.failed(time.Since(started))
		if !retry {
			break
		}
		// Per-attempt process/DNS cleanup has completed before restarting.
		message := fmt.Sprintf("%v; recovery attempt %d in %s", last, budget.failures, backoff)
		_ = a.write("recovery", []byte(message))
		fmt.Fprintf(&rollingLog{name: a.file("tailscaled.log")}, "%s %s\n", time.Now().UTC().Format(time.RFC3339), message)
		if !a.waitRecovery(signals, backoff) {
			return nil
		}
	}
	return fmt.Errorf("automatic recovery stopped after repeated failures: %w", last)
}

// Eight consecutive short-lived failures exhaust the budget (seven retries).
// A five-minute run resets it, allowing recovery from a later isolated failure.
type recoveryBudget struct{ failures int }

func (b *recoveryBudget) failed(uptime time.Duration) (time.Duration, bool) {
	if uptime >= 5*time.Minute {
		b.failures = 0
	}
	b.failures++
	if b.failures >= 8 {
		return 0, false
	}
	return min(time.Second<<(b.failures-1), 60*time.Second), true
}

func (a app) waitRecovery(signals <-chan os.Signal, delay time.Duration) bool {
	deadline := time.NewTimer(delay)
	defer deadline.Stop()
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for {
		if a.disabled() || exists(a.file("paused")) || exists(a.file("disconnected")) {
			return false
		}
		select {
		case <-signals:
			return false
		case <-tick.C:
		case <-deadline.C:
			return true
		}
	}
}

func daemonExit(err error) error {
	if err == nil {
		return errors.New("tailscaled exited unexpectedly with status 0")
	}
	return fmt.Errorf("tailscaled exited unexpectedly: %w", err)
}

func terminate(r processRecord) error {
	if !r.alive() {
		return nil
	}
	if err := syscall.Kill(r.PID, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	for range 100 {
		if !r.alive() {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return errors.New("process did not exit after SIGTERM; reboot to recover without killing unrelated processes")
}
func (a app) stop(pause bool) error {
	if pause {
		if err := a.write("paused", []byte("Stopped from module control\n")); err != nil {
			return err
		}
	}
	if err := terminate(a.record("supervisor.json")); err != nil {
		return err
	}
	// Also handles a daemon orphaned by a killed supervisor.
	if err := terminate(a.record("daemon.json")); err != nil {
		return err
	}
	_ = os.Remove(a.file("ready"))
	dnsErr := a.clearDNSRedirect()
	if dnsErr != nil {
		return dnsErr
	}
	return nil
}

// Keep a bounded log even when the WebUI is never opened.
type rollingLog struct {
	mu   sync.Mutex
	name string
}

func (w *rollingLog) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if info, err := os.Stat(w.name); err == nil && info.Size()+int64(len(p)) > 512*1024 {
		if err = os.Rename(w.name, w.name+".1"); err != nil {
			return 0, err
		}
	}
	f, err := os.OpenFile(w.name, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	if len(p) > 512*1024 {
		_, err = f.Write(p[len(p)-512*1024:])
		return len(p), err
	}
	return f.Write(p)
}

func (a app) runDaemon(signals <-chan os.Signal) error {
	var err error
	if err = a.preflight(); err != nil {
		return err
	}
	// Recover only this controller's journaled DNS rules.
	if err = a.clearDNSRedirect(); err != nil {
		return err
	}
	setup := a.setupTUN
	if setup == nil {
		setup = ensureTUN
	}
	if err = setup(); err != nil && !a.options().UserspaceFallback {
		return err
	}
	defer os.Remove(a.file("ready"))
	log := &rollingLog{name: a.file("tailscaled.log")}
	fmt.Fprintf(log, "\n%s Starting native Tailscale\n", time.Now().UTC().Format(time.RFC3339))
	// The socket is private to this module and removed only with our lifetime lock.
	_ = os.Remove(a.file("tailscaled.sock"))
	tun := "tailscale0"
	if a.options().UserspaceFallback {
		tun += ",userspace-networking"
	}
	cmd := exec.Command(filepath.Join(a.module, "bin/tailscaled"),
		"--state="+a.file("tailscaled.state"), "--statedir="+a.base,
		"--socket="+a.file("tailscaled.sock"), "--tun="+tun, "--port=41641", "--no-logs-no-support")
	cmd.Env = append(os.Environ(), "TS_MODULE_DNS=true", "TS_MODULE_SEARCH="+strconv.FormatBool(a.options().SearchDomains))
	cmd.Stdout, cmd.Stderr = log, log
	if err = cmd.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	defer func() {
		// Detach app DNS before shutting down its resolver.
		if err := a.clearDNSRedirect(); err != nil {
			fmt.Fprintf(log, "DNS cleanup: %v\n", err)
		}
		// os.Process tracks an already-reaped child and will not signal a
		// reused PID after cmd.Wait has completed.
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(7 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
		_ = os.Remove(a.file("daemon.json"))
		_ = os.Remove(a.file("tailscaled.sock"))
	}()
	if err = a.saveRecord("daemon.json", cmd.Process.Pid); err != nil {
		return err
	}
	ready := false
	for range 60 {
		select {
		case <-signals:
			return nil
		case err = <-done:
			done <- err
			return daemonExit(err)
		default:
		}
		if a.disabled() || exists(a.file("paused")) {
			return nil
		}
		if exists(a.file("tailscaled.sock")) {
			if _, _, err = a.readDNSBackend(); err == nil {
				ready = true
				break
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !ready {
		return errors.New("tailscaled did not become ready; inspect logs")
	}
	if !exists(a.file("policy-applied")) {
		policy, readErr := os.ReadFile(a.file("initialized"))
		if readErr != nil {
			return readErr
		}
		if string(policy) == "conservative\n" {
			if _, err = a.ts(4*time.Second, "set", "--accept-dns=false", "--accept-routes=false", "--shields-up=true", "--ssh=false", "--exit-node=", "--exit-node-allow-lan-access=false"); err != nil {
				return err
			}
		} else if string(policy) != "preserve\n" {
			return errors.New("invalid saved first-run policy")
		}
		if err = a.write("policy-applied", []byte("1\n")); err != nil {
			return err
		}
	}
	// Disconnect can race a daemon exit during backoff. Enforce the saved
	// intent on manual Start too, without rewriting the private state file.
	if exists(a.file("disconnected")) {
		if _, err = a.ts(4*time.Second, "down"); err != nil {
			return err
		}
	}
	if err = a.write("ready", []byte("1\n")); err != nil {
		return err
	}
	_ = os.Remove(a.file("recovery"))
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	lastDNSError := ""
	for {
		select {
		case <-signals:
			return nil
		case err = <-done:
			// Restore the completion result for the deferred shutdown path.
			done <- err
			return daemonExit(err)
		case <-tick.C:
			if a.disabled() || exists(a.file("paused")) {
				return nil
			}
			msg := ""
			if err := a.reconcileDNSRedirect(); err != nil {
				msg = err.Error()
			}
			if msg != "" && msg != lastDNSError {
				fmt.Fprintf(log, "DNS integration: %s\n", msg)
			}
			lastDNSError = msg
		}
	}
}

type tailStatus struct {
	BackendState string
	AuthURL      string
	TailscaleIPs []string
	Health       []string
	Self         *struct {
		HostName, DNSName string
		Online            bool
	}
	Peer map[string]struct {
		ID, HostName           string
		TailscaleIPs           []string
		ExitNodeOption, Online bool
	}
}
type prefs struct {
	RouteAll, ShieldsUp, ExitNodeAllowLANAccess, CorpDNS, RunSSH bool
	Hostname, ExitNodeIP, ExitNodeID                             string
}

func (a app) status() map[string]any {
	recovering := !a.running() && a.record("supervisor.json").alive() && exists(a.file("recovery"))
	s := map[string]any{"running": a.running(), "recovering": recovering, "paused": exists(a.file("paused")), "disconnected": exists(a.file("disconnected")), "version": version, "disabled": a.disabled(), "initialized": exists(a.file("initialized")), "options": a.options(), "coreVersion": "1.98.8"}
	dns := map[string]any{"enabled": false, "active": false}
	if b, err := os.ReadFile(a.file("dns-redirect-error")); err == nil {
		dns["error"] = strings.TrimSpace(string(b))
	}
	s["dns"] = dns
	s["tun"] = a.hasTUN()
	if b, err := os.ReadFile(a.file("startup-error")); err == nil {
		s["error"] = string(b)
	}
	if recovering {
		if b, err := os.ReadFile(a.file("recovery")); err == nil {
			s["recovery"] = string(b)
		}
	}
	if !a.running() {
		return s
	}
	ts, p, err := a.readDNSBackend()
	if err != nil {
		s["error"] = err.Error()
		return s
	}
	s["tailscale"], s["prefs"] = ts, p
	dns["enabled"] = p.CorpDNS
	journal := a.dnsJournal()
	dns["active"] = p.CorpDNS && ts.BackendState == "Running" && journal.Active && dns["error"] == nil
	dns["families"] = journal.Families
	if len(journal.Skipped) != 0 {
		dns["skipped"] = journal.Skipped
	}
	return s
}

var hostnameRE = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

func settingArgs(name, value string) ([]string, error) {
	switch name {
	case "accept-routes", "shields-up", "exit-node-allow-lan-access", "accept-dns", "ssh", "capture-dns", "hotspot-dns", "search-domains", "userspace-fallback":
		if value != "true" && value != "false" {
			return nil, errors.New("setting requires true or false")
		}
	case "hotspot-interface":
		if value != "" && !interfaceRE.MatchString(value) {
			return nil, errors.New("enter one exact interface name (no wildcards)")
		}
	case "hostname":
		if !hostnameRE.MatchString(value) {
			return nil, errors.New("hostname must contain 1–63 letters, numbers or hyphens, with a letter or number at either end")
		}
	case "exit-node":
		if value != "" {
			if _, err := netip.ParseAddr(value); err != nil {
				return nil, errors.New("choose an exit-node IP address, or empty to disable")
			}
		}
		if value == "" {
			return []string{"set", "--exit-node="}, nil
		}
	default:
		return nil, errors.New("unsupported setting")
	}
	return []string{"set", "--" + name + "=" + value}, nil
}

func (a app) dispatch(args []string) (any, error) {
	if len(args) == 0 {
		return nil, errors.New("missing command")
	}
	name := args[0]
	if name == "set" {
		if len(args) != 3 {
			return nil, errors.New("usage: tsctl set <name> <value>")
		}
		if _, err := settingArgs(args[1], args[2]); err != nil {
			return nil, err
		}
	} else if name == "initialize" {
		if len(args) != 2 || (args[1] != "conservative" && args[1] != "preserve") {
			return nil, errors.New("choose initialize conservative|preserve")
		}
	} else if name == "purge" {
		if len(args) != 2 || args[1] != "erase-identity" {
			return nil, errors.New("purge requires the explicit erase-identity confirmation")
		}
	} else if len(args) != 1 {
		return nil, errors.New("unexpected arguments")
	}
	switch name {
	case "status":
		return a.status(), nil
	case "logs":
		b, err := os.ReadFile(a.file("tailscaled.log"))
		if errors.Is(err, os.ErrNotExist) {
			return map[string]string{"text": "No logs yet."}, nil
		}
		if len(b) > 32768 {
			b = b[len(b)-32768:]
		}
		return map[string]string{"text": string(b)}, err
	case "diagnostics":
		return map[string]any{"status": a.status(), "addresses": command(3*time.Second, "/system/bin/ip", "addr", "show", "tailscale0"),
			"rules4": command(3*time.Second, "/system/bin/ip", "-4", "rule", "show"), "rules6": command(3*time.Second, "/system/bin/ip", "-6", "rule", "show"),
			"routes4": command(3*time.Second, "/system/bin/ip", "-4", "route", "show", "table", "52"), "routes6": command(3*time.Second, "/system/bin/ip", "-6", "route", "show", "table", "52")}, nil
	case "start", "boot", "stop", "restart", "connect", "disconnect", "logout", "set", "initialize", "purge":
	default:
		return nil, errors.New("unsupported command")
	}
	l, err := lock(a.file("control.lock"))
	if err != nil {
		return nil, err
	}
	defer l.Close()
	if name == "set" && isModuleOption(args[1]) {
		if err = a.setOption(args[1], args[2]); err != nil {
			return nil, err
		}
		return a.status(), nil
	}
	if name == "set" && args[1] == "accept-dns" {
		if err = a.setDNSRedirect(args[2]); err != nil {
			return nil, err
		}
		return a.status(), nil
	}
	switch name {
	case "initialize":
		if exists(a.file("initialized")) {
			return nil, errors.New("already initialized; change individual settings instead")
		}
		if err := a.validateIdentity(args[1] == "preserve"); err != nil {
			return nil, err
		}
		if args[1] == "conservative" && exists(a.file("tailscaled.state")) {
			return nil, errors.New("existing identity: choose preserve, then change individual settings explicitly")
		}
		if exists(a.file("tmp/tailscaled.state")) {
			return nil, errors.New("legacy tmp identity exists; choose/migrate its state path explicitly first")
		}
		err = a.write("initialized", []byte(args[1]+"\n"))
	case "purge":
		err = a.purge()
	case "boot":
		if !exists(a.file("initialized")) || exists(a.file("paused")) || exists(a.file("disconnected")) || a.disabled() {
			return map[string]string{"message": "Service remains stopped"}, nil
		}
		err = a.start()
	case "start":
		err = a.start()
	case "stop":
		err = a.stop(true)
	case "restart":
		if err = a.stop(false); err == nil {
			err = a.start()
		}
	case "connect":
		_ = os.Remove(a.file("disconnected"))
		if err = a.start(); err != nil {
			break
		}
		err = a.connect()
	case "disconnect":
		// Save intent before either operation; a crash must not reconnect.
		if err = a.write("disconnected", []byte("Stopped by disconnect\n")); err != nil {
			return nil, err
		}
		err = a.clearDNSRedirect()
		if a.running() {
			_, downErr := a.ts(6*time.Second, "down")
			err = errors.Join(err, downErr)
		}
	case "logout", "set":
		if !a.running() {
			return nil, errors.New("start the service first")
		}
		argv := []string{"logout"}
		if name == "set" {
			argv, err = settingArgs(args[1], args[2])
		}
		if err == nil {
			_, err = a.ts(6*time.Second, argv...)
		}
	}
	if err != nil {
		return nil, err
	}
	return a.status(), nil
}

// Ensure rollingLog can be used for stdout and stderr concurrently by os/exec.
var _ io.Writer = (*rollingLog)(nil)

func (a app) hasTUN() bool {
	if a.tunPresent != nil {
		return a.tunPresent()
	}
	_, err := net.InterfaceByName("tailscale0")
	return err == nil
}

func charDevice(p string) bool {
	info, err := os.Stat(p)
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
func ensureTUN() error {
	if charDevice("/dev/net/tun") {
		return nil
	}
	if !charDevice("/dev/tun") {
		return errors.New("kernel TUN is unavailable")
	}
	if err := os.MkdirAll("/dev/net", 0755); err != nil {
		return err
	}
	// wireguard-go opens the Linux path. Never overwrite an existing entry.
	// This shared /dev alias is harmless after stop and disappears on reboot.
	return os.Symlink("/dev/tun", "/dev/net/tun")
}

func (a app) localAPI(method, endpoint, body string) error {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", a.file("tailscaled.sock"))
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	req, err := http.NewRequest(method, "http://local-tailscaled.sock/localapi/v0/"+endpoint, strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return fmt.Errorf("Tailscale %s: %s: %s", endpoint, res.Status, b)
	}
	return nil
}
func (a app) connect() error {
	// Mask only WantRunning: all saved preferences survive reconnect and login.
	if err := a.localAPI("PATCH", "prefs", `{"WantRunning":true,"WantRunningSet":true}`); err != nil {
		return err
	}
	b, err := a.ts(4*time.Second, "status", "--json")
	var ts tailStatus
	if json.Unmarshal(b, &ts) != nil {
		return fmt.Errorf("cannot read login state: %v", err)
	}
	if ts.AuthURL != "" {
		return nil
	}
	// PATCH is asynchronous on a freshly started backend. Give it a short
	// window to leave Stopped before deciding that an explicit Start is needed.
	for range 15 {
		if ts.BackendState != "Stopped" && ts.BackendState != "Starting" {
			break
		}
		time.Sleep(200 * time.Millisecond)
		b, err = a.ts(2*time.Second, "status", "--json")
		if json.Unmarshal(b, &ts) != nil {
			return fmt.Errorf("cannot read login state: %v", err)
		}
	}
	if ts.BackendState == "NoState" {
		if err := a.localAPI("POST", "start", `{}`); err != nil {
			return err
		}
		b, err = a.ts(4*time.Second, "status", "--json")
		if json.Unmarshal(b, &ts) != nil {
			return fmt.Errorf("cannot read login state: %v", err)
		}
	}
	if ts.BackendState == "Stopped" {
		return errors.New("Tailscale did not accept the connect request; inspect diagnostics")
	}
	if ts.BackendState == "NeedsLogin" || ts.BackendState == "NoState" {
		return a.localAPI("POST", "login-interactive", "")
	}
	return nil
}
