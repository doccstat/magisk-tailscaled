// SPDX-License-Identifier: MIT
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"
)

const diagnosticLimit = 32 * 1024

type diagnosticResult struct {
	Output    string `json:"output"`
	Error     string `json:"error,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
}

type diagnosticBuffer struct {
	data      []byte
	truncated bool
}

func (b *diagnosticBuffer) Write(p []byte) (int, error) {
	n := min(len(p), diagnosticLimit-len(b.data))
	b.data = append(b.data, p[:n]...)
	b.truncated = b.truncated || n < len(p)
	return len(p), nil
}

func (a app) diagnosticCommand(timeout time.Duration, name string, args ...string) diagnosticResult {
	var b diagnosticBuffer
	var err error
	if a.android != nil && strings.HasPrefix(name, "/system/bin/") {
		var out []byte
		out, err = a.android(filepath.Base(name), args...)
		_, _ = b.Write(out)
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Stdout, cmd.Stderr = &b, &b
		cmd.WaitDelay = 500 * time.Millisecond
		err = cmd.Run()
		if ctx.Err() != nil {
			err = ctx.Err()
		}
	}
	r := diagnosticResult{Output: strings.TrimSpace(string(b.data)), Truncated: b.truncated}
	if err != nil {
		r.Error = err.Error()
	}
	return r
}

func diagnosticFile(path string, tail bool) diagnosticResult {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return diagnosticResult{Error: err.Error()}
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return diagnosticResult{Error: err.Error()}
	}
	if !info.Mode().IsRegular() {
		return diagnosticResult{Error: "not a regular file"}
	}
	truncated := info.Size() > diagnosticLimit
	if tail && truncated {
		if _, err = f.Seek(-diagnosticLimit, io.SeekEnd); err != nil {
			return diagnosticResult{Error: err.Error()}
		}
	}
	b, err := io.ReadAll(io.LimitReader(f, diagnosticLimit))
	if tail && truncated {
		// A partial leading line may have lost the prefix identifying a secret.
		if newline := bytes.IndexByte(b, '\n'); newline >= 0 {
			b = b[newline+1:]
		} else {
			b = nil
		}
	}
	r := diagnosticResult{Output: string(b), Truncated: truncated}
	if err != nil {
		r.Error = err.Error()
	}
	return r
}

type diagnosticResolver struct {
	Addr            string
	UseWithExitNode bool
}

type diagnosticDNSConfig struct {
	Resolvers         []diagnosticResolver
	FallbackResolvers []diagnosticResolver
	Routes            map[string][]diagnosticResolver
	Domains           []string
	Proxied           bool
}

var diagnosticNameRE = regexp.MustCompile(`^[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,62})(?:\.[a-zA-Z0-9_][a-zA-Z0-9_-]{0,62})*\.?$`)

func validateDiagnosticName(name string) error {
	if name != "" && (len(strings.TrimSuffix(name, ".")) > 253 || !diagnosticNameRE.MatchString(name)) {
		return errors.New("DNS test name must be an ASCII or punycode hostname, without spaces or a URL scheme")
	}
	return nil
}

func (a app) diagnostics(name string) (map[string]any, error) {
	if err := validateDiagnosticName(name); err != nil {
		return nil, err
	}
	probe := func(tool string, args ...string) diagnosticResult {
		return a.diagnosticCommand(2*time.Second, "/system/bin/"+tool, args...)
	}
	status := a.status()
	var cfg diagnosticDNSConfig
	dns := map[string]any{"captureJournal": a.dnsJournal()}
	if err := a.readLocalAPI("dns-config", &cfg); err != nil {
		dns["configurationError"] = err.Error()
	} else {
		dns["configuration"] = cfg
	}
	dns["privateDNSMode"] = probe("settings", "get", "global", "private_dns_mode")
	dns["privateDNSProvider"] = probe("settings", "get", "global", "private_dns_specifier")
	dns["androidResolver"] = probe("dumpsys", "dnsresolver")
	if name != "" {
		queries := map[string]diagnosticResult{}
		for _, kind := range []string{"A", "AAAA"} {
			queries[kind] = a.diagnosticCommand(6*time.Second, filepath.Join(a.module, "bin/tailscale"), "--socket="+a.file("tailscaled.sock"), "dns", "query", "--json", name, kind)
		}
		dns["query"] = map[string]any{"name": name, "source": "Tailscale internal forwarder (not Android app capture)", "results": queries}
	}
	network := map[string]diagnosticResult{
		"addresses":        probe("ip", "addr", "show", "tailscale0"),
		"captureInterface": probe("ip", "link", "show", "dev", dnsCaptureInterface),
	}
	for _, family := range []string{"4", "6"} {
		network["rules"+family] = probe("ip", "-"+family, "rule", "show")
		network["routes"+family] = probe("ip", "-"+family, "route", "show", "table", "52")
		network["captureRoutes"+family] = probe("ip", "-"+family, "route", "show", "table", dnsCaptureTable)
		tool, target := "iptables", dnsIPv4
		if family == "6" {
			tool, target = "ip6tables", dnsIPv6
		}
		network["quad100Route"+family] = probe("ip", "-"+family, "route", "get", target)
		for _, table := range []string{"mangle", "nat"} {
			prefix, hooks := "mangle", "mangleOutputHooks"
			if table == "nat" {
				prefix, hooks = "", "dnsOutputHooks"
			} // Preserve schema-1 NAT fields.
			for _, chain := range []string{dnsRedirectChain, hotspotChain} {
				network[prefix+chain+family] = probe(tool, "-w", "1", "-t", table, "-n", "-v", "-x", "-L", chain)
			}
			network[hooks+family] = probe(tool, "-w", "1", "-t", table, "-S", "OUTPUT")
		}
	}
	report := map[string]any{
		"schema": 1, "createdAt": time.Now().UTC().Format(time.RFC3339), "redacted": true,
		"status": status, "dns": dns, "network": network,
		"environment": map[string]any{
			"androidRelease": probe("getprop", "ro.build.version.release"),
			"androidSDK":     probe("getprop", "ro.build.version.sdk"),
			"kernel":         probe("uname", "-r"), "architecture": runtime.GOARCH, "controllerGo": runtime.Version(),
		},
		"build": diagnosticFile(filepath.Join(a.module, "build-info.json"), false),
		"logs": map[string]diagnosticResult{
			"current":  diagnosticFile(a.file("tailscaled.log"), true),
			"previous": diagnosticFile(a.file("tailscaled.log.1"), true),
		},
	}
	// Normalize typed projections before scrubbing values AND domain/peer map keys.
	b, err := json.Marshal(report)
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(b, &report); err != nil {
		return nil, err
	}
	r := diagnosticRedactor{aliases: map[string]string{}}
	r.identifiers(report)
	return r.scrub(report).(map[string]any), nil
}

func (a app) exportDiagnostics(path, name string, overwrite bool) (any, error) {
	if !filepath.IsAbs(path) || strings.ContainsAny(path, "\x00\r\n") {
		return nil, errors.New("choose an absolute output file path")
	}
	if err := validateDiagnosticName(name); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return nil, errors.New("choose a regular output file, not a directory or symbolic link")
		}
		if !overwrite {
			return map[string]any{"path": path, "needsOverwrite": true}, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	report, err := a.diagnostics(name)
	if err != nil {
		return nil, err
	}
	b, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, err
	}
	var f *os.File
	if overwrite {
		// Replace only after the complete report is written, without following links.
		f, err = os.CreateTemp(filepath.Dir(path), ".tsctl-report-*")
	} else {
		f, err = os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if errors.Is(err, os.ErrExist) {
			return map[string]any{"path": path, "needsOverwrite": true}, nil
		}
	}
	if err != nil {
		return nil, fmt.Errorf("cannot export to %s: %w", path, err)
	}
	if overwrite {
		defer os.Remove(f.Name())
	}
	_, writeErr := f.Write(append(b, '\n'))
	if err := errors.Join(writeErr, f.Close()); err != nil {
		if !overwrite {
			_ = os.Remove(path)
		}
		return nil, fmt.Errorf("cannot export to %s: %w", path, err)
	}
	if overwrite {
		if err := os.Rename(f.Name(), path); err != nil {
			return nil, fmt.Errorf("cannot replace %s: %w", path, err)
		}
	}
	return map[string]string{"path": path}, nil
}

var (
	diagnosticSecretRE = regexp.MustCompile(`(?i)(?:tskey-[a-z0-9_-]+|(?:privkey|nodekey|machinekey|discokey|discopriv):[a-z0-9]+|bearer\s+[^\s"']+|(?:authorization|auth[_-]?key|api[_-]?key|access[_-]?token|refresh[_-]?token|password|private\w*key)["']?\s*[:=]\s*(?:"[^"]*"|'[^']*'|(?:bearer\s+)?[^\s,;]+))`)
	diagnosticURLRE    = regexp.MustCompile(`(?i)\b(?:https?|wss?)://[^\s"'<>]+`)
	diagnosticEmailRE  = regexp.MustCompile(`[\pL\pN_.+%-]+@[\pL\pN.-]+\.[\pL]+`)
	diagnosticMACRE    = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b`)
	diagnosticIPRE     = regexp.MustCompile(`(?:[0-9]{1,3}\.){3}[0-9]{1,3}|[0-9a-fA-F]*:[0-9a-fA-F:.]+(?:%[a-zA-Z0-9_.-]+)?`)
	diagnosticDomainRE = regexp.MustCompile(`(?:[\pL\pN_-]+\.)+[\pL][\pL\pN_-]*\.?`)
	diagnosticWordRE   = regexp.MustCompile(`[\pL\pN_.-]+`)
)

type diagnosticRedactor struct {
	aliases map[string]string
	phrases []string
}

func (r *diagnosticRedactor) alias(kind, value string) string {
	key := strings.ToLower(strings.TrimSuffix(value, "."))
	if r.aliases[key] == "" {
		r.aliases[key] = fmt.Sprintf("[%s-%d]", kind, len(r.aliases)+1)
	}
	return r.aliases[key]
}

func diagnosticKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func (r *diagnosticRedactor) identifiers(v any) {
	switch v := v.(type) {
	case map[string]any:
		for _, k := range diagnosticKeys(v) {
			switch strings.ToLower(k) {
			case "hostname", "dnsname", "name", "id", "exitnodeid":
				if s, ok := v[k].(string); ok && s != "" {
					r.alias("name", s)
					if strings.ContainsAny(s, " \t") {
						r.phrases = append(r.phrases, s)
					}
				}
			}
			r.identifiers(v[k])
		}
	case []any:
		for _, item := range v {
			r.identifiers(item)
		}
	}
}

func (r *diagnosticRedactor) text(s string) string {
	for _, phrase := range r.phrases {
		s = regexp.MustCompile("(?i)"+regexp.QuoteMeta(phrase)).ReplaceAllString(s, r.alias("name", phrase))
	}
	s = diagnosticSecretRE.ReplaceAllString(s, "[redacted-secret]")
	for _, pattern := range []*regexp.Regexp{diagnosticURLRE, diagnosticEmailRE, diagnosticMACRE} {
		s = pattern.ReplaceAllStringFunc(s, func(value string) string { return r.alias("identifier", value) })
	}
	s = diagnosticIPRE.ReplaceAllStringFunc(s, func(value string) string {
		ip, err := netip.ParseAddr(value)
		if err != nil || ip.IsLoopback() || ip.IsUnspecified() || value == dnsIPv4 || value == dnsIPv6 {
			return value
		}
		kind := "ipv6"
		if ip.Is4() {
			kind = "ipv4"
		}
		if netip.MustParsePrefix("100.64.0.0/10").Contains(ip) || netip.MustParsePrefix("fd7a:115c:a1e0::/48").Contains(ip) {
			kind += "-tailnet"
		} else if ip.IsPrivate() {
			kind += "-private"
		}
		return r.alias(kind, value)
	})
	s = diagnosticWordRE.ReplaceAllStringFunc(s, func(value string) string {
		if alias := r.aliases[strings.ToLower(strings.TrimSuffix(value, "."))]; alias != "" {
			return alias
		}
		return value
	})
	return diagnosticDomainRE.ReplaceAllStringFunc(s, func(value string) string { return r.alias("domain", value) })
}

func (r *diagnosticRedactor) scrub(v any) any {
	switch v := v.(type) {
	case string:
		return r.text(v)
	case map[string]any:
		out := make(map[string]any, len(v))
		for _, k := range diagnosticKeys(v) {
			switch strings.ToLower(k) {
			case "authurl", "privatenodekey", "privatemachinekey":
				out[k] = "[redacted-secret]"
			case "version", "coreversion", "controllergo":
				out[k] = v[k]
			case "hostname", "dnsname", "name", "id", "exitnodeid":
				if s, ok := v[k].(string); ok && s != "" {
					out[k] = r.alias("name", s)
				} else {
					out[k] = r.scrub(v[k])
				}
			case "routes", "peer":
				if entries, ok := v[k].(map[string]any); ok {
					clean := map[string]any{}
					for _, key := range diagnosticKeys(entries) {
						clean[r.alias("name", key)] = r.scrub(entries[key])
					}
					out[k] = clean
				} else {
					out[k] = r.scrub(v[k])
				}
			default:
				out[k] = r.scrub(v[k])
			}
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = r.scrub(item)
		}
		return out
	default:
		return v
	}
}
