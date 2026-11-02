// SPDX-License-Identifier: MIT
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
)

type moduleOptions struct {
	CaptureDNS        bool   `json:"captureDNS"`
	HotspotDNS        bool   `json:"hotspotDNS"`
	HotspotInterface  string `json:"hotspotInterface"`
	SearchDomains     bool   `json:"searchDomains"`
	UserspaceFallback bool   `json:"userspaceFallback"`
}

func (a app) loadOptions() (o moduleOptions, err error) {
	b, err := os.ReadFile(a.file("module-options.json"))
	if errors.Is(err, os.ErrNotExist) {
		return o, nil
	}
	if err != nil {
		return o, err
	}
	err = json.Unmarshal(b, &o)
	if err == nil && o.HotspotDNS && !interfaceRE.MatchString(o.HotspotInterface) {
		err = errors.New("hotspot capture requires an explicit interface")
	}
	return o, err
}
func (a app) options() moduleOptions { o, _ := a.loadOptions(); return o }

var interfaceRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$`)

func isModuleOption(name string) bool {
	switch name {
	case "capture-dns", "hotspot-dns", "hotspot-interface", "search-domains", "userspace-fallback":
		return true
	}
	return false
}
func (a app) setOption(name, value string) error {
	o, err := a.loadOptions()
	if err != nil {
		return err
	}
	enabled := value == "true"
	switch name {
	case "capture-dns":
		o.CaptureDNS = enabled
	case "hotspot-dns":
		if enabled && !interfaceRE.MatchString(o.HotspotInterface) {
			return errors.New("set hotspot-interface before enabling hotspot DNS capture")
		}
		o.HotspotDNS = enabled
	case "hotspot-interface":
		if value == "" && o.HotspotDNS {
			return errors.New("disable hotspot DNS before clearing its interface")
		}
		o.HotspotInterface = value
	case "search-domains", "userspace-fallback":
		if a.record("supervisor.json").alive() || a.record("daemon.json").alive() {
			return errors.New("stop the service before changing this daemon option")
		}
		if name == "search-domains" {
			o.SearchDomains = enabled
		} else {
			o.UserspaceFallback = enabled
		}
	default:
		return errors.New("unsupported module option")
	}
	// Keep cleanup and scope replacement atomic with respect to reconciliation.
	l, err := lock(a.file("dns.lock"))
	if err != nil {
		return err
	}
	defer l.Close()
	if err = a.clearDNSLocked(true); err != nil {
		return err
	}
	b, err := json.Marshal(o)
	if err != nil {
		return err
	}
	return a.write("module-options.json", b)
}

func (a app) validateIdentity(required bool) error {
	info, err := os.Lstat(a.file("tailscaled.state"))
	if errors.Is(err, os.ErrNotExist) && !required {
		return nil
	}
	if err != nil {
		return fmt.Errorf("identity unavailable; restore it or explicitly erase state before creating another: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() == 0 {
		return errors.New("identity must be a nonempty regular file, not a symlink")
	}
	return nil
}

func foreignDaemon() error {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return err
	}
	for _, e := range entries {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		b, _ := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))
		parts := bytes.Split(b, []byte{0})
		if len(parts) > 0 && filepath.Base(string(parts[0])) == "tailscaled" {
			return fmt.Errorf("another tailscaled is running (PID %s); stop it first", e.Name())
		}
	}
	return nil
}

func (a app) purge() error {
	if err := a.stop(true); err != nil {
		return err
	}
	if a.checkSystem == nil {
		if err := foreignDaemon(); err != nil {
			return err
		}
	}
	info, err := os.Lstat(a.base)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("refusing to erase a redirected state directory")
	}
	entries, err := os.ReadDir(a.base)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		switch entry.Name() {
		case "control.lock", "supervisor.lock", "dns.lock", "paused":
			continue
		}
		if err := os.RemoveAll(a.file(entry.Name())); err != nil {
			return err
		}
	}
	return nil
}
