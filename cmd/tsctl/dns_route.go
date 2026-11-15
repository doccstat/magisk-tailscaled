// SPDX-License-Identifier: MIT
package main

import (
	"errors"
	"fmt"
	"strings"
)

const dnsCaptureInterface = "tsdns0"
const dnsCaptureTable = "5300"
const dnsCapturePriority = "12400"
const dnsCaptureMark = "0x40000000/0x40000000"

func (a app) dnsIP(family string, args ...string) (string, error) {
	flag := "-4"
	if family == "ipv6" {
		flag = "-6"
	}
	return a.dnsCommand("ip", append([]string{flag}, args...)...)
}

// Reserve one table and one priority; never replace another owner's rules.
func (a app) dnsRouteState(family string) (route, rule bool, err error) {
	routes, err := a.dnsIP(family, "route", "show", "table", dnsCaptureTable)
	if err != nil {
		if !strings.Contains(err.Error(), "FIB table does not exist") {
			return false, false, err
		}
		routes = "" // Some ip versions print the missing-table error on stderr.
	}
	if routes != "" {
		fields := strings.Fields(routes)
		valid := len(fields) >= 7 && fields[0] == "default" && len(fields)%2 == 1
		seen := map[string]bool{}
		want := map[string]string{"dev": dnsCaptureInterface, "proto": "static", "scope": "link", "metric": "1", "pref": "medium"}
		for i := 1; valid && i < len(fields); i += 2 {
			valid = want[fields[i]] == fields[i+1] && !seen[fields[i]]
			seen[fields[i]] = true
		}
		if !valid || !seen["dev"] || !seen["proto"] || !seen["metric"] {
			return false, false, fmt.Errorf("DNS routing table %s is occupied by another route", dnsCaptureTable)
		}
		route = true
	}
	rules, err := a.dnsIP(family, "rule", "show", "pref", dnsCapturePriority)
	if err != nil {
		return route, false, err
	}
	if rules != "" {
		want := dnsCapturePriority + ": from all fwmark " + dnsCaptureMark + " lookup " + dnsCaptureTable
		if strings.Join(strings.Fields(rules), " ") != want {
			return route, false, fmt.Errorf("DNS rule priority %s is occupied by another rule", dnsCapturePriority)
		}
		rule = true
	}
	return route, rule, nil
}

func (a app) installDNSRoutes(family string) error {
	route, rule, err := a.dnsRouteState(family)
	if err != nil {
		return err
	}
	if route || rule {
		return errors.New("DNS routing cleanup incomplete")
	}
	if _, err = a.dnsIP(family, "route", "add", "default", "dev", dnsCaptureInterface, "table", dnsCaptureTable, "proto", "static", "metric", "1"); err != nil {
		return err
	}
	_, err = a.dnsIP(family, "rule", "add", "pref", dnsCapturePriority, "fwmark", dnsCaptureMark, "lookup", dnsCaptureTable)
	return err
}

func (a app) clearDNSRoutes(family string) error {
	route, rule, err := a.dnsRouteState(family)
	if err != nil {
		return err
	}
	if rule {
		if _, err = a.dnsIP(family, "rule", "del", "pref", dnsCapturePriority, "fwmark", dnsCaptureMark, "lookup", dnsCaptureTable); err != nil {
			return err
		}
	}
	if route {
		_, err = a.dnsIP(family, "route", "del", "default", "dev", dnsCaptureInterface, "table", dnsCaptureTable, "proto", "static", "metric", "1")
	}
	return err
}
