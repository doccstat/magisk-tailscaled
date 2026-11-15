// SPDX-License-Identifier: MIT
package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type freezerGroup struct {
	Version   int              `json:"version"`
	Mount     string           `json:"mount"`
	Path      string           `json:"path"`
	State     diagnosticResult `json:"state"`
	Frozen    bool             `json:"frozen"`
	mountRoot string
}

type serviceProcess struct {
	PID    int            `json:"pid"`
	Groups []freezerGroup `json:"freezerGroups"`
	Frozen bool           `json:"frozen"`
	Error  string         `json:"error,omitempty"`
}

func rooted(root, path string) string { return filepath.Join(root, strings.TrimPrefix(path, "/")) }

// Discover both unified and legacy freezer hierarchies, independent of manager/UID.
func processFreezerGroups(root string, pid int) ([]freezerGroup, error) {
	proc := rooted(root, "/proc/"+strconv.Itoa(pid))
	membership, err := os.ReadFile(filepath.Join(proc, "cgroup"))
	if err != nil {
		return nil, err
	}
	mounts, err := os.ReadFile(filepath.Join(proc, "mountinfo"))
	if err != nil {
		return nil, err
	}
	unescape := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	var groups []freezerGroup
	for _, line := range strings.Split(strings.TrimSpace(string(membership)), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			return nil, errors.New("invalid process cgroup membership")
		}
		version := 1
		if parts[0] == "0" && parts[1] == "" {
			version = 2
		} else if !strings.Contains(","+parts[1]+",", ",freezer,") {
			continue
		}
		found := false
		for _, mount := range strings.Split(string(mounts), "\n") {
			left, right, ok := strings.Cut(mount, " - ")
			fields, fs := strings.Fields(left), strings.Fields(right)
			if !ok || len(fields) < 6 || len(fs) < 3 {
				continue
			}
			if (version == 2 && fs[0] != "cgroup2") || (version == 1 && (fs[0] != "cgroup" || !strings.Contains(","+fs[2]+",", ",freezer,"))) {
				continue
			}
			mountRoot, point := unescape.Replace(fields[3]), unescape.Replace(fields[4])
			rel, err := filepath.Rel(mountRoot, parts[2])
			if err != nil || rel == ".." || strings.HasPrefix(rel, "../") || !filepath.IsAbs(point) {
				continue
			}
			groups = append(groups, freezerGroup{Version: version, Mount: point, Path: filepath.Join(point, rel), mountRoot: mountRoot})
			found = true
			break
		}
		if !found {
			return nil, fmt.Errorf("cannot locate freezer hierarchy for %s", line)
		}
	}
	return groups, nil
}

func leaveServiceCgroup(root string, pid int) error {
	groups, err := processFreezerGroups(root, pid)
	if err != nil {
		return err
	}
	for _, group := range groups {
		if group.mountRoot != "/" {
			return fmt.Errorf("freezer hierarchy at %s does not expose its root", group.Mount)
		}
		if group.Path == group.Mount {
			continue
		}
		// cgroup.procs moves every thread; setsid alone does not escape app freezing.
		f, err := os.OpenFile(rooted(root, filepath.Join(group.Mount, "cgroup.procs")), os.O_WRONLY, 0)
		if err != nil {
			return err
		}
		_, writeErr := fmt.Fprintln(f, pid)
		if err := errors.Join(writeErr, f.Close()); err != nil {
			return err
		}
	}
	return nil
}

func (a app) serviceProcesses() map[string]serviceProcess {
	root := a.cgroupRoot
	if root == "" {
		root = "/"
	}
	processes := map[string]serviceProcess{}
	for _, name := range []string{"supervisor", "daemon"} {
		r := a.record(name + ".json")
		if !r.alive() {
			continue
		}
		p := serviceProcess{PID: r.PID}
		var err error
		p.Groups, err = processFreezerGroups(root, r.PID)
		if err != nil {
			p.Error = err.Error()
		}
		for i := range p.Groups {
			group := &p.Groups[i]
			file := "freezer.state"
			if group.Version == 2 {
				file = "cgroup.events"
			}
			group.State = diagnosticFile(rooted(root, filepath.Join(group.Path, file)), false)
			fields := strings.Fields(group.State.Output)
			if group.Version == 1 {
				group.Frozen = len(fields) == 1 && (fields[0] == "FROZEN" || fields[0] == "FREEZING")
			} else {
				for j := 0; j+1 < len(fields); j += 2 {
					group.Frozen = group.Frozen || (fields[j] == "frozen" && fields[j+1] == "1")
				}
			}
			p.Frozen = p.Frozen || group.Frozen
		}
		processes[name] = p
	}
	return processes
}
