package main

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func freezerFixture(t *testing.T, root string, pid int, membership, mounts string) {
	t.Helper()
	proc := rooted(root, "/proc/"+strconv.Itoa(pid))
	if err := os.MkdirAll(proc, 0700); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{"cgroup": membership, "mountinfo": mounts} {
		if err := os.WriteFile(filepath.Join(proc, name), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestServiceLeavesOnlyFreezerHierarchies(t *testing.T) {
	root, pid := t.TempDir(), 123
	freezerFixture(t, root, pid,
		"3:cpuset:/top-app\n2:freezer:/apps/uid_123/pid_456\n0::/apps/uid_123/pid_456\n",
		"1 0 0:1 / /sys/fs/cgroup rw - cgroup2 none rw\n2 0 0:2 / /dev/freezer rw - cgroup none rw,freezer\n3 0 0:3 / /dev/cpuset rw - cgroup none rw,cpuset\n")
	for _, mount := range []string{"/sys/fs/cgroup", "/dev/freezer", "/dev/cpuset"} {
		dir := rooted(root, mount)
		os.MkdirAll(dir, 0700)
		os.WriteFile(filepath.Join(dir, "cgroup.procs"), nil, 0600)
	}
	if err := leaveServiceCgroup(root, pid); err != nil {
		t.Fatal(err)
	}
	for _, mount := range []string{"/sys/fs/cgroup", "/dev/freezer", "/dev/cpuset"} {
		b, _ := os.ReadFile(rooted(root, mount+"/cgroup.procs"))
		want := "123\n"
		if mount == "/dev/cpuset" {
			want = ""
		}
		if string(b) != want {
			t.Fatalf("%s = %q, want %q", mount, b, want)
		}
	}
	os.Remove(rooted(root, "/dev/freezer/cgroup.procs"))
	if err := leaveServiceCgroup(root, pid); err == nil {
		t.Fatal("ignored failed detachment")
	}
	freezerFixture(t, root, pid, "0::/\n", "1 0 0:1 / /sys/fs/cgroup rw - cgroup2 none rw\n")
	os.Remove(rooted(root, "/sys/fs/cgroup/cgroup.procs"))
	if err := leaveServiceCgroup(root, pid); err != nil {
		t.Fatal("already detached", err)
	}
}

func TestFreezerMountParsing(t *testing.T) {
	for _, tc := range []struct {
		name, membership, mounts string
		fail                     bool
	}{
		{"escaped mount", "0::/apps/test\n", "1 0 0:1 / /sys/cgroup\\040space rw - cgroup2 none rw\n", false},
		{"no freezer", "2:cpu:/apps/test\n", "", false},
		{"missing mount", "0::/apps/test\n", "", true},
		{"malformed", "invalid\n", "", true},
		{"unreachable root", "0::/apps/test\n", "1 0 0:1 /other /sys/fs/cgroup rw - cgroup2 none rw\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			freezerFixture(t, root, 123, tc.membership, tc.mounts)
			groups, err := processFreezerGroups(root, 123)
			if (err != nil) != tc.fail {
				t.Fatalf("groups %v, err %v", groups, err)
			}
			if tc.name == "escaped mount" && groups[0].Path != "/sys/cgroup space/apps/test" {
				t.Fatal(groups)
			}
		})
	}
}

func TestFrozenServiceStatusAndDiagnostics(t *testing.T) {
	a := diagnosticTestApp(t)
	a.cgroupRoot = t.TempDir()
	pid := os.Getpid()
	freezerFixture(t, a.cgroupRoot, pid, "0::/apps/test\n", "1 0 0:1 / /sys/fs/cgroup rw - cgroup2 none rw\n")
	dir := rooted(a.cgroupRoot, "/sys/fs/cgroup/apps/test")
	os.MkdirAll(dir, 0700)
	os.WriteFile(filepath.Join(dir, "cgroup.events"), []byte("populated 1\nfrozen 1\n"), 0600)
	status := a.status()
	if status["frozen"] != true || status["dns"].(map[string]any)["active"] != false {
		t.Fatal(status)
	}
	report, err := a.diagnostics("")
	if err != nil {
		t.Fatal(err)
	}
	processes := report["status"].(map[string]any)["processes"].(map[string]any)
	if processes["supervisor"].(map[string]any)["frozen"] != true {
		t.Fatal(processes)
	}
	os.WriteFile(filepath.Join(dir, "cgroup.events"), []byte("populated 1\nfrozen 0\n"), 0600)
	if a.status()["frozen"] == true {
		t.Fatal("thawed service reported frozen")
	}
}
