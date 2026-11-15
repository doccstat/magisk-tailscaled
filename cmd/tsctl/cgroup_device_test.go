package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

func freezerTestChild() error {
	input := bufio.NewScanner(os.Stdin)
	if !input.Scan() {
		return errors.New("missing detach request")
	}
	if err := leaveServiceCgroup("/", os.Getpid()); err != nil {
		return err
	}
	groups, err := processFreezerGroups("/", os.Getpid())
	if err != nil {
		return err
	}
	for _, group := range groups {
		if group.Path != group.Mount {
			return fmt.Errorf("still attached to %s", group.Path)
		}
	}
	fmt.Println("DETACHED")
	if !input.Scan() {
		return errors.New("missing liveness request")
	}
	fmt.Println("ALIVE")
	return nil
}

func TestDeviceServiceSurvivesAppFreeze(t *testing.T) {
	if runtime.GOOS != "android" || os.Geteuid() != 0 || os.Getenv("TSM_DEVICE_TESTS") != "1" {
		t.Skip("opt-in rooted Android test: TSM_DEVICE_TESTS=1")
	}
	groups, err := processFreezerGroups("/", os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	mount := ""
	for _, group := range groups {
		if group.Version == 2 && group.mountRoot == "/" {
			mount = group.Mount
		}
	}
	if mount == "" {
		t.Skip("no unified freezer hierarchy")
	}
	group, err := os.MkdirTemp(mount, "tsctl-freezer-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		os.WriteFile(filepath.Join(group, "cgroup.freeze"), []byte("0"), 0600)
		if err := os.Remove(group); err != nil {
			t.Error(err)
		}
	})
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(), "TSM_TEST_FREEZER_CHILD=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Stderr = os.Stderr
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		os.WriteFile(filepath.Join(group, "cgroup.freeze"), []byte("0"), 0600)
		input.Close()
		cmd.Process.Kill()
		cmd.Wait()
	})
	if err := os.WriteFile(filepath.Join(group, "cgroup.procs"), []byte(fmt.Sprint(cmd.Process.Pid)), 0600); err != nil {
		t.Fatal(err)
	}
	lines := make(chan string, 2)
	go func() {
		scanner := bufio.NewScanner(output)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
		close(lines)
	}()
	expect := func(want string) {
		t.Helper()
		select {
		case got := <-lines:
			if got != want {
				t.Fatalf("got %q, want %q", got, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("service stopped responding after app freeze")
		}
	}
	fmt.Fprintln(input, "detach")
	expect("DETACHED")
	if err := os.WriteFile(filepath.Join(group, "cgroup.freeze"), []byte("1"), 0600); err != nil {
		t.Fatal(err)
	}
	state, err := os.ReadFile(filepath.Join(group, "cgroup.events"))
	if err != nil || !strings.Contains(string(state), "frozen 1") {
		t.Fatalf("freezer did not engage: %s %v", state, err)
	}
	fmt.Fprintln(input, "ping")
	expect("ALIVE")
}
