package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeHostRunner struct {
	files map[string]bool
	calls []string
	fail  string
}

func (f *fakeHostRunner) Exists(_ string, path string) bool { return f.files[path] }
func (f *fakeHostRunner) Run(_ string, command string, args ...string) error {
	call := strings.Join(append([]string{command}, args...), " ")
	f.calls = append(f.calls, call)
	if f.fail != "" && strings.Contains(call, f.fail) {
		return errors.New("injected failure")
	}
	return nil
}

func writeOSRelease(t *testing.T, root, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "os-release"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestExecuteHostOSPatchDebian(t *testing.T) {
	root := t.TempDir()
	writeOSRelease(t, root, "ID=ubuntu\nVERSION_ID=24.04\n")
	r := &fakeHostRunner{files: map[string]bool{"/usr/bin/apt-get": true, "/var/run/reboot-required": true}}
	stamp := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	out, err := executeHostOSPatch(root, r, func() time.Time { stamp = stamp.Add(time.Second); return stamp })
	if err != nil {
		t.Fatal(err)
	}
	if out.Authority != hostMaintenanceAuthority || out.Action != "OS_PATCH" || out.OSID != "ubuntu" || out.PackageManager != "apt-get" || !out.RebootRequired {
		t.Fatalf("unexpected result: %+v", out)
	}
	if len(r.calls) != 2 || !strings.Contains(r.calls[0], "apt-get update") || !strings.Contains(r.calls[1], "apt-get -y") {
		t.Fatalf("unexpected commands: %#v", r.calls)
	}
}

func TestExecuteHostOSPatchEnterpriseLinuxFailsClosed(t *testing.T) {
	root := t.TempDir()
	writeOSRelease(t, root, "ID=rocky\n")
	r := &fakeHostRunner{files: map[string]bool{"/usr/bin/dnf": true}, fail: "upgrade"}
	if _, err := executeHostOSPatch(root, r, time.Now); err == nil || !strings.Contains(err.Error(), "host patch command") {
		t.Fatalf("expected patch failure, got %v", err)
	}
}

func TestExecuteHostOSPatchUnsupportedOS(t *testing.T) {
	root := t.TempDir()
	writeOSRelease(t, root, "ID=flatcar\n")
	r := &fakeHostRunner{files: map[string]bool{}}
	if _, err := executeHostOSPatch(root, r, time.Now); err == nil || !strings.Contains(err.Error(), "unsupported host OS") {
		t.Fatalf("expected unsupported OS, got %v", err)
	}
}
