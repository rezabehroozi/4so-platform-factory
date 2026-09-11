package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteCatalogBundleOutputRejectsSymlinkAndPreservesTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.zip")
	if err := os.WriteFile(target, []byte("do-not-touch"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "bundle.zip")
	if err := os.Symlink(target, out); err != nil {
		t.Fatal(err)
	}

	err := writeCatalogBundleOutput(out, []byte("new-bundle"))
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("expected fail-closed symlink rejection, got %v", err)
	}
	raw, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "do-not-touch" {
		t.Fatalf("symlink target was modified: %q", raw)
	}
}

func TestWriteCatalogBundleOutputAtomicallyReplacesRegularFile(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "bundle.zip")
	if err := os.WriteFile(out, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeCatalogBundleOutput(out, []byte("new-bundle")); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "new-bundle" {
		t.Fatalf("unexpected output %q", raw)
	}
	info, err := os.Lstat(out)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("output is not a real regular file: %v", info.Mode())
	}
}
