package durablefile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReplacePersistsExactContentsAndMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "state.json")
	if err := Replace(path, []byte("first\n"), 0o700, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Replace(path, []byte("second\n"), 0o700, 0o600); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "second\n" {
		t.Fatalf("contents=%q", raw)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%#o", info.Mode().Perm())
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "state.json" {
		t.Fatalf("unexpected durable temp residue: %+v", entries)
	}
}

func TestReplaceFailsClosedWhenParentIsNotDirectory(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "state")
	if err := os.WriteFile(parent, []byte("not-a-directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Replace(filepath.Join(parent, "state.json"), []byte("x"), 0o700, 0o600); err == nil {
		t.Fatal("expected non-directory parent to fail")
	}
}
