package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestVersionIsSet(t *testing.T) {
	if version == "" {
		t.Fatal("version is empty")
	}
}

func TestStorageProbeWriteReadAndVerifyRestoredMarker(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cert-data", "marker")
	t.Setenv("PLATFORM_PROBE_STORAGE_MARKER", "rtc-marker-123")
	t.Setenv("PLATFORM_PROBE_STORAGE_VERIFY_ONLY", "false")
	out, err := storageProbe(path)
	if err != nil {
		t.Fatal(err)
	}
	if !out.StorageWritten || !out.StorageRead {
		t.Fatalf("unexpected write/read result: %+v", out)
	}
	if raw, err := os.ReadFile(path); err != nil || string(raw) != "rtc-marker-123" {
		t.Fatalf("marker was not persisted: %q err=%v", string(raw), err)
	}

	t.Setenv("PLATFORM_PROBE_STORAGE_VERIFY_ONLY", "true")
	out, err = storageProbe(path)
	if err != nil {
		t.Fatal(err)
	}
	if out.StorageWritten || !out.StorageRead {
		t.Fatalf("verify-only result must read without writing: %+v", out)
	}
}

func TestStorageProbeRejectsMarkerMismatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "marker")
	if err := os.WriteFile(path, []byte("old-marker"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PLATFORM_PROBE_STORAGE_MARKER", "expected-marker")
	t.Setenv("PLATFORM_PROBE_STORAGE_VERIFY_ONLY", "true")
	if _, err := storageProbe(path); err == nil {
		t.Fatal("expected marker mismatch to fail")
	}
}

func TestProbeTerminationMessageIsCompactJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "termination.log")
	out := result{Version: "test", Target: "kubernetes.default.svc:443", DNSResolved: true, Addresses: []string{"10.43.0.1"}, TCPConnected: true, DurationMillis: 7}
	if err := writeProbeTerminationMessage(path, out); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var decoded result
	if err := json.Unmarshal(bytes.TrimSpace(raw), &decoded); err != nil {
		t.Fatalf("termination message is not valid JSON: %v raw=%q", err, raw)
	}
	if !decoded.DNSResolved || !decoded.TCPConnected || decoded.Target != out.Target {
		t.Fatalf("termination message lost probe result: %+v", decoded)
	}
}
