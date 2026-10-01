package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBuildManualInstallerSpecUsesProductDefaults(t *testing.T) {
	input := manualInstallerInputs{
		InstallerBinary:  "/tmp/platform-installer",
		BundleDirectory:  "/tmp/bundle",
		Listen:           "127.0.0.1:9080",
		ExecutionEnabled: true,
		Root:             "/",
		Timeout:          2 * time.Minute,
	}
	spec, err := buildManualInstallerSpec(input)
	if err != nil {
		t.Fatal(err)
	}
	if spec.Metadata.Name != "manual-installer" || spec.Metadata.Version != version {
		t.Fatalf("unexpected identity %#v", spec.Metadata)
	}
	if spec.Spec.InstallerBinary != input.InstallerBinary || spec.Spec.BundleDirectory != input.BundleDirectory || spec.Spec.Listen != input.Listen {
		t.Fatalf("unexpected source inputs %#v", spec.Spec)
	}
	if !spec.Spec.ExecutionEnabled || spec.Spec.Admission == nil || spec.Spec.Admission.AllowDowngrade {
		t.Fatalf("unexpected execution/admission defaults %#v", spec.Spec)
	}
	if !spec.Spec.Service.Enable || !spec.Spec.Service.Start {
		t.Fatalf("manual workflow must enable and start Installer service: %#v", spec.Spec.Service)
	}
}

func TestBuildManualInstallerSpecRequiresCompleteTLSInput(t *testing.T) {
	base := manualInstallerInputs{InstallerBinary: "/tmp/platform-installer", BundleDirectory: "/tmp/bundle", Listen: "0.0.0.0:9443"}
	base.TLSCertificate = "/tmp/installer.crt"
	if _, err := buildManualInstallerSpec(base); err == nil {
		t.Fatal("expected incomplete TLS pair rejection")
	}
	base.TLSPrivateKey = "/tmp/installer.key"
	if _, err := buildManualInstallerSpec(base); err != nil {
		t.Fatal(err)
	}
}

func TestMaterializeManualInstallerSpecIsPrivateAndRefusesOverwrite(t *testing.T) {
	spec, err := buildManualInstallerSpec(manualInstallerInputs{
		InstallerBinary: "/tmp/platform-installer",
		BundleDirectory: "/tmp/bundle",
		Listen:          "127.0.0.1:9080",
	})
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "installer.json")
	path, cleanup, err := materializeManualInstallerSpec(spec, out)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if path != out {
		t.Fatalf("path %q want %q", path, out)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %04o want 0600", info.Mode().Perm())
	}
	if _, _, err = materializeManualInstallerSpec(spec, out); err == nil {
		t.Fatal("expected overwrite rejection")
	}
}

func TestManualInstallerConsoleURL(t *testing.T) {
	if got := manualInstallerConsoleURL("https://installer.example:9443/healthz"); got != "https://installer.example:9443" {
		t.Fatalf("console URL %q", got)
	}
	if got := manualInstallerConsoleURL("not-a-url"); got != "" {
		t.Fatalf("invalid URL should be empty, got %q", got)
	}
}
