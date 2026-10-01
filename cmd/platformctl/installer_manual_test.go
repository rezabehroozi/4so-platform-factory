package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"platform.4so.io/factory/internal/hostdeployment"
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

func TestManualInstallerPreflightResultPreservesAdmissionAndGuidance(t *testing.T) {
	admission := hostdeployment.HostAdmissionReport{SchemaVersion: 1, Ready: true, Mode: "live", TargetVersion: version}
	result := newManualInstallerPreflightResult(admission, "sha256:"+strings.Repeat("a", 64))
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err = json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if ready, ok := decoded["ready"].(bool); !ok || !ready {
		t.Fatalf("top-level ready field lost: %s", raw)
	}
	if decoded["authority"] != installerGuidedManualWorkflowAuthority || decoded["preflightGuidanceAuthority"] != installerManualPreflightGuidanceAuthority {
		t.Fatalf("guidance authority drift: %s", raw)
	}
	if decoded["sourceReleaseDigest"] == "" || decoded["nextAction"] == "" {
		t.Fatalf("exact release guidance incomplete: %s", raw)
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


func TestManualInstallerAccessPlanExplainsLoopbackSSHForward(t *testing.T) {
	plan := hostdeployment.Plan{}
	plan.Transport.Mode = "http-loopback"
	plan.Transport.LoopbackOnly = true
	plan.Health.URL = "http://127.0.0.1:9080/healthz"
	access := manualInstallerAccessPlan(plan)
	if access.WorkstationURL != "http://127.0.0.1:9080" {
		t.Fatalf("workstation URL %q", access.WorkstationURL)
	}
	if access.SSHForwardCommand != "ssh -N -L 9080:127.0.0.1:9080 <user>@<installer-host>" {
		t.Fatalf("ssh forward command %q", access.SSHForwardCommand)
	}
	if !access.LoopbackOnly || access.Mode != "http-loopback" || access.Note == "" {
		t.Fatalf("unexpected access plan %#v", access)
	}
}

func TestManualInstallerAccessPlanKeepsDirectTLSURL(t *testing.T) {
	plan := hostdeployment.Plan{}
	plan.Transport.Mode = "https"
	plan.Transport.TransportProtected = true
	plan.Health.URL = "https://installer.example.test:9443/healthz"
	access := manualInstallerAccessPlan(plan)
	if access.WorkstationURL != "https://installer.example.test:9443" || access.SSHForwardCommand != "" || access.LoopbackOnly {
		t.Fatalf("unexpected TLS access plan %#v", access)
	}
}
