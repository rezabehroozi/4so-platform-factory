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
	if decoded["machineNextActionAuthority"] != installerManualMachineNextActionAuthority || decoded["nextActionCode"] != "REVIEW_PLAN" {
		t.Fatalf("machine next-action guidance drift: %s", raw)
	}
}

func TestManualInstallerPreflightResultBlocksMachineProgressWhenAdmissionIsNotReady(t *testing.T) {
	admission := hostdeployment.HostAdmissionReport{SchemaVersion: 1, Ready: false, Mode: "live", TargetVersion: version}
	result := newManualInstallerPreflightResult(admission, "sha256:"+strings.Repeat("b", 64))
	if result.NextActionCode != "RESOLVE_HOST_ADMISSION" || result.MachineNextActionAuthority != installerManualMachineNextActionAuthority {
		t.Fatalf("blocked preflight machine guidance %#v", result)
	}
}

func TestManualInstallerContinuationCommandPreservesNonSecretInputsWithoutImmutableOutSpec(t *testing.T) {
	input := manualInstallerInputs{
		InstallerBinary:   "/opt/4so/bin/platform-installer",
		BundleDirectory:   "/srv/4so/bundle",
		ReleaseArtifact:   "/srv/4so/release.zip",
		Listen:            "0.0.0.0:9443",
		TLSCertificate:    "/etc/4so/tls.crt",
		TLSPrivateKey:     "/etc/4so/tls.key",
		AllowInsecureHTTP: true,
		AllowDowngrade:    true,
		Root:              "/staged-root",
		OutputSpec:        "/var/tmp/immutable-spec.json",
		Timeout:           7 * time.Minute,
	}
	command := manualInstallerContinuationCommand(input, "install", true)
	joined := strings.Join(command, " ")
	for _, want := range []string{
		"installer-manual install",
		"--installer-binary /opt/4so/bin/platform-installer",
		"--bundle-dir /srv/4so/bundle",
		"--release-artifact /srv/4so/release.zip",
		"--listen 0.0.0.0:9443",
		"--tls-cert /etc/4so/tls.crt",
		"--tls-key /etc/4so/tls.key",
		"--allow-insecure-http",
		"--allow-downgrade",
		"--root /staged-root",
		"--timeout 7m0s",
		"--enable-execution",
		"--confirmation DEPLOY",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("continuation command missing %q: %#v", want, command)
		}
	}
	if strings.Contains(joined, "--out-spec") || strings.Contains(joined, input.OutputSpec) {
		t.Fatalf("immutable out-spec must not be replayed by continuation: %#v", command)
	}
}

func TestManualInstallerLiveNextActionsMakeNextResolverCanonical(t *testing.T) {
	actions := strings.Join(manualInstallerLiveNextActions(), "\n")
	for _, want := range []string{
		"sudo bash install.sh next",
		"reads durable host state",
		"status/verify/bootstrap-status/recover/rollback remain lower-level",
		"do not guess or replay a mutation",
	} {
		if !strings.Contains(actions, want) {
			t.Fatalf("live handoff missing %q: %s", want, actions)
		}
	}
	if strings.Contains(actions, "use install.sh status/verify/recover/rollback") {
		t.Fatalf("legacy post-install continuation guidance returned: %s", actions)
	}
}

func TestManualInstallerNextGuidanceRoutesAppliedHostToBootstrapReadback(t *testing.T) {
	state := hostdeployment.State{Status: "APPLIED", Activated: true}
	state.Plan.DeploymentID = "deploy-1"
	state.Plan.Root = "/"
	state.Plan.Health.URL = "http://127.0.0.1:9080/healthz"
	state.Plan.Transport.Mode = "http-loopback"
	state.Plan.Transport.LoopbackOnly = true
	state.Plan.Paths.State = "/var/lib/4so-platform-installer/host-deployment.json"
	result := manualInstallerNextGuidance(state, state.Plan.Paths.State, "/")
	if result.Authority != installerManualContinuationResolverAuthority || result.AutomaticReplay {
		t.Fatalf("unexpected resolver authority/replay: %#v", result)
	}
	if result.NextActionCode != "CHECK_BOOTSTRAP_STATUS" {
		t.Fatalf("nextActionCode=%q", result.NextActionCode)
	}
	if result.Access == nil || result.Access.SSHForwardCommand != "ssh -N -L 9080:127.0.0.1:9080 <user>@<installer-host>" {
		t.Fatalf("reconnect access handoff missing: %#v", result.Access)
	}
	joined := strings.Join(result.NextCommand, " ")
	for _, want := range []string{"installer-access run-status", "--installer-url http://127.0.0.1:9080", "--token-file /var/lib/4so-platform-installer/bootstrap-token"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("bootstrap readback command missing %q: %#v", want, result.NextCommand)
		}
	}
}

func TestManualInstallerNextGuidanceRequiresExplicitRecoveryForIncompleteHostTransaction(t *testing.T) {
	state := hostdeployment.State{Status: "RECOVERY_REQUIRED", RecoveryRequired: true, CurrentStep: "bundle-install"}
	state.Plan.DeploymentID = "deploy-recovery"
	result := manualInstallerNextGuidance(state, "/var/lib/4so-platform-installer/host-deployment.json", "/")
	if result.NextActionCode != "RECOVER_HOST_DEPLOYMENT" || result.AutomaticReplay {
		t.Fatalf("unexpected recovery guidance %#v", result)
	}
	joined := strings.Join(result.NextCommand, " ")
	if !strings.Contains(joined, "installer-manual recover") || !strings.Contains(joined, "--confirmation RECOVER") {
		t.Fatalf("recovery command must remain explicit: %#v", result.NextCommand)
	}
}

func TestManualInstallerNextGuidanceDoesNotInventMutationForRecoveredOrUnknownState(t *testing.T) {
	for _, status := range []string{"RECOVERED", "ROLLED_BACK", "FUTURE_STATE"} {
		state := hostdeployment.State{Status: status}
		result := manualInstallerNextGuidance(state, "/tmp/state.json", "/")
		if result.AutomaticReplay {
			t.Fatalf("%s unexpectedly allows replay: %#v", status, result)
		}
		if status != "FUTURE_STATE" && len(result.NextCommand) != 0 {
			t.Fatalf("%s should require a fresh doctor/preflight decision, got %#v", status, result.NextCommand)
		}
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
