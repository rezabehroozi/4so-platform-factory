package bootstrap

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"platform.4so.io/factory/internal/installation"
)

type offlineSystemdTestSystem struct{ *SimulatedSystem }

func (s *offlineSystemdTestSystem) Run(ctx context.Context, name string, args []string, environment map[string]string) error {
	if name == "systemctl" && slices.Equal(args, []string{"show", "--property=Version", "--value"}) {
		return errors.New("Failed to connect to system scope bus: Host is down")
	}
	return s.SimulatedSystem.Run(ctx, name, args, environment)
}

func TestSystemdOperationalCheckRejectsInstalledButOfflineManager(t *testing.T) {
	system := &offlineSystemdTestSystem{SimulatedSystem: &SimulatedSystem{Root: t.TempDir()}}
	runner := &Runner{system: system}
	if err := runner.verifySystemdOperational(context.Background()); err == nil || !strings.Contains(err.Error(), "not operational") {
		t.Fatalf("offline systemd manager was not rejected: %v", err)
	}
}

func TestFreshInstallDetectsUnitInUsrLocalSystemdSearchPath(t *testing.T) {
	system := &SimulatedSystem{Root: t.TempDir()}
	path := "/usr/local/lib/systemd/system/rke2-server.service"
	if err := system.WriteFile(path, []byte("[Unit]\nDescription=stale RKE2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runner := &Runner{system: system}
	residue := runner.existingKubernetesResidue(context.Background())
	if !slices.Contains(residue, path) {
		t.Fatalf("systemd load-path residue was not detected: residue=%v want=%s", residue, path)
	}
}

func TestPublicPreflightCannotOverwriteAcceptedRunEvidence(t *testing.T) {
	bundle := t.TempDir()
	makeBundle(t, bundle)
	state := t.TempDir()
	runner, err := NewRunner(RunnerOptions{Version: "0.0.test", BundleDir: bundle, StateDir: state, Simulation: true, RequireBundleLock: false, System: &SimulatedSystem{Root: t.TempDir()}})
	if err != nil {
		t.Fatal(err)
	}
	request := bootstrapRequest()
	first, err := runner.Preflight(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.journal.Save(Run{ID: "bootstrap-evidence-owner", State: RunFailed, Request: request, PreflightDigest: first.Digest}); err != nil {
		t.Fatal(err)
	}
	mutated := request
	mutated.Connectivity = installation.ConnectivityDisconnected
	if _, err = runner.Preflight(context.Background(), mutated); err == nil || !errors.Is(err, ErrPreflightEvidenceOwned) {
		t.Fatalf("preflight overwrite after durable run was not rejected: %v", err)
	}
	persisted, err := runner.PreflightStatus()
	if err != nil {
		t.Fatal(err)
	}
	if persisted == nil || persisted.Digest != first.Digest {
		t.Fatalf("accepted preflight evidence changed: got=%+v wantDigest=%s", persisted, first.Digest)
	}
	if _, err := os.Stat(filepath.Join(state, "preflight-report.json")); err != nil {
		t.Fatalf("accepted preflight evidence disappeared: %v", err)
	}
}

func TestPublicPreflightMayEvaluateANewRequestAfterSucceededRun(t *testing.T) {
	bundle := t.TempDir()
	makeBundle(t, bundle)
	state := t.TempDir()
	runner, err := NewRunner(RunnerOptions{Version: "0.0.test", BundleDir: bundle, StateDir: state, Simulation: true, RequireBundleLock: false, System: &SimulatedSystem{Root: t.TempDir()}})
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.journal.Save(Run{ID: "bootstrap-complete", State: RunSucceeded}); err != nil {
		t.Fatal(err)
	}
	if _, err = runner.Preflight(context.Background(), bootstrapRequest()); err != nil {
		t.Fatalf("succeeded run must not permanently fence a future preflight evaluation: %v", err)
	}
}

func TestPublicPreflightRejectsConcurrentBootstrapExecution(t *testing.T) {
	bundle := t.TempDir()
	makeBundle(t, bundle)
	runner, err := NewRunner(RunnerOptions{Version: "0.0.test", BundleDir: bundle, StateDir: t.TempDir(), Simulation: true, System: &SimulatedSystem{Root: t.TempDir()}})
	if err != nil {
		t.Fatal(err)
	}
	runner.mu.Lock()
	runner.active = true
	runner.mu.Unlock()
	if _, err = runner.Preflight(context.Background(), bootstrapRequest()); err == nil || !errors.Is(err, ErrBootstrapExecutionActive) {
		t.Fatalf("concurrent preflight was not rejected: %v", err)
	}
}

type synchronizedClockTestSystem struct{ *SimulatedSystem }

func (s *synchronizedClockTestSystem) Output(ctx context.Context, name string, args []string, environment map[string]string) ([]byte, error) {
	if name == "timedatectl" && slices.Equal(args, []string{"show", "--property=NTPSynchronized", "--value"}) {
		return []byte("yes\n"), nil
	}
	return s.SimulatedSystem.Output(ctx, name, args, environment)
}

func TestTimeSynchronizationPreflightFailsClosedAndAcceptsSynchronizedClock(t *testing.T) {
	unsynchronized := &Runner{system: &SimulatedSystem{Root: t.TempDir()}}
	if err := unsynchronized.verifyTimeSynchronization(context.Background()); err == nil || !strings.Contains(err.Error(), "not NTP-synchronized") {
		t.Fatalf("unsynchronized clock was not rejected: %v", err)
	}
	synchronized := &Runner{system: &synchronizedClockTestSystem{SimulatedSystem: &SimulatedSystem{Root: t.TempDir()}}}
	if err := synchronized.verifyTimeSynchronization(context.Background()); err != nil {
		t.Fatalf("synchronized clock was rejected: %v", err)
	}
}

func TestExternalServiceReachabilityChecksDNSAndTCPBoundary(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := verifyTCPEndpointReachability(context.Background(), "http://"+listener.Addr().String()); err != nil {
		t.Fatalf("reachable endpoint was rejected: %v", err)
	}
	if err := verifyTCPEndpointReachability(context.Background(), "s3-compatible://example.test"); err == nil || !strings.Contains(err.Error(), "explicit TCP port") {
		t.Fatalf("endpoint without a resolvable transport contract was accepted: %v", err)
	}
}

func TestSizingEnforcementRejectsAnyUnderMinimumResource(t *testing.T) {
	sizing := installation.ApplianceSizing{MinimumVCPU: 8, MinimumMemoryGiB: 16, MinimumDiskGiB: 160, MinimumFreeDiskGiB: 120}
	if err := enforceSizing(hostCapacity{VCPU: 8, MemoryGiB: 16, DiskGiB: 160, FreeDiskGiB: 120}, sizing); err != nil {
		t.Fatalf("exact minimum must pass: %v", err)
	}
	cases := []hostCapacity{
		{VCPU: 7, MemoryGiB: 16, DiskGiB: 160, FreeDiskGiB: 120},
		{VCPU: 8, MemoryGiB: 15, DiskGiB: 160, FreeDiskGiB: 120},
		{VCPU: 8, MemoryGiB: 16, DiskGiB: 159, FreeDiskGiB: 120},
		{VCPU: 8, MemoryGiB: 16, DiskGiB: 160, FreeDiskGiB: 119},
	}
	for _, capacity := range cases {
		if err := enforceSizing(capacity, sizing); err == nil {
			t.Fatalf("under-minimum capacity unexpectedly passed: %+v", capacity)
		}
	}
}

func TestNoProxyCoverageHandlesExactSuffixAndCIDRWithoutWildcardingUnrelatedHosts(t *testing.T) {
	for _, tc := range []struct{ token, host string }{
		{"127.0.0.1", "127.0.0.1"},
		{".example.test", "api.example.test"},
		{"10.0.0.0/8", "10.4.5.6"},
	} {
		if !noProxyCovers(tc.token, tc.host) {
			t.Fatalf("NO_PROXY token %q should cover %q", tc.token, tc.host)
		}
	}
	if noProxyCovers(".example.test", "notexample.test") {
		t.Fatal("suffix matching must not cover unrelated host")
	}
}

type repairableTimeTestSystem struct {
	*SimulatedSystem
	synchronized bool
}

func (s *repairableTimeTestSystem) Output(ctx context.Context, name string, args []string, environment map[string]string) ([]byte, error) {
	if name == "timedatectl" && slices.Equal(args, []string{"show", "--property=NTPSynchronized", "--value"}) {
		if s.synchronized {
			return []byte("yes\n"), nil
		}
		return []byte("no\n"), nil
	}
	if name == "chronyc" && slices.Equal(args, []string{"reload", "sources"}) {
		s.synchronized = true
		return []byte("200 OK\n"), nil
	}
	return s.SimulatedSystem.Output(ctx, name, args, environment)
}

func TestEnsureTimeSynchronizationRepairsChronySourcesAndRechecks(t *testing.T) {
	system := &repairableTimeTestSystem{SimulatedSystem: &SimulatedSystem{Root: t.TempDir()}}
	runner := &Runner{system: system}
	if err := runner.ensureTimeSynchronization(context.Background()); err != nil {
		t.Fatalf("time synchronization remediation failed: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(system.Root, "etc", "chrony", "sources.d", "4so-time.sources"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, source := range []string{"time.windows.com", "time.apple.com", "time.facebook.com", "rolex.ripe.net", "time.nist.gov", "ntp.nict.jp", "162.159.200.1", "162.159.200.123", "0.pool.ntp.org", "1.pool.ntp.org", "time.google.com", "time.cloudflare.com", "ntp.ubuntu.com"} {
		if !strings.Contains(text, source) {
			t.Fatalf("time source %q missing from durable remediation: %s", source, text)
		}
	}
	for _, diagnostic := range []string{"server time.google.com iburst noselect", "server time.cloudflare.com iburst noselect", "server ntp.ubuntu.com iburst noselect"} {
		if !strings.Contains(text, diagnostic) {
			t.Fatalf("SNI-prone time source must remain diagnostic-only %q: %s", diagnostic, text)
		}
	}
}

func TestStartRepairsTimeBeforeLivePreflight(t *testing.T) {
	bundle := t.TempDir()
	makeBundle(t, bundle)
	system := &repairableTimeTestSystem{SimulatedSystem: &SimulatedSystem{Root: t.TempDir()}}
	runner, err := NewRunner(RunnerOptions{
		Version: "0.0.16", BundleDir: bundle, StateDir: t.TempDir(),
		Simulation: false, System: system,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = runner.Start(context.Background(), bootstrapRequest())
	if !system.synchronized {
		t.Fatal("live Start did not repair time before evaluating the read-only preflight")
	}
	if _, err := os.Stat(filepath.Join(system.Root, "etc", "chrony", "sources.d", "4so-time.sources")); err != nil {
		t.Fatalf("managed time sources were not persisted before preflight: %v", err)
	}
}

func TestResumeRepairsTimeBeforeReevaluatingPreflight(t *testing.T) {
	bundle := t.TempDir()
	makeBundle(t, bundle)
	system := &repairableTimeTestSystem{SimulatedSystem: &SimulatedSystem{Root: t.TempDir()}}
	runner, err := NewRunner(RunnerOptions{Version: "0.0.16", BundleDir: bundle, StateDir: t.TempDir(), Simulation: false, System: system})
	if err != nil {
		t.Fatal(err)
	}
	plan, bundleDigest, err := runner.PlanUnlocked(bootstrapRequest())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	run := Run{ID: "bootstrap-time-resume", Version: "0.0.16", State: RunFailed, Request: plan.EffectiveRequest, SpecDigest: plan.SpecDigest, BundleDigest: bundleDigest, CreatedAt: now, UpdatedAt: now, Steps: []Step{{Key: "preflight", Title: "Preflight", State: StepPending}}}
	if err := runner.journal.Save(run); err != nil {
		t.Fatal(err)
	}
	_, _ = runner.Resume(context.Background())
	if !system.synchronized {
		t.Fatal("live Resume did not repair time before reevaluating preflight")
	}
}
