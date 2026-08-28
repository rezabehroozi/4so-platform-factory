package disasterrecovery

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"platform.4so.io/factory/internal/bootstrap"
	"platform.4so.io/factory/internal/installation"
)

func request() installation.InstallRequest {
	return installation.InstallRequest{ProfileID: "production-standard-ha", Services: installation.ServicesSpec{ObjectStorage: installation.ServiceSpec{Mode: installation.ServiceModeExternal, URL: "https://s3.example.test", Bucket: "backups", Prefix: "factory", CredentialRef: "external-secret://platform-system/s3-credentials"}}}
}

type disasterRecoveryNodeSystem struct {
	*bootstrap.SimulatedSystem
}

func (s *disasterRecoveryNodeSystem) Output(ctx context.Context, name string, args []string, environment map[string]string) ([]byte, error) {
	joined := strings.Join(args, " ")
	s.Commands = append(s.Commands, name+" "+joined)
	switch {
	case strings.Contains(joined, "app=platform-forgejo"):
		return []byte("manager-a"), nil
	case strings.Contains(joined, "app=platform-zot"):
		return []byte("manager-b"), nil
	default:
		return nil, nil
	}
}

func defaultDisasterRecoveryReplicas() map[string]int {
	return map[string]int{
		"deployment platform-api":       3,
		"statefulset platform-keycloak": 2,
		"statefulset platform-forgejo":  1,
		"deployment platform-zot":       1,
	}
}

func disasterRecoveryWorkloadResponse(command string, replicas map[string]int) ([]byte, bool) {
	metadata := map[string][2]string{
		"deployment platform-api":       {"uid-api", "11"},
		"statefulset platform-keycloak": {"uid-keycloak", "12"},
		"statefulset platform-forgejo":  {"uid-forgejo", "13"},
		"deployment platform-zot":       {"uid-zot", "14"},
	}
	for resource, identity := range metadata {
		if !strings.Contains(command, " get "+resource+" -o json") && !strings.Contains(command, " patch "+resource+" --type=json ") {
			continue
		}
		if strings.Contains(command, " patch "+resource+" --type=json ") {
			marker := `"path":"/spec/replicas","value":`
			if index := strings.Index(command, marker); index >= 0 {
				tail := command[index+len(marker):]
				end := strings.IndexAny(tail, "},]")
				if end > 0 {
					value, err := strconv.Atoi(tail[:end])
					if err == nil {
						replicas[resource] = value
					}
				}
			}
		}
		rv := identity[1]
		if strings.Contains(command, " patch "+resource+" --type=json ") {
			rv = "20"
		}
		return []byte(fmt.Sprintf(`{"metadata":{"uid":%q,"resourceVersion":%q},"spec":{"replicas":%d}}`, identity[0], rv, replicas[resource])), true
	}
	return nil, false
}

type disasterRecoveryBarrierSystem struct {
	*bootstrap.SimulatedSystem
	apiObservations int
	failObservation bool
	replicas        map[string]int
}

func (s *disasterRecoveryBarrierSystem) Output(_ context.Context, name string, args []string, _ map[string]string) ([]byte, error) {
	command := name + " " + strings.Join(args, " ")
	s.Commands = append(s.Commands, command)
	if s.replicas == nil {
		s.replicas = defaultDisasterRecoveryReplicas()
	}
	if raw, ok := disasterRecoveryWorkloadResponse(command, s.replicas); ok {
		return raw, nil
	}
	if strings.Contains(command, "get pods") && strings.Contains(command, "app=platform-api") {
		s.apiObservations++
		if s.failObservation {
			return nil, errors.New("injected pod observation failure")
		}
		if s.apiObservations == 1 {
			return []byte("pod/platform-api-0"), nil
		}
	}
	return nil, nil
}

type disasterRecoveryCommandSystem struct {
	*bootstrap.SimulatedSystem
	failSubstring             string
	failed                    bool
	replicas                  map[string]int
	driftAfterRolloutResource string
}

func (s *disasterRecoveryCommandSystem) Run(ctx context.Context, name string, args []string, environment map[string]string) error {
	command := name + " " + strings.Join(args, " ")
	if s.failSubstring != "" && !s.failed && strings.Contains(command, s.failSubstring) {
		s.Commands = append(s.Commands, command)
		s.failed = true
		return errors.New("injected command failure")
	}
	if s.replicas == nil {
		s.replicas = defaultDisasterRecoveryReplicas()
	}
	if s.driftAfterRolloutResource != "" && strings.Contains(command, " rollout status "+strings.ReplaceAll(s.driftAfterRolloutResource, " ", "/")+" ") {
		s.Commands = append(s.Commands, command)
		s.replicas[s.driftAfterRolloutResource] = 2
		return nil
	}
	return s.SimulatedSystem.Run(ctx, name, args, environment)
}

func (s *disasterRecoveryCommandSystem) Output(ctx context.Context, name string, args []string, environment map[string]string) ([]byte, error) {
	command := name + " " + strings.Join(args, " ")
	s.Commands = append(s.Commands, command)
	if s.failSubstring != "" && !s.failed && strings.Contains(command, s.failSubstring) {
		s.failed = true
		return nil, errors.New("injected command failure")
	}
	if s.replicas == nil {
		s.replicas = defaultDisasterRecoveryReplicas()
	}
	if raw, ok := disasterRecoveryWorkloadResponse(command, s.replicas); ok {
		return raw, nil
	}
	return s.SimulatedSystem.Output(ctx, name, args, environment)
}

func TestDisasterRecoveryPersistsRWONodePlacementBeforeQuiesce(t *testing.T) {
	state := t.TempDir()
	system := &disasterRecoveryNodeSystem{SimulatedSystem: &bootstrap.SimulatedSystem{Root: t.TempDir()}}
	run := Run{ID: "dr-backup-placement", Action: ActionBackup, State: StateRunning, BackupID: "backup-placement", CreatedAt: time.Now().UTC()}
	manager := &Manager{stateDir: state, system: system, runs: []Run{run}, simulation: true}
	updated, err := manager.ensureBackupWorkloadNodes(context.Background(), run.ID, &run)
	if err != nil {
		t.Fatal(err)
	}
	if updated.AuthorityBackupNode != "simulation-node" || updated.ForgejoBackupNode != "manager-a" || updated.ZotBackupNode != "manager-b" {
		t.Fatalf("unexpected workload placement: authority=%q forgejo=%q zot=%q", updated.AuthorityBackupNode, updated.ForgejoBackupNode, updated.ZotBackupNode)
	}
	raw, err := os.ReadFile(filepath.Join(state, "disaster-recovery-runs.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"authorityBackupNode": "simulation-node"`) || !strings.Contains(string(raw), `"forgejoBackupNode": "manager-a"`) || !strings.Contains(string(raw), `"zotBackupNode": "manager-b"`) {
		t.Fatalf("workload placement was not durably persisted before quiesce:\n%s", raw)
	}
}

func TestDisasterRecoveryQuiescesWritersAndRestoresProfileReplicaCounts(t *testing.T) {
	system := &disasterRecoveryCommandSystem{SimulatedSystem: &bootstrap.SimulatedSystem{Root: t.TempDir()}}
	manager := &Manager{system: system, stateDir: t.TempDir()}
	if err := manager.quiesceWorkloads(context.Background(), "test-op", request()); err != nil {
		t.Fatal(err)
	}
	if err := manager.resumeWorkloads(context.Background(), "test-op", request()); err != nil {
		t.Fatal(err)
	}
	commands := strings.Join(system.Commands, "\n")
	for _, expected := range []string{
		"patch deployment platform-api --type=json -p [{\"op\":\"test\"",
		"patch statefulset platform-keycloak --type=json -p [{\"op\":\"test\"",
		"patch statefulset platform-forgejo --type=json -p [{\"op\":\"test\"",
		"patch deployment platform-zot --type=json -p [{\"op\":\"test\"",
		"patch deployment platform-api --type=json -p [{\"op\":\"test\"",
		"patch statefulset platform-keycloak --type=json -p [{\"op\":\"test\"",
		"patch statefulset platform-forgejo --type=json -p [{\"op\":\"test\"",
		"patch deployment platform-zot --type=json -p [{\"op\":\"test\"",
		"rollout status deployment/platform-api --timeout=10m",
		"rollout status statefulset/platform-keycloak --timeout=10m",
	} {
		if !strings.Contains(commands, expected) {
			t.Fatalf("missing disaster-recovery workload command %q in:\n%s", expected, commands)
		}
	}
}

func TestDisasterRecoveryQuiesceWaitsForWriterPodsToTerminate(t *testing.T) {
	system := &disasterRecoveryBarrierSystem{SimulatedSystem: &bootstrap.SimulatedSystem{Root: t.TempDir()}}
	manager := &Manager{system: system, stateDir: t.TempDir()}
	if err := manager.quiesceWorkloads(context.Background(), "test-op", request()); err != nil {
		t.Fatal(err)
	}
	if system.apiObservations < 2 {
		t.Fatalf("quiesce did not wait for the API pod to disappear; observations=%d", system.apiObservations)
	}
	commands := system.Commands
	firstAPIObserve, secondAPIObserve, keycloakScale := -1, -1, -1
	for i, command := range commands {
		switch {
		case strings.Contains(command, "get pods") && strings.Contains(command, "app=platform-api"):
			if firstAPIObserve < 0 {
				firstAPIObserve = i
			} else if secondAPIObserve < 0 {
				secondAPIObserve = i
			}
		case strings.Contains(command, "patch statefulset platform-keycloak --type=json"):
			keycloakScale = i
		}
	}
	if firstAPIObserve < 0 || secondAPIObserve < 0 || keycloakScale < 0 || !(firstAPIObserve < secondAPIObserve && secondAPIObserve < keycloakScale) {
		t.Fatalf("next writer was quiesced before API termination barrier completed:\n%s", strings.Join(commands, "\n"))
	}
}

func TestDisasterRecoveryQuiesceObservationFailureRecoversScaledWorkload(t *testing.T) {
	system := &disasterRecoveryBarrierSystem{SimulatedSystem: &bootstrap.SimulatedSystem{Root: t.TempDir()}, failObservation: true}
	manager := &Manager{system: system, stateDir: t.TempDir()}
	err := manager.quiesceWorkloads(context.Background(), "test-op", request())
	if err == nil || !strings.Contains(err.Error(), "observe deployment/platform-api shutdown") {
		t.Fatalf("expected quiesce observation failure, got %v", err)
	}
	commands := strings.Join(system.Commands, "\n")
	if !strings.Contains(commands, `"path":"/spec/replicas","value":3`) {
		t.Fatalf("scaled API was not recovered after quiesce barrier failure:\n%s", commands)
	}
	if strings.Contains(commands, "patch statefulset platform-keycloak --type=json -p [{\"op\":\"test\"") {
		t.Fatalf("quiesce continued after API shutdown could not be proven:\n%s", commands)
	}
}

func TestDisasterRecoveryRejectsMissingProfileInsteadOfAssumingSingleNode(t *testing.T) {
	req := request()
	req.ProfileID = ""
	if err := validateTarget(req); err == nil || !strings.Contains(err.Error(), "installation profile") {
		t.Fatalf("missing durable profile must fail closed, got %v", err)
	}
}

func TestDisasterRecoveryQuiesceFailureRecoversAlreadyStoppedWorkloads(t *testing.T) {
	system := &disasterRecoveryCommandSystem{
		SimulatedSystem: &bootstrap.SimulatedSystem{Root: t.TempDir()},
		failSubstring:   "patch statefulset platform-keycloak --type=json",
	}
	manager := &Manager{system: system, stateDir: t.TempDir()}
	err := manager.quiesceWorkloads(context.Background(), "test-op", request())
	if err == nil || !strings.Contains(err.Error(), "quiesce statefulset/platform-keycloak") {
		t.Fatalf("expected quiesce failure, got %v", err)
	}
	commands := strings.Join(system.Commands, "\n")
	if !strings.Contains(commands, "patch deployment platform-api --type=json -p [{\"op\":\"test\"") {
		t.Fatalf("API was not quiesced before injected failure:\n%s", commands)
	}
	if !strings.Contains(commands, `"path":"/spec/replicas","value":3`) || !strings.Contains(commands, "rollout status deployment/platform-api --timeout=10m") {
		t.Fatalf("already-quiesced API was not recovered after pre-restore failure:\n%s", commands)
	}
	if strings.Contains(commands, "patch statefulset platform-forgejo --type=json -p [{\"op\":\"test\"") {
		t.Fatalf("quiesce continued after failure:\n%s", commands)
	}
}

func TestDisasterRecoveryBackupResumesWorkloadsAfterFailure(t *testing.T) {
	system := &disasterRecoveryCommandSystem{SimulatedSystem: &bootstrap.SimulatedSystem{Root: t.TempDir()}}
	manager := &Manager{system: system, stateDir: t.TempDir()}
	err := manager.withBackupQuiesced(context.Background(), "test-op", request(), func() error {
		return errors.New("injected backup failure")
	})
	if err == nil || !strings.Contains(err.Error(), "injected backup failure") {
		t.Fatalf("expected backup failure, got %v", err)
	}
	commands := strings.Join(system.Commands, "\n")
	for _, expected := range []string{
		"patch deployment platform-api --type=json -p [{\"op\":\"test\"",
		"patch deployment platform-api --type=json -p [{\"op\":\"test\"",
		"patch statefulset platform-keycloak --type=json -p [{\"op\":\"test\"",
		"patch statefulset platform-forgejo --type=json -p [{\"op\":\"test\"",
		"patch deployment platform-zot --type=json -p [{\"op\":\"test\"",
	} {
		if !strings.Contains(commands, expected) {
			t.Fatalf("backup failure did not restore workload state; missing %q in:\n%s", expected, commands)
		}
	}
}

func TestDisasterRecoveryRestoreFailureStaysQuiesced(t *testing.T) {
	system := &disasterRecoveryCommandSystem{SimulatedSystem: &bootstrap.SimulatedSystem{Root: t.TempDir()}}
	manager := &Manager{system: system, stateDir: t.TempDir()}
	err := manager.withRestoreQuiesced(context.Background(), "test-op", request(), func() error {
		return errors.New("injected restore failure")
	})
	if err == nil || !strings.Contains(err.Error(), "remain quiesced for safe retry") {
		t.Fatalf("expected fail-closed restore error, got %v", err)
	}
	if !destructiveRecoveryRequired(err) {
		t.Fatalf("failed destructive restore was not classified as recovery-required: %v", err)
	}
	commands := strings.Join(system.Commands, "\n")
	if !strings.Contains(commands, "patch deployment platform-api --type=json -p [{\"op\":\"test\"") {
		t.Fatalf("restore did not quiesce API:\n%s", commands)
	}
	for _, forbidden := range []string{
		`"path":"/spec/replicas","value":3`,
		`"path":"/spec/replicas","value":2`,
		`"path":"/spec/replicas","value":1`,
	} {
		if strings.Contains(commands, forbidden) {
			t.Fatalf("failed restore resumed a workload via %q:\n%s", forbidden, commands)
		}
	}
}

func TestDisasterRecoverySingleNodeReplicaTargets(t *testing.T) {
	req := request()
	req.ProfileID = "evaluation-single-node"
	targets := workloadTargets(req)
	got := map[string]int{}
	for _, target := range targets {
		got[target.kind+"/"+target.name] = target.replicas
	}
	for resource, want := range map[string]int{
		"deployment/platform-api":       1,
		"statefulset/platform-keycloak": 1,
		"statefulset/platform-forgejo":  1,
		"deployment/platform-zot":       1,
	} {
		if got[resource] != want {
			t.Fatalf("%s replicas=%d want=%d", resource, got[resource], want)
		}
	}
}
func TestSimulatedBackupAndRestore(t *testing.T) {
	state := t.TempDir()
	bundle := t.TempDir()
	// Simulation never loads the bundle, but the directory remains required by the manager contract.
	m, err := New(Options{StateDir: state, BundleDir: bundle, Simulation: true, System: &bootstrap.SimulatedSystem{Root: t.TempDir()}})
	if err != nil {
		t.Fatal(err)
	}
	run, err := m.StartBackup(context.Background(), request())
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		runs := m.List()
		if len(runs) > 0 && runs[0].State == StateSucceeded {
			run = runs[0]
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if run.State != StateSucceeded {
		t.Fatalf("backup state=%s", run.State)
	}
	restore, err := m.StartRestore(context.Background(), request(), run.BackupID)
	if err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		runs := m.List()
		for _, r := range runs {
			if r.ID == restore.ID && r.State == StateSucceeded {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("restore did not complete")
}
func TestBackupIDsRemainUniqueWithinSameSecond(t *testing.T) {
	fixed := time.Date(2026, 8, 9, 12, 34, 56, 123456789, time.UTC)
	m, err := New(Options{
		StateDir:   t.TempDir(),
		BundleDir:  t.TempDir(),
		Simulation: true,
		System:     &bootstrap.SimulatedSystem{Root: t.TempDir()},
		Now:        func() time.Time { return fixed },
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := m.StartBackup(context.Background(), request())
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		for _, run := range m.List() {
			if run.ID == first.ID && run.State == StateSucceeded {
				goto firstDone
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("first backup did not complete")
firstDone:
	second, err := m.StartBackup(context.Background(), request())
	if err != nil {
		t.Fatal(err)
	}
	if first.BackupID == second.BackupID {
		t.Fatalf("sequential backups in the same second reused backupId %q", first.BackupID)
	}
	if second.BackupID != first.BackupID+"-2" {
		t.Fatalf("second backupId=%q want=%q", second.BackupID, first.BackupID+"-2")
	}
	if first.ID == second.ID {
		t.Fatalf("sequential operations reused run id %q", first.ID)
	}
	// StartBackup is intentionally asynchronous. Wait for the second operation
	// to reach a terminal state before the test's TempDir cleanup begins; otherwise
	// the background durability write can race testing.TempDir RemoveAll and make
	// the canonical suite flaky despite correct backup-ID behavior.
	deadline = time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		for _, run := range m.List() {
			if run.ID == second.ID && run.State == StateSucceeded {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("second backup did not complete")
}

func TestRejectsCrossNamespaceCredential(t *testing.T) {
	m, _ := New(Options{StateDir: t.TempDir(), BundleDir: t.TempDir(), Simulation: true, System: &bootstrap.SimulatedSystem{Root: t.TempDir()}})
	r := request()
	r.Services.ObjectStorage.CredentialRef = "external-secret://other/s3"
	if _, err := m.StartBackup(context.Background(), r); err == nil {
		t.Fatal("expected credential namespace rejection")
	}
}
func TestRunStatePersists(t *testing.T) {
	state := t.TempDir()
	m, _ := New(Options{StateDir: state, BundleDir: t.TempDir(), Simulation: true, System: &bootstrap.SimulatedSystem{Root: t.TempDir()}})
	_, _ = m.StartBackup(context.Background(), request())
	time.Sleep(30 * time.Millisecond)
	if _, err := os.Stat(filepath.Join(state, "disaster-recovery-runs.json")); err != nil {
		t.Fatal(err)
	}
}

func TestBackupJobsUseDurableRWOPlacementAfterWorkloadQuiesce(t *testing.T) {
	bundle := bootstrap.BundleManifest{}
	bundle.Spec.Workloads.MaintenanceImage = "registry.example.test/maintenance@sha256:" + strings.Repeat("a", 64)
	run := Run{ID: "dr-operation-backup-1234567890", BackupID: "backup-1234567890", ObjectPrefix: "factory/backup-1234567890"}
	forgejo := backupManifest("forgejo", run, request(), bundle, "worker-a")
	zot := backupManifest("zot", run, request(), bundle, "worker-b")
	if !strings.Contains(forgejo, `nodeName: "worker-a"`) {
		t.Fatalf("Forgejo backup must retain its pre-quiesce RWO node placement:\n%s", forgejo)
	}
	if !strings.Contains(zot, `nodeName: "worker-b"`) {
		t.Fatalf("zot backup must retain its pre-quiesce RWO node placement:\n%s", zot)
	}
	for name, manifest := range map[string]string{"forgejo": forgejo, "zot": zot} {
		if strings.Contains(manifest, "requiredDuringSchedulingIgnoredDuringExecution") {
			t.Fatalf("%s backup must not require a live service pod after quiesce", name)
		}
	}
	postgresql := backupManifest("postgresql", run, request(), bundle, "")
	if strings.Contains(postgresql, "nodeName:") {
		t.Fatal("PostgreSQL logical backup must not be pinned to a workload node")
	}
}

func TestAgentPKIBackupAndRestoreContract(t *testing.T) {
	bundle := bootstrap.BundleManifest{}
	bundle.Spec.Workloads.MaintenanceImage = "registry.example.test/maintenance@sha256:" + strings.Repeat("b", 64)
	run := Run{ID: "dr-operation-backup-agent-pki", BackupID: "backup-agent-pki", ObjectPrefix: "factory/backup-agent-pki"}
	backup := backupManifest("agent-pki", run, request(), bundle, "")
	for _, term := range []string{"platform-agent-mtls", "client-ca.crt", "client-ca.key", "tls.crt", "tls.key", "--sse AES256"} {
		if !strings.Contains(backup, term) {
			t.Fatalf("agent PKI backup missing %q", term)
		}
	}
	restore := restoreManifest("agent-pki", run, request(), bundle)
	for _, term := range []string{"platform-agent-mtls", "/host/kubectl", "/host/kubeconfig", "patch secret/platform-agent-mtls --type=json", "/metadata/uid", "/metadata/resourceVersion", "client-ca.key"} {
		if !strings.Contains(restore, term) {
			t.Fatalf("agent PKI restore missing %q", term)
		}
	}
}

func TestDisasterRecoveryStateCorruptionFailsClosed(t *testing.T) {
	state := t.TempDir()
	if err := os.WriteFile(filepath.Join(state, "disaster-recovery-runs.json"), []byte("{not-json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Options{StateDir: state, BundleDir: t.TempDir(), Simulation: true, System: &bootstrap.SimulatedSystem{Root: t.TempDir()}}); err == nil {
		t.Fatal("expected corrupt disaster-recovery state to fail startup")
	}
}

func TestDisasterRecoveryQueuePersistenceFailureRejectsOperation(t *testing.T) {
	state := t.TempDir()
	m, err := New(Options{StateDir: state, BundleDir: t.TempDir(), Simulation: true, System: &bootstrap.SimulatedSystem{Root: t.TempDir()}})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.RemoveAll(state); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(state, []byte("not-a-directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = m.StartBackup(context.Background(), request()); err == nil {
		t.Fatal("expected disaster-recovery start to reject undurable queue state")
	}
	if len(m.List()) != 0 {
		t.Fatalf("failed queue persistence must roll back in-memory run: %+v", m.List())
	}
}

func TestInterruptedDisasterRecoveryRunRemainsBlockingAfterRestart(t *testing.T) {
	state := t.TempDir()
	now := time.Now().UTC()
	runs := []Run{{ID: "dr-backup-interrupted", Action: ActionBackup, State: StateRunning, BackupID: "backup-interrupted", ObjectPrefix: "factory/backup-interrupted", CreatedAt: now, StartedAt: &now}}
	raw, _ := json.Marshal(runs)
	if err := os.WriteFile(filepath.Join(state, "disaster-recovery-runs.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := New(Options{StateDir: state, BundleDir: t.TempDir(), Simulation: true, System: &bootstrap.SimulatedSystem{Root: t.TempDir()}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.StartBackup(context.Background(), request()); err == nil {
		t.Fatal("interrupted disaster-recovery run must block overlapping mutation after restart")
	}
}

func TestInterruptedDisasterRecoveryRunReconcilesAfterRestart(t *testing.T) {
	state := t.TempDir()
	now := time.Now().UTC()
	runs := []Run{{ID: "dr-backup-interrupted-reconcile", Action: ActionBackup, State: StateRunning, BackupID: "backup-interrupted", ObjectPrefix: "factory/backup-interrupted", CreatedAt: now, StartedAt: &now}}
	raw, _ := json.Marshal(runs)
	if err := os.WriteFile(filepath.Join(state, "disaster-recovery-runs.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := New(Options{StateDir: state, BundleDir: t.TempDir(), Simulation: true, System: &bootstrap.SimulatedSystem{Root: t.TempDir()}})
	if err != nil {
		t.Fatal(err)
	}
	if resumed := m.Reconcile(context.Background(), request()); resumed != 1 {
		t.Fatalf("reconciled runs=%d", resumed)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		for _, run := range m.List() {
			if run.ID == runs[0].ID && run.State == StateSucceeded {
				if run.ObjectStorage.URL != request().Services.ObjectStorage.URL {
					t.Fatalf("recovery target not persisted: %+v", run.ObjectStorage)
				}
				if run.ProfileID != request().ProfileID {
					t.Fatalf("recovery profile not durably persisted: got=%q want=%q", run.ProfileID, request().ProfileID)
				}
				if run.StartedAt == nil || !run.StartedAt.Equal(now) {
					t.Fatalf("reconcile changed original startedAt: before=%v after=%v", now, run.StartedAt)
				}
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("interrupted disaster-recovery run did not reconcile")
}

func TestDisasterRecoveryCredentialReferenceIsStrictKubernetesSecretContract(t *testing.T) {
	valid := []string{
		"external-secret://platform-system/s3-credentials",
		"external-secret://platform-system/s3.credentials-prod",
	}
	for _, ref := range valid {
		req := request()
		req.Services.ObjectStorage.CredentialRef = ref
		if err := validateTarget(req); err != nil {
			t.Fatalf("valid credentialRef %q rejected: %v", ref, err)
		}
	}
	invalid := []string{
		"platform-system/s3-credentials",
		"external-secret://platform-system/",
		"external-secret://platform-system/-secret",
		"external-secret://platform-system/secret-",
		"external-secret://platform-system/UPPER",
		"external-secret://platform-system/a..b",
		"external-secret://platform-system/a/b",
		"external-secret://other/s3-credentials",
		"external-secret://platform-system/secret}\nmetadata: {name: injected}",
	}
	for _, ref := range invalid {
		req := request()
		req.Services.ObjectStorage.CredentialRef = ref
		if err := validateTarget(req); err == nil {
			t.Fatalf("invalid credentialRef %q was accepted", ref)
		}
	}
}

func TestDisasterRecoveryManifestKeepsObjectKeyOutOfShellProgram(t *testing.T) {
	bundle := bootstrap.BundleManifest{}
	bundle.Spec.Workloads.MaintenanceImage = "registry.example.test/maintenance@sha256:" + strings.Repeat("c", 64)
	malicious := `factory/$(touch /tmp/dr-owned);echo injected`
	run := Run{ID: "dr-operation-backup-shell-boundary", BackupID: "backup-shell-boundary", ObjectPrefix: malicious + "/backup-shell-boundary"}
	for _, manifest := range []string{
		backupManifest("forgejo", run, request(), bundle, "worker-a"),
		restoreManifest("forgejo", run, request(), bundle),
		backupManifest("postgresql", run, request(), bundle, ""),
		restoreManifest("postgresql", run, request(), bundle),
	} {
		if !strings.Contains(manifest, "S3_OBJECT_KEY") || !strings.Contains(manifest, `$S3_OBJECT_KEY`) {
			t.Fatalf("manifest does not use the isolated object-key environment boundary:\n%s", manifest)
		}
		if strings.Count(manifest, malicious) != 2 {
			t.Fatalf("untrusted object prefix must appear only in object/checksum environment values:\n%s", manifest)
		}
		if strings.Contains(manifest, `s3://$S3_BUCKET/`+malicious) {
			t.Fatalf("untrusted object prefix was interpolated into the shell program:\n%s", manifest)
		}
	}
}

func TestDisasterRecoveryPostgreSQLHAUsesDatabaseOwnerCredentials(t *testing.T) {
	bundle := bootstrap.BundleManifest{}
	bundle.Spec.Workloads.MaintenanceImage = "registry.example.test/maintenance@sha256:" + strings.Repeat("d", 64)
	run := Run{ID: "dr-operation-backup-postgresql-owner", BackupID: "backup-postgresql-owner", ObjectPrefix: "factory/backup-postgresql-owner"}
	backup := backupManifest("postgresql", run, request(), bundle, "")
	restore := restoreManifest("postgresql", run, request(), bundle)
	for _, term := range []string{
		"platform-postgresql-app",
		"platform-keycloak-db",
		"platform-forgejo-db",
		"pg_dump --clean --if-exists --no-owner -h platform-postgresql -U platform -d platform_factory -f /work/platform_factory.sql",
		"pg_dump --clean --if-exists --no-owner -h platform-postgresql -U keycloak -d keycloak -f /work/keycloak.sql",
		"pg_dump --clean --if-exists --no-owner -h platform-postgresql -U forgejo -d forgejo -f /work/forgejo.sql",
	} {
		if !strings.Contains(backup, term) {
			t.Fatalf("HA PostgreSQL backup is missing owner-scoped contract %q:\n%s", term, backup)
		}
	}
	if strings.Contains(backup, "pg_dumpall") {
		t.Fatalf("HA PostgreSQL backup must not depend on pg_dumpall/app-role superuser privileges:\n%s", backup)
	}
	for _, term := range []string{
		"-U platform -d platform_factory",
		"-U keycloak -d keycloak",
		"-U forgejo -d forgejo",
		"legacy HA PostgreSQL pg_dumpall backups are not safely restorable",
	} {
		if !strings.Contains(restore, term) {
			t.Fatalf("HA PostgreSQL restore is missing owner-scoped contract %q:\n%s", term, restore)
		}
	}
}

func TestDisasterRecoveryPostgreSQLSingleNodeRetainsLegacyRestoreCompatibility(t *testing.T) {
	bundle := bootstrap.BundleManifest{}
	bundle.Spec.Workloads.MaintenanceImage = "registry.example.test/maintenance@sha256:" + strings.Repeat("e", 64)
	run := Run{ID: "dr-operation-backup-postgresql-single", BackupID: "backup-postgresql-single", ObjectPrefix: "factory/backup-postgresql-single"}
	req := request()
	req.ProfileID = "evaluation-single-node"
	backup := backupManifest("postgresql", run, req, bundle, "")
	restore := restoreManifest("postgresql", run, req, bundle)
	if strings.Contains(backup, "platform-keycloak-db") || strings.Contains(backup, "platform-forgejo-db") {
		t.Fatalf("single-node PostgreSQL backup referenced HA-only secrets:\n%s", backup)
	}
	for _, database := range []string{"platform_factory", "keycloak", "forgejo"} {
		if !strings.Contains(backup, "-U platform -d "+database) {
			t.Fatalf("single-node backup does not use platform owner for %s:\n%s", database, backup)
		}
	}
	if !strings.Contains(restore, `psql -v ON_ERROR_STOP=1 -h platform-postgresql -U platform -d postgres -f /tmp/postgresql-legacy.sql`) {
		t.Fatalf("single-node restore lost compatibility with legacy pg_dumpall backup objects:\n%s", restore)
	}
}

func TestDisasterRecoveryPostgreSQLCommandsDoNotHidePipelineFailures(t *testing.T) {
	backup := postgresqlBackupCommand(request())
	restore := postgresqlRestoreCommand(request())
	for _, command := range []string{backup, restore} {
		for _, unsafe := range []string{"pg_dump --clean --if-exists --no-owner -h platform-postgresql -U platform -d platform_factory |", "gunzip -c /work/platform_factory.sql.gz |", "gunzip -c /work/keycloak.sql.gz |", "gunzip -c /work/forgejo.sql.gz |"} {
			if strings.Contains(command, unsafe) {
				t.Fatalf("PostgreSQL DR command can hide a left-side pipeline failure %q:\n%s", unsafe, command)
			}
		}
	}
	for _, required := range []string{"pg_dump --clean --if-exists --no-owner", "-f /work/platform_factory.sql", "gzip -c /work/platform_factory.sql", "gunzip -c /work/platform_factory.sql.gz > /work/platform_factory.sql", "psql -v ON_ERROR_STOP=1"} {
		if !strings.Contains(backup+restore, required) {
			t.Fatalf("failure-propagating PostgreSQL DR step %q is missing", required)
		}
	}
}

func TestDisasterRecoveryMaintenanceJobsRunWithFilesystemAuthority(t *testing.T) {
	bundle := bootstrap.BundleManifest{}
	bundle.Spec.Workloads.MaintenanceImage = "registry.example.test/maintenance@sha256:" + strings.Repeat("f", 64)
	run := Run{ID: "dr-operation-backup-filesystem-authority", BackupID: "backup-filesystem-authority", ObjectPrefix: "factory/backup-filesystem-authority"}
	for name, manifest := range map[string]string{
		"forgejo-backup":    backupManifest("forgejo", run, request(), bundle, "worker-a"),
		"zot-restore":       restoreManifest("zot", run, request(), bundle),
		"agent-pki-restore": restoreManifest("agent-pki", run, request(), bundle),
	} {
		for _, term := range []string{"securityContext:", "runAsUser: 0", "runAsGroup: 0", "allowPrivilegeEscalation: false"} {
			if !strings.Contains(manifest, term) {
				t.Fatalf("%s lacks required DR filesystem authority %q:\n%s", name, term, manifest)
			}
		}
	}
}

func testRestoreTargets() []RestoreTargetIdentity {
	return []RestoreTargetIdentity{
		{Namespace: "platform-system", Name: "platform-internal-services", UID: "secret-uid-1", ResourceVersion: "17"},
		{Namespace: "platform-system", Name: "platform-ingress-tls", UID: "ingress-uid-1", ResourceVersion: "21"},
		{Namespace: "platform-gitops", Name: "platform-internal-git", UID: "git-uid-1", ResourceVersion: "31"},
		{Namespace: "platform-system", Name: "platform-agent-mtls", UID: "agent-uid-1", ResourceVersion: "41"},
	}
}

func secretFixture(uid, resourceVersion, secretType string, labels map[string]string, data map[string]string) map[string]any {
	return map[string]any{
		"metadata": map[string]any{"uid": uid, "resourceVersion": resourceVersion, "labels": labels},
		"type":     secretType,
		"data":     data,
	}
}

type disasterRecoverySecretMirrorSystem struct {
	*bootstrap.SimulatedSystem
	objects map[string]map[string]any
}

func (s *disasterRecoverySecretMirrorSystem) namespace(args []string) string {
	for i, arg := range args {
		if arg == "-n" && i+1 < len(args) {
			return args[i+1]
		}
	}
	return "platform-system"
}

func (s *disasterRecoverySecretMirrorSystem) secretKey(args []string) string {
	ns := s.namespace(args)
	for _, arg := range args {
		if strings.HasPrefix(arg, "secret/") {
			return ns + "/" + strings.TrimPrefix(arg, "secret/")
		}
	}
	return ""
}

func (s *disasterRecoverySecretMirrorSystem) Output(ctx context.Context, name string, args []string, environment map[string]string) ([]byte, error) {
	joined := strings.Join(args, " ")
	s.Commands = append(s.Commands, name+" "+joined)
	if strings.Contains(joined, " get secret/") && strings.Contains(joined, " -o json") {
		key := s.secretKey(args)
		obj := s.objects[key]
		if obj == nil {
			return nil, errors.New("unexpected secret selector: " + key)
		}
		return json.Marshal(obj)
	}
	return s.SimulatedSystem.Output(ctx, name, args, environment)
}

func (s *disasterRecoverySecretMirrorSystem) Run(ctx context.Context, name string, args []string, environment map[string]string) error {
	joined := strings.Join(args, " ")
	if strings.Contains(joined, " patch secret/platform-internal-services ") && strings.Contains(joined, `"op":"remove","path":"/data/gitops-signing-key"`) {
		key := s.secretKey(args)
		if obj := s.objects[key]; obj != nil {
			if data, ok := obj["data"].(map[string]string); ok {
				delete(data, "gitops-signing-key")
			}
			if metadata, ok := obj["metadata"].(map[string]any); ok {
				metadata["resourceVersion"] = "18"
			}
		}
	}
	return s.SimulatedSystem.Run(ctx, name, args, environment)
}

func restoreSecretObjects(enc func(string) string) map[string]map[string]any {
	return map[string]map[string]any{
		"platform-system/platform-internal-services": secretFixture("secret-uid-1", "17", "Opaque", nil, map[string]string{
			"forgejo-admin-password": enc("forgejo-old"), "identity-admin-password": enc("identity-old"), "identity-admin-email": enc("admin@example.test"),
			"session-secret": enc("session-old"), "catalog-signing-key": enc("catalog-old"), "gitops-signing-key": enc("gitops-old"),
		}),
		"platform-system/platform-ingress-tls": secretFixture("ingress-uid-1", "21", "kubernetes.io/tls", nil, map[string]string{
			"ca.crt": enc("ca-old"), "tls.crt": enc("cert-old"), "tls.key": enc("key-old"),
		}),
		"platform-gitops/platform-internal-git": secretFixture("git-uid-1", "31", "Opaque", map[string]string{"argocd.argoproj.io/secret-type": "repository"}, map[string]string{
			"type": enc("git"), "url": enc("http://forgejo/repo.git"), "username": enc("platform-admin"), "password": enc("forgejo-old"),
		}),
		"platform-system/platform-agent-mtls": secretFixture("agent-uid-1", "41", "Opaque", nil, map[string]string{
			"client-ca.crt": enc("agent-ca-old"), "client-ca.key": enc("agent-key-old"), "tls.crt": enc("agent-cert-old"), "tls.key": enc("agent-tls-key-old"),
		}),
	}
}

func TestDisasterRecoveryCaptureRestoreTargetsBindsProductAuthorityShapeAndIdentity(t *testing.T) {
	enc := func(v string) string { return base64.StdEncoding.EncodeToString([]byte(v)) }
	system := &disasterRecoverySecretMirrorSystem{SimulatedSystem: &bootstrap.SimulatedSystem{Root: t.TempDir()}, objects: restoreSecretObjects(enc)}
	manager := &Manager{system: system, stateDir: t.TempDir()}
	targets, err := manager.captureRestoreTargets(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != len(restoreTargetRequirements) {
		t.Fatalf("restore target count=%d want=%d", len(targets), len(restoreTargetRequirements))
	}
	run := Run{RestoreTargets: targets}
	for _, expected := range testRestoreTargets() {
		got, err := restoreTarget(run, expected.Namespace, expected.Name)
		if err != nil {
			t.Fatal(err)
		}
		if got.UID != expected.UID || got.ResourceVersion != expected.ResourceVersion {
			t.Fatalf("restore target %s/%s=%+v want=%+v", expected.Namespace, expected.Name, got, expected)
		}
	}
	internal := system.objects["platform-system/platform-internal-services"]
	internal["type"] = "kubernetes.io/tls"
	if _, err = manager.captureRestoreTargets(context.Background()); err == nil || !strings.Contains(err.Error(), "does not match product authority type") {
		t.Fatalf("foreign secret shape was accepted: %v", err)
	}
}

func TestDisasterRecoveryRestoredAuthorityRejectsSameNameReplacement(t *testing.T) {
	enc := func(v string) string { return base64.StdEncoding.EncodeToString([]byte(v)) }
	system := &disasterRecoverySecretMirrorSystem{SimulatedSystem: &bootstrap.SimulatedSystem{Root: t.TempDir()}, objects: restoreSecretObjects(enc)}
	manager := &Manager{system: system, stateDir: t.TempDir()}
	run := Run{RestoreTargets: testRestoreTargets()}
	metadata := system.objects["platform-system/platform-internal-services"]["metadata"].(map[string]any)
	metadata["uid"] = "foreign-replacement-uid"
	metadata["resourceVersion"] = "99"
	if err := manager.syncRestoredPlatformAuthority(context.Background(), run); err == nil || !strings.Contains(err.Error(), "refusing same-name replacement") {
		t.Fatalf("same-name Secret replacement was accepted: %v", err)
	}
	if _, err := os.Stat(filepath.Join(system.Root, "var/lib/4so-platform-installer/secrets/forgejo-admin-password")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("foreign Secret data reached installer authority before failure: %v", err)
	}
}

func TestDisasterRecoveryLegacyInterruptedRestoreWithoutTargetIdentityFailsClosed(t *testing.T) {
	run := Run{ID: "dr-restore-legacy-no-targets", Action: ActionRestore, State: StateRunning, BackupID: "backup-legacy", ObjectPrefix: "factory/backup-legacy", ProfileID: "production-standard-ha", CreatedAt: time.Now().UTC()}
	if err := validateRestoreTargets(run); err == nil || !strings.Contains(err.Error(), "automatic legacy restore replay is forbidden") {
		t.Fatalf("legacy restore without durable target identities was accepted: %v", err)
	}
}

func TestDisasterRecoveryWholeApplianceBackupIncludesRuntimeAuthority(t *testing.T) {
	bundle := bootstrap.BundleManifest{}
	bundle.Spec.Workloads.MaintenanceImage = "registry.example.test/maintenance@sha256:" + strings.Repeat("a", 64)
	run := Run{ID: "dr-operation-backup-runtime-authority", BackupID: "backup-runtime-authority", ObjectPrefix: "factory/backup-runtime-authority", RestoreTargets: testRestoreTargets()}
	backup := backupManifest("platform-secrets", run, request(), bundle, "manager-node")
	for _, required := range []string{
		"platform-internal-services",
		"platform-ingress-tls",
		"forgejo-admin-password",
		"identity-admin-password",
		"identity-admin-email",
		"session-secret",
		"catalog-signing-key",
		"gitops-signing-key",
		"/var/lib/4so-platform-installer/secrets/gitops-signing-key",
		`nodeName: "manager-node"`,
		"ingress/tls.crt",
		"ingress/tls.key",
		"ingress/ca.crt",
		"--sse AES256",
	} {
		if !strings.Contains(backup, required) {
			t.Fatalf("whole-appliance authority backup is missing %q:\n%s", required, backup)
		}
	}
	if strings.Contains(backup, "bootstrap-token") {
		t.Fatalf("revoked bootstrap credential must not be reintroduced into a DR backup:\n%s", backup)
	}

	restore := restoreManifest("platform-secrets", run, request(), bundle)
	restoreShell := renderedShellCommandText(t, restore)
	for _, required := range []string{
		"patch secret/platform-internal-services --type=json",
		"patch secret/platform-ingress-tls --type=json",
		"patch secret/platform-internal-git --type=json",
		"/metadata/uid",
		"/metadata/resourceVersion",
		"gitops-signing-key",
		"CA_CRT_B64=",
		"FORGEJO_PASSWORD_B64=",
		`test "$INTERNAL_UID" = "secret-uid-1"`,
		`test "$INTERNAL_RV" = "17"`,
		`test "$INGRESS_UID" = "ingress-uid-1"`,
		`test "$GIT_UID" = "git-uid-1"`,
	} {
		if !strings.Contains(restoreShell, required) {
			t.Fatalf("whole-appliance authority restore is missing %q:\n%s", required, restore)
		}
	}
	if strings.Contains(restore, "--from-file=bootstrap-token") {
		t.Fatalf("restore must not recreate the revoked bootstrap credential from backup:\n%s", restore)
	}
	if strings.Contains(restore, "bootstrap-token") {
		t.Fatalf("restored authority must contain no bootstrap credential at all:\n%s", restore)
	}
}

func TestInterruptedLegacyBackupResetsProgressBeforeIntegrityV2Resume(t *testing.T) {
	stateDir := t.TempDir()
	now := time.Now().UTC()
	legacy := Run{
		ID:                  "dr-backup-legacy-resume",
		Action:              ActionBackup,
		State:               StateRunning,
		BackupID:            "backup-legacy-resume",
		ObjectPrefix:        "factory/backup-legacy-resume",
		ProfileID:           "production-standard-ha",
		CompletedComponents: []string{"postgresql", "platform-secrets", "commit"},
		CreatedAt:           now,
		StartedAt:           &now,
	}
	m := &Manager{stateDir: stateDir, runs: []Run{legacy}, active: true, now: time.Now}
	migrated, err := m.ensureCurrentBackupFormat(legacy.ID, &legacy)
	if err != nil {
		t.Fatal(err)
	}
	if migrated.BackupFormat != backupFormatIntegrityV2 {
		t.Fatalf("backup format=%q want=%q", migrated.BackupFormat, backupFormatIntegrityV2)
	}
	if len(migrated.CompletedComponents) != 0 {
		t.Fatalf("legacy completed components must be replayed under v2 integrity format: %v", migrated.CompletedComponents)
	}
	raw, err := os.ReadFile(filepath.Join(stateDir, "disaster-recovery-runs.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), backupFormatIntegrityV2) {
		t.Fatalf("migrated backup format was not durably persisted:\n%s", raw)
	}
}

func TestDisasterRecoveryBackupCommitAndRestorePreflightCoverEveryComponent(t *testing.T) {
	bundle := bootstrap.BundleManifest{}
	bundle.Spec.Workloads.MaintenanceImage = "registry.example.test/maintenance@sha256:" + strings.Repeat("b", 64)
	run := Run{ID: "dr-operation-backup-commit", BackupID: "backup-commit", ObjectPrefix: "factory/backup-commit"}
	commit := backupCommitManifest(run, request(), bundle)
	marker := backupCommitSuffix(request())
	if !strings.Contains(commit, marker) || !strings.Contains(commit, "--sse AES256") {
		t.Fatalf("backup completion marker is not durable/encrypted:\n%s", commit)
	}
	preflight := restorePreflightManifest(run, request(), bundle)
	preflightShell := renderedShellCommandText(t, preflight)
	if !strings.Contains(preflightShell, marker) || !strings.Contains(preflightShell, "s3api head-object") {
		t.Fatalf("restore preflight does not require the completion marker:\n%s", preflight)
	}
	for _, component := range disasterRecoveryComponents {
		if !strings.Contains(preflightShell, `"`+component+`"`) {
			t.Fatalf("restore preflight does not enumerate %s payload:\n%s", component, preflight)
		}
	}
	for _, required := range []string{"$component.tar.gz", "$component.sha256", "sha256sum", `test "$actual" = "$expected"`, `tar -tzf "/tmp/$component.tar.gz"`, `tar -tvzf "/tmp/$component.tar.gz"`} {
		if !strings.Contains(preflightShell, required) {
			t.Fatalf("restore preflight does not verify backup integrity/archive safety with %q:\n%s", required, preflight)
		}
	}
	digestIndex := strings.Index(preflightShell, `test "$actual" = "$expected"`)
	archiveIndex := strings.Index(preflightShell, `tar -tvzf "/tmp/$component.tar.gz"`)
	cleanupIndex := strings.Index(preflightShell, `rm -f "/tmp/$component.tar.gz"`)
	if digestIndex < 0 || archiveIndex < 0 || cleanupIndex < 0 || digestIndex > archiveIndex || archiveIndex > cleanupIndex {
		t.Fatalf("restore preflight must prove digest then archive safety before deleting staged payload:\n%s", preflightShell)
	}
	if strings.Count(preflight, run.ObjectPrefix) != 1 {
		t.Fatalf("untrusted object prefix must only appear in its environment value boundary:\n%s", preflight)
	}
}

func TestSafeTarArchiveCommandAcceptsRegularArchivesAndRejectsUnsafeEntries(t *testing.T) {
	root := t.TempDir()
	makeArchive := func(name string, setup func(string)) string {
		dir := filepath.Join(root, name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		setup(dir)
		archive := filepath.Join(root, name+".tar.gz")
		cmd := exec.Command("tar", "-C", dir, "-czf", archive, ".")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("create archive %s: %v\n%s", name, err, output)
		}
		return archive
	}

	safe := makeArchive("safe", func(dir string) {
		if err := os.WriteFile(filepath.Join(dir, "regular"), []byte("ok"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(dir, "nested"), 0o755); err != nil {
			t.Fatal(err)
		}
	})
	unsafeFIFODir := filepath.Join(root, "fifo")
	if err := os.MkdirAll(unsafeFIFODir, 0o755); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("mkfifo", filepath.Join(unsafeFIFODir, "queue")).CombinedOutput(); err != nil {
		t.Fatalf("create fifo: %v\n%s", err, output)
	}
	if err := os.Chmod(filepath.Join(unsafeFIFODir, "queue"), 0o600); err != nil {
		t.Fatal(err)
	}
	unsafeFIFO := filepath.Join(root, "fifo.tar.gz")
	if output, err := exec.Command("tar", "-C", unsafeFIFODir, "-czf", unsafeFIFO, ".").CombinedOutput(); err != nil {
		t.Fatalf("create fifo archive: %v\n%s", err, output)
	}
	unsafeModeDir := filepath.Join(root, "setuid")
	if err := os.MkdirAll(unsafeModeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	setuid := filepath.Join(unsafeModeDir, "helper")
	if err := os.WriteFile(setuid, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(setuid, 0o755|os.ModeSetuid); err != nil {
		t.Fatal(err)
	}
	unsafeMode := filepath.Join(root, "setuid.tar.gz")
	if output, err := exec.Command("tar", "-C", unsafeModeDir, "-czf", unsafeMode, ".").CombinedOutput(); err != nil {
		t.Fatalf("create setuid archive: %v\n%s", err, output)
	}

	runCheck := func(label string, archive string, wantSuccess bool) {
		shell := safeTarArchiveCommand(archive) + "true"
		cmd := exec.Command("/bin/sh", "-ec", shell)
		output, err := cmd.CombinedOutput()
		if (err == nil) != wantSuccess {
			t.Fatalf("%s safety result=%v wantSuccess=%v: %v\n%s\ncommand=%s", label, err == nil, wantSuccess, err, output, shell)
		}
	}
	runCheck("regular archive", safe, true)
	runCheck("FIFO archive", unsafeFIFO, false)
	runCheck("setuid archive", unsafeMode, false)
}

func TestDisasterRecoveryBackupAndRestoreVerifyEncryptedPayloadIntegrity(t *testing.T) {
	bundle := bootstrap.BundleManifest{}
	bundle.Spec.Workloads.MaintenanceImage = "registry.example.test/maintenance@sha256:" + strings.Repeat("9", 64)
	run := Run{ID: "dr-operation-backup-integrity", BackupID: "backup-integrity", ObjectPrefix: "factory/backup-integrity", ProfileID: "production-standard-ha", ForgejoBackupNode: "manager-a", ZotBackupNode: "manager-b"}
	for _, component := range disasterRecoveryComponents {
		backup := backupManifest(component, run, request(), bundle, backupNodeForComponent(run, component))
		backupShell := renderedShellCommandText(t, backup)
		for _, required := range []string{"sha256sum", "--sse AES256"} {
			if !strings.Contains(backupShell, required) {
				t.Fatalf("%s backup is missing %q integrity/encryption contract:\n%s", component, required, backup)
			}
		}
		if !strings.Contains(backup, "S3_CHECKSUM_KEY") || strings.Count(backupShell, "--sse AES256") < 2 {
			t.Fatalf("%s backup must encrypt both payload and checksum sidecar:\n%s", component, backup)
		}
		restore := restoreManifest(component, run, request(), bundle)
		restoreShell := renderedShellCommandText(t, restore)
		if !strings.Contains(restore, "S3_CHECKSUM_KEY") {
			t.Fatalf("%s restore is missing checksum object environment boundary:\n%s", component, restore)
		}
		for _, required := range []string{`test "$actual" = "$expected"`, "sha256sum"} {
			if !strings.Contains(restoreShell, required) {
				t.Fatalf("%s restore is missing %q integrity verification:\n%s", component, required, restore)
			}
		}
		integrityIndex := strings.Index(restoreShell, `test "$actual" = "$expected"`)
		mutationNeedle := ""
		switch component {
		case "postgresql":
			mutationNeedle = "psql -v ON_ERROR_STOP=1"
		case "platform-secrets", "agent-pki":
			mutationNeedle = "patch secret/"
		default:
			mutationNeedle = "find /data"
		}
		mutationIndex := strings.Index(restoreShell, mutationNeedle)
		if integrityIndex < 0 || mutationIndex < 0 || integrityIndex > mutationIndex {
			t.Fatalf("%s restore must verify digest before destructive mutation %q:\n%s", component, mutationNeedle, restore)
		}
	}
}

func TestDisasterRecoveryRestoredAuthorityMirrorsInstallerState(t *testing.T) {
	root := t.TempDir()
	enc := func(v string) string { return base64.StdEncoding.EncodeToString([]byte(v)) }
	system := &disasterRecoverySecretMirrorSystem{SimulatedSystem: &bootstrap.SimulatedSystem{Root: root}, objects: restoreSecretObjects(enc)}
	manager := &Manager{system: system, stateDir: t.TempDir()}
	run := Run{RestoreTargets: testRestoreTargets()}
	if err := manager.syncRestoredPlatformAuthority(context.Background(), run); err != nil {
		t.Fatal(err)
	}
	if err := manager.syncRestoredAgentAuthority(context.Background(), run); err != nil {
		t.Fatal(err)
	}
	checks := map[string]string{
		"var/lib/4so-platform-installer/secrets/forgejo-admin-password":  "forgejo-old",
		"var/lib/4so-platform-installer/secrets/identity-admin-password": "identity-old",
		"var/lib/4so-platform-installer/secrets/session-secret":          "session-old",
		"var/lib/4so-platform-installer/secrets/catalog-signing-key":     "catalog-old",
		"var/lib/4so-platform-installer/secrets/gitops-signing-key":      "gitops-old",
		"var/lib/4so-platform-installer/secrets/platform-ca.crt":         "ca-old",
		"var/lib/4so-platform-installer/secrets/platform-tls.crt":        "cert-old",
		"var/lib/4so-platform-installer/secrets/platform-tls.key":        "key-old",
		"var/lib/4so-platform-installer/secrets/agent-ca.crt":            "agent-ca-old",
		"var/lib/4so-platform-installer/secrets/agent-ca.key":            "agent-key-old",
	}
	for relative, expected := range checks {
		raw, err := os.ReadFile(filepath.Join(root, relative))
		if err != nil {
			t.Fatalf("read mirrored installer authority %s: %v", relative, err)
		}
		if string(raw) != expected {
			t.Fatalf("mirrored installer authority %s=%q want=%q", relative, raw, expected)
		}
	}
	commands := strings.Join(system.Commands, "\n")
	if strings.Contains(commands, `remove`) && strings.Contains(commands, `gitops-signing-key`) {
		t.Fatalf("transient GitOps key cleanup must not run before restored authority is durably marked complete:\n%s", commands)
	}
}

func TestDisasterRecoveryTransientSigningKeyCleanupIsUIDAndResourceVersionFenced(t *testing.T) {
	enc := func(v string) string { return base64.StdEncoding.EncodeToString([]byte(v)) }
	system := &disasterRecoverySecretMirrorSystem{SimulatedSystem: &bootstrap.SimulatedSystem{Root: t.TempDir()}, objects: restoreSecretObjects(enc)}
	manager := &Manager{system: system, stateDir: t.TempDir()}
	if err := manager.removeSecretKeyWithIdentity(context.Background(), "platform-system", "platform-internal-services", "gitops-signing-key", "secret-uid-1"); err != nil {
		t.Fatal(err)
	}
	commands := strings.Join(system.Commands, "\n")
	for _, required := range []string{`patch secret/platform-internal-services --type=json`, `"op":"test","path":"/metadata/uid","value":"secret-uid-1"`, `"op":"test","path":"/metadata/resourceVersion","value":"17"`, `"op":"remove","path":"/data/gitops-signing-key"`} {
		if !strings.Contains(commands, required) {
			t.Fatalf("identity-fenced transient key cleanup is missing %q:\n%s", required, commands)
		}
	}
}

func TestDisasterRecoveryRestoreCommandsAvoidCreateApplyPipelines(t *testing.T) {
	bundle := bootstrap.BundleManifest{}
	bundle.Spec.Workloads.MaintenanceImage = "registry.example.test/maintenance@sha256:" + strings.Repeat("c", 64)
	run := Run{ID: "dr-operation-backup-no-hidden-pipeline", BackupID: "backup-no-hidden-pipeline", ObjectPrefix: "factory/backup-no-hidden-pipeline"}
	for _, component := range []string{"platform-secrets", "agent-pki"} {
		manifest := restoreManifest(component, run, request(), bundle)
		shell := renderedShellCommandText(t, manifest)
		if strings.Contains(shell, "-o yaml |") {
			t.Fatalf("%s restore can hide kubectl create failure behind a pipeline:\n%s", component, manifest)
		}
		if strings.Contains(shell, "apply -f -") {
			t.Fatalf("%s restore must not stream generated secret manifests through a pipeline:\n%s", component, manifest)
		}
		if strings.Contains(shell, "delete secret") || strings.Contains(shell, "create secret") {
			t.Fatalf("%s restore must not delete/recreate authority Secrets by name:\n%s", component, manifest)
		}
		for _, required := range []string{"patch secret/", "--type=json", "/metadata/uid", "/metadata/resourceVersion", `"op":"replace"`, `"path":"/data"`} {
			if !strings.Contains(shell, required) {
				t.Fatalf("%s restore is missing identity-fenced exact data replacement %q:\n%s", component, required, shell)
			}
		}
	}
}

type disasterRecoveryJobSystem struct {
	*bootstrap.SimulatedSystem
	jobs map[string]map[string]any
}

func (s *disasterRecoveryJobSystem) Output(ctx context.Context, name string, args []string, environment map[string]string) ([]byte, error) {
	command := name + " " + strings.Join(args, " ")
	s.Commands = append(s.Commands, command)
	verb := ""
	for _, arg := range args {
		if arg == "get" || arg == "create" {
			verb = arg
			break
		}
	}
	if verb == "get" {
		jobName := ""
		for i, arg := range args {
			if arg == "job" && i+1 < len(args) {
				jobName = args[i+1]
				break
			}
		}
		job := s.jobs[jobName]
		if job == nil {
			return nil, nil
		}
		return json.Marshal(job)
	}
	if verb == "create" {
		jobName := "dr-backup-commit-operation-1"
		job := map[string]any{
			"metadata": map[string]any{
				"name": jobName, "uid": "uid-1", "resourceVersion": "1",
				"annotations": map[string]any{
					"platform.4so.io/job-owner":    "disaster-recovery",
					"platform.4so.io/operation-id": "operation-1",
					"platform.4so.io/job-name":     jobName,
				},
			},
			"status": map[string]any{"conditions": []any{map[string]any{"type": "Complete", "status": "True"}}},
		}
		s.jobs[jobName] = job
		return json.Marshal(job)
	}
	return s.SimulatedSystem.Output(ctx, name, args, environment)
}

func TestDisasterRecoveryRunJobBindsDurableUIDAndNeverDeletesByName(t *testing.T) {
	system := &disasterRecoveryJobSystem{SimulatedSystem: &bootstrap.SimulatedSystem{Root: t.TempDir()}, jobs: map[string]map[string]any{}}
	m := &Manager{stateDir: t.TempDir(), system: system}
	manifest := `apiVersion: batch/v1
kind: Job
metadata: {name: dr-backup-commit-operation-1, namespace: platform-system, annotations: {"platform.4so.io/job-owner": "disaster-recovery", "platform.4so.io/operation-id": "operation-1", "platform.4so.io/job-name": "dr-backup-commit-operation-1"}}
spec: {template: {spec: {restartPolicy: Never, containers: [{name: noop, image: example.invalid/noop}]}}}
`
	if err := m.runJob(context.Background(), "operation-1", "dr-backup-commit-operation-1", "dr-backup-commit-legacy", manifest); err != nil {
		t.Fatal(err)
	}
	commands := strings.Join(system.Commands, "\n")
	if strings.Contains(commands, " delete job ") || strings.Contains(commands, " apply -f ") {
		t.Fatalf("DR job runner used name-only delete/apply:\n%s", commands)
	}
	job := system.jobs["dr-backup-commit-operation-1"]
	metadata := job["metadata"].(map[string]any)
	metadata["uid"] = "replacement-uid"
	metadata["resourceVersion"] = "2"
	if err := m.runJob(context.Background(), "operation-1", "dr-backup-commit-operation-1", "dr-backup-commit-legacy", manifest); err == nil || !strings.Contains(err.Error(), "UID changed") {
		t.Fatalf("same-name replacement must fail closed, got %v", err)
	}
}

func renderedShellCommandText(t *testing.T, manifest string) string {
	t.Helper()
	commands := make([]string, 0, 1)
	for _, line := range strings.Split(manifest, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "args: [") || !strings.HasSuffix(trimmed, "]") {
			continue
		}
		raw := strings.TrimSuffix(strings.TrimPrefix(trimmed, "args: ["), "]")
		command, err := strconv.Unquote(raw)
		if err != nil {
			t.Fatalf("decode rendered shell command %q: %v\n%s", raw, err, manifest)
		}
		commands = append(commands, command)
	}
	if len(commands) == 0 {
		t.Fatalf("manifest did not contain a rendered shell args command:\n%s", manifest)
	}
	return strings.Join(commands, "\n")
}

func assertRenderedShellSyntax(t *testing.T, manifest string) {
	t.Helper()
	found := 0
	for _, line := range strings.Split(manifest, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "args: [") || !strings.HasSuffix(trimmed, "]") {
			continue
		}
		raw := strings.TrimSuffix(strings.TrimPrefix(trimmed, "args: ["), "]")
		command, err := strconv.Unquote(raw)
		if err != nil {
			t.Fatalf("decode rendered shell command %q: %v\n%s", raw, err, manifest)
		}
		found++
		if output, err := exec.Command("/bin/sh", "-n", "-c", command).CombinedOutput(); err != nil {
			t.Fatalf("rendered shell command is invalid: %v\n%s\nmanifest:\n%s", err, output, manifest)
		}
	}
	if found == 0 {
		t.Fatalf("manifest did not contain a rendered shell args command:\n%s", manifest)
	}
}

func TestDisasterRecoveryRenderedShellCommandsAreSyntacticallyValid(t *testing.T) {
	bundle := bootstrap.BundleManifest{}
	bundle.Spec.Workloads.MaintenanceImage = "registry.example.test/maintenance@sha256:" + strings.Repeat("d", 64)
	bundle.Spec.Workloads.PostgreSQLImage = "registry.example.test/postgres@sha256:" + strings.Repeat("e", 64)
	run := Run{ID: "dr-operation-backup-shell-syntax", BackupID: "backup-shell-syntax", ObjectPrefix: "factory/backup-shell-syntax", ProfileID: "production-standard-ha", ForgejoBackupNode: "manager-a", ZotBackupNode: "manager-b"}
	req := request()
	for _, component := range disasterRecoveryComponents {
		assertRenderedShellSyntax(t, backupManifest(component, run, req, bundle, backupNodeForComponent(run, component)))
		assertRenderedShellSyntax(t, restoreManifest(component, run, req, bundle))
	}
	assertRenderedShellSyntax(t, backupCommitManifest(run, req, bundle))
	assertRenderedShellSyntax(t, restorePreflightManifest(run, req, bundle))
}

func TestDisasterRecoveryResumeRejectsSameUIDReplicaDriftAfterRollout(t *testing.T) {
	system := &disasterRecoveryCommandSystem{SimulatedSystem: &bootstrap.SimulatedSystem{Root: t.TempDir()}, driftAfterRolloutResource: "deployment platform-api"}
	manager := &Manager{system: system, stateDir: t.TempDir()}
	err := manager.resumeWorkloadTargets(context.Background(), "test-op", []workloadReplicaTarget{{kind: "deployment", name: "platform-api", replicas: 3}})
	if err == nil || !strings.Contains(err.Error(), "replicas postcondition mismatch") {
		t.Fatalf("expected same-UID post-rollout replica drift rejection, got %v", err)
	}
}

func TestDisasterRecoveryDurableRestoreRecoveryFenceBlocksBackupAndClearsAfterRestore(t *testing.T) {
	state := t.TempDir()
	req := request()
	m, err := New(Options{StateDir: state, BundleDir: t.TempDir(), Simulation: true, System: &bootstrap.SimulatedSystem{Root: t.TempDir()}})
	if err != nil {
		t.Fatal(err)
	}
	targets := []RestoreTargetIdentity{
		{Namespace: "platform-system", Name: "platform-internal-services", UID: "simulation-uid-1", ResourceVersion: "1"},
		{Namespace: "platform-system", Name: "platform-ingress-tls", UID: "simulation-uid-2", ResourceVersion: "1"},
		{Namespace: "platform-gitops", Name: "platform-internal-git", UID: "simulation-uid-3", ResourceVersion: "1"},
		{Namespace: "platform-system", Name: "platform-agent-mtls", UID: "simulation-uid-4", ResourceVersion: "1"},
	}
	m.mu.Lock()
	m.runs = append(m.runs, Run{
		ID:                  "dr-restore-recovery-required",
		Action:              ActionRestore,
		State:               StateFailed,
		BackupID:            "backup-a",
		ObjectPrefix:        "factory/backup-a",
		ObjectStorage:       req.Services.ObjectStorage,
		ProfileID:           req.ProfileID,
		CompletedComponents: []string{"postgresql"},
		RestoreTargets:      targets,
		RecoveryRequired:    true,
		Error:               "partial appliance restore remains quiesced",
		CreatedAt:           time.Now().UTC(),
	})
	if err = m.saveLocked(); err != nil {
		m.mu.Unlock()
		t.Fatal(err)
	}
	m.mu.Unlock()

	reloaded, err := New(Options{StateDir: state, BundleDir: t.TempDir(), Simulation: true, System: &bootstrap.SimulatedSystem{Root: t.TempDir()}})
	if err != nil {
		t.Fatal(err)
	}
	if !reloaded.HasActive() {
		t.Fatal("durable DR restore recovery requirement did not remain blocking after restart")
	}
	if _, err = reloaded.StartBackup(context.Background(), req); err == nil || !strings.Contains(err.Error(), "requires recovery") {
		t.Fatalf("DR backup was admitted across partial restore recovery fence: %v", err)
	}
	if _, err = reloaded.StartRestore(context.Background(), req, "backup-b"); err == nil || !strings.Contains(err.Error(), "exact backup/profile/object-storage authority") {
		t.Fatalf("different DR backup was admitted as recovery: %v", err)
	}
	otherAuthority := req
	otherAuthority.Services.ObjectStorage.URL = "https://other-s3.example.test"
	if _, err = reloaded.StartRestore(context.Background(), otherAuthority, "backup-a"); err == nil || !strings.Contains(err.Error(), "exact backup/profile/object-storage authority") {
		t.Fatalf("different object-storage authority was admitted as DR recovery: %v", err)
	}
	rotatedCredential := req
	rotatedCredential.Services.ObjectStorage.CredentialRef = "external-secret://platform-system/s3-credentials-rotated"
	restore, err := reloaded.StartRestore(context.Background(), rotatedCredential, "backup-a")
	if err != nil {
		t.Fatal(err)
	}
	if restore.ObjectStorage.CredentialRef != rotatedCredential.Services.ObjectStorage.CredentialRef {
		t.Fatalf("credential rotation was not retained for exact-authority DR recovery: %+v", restore.ObjectStorage)
	}
	if len(restore.CompletedComponents) != 1 || restore.CompletedComponents[0] != "postgresql" {
		t.Fatalf("DR recovery did not inherit durable completed components: %+v", restore.CompletedComponents)
	}
	if len(restore.RestoreTargets) != len(targets) || restore.RestoreTargets[0] != targets[0] {
		t.Fatalf("DR recovery did not retain original restore target authority: %+v", restore.RestoreTargets)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		for _, run := range reloaded.List() {
			if run.ID == restore.ID && run.State == StateSucceeded {
				if reloaded.HasActive() {
					t.Fatalf("successful DR recovery restore did not clear durable recovery fence: %+v", reloaded.List())
				}
				for _, prior := range reloaded.List() {
					if prior.ID == "dr-restore-recovery-required" && prior.RecoveryRequired {
						t.Fatalf("successful DR restore did not clear blocker: %+v", prior)
					}
				}
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("DR recovery restore did not complete")
}

func TestDisasterRecoveryLoadRejectsInvalidRecoveryRequiredAuthority(t *testing.T) {
	state := t.TempDir()
	runs := []Run{{
		ID: "dr-invalid-recovery-marker", Action: ActionBackup, State: StateFailed,
		BackupID: "backup-a", RecoveryRequired: true, CreatedAt: time.Now().UTC(),
	}}
	raw, _ := json.Marshal(runs)
	if err := os.WriteFile(filepath.Join(state, "disaster-recovery-runs.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Options{StateDir: state, BundleDir: t.TempDir(), Simulation: true, System: &bootstrap.SimulatedSystem{Root: t.TempDir()}}); err == nil || !strings.Contains(err.Error(), "invalid recoveryRequired authority") {
		t.Fatalf("invalid DR recovery marker was accepted: %v", err)
	}
}

func TestDisasterRecoveryLoadRejectsNonPrefixRestoreProgress(t *testing.T) {
	state := t.TempDir()
	req := request()
	runs := []Run{{
		ID: "dr-restore-invalid-progress", Action: ActionRestore, State: StateRunning,
		BackupID: "backup-a", ObjectPrefix: "factory/backup-a", ObjectStorage: req.Services.ObjectStorage, ProfileID: req.ProfileID,
		CompletedComponents: []string{"postgresql", "agent-pki"}, CreatedAt: time.Now().UTC(),
	}}
	raw, _ := json.Marshal(runs)
	if err := os.WriteFile(filepath.Join(state, "disaster-recovery-runs.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Options{StateDir: state, BundleDir: t.TempDir(), Simulation: true, System: &bootstrap.SimulatedSystem{Root: t.TempDir()}}); err == nil || !strings.Contains(err.Error(), "invalid durable restore progress") {
		t.Fatalf("non-prefix restore progress was accepted: %v", err)
	}
}

func TestDisasterRecoveryLoadRejectsConflictingRecoveryRequiredAuthorities(t *testing.T) {
	state := t.TempDir()
	req := request()
	targets := []RestoreTargetIdentity{
		{Namespace: "platform-system", Name: "platform-internal-services", UID: "uid-1", ResourceVersion: "1"},
		{Namespace: "platform-system", Name: "platform-ingress-tls", UID: "uid-2", ResourceVersion: "1"},
		{Namespace: "platform-gitops", Name: "platform-internal-git", UID: "uid-3", ResourceVersion: "1"},
		{Namespace: "platform-system", Name: "platform-agent-mtls", UID: "uid-4", ResourceVersion: "1"},
	}
	now := time.Now().UTC()
	runs := []Run{
		{ID: "dr-restore-a", Action: ActionRestore, State: StateFailed, BackupID: "backup-a", ObjectPrefix: "factory/backup-a", ObjectStorage: req.Services.ObjectStorage, ProfileID: req.ProfileID, RestoreTargets: targets, RecoveryRequired: true, CreatedAt: now},
		{ID: "dr-restore-b", Action: ActionRestore, State: StateFailed, BackupID: "backup-b", ObjectPrefix: "factory/backup-b", ObjectStorage: req.Services.ObjectStorage, ProfileID: req.ProfileID, RestoreTargets: targets, RecoveryRequired: true, CreatedAt: now.Add(time.Second)},
	}
	raw, _ := json.Marshal(runs)
	if err := os.WriteFile(filepath.Join(state, "disaster-recovery-runs.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Options{StateDir: state, BundleDir: t.TempDir(), Simulation: true, System: &bootstrap.SimulatedSystem{Root: t.TempDir()}}); err == nil || !strings.Contains(err.Error(), "conflicting recoveryRequired authorities") {
		t.Fatalf("conflicting DR recovery authorities were accepted: %v", err)
	}
}
