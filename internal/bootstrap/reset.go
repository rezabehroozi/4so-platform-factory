package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"platform.4so.io/factory/internal/durablefile"
	"platform.4so.io/factory/internal/installation"
)

const (
	ResetAuthority      = "INSTALLER_JOURNALED_RESET_AUTHORITY_V1"
	ResetSchemaVersion  = 1
	ResetStateQueued    = "QUEUED"
	ResetStateRunning   = "RUNNING"
	ResetStateSucceeded = "SUCCEEDED"
	ResetStateFailed    = "FAILED"
)

type ResetStep struct {
	Key        string     `json:"key"`
	Title      string     `json:"title"`
	State      string     `json:"state"`
	Attempt    int        `json:"attempt"`
	StartedAt  *time.Time `json:"startedAt,omitempty"`
	FinishedAt *time.Time `json:"finishedAt,omitempty"`
	Error      string     `json:"error,omitempty"`
}

type ResetRun struct {
	Authority          string                      `json:"authority"`
	SchemaVersion      int                         `json:"schemaVersion"`
	ID                 string                      `json:"id"`
	SourceRunID        string                      `json:"sourceRunId"`
	SourceSpecDigest   string                      `json:"sourceSpecDigest"`
	SourceBundleDigest string                      `json:"sourceBundleDigest"`
	Request            installation.InstallRequest `json:"request"`
	State              string                      `json:"state"`
	Steps              []ResetStep                 `json:"steps"`
	CreatedAt          time.Time                   `json:"createdAt"`
	UpdatedAt          time.Time                   `json:"updatedAt"`
	LastError          string                      `json:"lastError,omitempty"`
	Simulation         bool                        `json:"simulation"`
}

type resetHistory struct {
	Authority     string     `json:"authority"`
	SchemaVersion int        `json:"schemaVersion"`
	Runs          []ResetRun `json:"runs"`
}

type ResetJournal struct{ path string }

func NewResetJournal(stateDir string) *ResetJournal {
	return &ResetJournal{path: filepath.Join(stateDir, "reset-runs.json")}
}

func (j *ResetJournal) load() (resetHistory, error) {
	history := resetHistory{Authority: ResetAuthority, SchemaVersion: ResetSchemaVersion}
	raw, err := os.ReadFile(j.path)
	if errors.Is(err, os.ErrNotExist) {
		return history, nil
	}
	if err != nil {
		return history, fmt.Errorf("read reset journal: %w", err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&history); err != nil {
		return history, fmt.Errorf("decode reset journal: %w", err)
	}
	var extra any
	if err = decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return history, errors.New("reset journal has trailing data")
	}
	if history.Authority != ResetAuthority || history.SchemaVersion != ResetSchemaVersion {
		return history, errors.New("unsupported reset journal authority")
	}
	return history, nil
}

func (j *ResetJournal) saveRun(run ResetRun) error {
	history, err := j.load()
	if err != nil {
		return err
	}
	replaced := false
	for index := range history.Runs {
		if history.Runs[index].ID == run.ID {
			history.Runs[index] = run
			replaced = true
			break
		}
	}
	if !replaced {
		history.Runs = append(history.Runs, run)
	}
	raw, err := json.MarshalIndent(history, "", "  ")
	if err != nil {
		return fmt.Errorf("encode reset journal: %w", err)
	}
	if err = durablefile.Replace(j.path, append(raw, '\n'), 0o700, 0o600); err != nil {
		return fmt.Errorf("persist reset journal: %w", err)
	}
	return nil
}

func (j *ResetJournal) list() ([]ResetRun, error) {
	history, err := j.load()
	if err != nil {
		return nil, err
	}
	out := append([]ResetRun(nil), history.Runs...)
	return out, nil
}

var resetSteps = []struct{ key, title string }{
	{"validate-source", "Bind reset to the exact persisted installation authority"},
	{"uninstall-remote-rke2", "Uninstall product-owned RKE2 from remote HA management nodes"},
	{"uninstall-local-rke2", "Uninstall product-owned RKE2 from the local management node"},
	{"purge-generated-state", "Remove generated installer, lifecycle and local backup state while preserving operator access inputs"},
	{"verify-clean-hosts", "Verify product-owned Kubernetes runtime and generated bootstrap state are absent"},
}

var productOwnedRKE2Paths = []string{
	"/etc/rancher/rke2",
	"/var/lib/rancher/rke2",
	"/usr/local/bin/rke2",
	"/usr/bin/rke2",
	"/usr/local/bin/rke2-uninstall.sh",
	"/usr/local/bin/rke2-killall.sh",
}

var generatedInstallerStateRelativePaths = []string{
	"bootstrap-state.json",
	"preflight-report.json",
	"install-request.json",
	"gitops-handover.json",
	"bootstrap-object-identities",
	"ha-nodes",
	"lifecycle-runs.json",
	"disaster-recovery-runs.json",
	"lifecycle",
	"disaster-recovery",
	"backups",
	"bundle/rke2",
	"bundle/gitops",
	"bundle/fleet",
	"secrets/rke2-token",
	"secrets/postgres-password",
	"secrets/keycloak-db-password",
	"secrets/forgejo-db-password",
	"secrets/forgejo-admin-password",
	"secrets/identity-admin-password",
	"secrets/session-secret",
	"secrets/bootstrap-token",
	"secrets/platform-ca.crt",
	"secrets/platform-tls.crt",
	"secrets/platform-tls.key",
	"secrets/agent-ca.crt",
	"secrets/agent-ca.key",
	"secrets/gitops-signing-key",
	"secrets/catalog-signing-key",
}

func (r *Runner) ResetRuns() ([]ResetRun, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.resetJournal.list()
}

func (r *Runner) HasBlockingReset() (bool, error) {
	runs, err := r.resetJournal.list()
	if err != nil {
		return false, err
	}
	if len(runs) == 0 {
		return false, nil
	}
	return runs[len(runs)-1].State != ResetStateSucceeded, nil
}

func (r *Runner) blockingReset() (*ResetRun, error) {
	runs, err := r.resetJournal.list()
	if err != nil || len(runs) == 0 {
		return nil, err
	}
	latest := runs[len(runs)-1]
	if latest.State == ResetStateSucceeded {
		return nil, nil
	}
	return &latest, nil
}

func (r *Runner) StartReset(ctx context.Context, confirmation string) (ResetRun, error) {
	if err := r.beginExecution(); err != nil {
		return ResetRun{}, err
	}
	defer r.endExecution()
	if existing, err := r.blockingReset(); err != nil {
		return ResetRun{}, err
	} else if existing != nil {
		return *existing, fmt.Errorf("reset run %s is %s and must be resumed", existing.ID, existing.State)
	}
	source, err := r.journal.Load()
	if err != nil {
		return ResetRun{}, err
	}
	if source == nil {
		return ResetRun{}, errors.New("no installation authority exists to reset")
	}
	if source.State != RunSucceeded && source.State != RunFailed {
		return ResetRun{}, fmt.Errorf("installation run %s is %s; reconcile it with Resume before destructive reset", source.ID, source.State)
	}
	expected := "reset:" + source.ID
	if strings.TrimSpace(confirmation) != expected {
		return ResetRun{}, fmt.Errorf("reset confirmation must be exactly %q", expected)
	}
	now := r.now().UTC()
	run := ResetRun{
		Authority: ResetAuthority, SchemaVersion: ResetSchemaVersion,
		ID:          fmt.Sprintf("reset-%s-%d", strings.TrimPrefix(source.ID, "bootstrap-"), now.UnixNano()),
		SourceRunID: source.ID, SourceSpecDigest: source.SpecDigest, SourceBundleDigest: source.BundleDigest,
		Request: source.Request, State: ResetStateQueued, CreatedAt: now, UpdatedAt: now, Simulation: r.simulation,
	}
	for _, item := range resetSteps {
		run.Steps = append(run.Steps, ResetStep{Key: item.key, Title: item.title, State: ResetStateQueued})
	}
	if err = r.resetJournal.saveRun(run); err != nil {
		return run, err
	}
	return r.executeReset(ctx, run)
}

func (r *Runner) ResumeReset(ctx context.Context, resetID string) (ResetRun, error) {
	if err := r.beginExecution(); err != nil {
		return ResetRun{}, err
	}
	defer r.endExecution()
	run, err := r.blockingReset()
	if err != nil {
		return ResetRun{}, err
	}
	if run == nil {
		return ResetRun{}, errors.New("no reset run requires resume")
	}
	if strings.TrimSpace(resetID) != run.ID {
		return *run, fmt.Errorf("reset resume must bind the active reset id %s", run.ID)
	}
	for index := range run.Steps {
		if run.Steps[index].State == ResetStateRunning {
			run.Steps[index].State = ResetStateFailed
			run.Steps[index].Error = "interrupted reset step detected; owner step is idempotent and will be reconciled on explicit resume"
			run.Steps[index].FinishedAt = nil
		}
	}
	run.State = ResetStateFailed
	run.UpdatedAt = r.now().UTC()
	if err = r.resetJournal.saveRun(*run); err != nil {
		return *run, err
	}
	return r.executeReset(ctx, *run)
}

func (r *Runner) executeReset(ctx context.Context, run ResetRun) (ResetRun, error) {
	run.State = ResetStateRunning
	run.LastError = ""
	run.UpdatedAt = r.now().UTC()
	if err := r.resetJournal.saveRun(run); err != nil {
		return run, err
	}
	for index := range run.Steps {
		if run.Steps[index].State == ResetStateSucceeded {
			continue
		}
		started := r.now().UTC()
		run.Steps[index].State = ResetStateRunning
		run.Steps[index].Attempt++
		run.Steps[index].StartedAt = &started
		run.Steps[index].FinishedAt = nil
		run.Steps[index].Error = ""
		run.UpdatedAt = started
		if err := r.resetJournal.saveRun(run); err != nil {
			return run, err
		}
		err := r.executeResetStep(ctx, run.Steps[index].Key, run)
		finished := r.now().UTC()
		run.Steps[index].FinishedAt = &finished
		run.UpdatedAt = finished
		if err != nil {
			run.Steps[index].State = ResetStateFailed
			run.Steps[index].Error = err.Error()
			run.State = ResetStateFailed
			run.LastError = run.Steps[index].Key + ": " + err.Error()
			if saveErr := r.resetJournal.saveRun(run); saveErr != nil {
				return run, fmt.Errorf("%w; persist failed reset: %v", err, saveErr)
			}
			return run, err
		}
		run.Steps[index].State = ResetStateSucceeded
		if err := r.resetJournal.saveRun(run); err != nil {
			return run, err
		}
	}
	run.State = ResetStateSucceeded
	run.LastError = ""
	run.UpdatedAt = r.now().UTC()
	if err := r.resetJournal.saveRun(run); err != nil {
		return run, err
	}
	return run, nil
}

func (r *Runner) executeResetStep(ctx context.Context, key string, run ResetRun) error {
	switch key {
	case "validate-source":
		source, err := r.journal.Load()
		if err != nil {
			return err
		}
		if source == nil || source.ID != run.SourceRunID || source.SpecDigest != run.SourceSpecDigest || source.BundleDigest != run.SourceBundleDigest {
			return errors.New("persisted installation authority changed after reset admission")
		}
		status, err := InspectBundle(r.bundleDir, r.requireBundleLock)
		if err != nil {
			return fmt.Errorf("reset requires the admitted source bundle: %w", err)
		}
		if status.BundleDigest != run.SourceBundleDigest {
			return fmt.Errorf("reset bundle digest changed: accepted %s observed %s", run.SourceBundleDigest, status.BundleDigest)
		}
		return nil
	case "uninstall-remote-rke2":
		if run.Request.ProfileID != "production-standard-ha" || r.simulation {
			return nil
		}
		bootstrapRun := Run{Request: run.Request}
		peers := run.Request.Infrastructure.NodeAddresses
		if len(peers) > 1 {
			peers = peers[1:]
		} else {
			peers = nil
		}
		for _, peer := range peers {
			if _, err := r.system.Output(ctx, "ssh", r.sshArgs(bootstrapRun, peer, remoteRKE2ResetCommand()), nil); err != nil {
				return fmt.Errorf("reset HA peer %s: %w", peer, err)
			}
		}
		return nil
	case "uninstall-local-rke2":
		return r.uninstallLocalRKE2(ctx)
	case "purge-generated-state":
		return r.purgeGeneratedInstallerState()
	case "verify-clean-hosts":
		return r.verifyResetClean(ctx, run)
	default:
		return fmt.Errorf("unknown reset step %q", key)
	}
}

func remoteRKE2ResetCommand() string {
	return `set -eu; if [ -x /usr/local/bin/rke2-uninstall.sh ]; then /usr/local/bin/rke2-uninstall.sh; fi; for p in /etc/rancher/rke2 /var/lib/rancher/rke2 /usr/local/bin/rke2 /usr/bin/rke2 /usr/local/bin/rke2-uninstall.sh /usr/local/bin/rke2-killall.sh; do if [ -e "$p" ]; then echo "product-owned RKE2 residue remains: $p" >&2; exit 31; fi; done; for u in rke2-server.service rke2-agent.service; do if systemctl cat "$u" >/dev/null 2>&1; then echo "product-owned RKE2 unit remains: $u" >&2; exit 32; fi; done`
}

func removeSystemPath(system System, path string) error {
	switch typed := system.(type) {
	case LocalSystem:
		return os.RemoveAll(path)
	case *LocalSystem:
		return os.RemoveAll(path)
	case *SimulatedSystem:
		return os.RemoveAll(typed.path(path))
	default:
		return fmt.Errorf("system adapter does not expose safe remove-all semantics for %s", path)
	}
}

func (r *Runner) productOwnedRKE2Residue(ctx context.Context) []string {
	found := make([]string, 0, len(productOwnedRKE2Paths)+2)
	for _, path := range productOwnedRKE2Paths {
		if r.system.Exists(path) {
			found = append(found, path)
		}
	}
	if r.usesLocalHostFilesystem() {
		for _, unit := range []string{"rke2-server.service", "rke2-agent.service"} {
			if err := r.system.Run(ctx, "systemctl", []string{"cat", unit}, nil); err == nil {
				found = append(found, "systemd-unit:"+unit)
			}
		}
	}
	return found
}

func (r *Runner) uninstallLocalRKE2(ctx context.Context) error {
	if r.simulation {
		for _, path := range productOwnedRKE2Paths {
			if err := removeSystemPath(r.system, path); err != nil {
				return err
			}
		}
		for _, directory := range systemdUnitSearchFallbackDirectories {
			for _, unit := range []string{"rke2-server.service", "rke2-agent.service"} {
				if err := removeSystemPath(r.system, filepath.Join(directory, unit)); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if r.system.Exists("/usr/local/bin/rke2-uninstall.sh") {
		if err := r.system.Run(ctx, "/usr/local/bin/rke2-uninstall.sh", nil, nil); err != nil {
			return fmt.Errorf("run RKE2 uninstall script: %w", err)
		}
	} else if residue := r.productOwnedRKE2Residue(ctx); len(residue) > 0 {
		return fmt.Errorf("RKE2 residue exists but canonical uninstall script is unavailable (%s); refusing blind filesystem deletion", strings.Join(residue, ", "))
	}
	if residue := r.productOwnedRKE2Residue(ctx); len(residue) > 0 {
		return fmt.Errorf("RKE2 uninstall did not reach a clean product-owned state: %s", strings.Join(residue, ", "))
	}
	return nil
}

func (r *Runner) purgeGeneratedInstallerState() error {
	// The reset journal, installer access token and HA SSH identity/trust are
	// deliberately preserved. They are operator access inputs, not generated
	// installation authority, and retaining them makes clean reinstall both
	// explicit and recoverable without silently replacing trust.
	for _, relative := range generatedInstallerStateRelativePaths {
		actual := filepath.Join(r.stateDir, relative)
		if err := os.RemoveAll(actual); err != nil {
			return fmt.Errorf("remove generated installer state %s: %w", relative, err)
		}
		canonical := filepath.Join(canonicalLiveInstallerStateDir, relative)
		if filepath.Clean(canonical) != filepath.Clean(actual) {
			if err := removeSystemPath(r.system, canonical); err != nil {
				return fmt.Errorf("remove generated simulated/canonical state %s: %w", relative, err)
			}
		}
	}
	return nil
}

func (r *Runner) verifyResetClean(ctx context.Context, run ResetRun) error {
	if source, err := r.journal.Load(); err != nil {
		return err
	} else if source != nil {
		return errors.New("bootstrap journal still exists after reset purge")
	}
	if residue := r.productOwnedRKE2Residue(ctx); len(residue) > 0 {
		return fmt.Errorf("local product-owned RKE2 residue remains after reset: %s", strings.Join(residue, ", "))
	}
	if !r.simulation && run.Request.ProfileID == "production-standard-ha" {
		bootstrapRun := Run{Request: run.Request}
		peers := run.Request.Infrastructure.NodeAddresses
		if len(peers) > 1 {
			peers = peers[1:]
		} else {
			peers = nil
		}
		for _, peer := range peers {
			if _, err := r.system.Output(ctx, "ssh", r.sshArgs(bootstrapRun, peer, remoteRKE2ResetCommand()), nil); err != nil {
				return fmt.Errorf("verify clean HA peer %s: %w", peer, err)
			}
		}
	}
	for _, relative := range generatedInstallerStateRelativePaths {
		if _, err := os.Stat(filepath.Join(r.stateDir, relative)); err == nil {
			return fmt.Errorf("generated installer state remains after reset: %s", relative)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}
