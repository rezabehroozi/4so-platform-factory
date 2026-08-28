package lifecycle

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"platform.4so.io/factory/internal/bootstrap"
	"platform.4so.io/factory/internal/durablefile"
	"platform.4so.io/factory/internal/kubejob"
	"platform.4so.io/factory/internal/kubeworkload"
)

type Options struct {
	StateDir          string
	BundleDir         string
	Simulation        bool
	RequireBundleLock bool
	System            bootstrap.System
	Now               func() time.Time
}

type Manager struct {
	stateDir          string
	backupDir         string
	bundleDir         string
	simulation        bool
	requireBundleLock bool
	system            bootstrap.System
	now               func() time.Time
	mu                sync.Mutex
	runs              []Run
	active            map[string]bool
	reconciling       map[string]bool
}

var digestImage = regexp.MustCompile(`^[^@\s]+@sha256:[a-f0-9]{64}$`)
var backupDigest = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

type destructiveRecoveryRequiredError struct {
	err error
}

func (e *destructiveRecoveryRequiredError) Error() string { return e.err.Error() }
func (e *destructiveRecoveryRequiredError) Unwrap() error { return e.err }

func requireDestructiveRecovery(err error) error {
	if err == nil {
		return nil
	}
	var existing *destructiveRecoveryRequiredError
	if errors.As(err, &existing) {
		return err
	}
	return &destructiveRecoveryRequiredError{err: err}
}

func destructiveRecoveryRequired(err error) bool {
	var target *destructiveRecoveryRequiredError
	return errors.As(err, &target)
}

func New(options Options) (*Manager, error) {
	if options.StateDir == "" || options.BundleDir == "" {
		return nil, errors.New("lifecycle state and bundle directories are required")
	}
	if options.System == nil {
		options.System = bootstrap.LocalSystem{}
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	manager := &Manager{stateDir: options.StateDir, backupDir: filepath.Join(options.StateDir, "backups"), bundleDir: options.BundleDir, simulation: options.Simulation, requireBundleLock: options.RequireBundleLock, system: options.System, now: options.Now, active: map[string]bool{}, reconciling: map[string]bool{}}
	if err := os.MkdirAll(manager.backupDir, 0o700); err != nil && !options.Simulation {
		return nil, err
	}
	if err := manager.load(); err != nil {
		return nil, fmt.Errorf("load lifecycle state: %w", err)
	}
	return manager, nil
}

func (m *Manager) loadBundle() (bootstrap.BundleManifest, string, error) {
	if m.requireBundleLock {
		status, err := bootstrap.InspectBundle(m.bundleDir, true)
		if err != nil {
			return bootstrap.BundleManifest{}, "", err
		}
		bundle, _, err := bootstrap.LoadBundle(m.bundleDir)
		return bundle, status.BundleDigest, err
	}
	return bootstrap.LoadBundle(m.bundleDir)
}

func (m *Manager) List() []Run {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := append([]Run(nil), m.runs...)
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

func (m *Manager) HasActive() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, active := range m.active {
		if active {
			return true
		}
	}
	for _, run := range m.runs {
		if run.State == StateFailed && run.RecoveryRequired {
			return true
		}
	}
	return false
}

func (m *Manager) Backups(service string) ([]BackupMetadata, error) {
	service, err := normalizeService(service)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(m.backupDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var out []BackupMetadata
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		meta, readErr := m.readBackupMetadata(entry.Name())
		if readErr != nil {
			return nil, fmt.Errorf("read backup metadata %s: %w", entry.Name(), readErr)
		}
		if err := m.verifyBackupPayload(meta); err != nil {
			return nil, fmt.Errorf("verify backup %s: %w", entry.Name(), err)
		}
		if meta.Service == service {
			out = append(out, meta)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (m *Manager) StartBackup(ctx context.Context, service, profileID string) (Run, error) {
	service, err := normalizeService(service)
	if err != nil {
		return Run{}, err
	}
	profileID, err = normalizeProfile(profileID)
	if err != nil {
		return Run{}, err
	}
	return m.start(ctx, Run{Service: service, ProfileID: profileID, Action: ActionBackup})
}
func (m *Manager) StartRestore(ctx context.Context, request RestoreRequest, profileID string) (Run, error) {
	service, err := normalizeService(request.Service)
	if err != nil {
		return Run{}, err
	}
	if !safeID(request.BackupID) {
		return Run{}, errors.New("backupId is invalid")
	}
	profileID, err = normalizeProfile(profileID)
	if err != nil {
		return Run{}, err
	}
	return m.start(ctx, Run{Service: service, ProfileID: profileID, Action: ActionRestore, BackupID: request.BackupID})
}
func (m *Manager) StartUpgrade(ctx context.Context, request UpgradeRequest, profileID string) (Run, error) {
	service, err := normalizeService(request.Service)
	if err != nil {
		return Run{}, err
	}
	if !digestImage.MatchString(strings.TrimSpace(request.Image)) {
		return Run{}, errors.New("upgrade image must be digest-pinned")
	}
	profileID, err = normalizeProfile(profileID)
	if err != nil {
		return Run{}, err
	}
	return m.start(ctx, Run{Service: service, ProfileID: profileID, Action: ActionUpgrade, RequestedImage: strings.TrimSpace(request.Image), UpgradePhase: UpgradePhaseBackupPending})
}

func (m *Manager) StartUpgradeRecovery(ctx context.Context, request UpgradeRecoveryRequest, profileID string) (Run, error) {
	upgradeRunID := strings.TrimSpace(request.UpgradeRunID)
	if upgradeRunID == "" {
		return Run{}, errors.New("upgradeRunId is required")
	}
	profileID, err := normalizeProfile(profileID)
	if err != nil {
		return Run{}, err
	}
	executionNode, err := m.prepareStart(ctx)
	if err != nil {
		return Run{}, err
	}

	// Source validation, prior-recovery inspection and acquisition of the
	// service mutation slot are one authority transaction under m.mu. Older
	// code validated the source, dropped the lock and only then called start();
	// a concurrently finishing recovery could therefore close the source and
	// release the active slot in between, allowing a stale second recovery.
	m.mu.Lock()
	original := m.findLocked(upgradeRunID)
	if original == nil {
		m.mu.Unlock()
		return Run{}, errors.New("upgrade run was not found")
	}
	source := *original
	if source.Action != ActionUpgrade || source.State != StateFailed || source.UpgradePhase != UpgradePhaseRecoveryRequired {
		m.mu.Unlock()
		return Run{}, errors.New("upgrade recovery requires a failed upgrade in RECOVERY_REQUIRED state")
	}
	if source.ProfileID != profileID {
		m.mu.Unlock()
		return Run{}, fmt.Errorf("upgrade recovery profile %s does not match installed profile %s", source.ProfileID, profileID)
	}
	if !safeID(source.BackupID) || !digestImage.MatchString(strings.TrimSpace(source.PreviousImage)) {
		m.mu.Unlock()
		return Run{}, errors.New("upgrade recovery authority is missing the exact backup or previous digest")
	}
	recoveryPhase, err := m.recoveryRetryPhaseLocked(source)
	if err != nil {
		m.mu.Unlock()
		return Run{}, err
	}
	run := Run{
		Service: source.Service, ProfileID: profileID, ExecutionNode: executionNode, Action: ActionUpgradeRecovery,
		BackupID: source.BackupID, PreviousImage: source.PreviousImage, RequestedImage: source.RequestedImage,
		UpgradeRecoveryPhase: recoveryPhase, SourceUpgradeRunID: source.ID,
	}
	run, err = m.enqueueLocked(run)
	m.mu.Unlock()
	if err != nil {
		return Run{}, err
	}
	go m.execute(context.WithoutCancel(ctx), run.ID)
	return run, nil
}

func (m *Manager) recoveryRetryPhaseLocked(source Run) (UpgradeRecoveryPhase, error) {
	phase := UpgradeRecoveryPhaseRestorePending
	rank := 0
	for _, candidate := range m.runs {
		if candidate.Action != ActionUpgradeRecovery || candidate.SourceUpgradeRunID != source.ID {
			continue
		}
		if candidate.Service != source.Service || candidate.ProfileID != source.ProfileID || candidate.BackupID != source.BackupID || strings.TrimSpace(candidate.PreviousImage) != strings.TrimSpace(source.PreviousImage) || strings.TrimSpace(candidate.RequestedImage) != strings.TrimSpace(source.RequestedImage) {
			return "", fmt.Errorf("prior upgrade recovery %s does not match source upgrade authority; refusing destructive retry", candidate.ID)
		}
		if candidate.State == StateSucceeded {
			return "", fmt.Errorf("upgrade recovery already completed for %s", source.ID)
		}
		if candidate.State == StateQueued || candidate.State == StateRunning {
			return "", fmt.Errorf("upgrade recovery %s is already active for %s", candidate.ID, source.ID)
		}
		switch candidate.UpgradeRecoveryPhase {
		case "", UpgradeRecoveryPhaseRestorePending:
			// No durable proof that the destructive restore completed. A new,
			// explicitly confirmed attempt may restart from RESTORE_PENDING.
		case UpgradeRecoveryPhaseRestoreCompleted:
			if rank < 1 {
				phase, rank = UpgradeRecoveryPhaseRestoreCompleted, 1
			}
		case UpgradeRecoveryPhaseResumeVerified:
			phase, rank = UpgradeRecoveryPhaseResumeVerified, 2
		default:
			return "", fmt.Errorf("prior upgrade recovery %s has unsupported durable phase %q; refusing destructive retry", candidate.ID, candidate.UpgradeRecoveryPhase)
		}
	}
	return phase, nil
}

func (m *Manager) prepareStart(ctx context.Context) (string, error) {
	if m.requireBundleLock {
		if _, err := bootstrap.InspectBundle(m.bundleDir, true); err != nil {
			return "", fmt.Errorf("bundle admission: %w", err)
		}
	}
	return m.resolveExecutionNode(ctx)
}

func (m *Manager) recoveryBlockerLocked(service string) *Run {
	for i := len(m.runs) - 1; i >= 0; i-- {
		run := &m.runs[i]
		if run.Service == service && run.State == StateFailed && run.RecoveryRequired {
			return run
		}
	}
	return nil
}

func restoreRecoveryAuthorityMatches(blocker Run, candidate Run) bool {
	return blocker.Action == ActionRestore &&
		candidate.Action == ActionRestore &&
		blocker.Service == candidate.Service &&
		blocker.ProfileID == candidate.ProfileID &&
		blocker.BackupID != "" &&
		blocker.BackupID == candidate.BackupID
}

func recoveryContinuationAllowed(blocker Run, candidate Run) bool {
	switch blocker.Action {
	case ActionRestore:
		return restoreRecoveryAuthorityMatches(blocker, candidate)
	case ActionUpgradeRecovery:
		return candidate.Action == ActionUpgradeRecovery && blocker.SourceUpgradeRunID != "" && blocker.SourceUpgradeRunID == candidate.SourceUpgradeRunID
	default:
		return false
	}
}

func (m *Manager) clearRecoveryBlockersLocked(success Run) {
	for i := range m.runs {
		blocker := &m.runs[i]
		if !blocker.RecoveryRequired || blocker.Service != success.Service {
			continue
		}
		switch success.Action {
		case ActionRestore:
			if restoreRecoveryAuthorityMatches(*blocker, success) {
				blocker.RecoveryRequired = false
			}
		case ActionUpgradeRecovery:
			if blocker.Action == ActionUpgradeRecovery && blocker.SourceUpgradeRunID == success.SourceUpgradeRunID {
				blocker.RecoveryRequired = false
			}
		}
	}
}

// enqueueLocked persists one lifecycle mutation admission while m.mu is held.
// Keeping the active-slot check and durable queue write in the same critical
// section lets callers bind additional source authority without a TOCTOU gap.
func (m *Manager) enqueueLocked(run Run) (Run, error) {
	if m.active[run.Service] {
		return Run{}, fmt.Errorf("a lifecycle operation is already active for %s", run.Service)
	}
	if blocker := m.recoveryBlockerLocked(run.Service); blocker != nil && !recoveryContinuationAllowed(*blocker, run) {
		return Run{}, fmt.Errorf("%s requires recovery after failed %s operation %s; unrelated lifecycle mutation %s is fenced", run.Service, blocker.Action, blocker.ID, run.Action)
	}
	now := m.now().UTC()
	run.ID = m.uniqueRunIDLocked(fmt.Sprintf("lifecycle-%s-%s-%d", run.Service, run.Action, now.UnixNano()))
	if (run.Action == ActionBackup || run.Action == ActionUpgrade) && run.BackupID == "" {
		run.BackupID = m.uniqueBackupIDLocked(fmt.Sprintf("%s-%d", run.Service, now.UnixNano()))
	}
	run.State = StateQueued
	run.CreatedAt = now
	m.runs = append(m.runs, run)
	m.active[run.Service] = true
	if err := m.saveLocked(); err != nil {
		m.runs = m.runs[:len(m.runs)-1]
		delete(m.active, run.Service)
		return Run{}, fmt.Errorf("persist queued lifecycle operation: %w", err)
	}
	return run, nil
}

func (m *Manager) start(ctx context.Context, run Run) (Run, error) {
	executionNode, err := m.prepareStart(ctx)
	if err != nil {
		return Run{}, err
	}
	run.ExecutionNode = executionNode
	m.mu.Lock()
	run, err = m.enqueueLocked(run)
	m.mu.Unlock()
	if err != nil {
		return Run{}, err
	}
	go m.execute(context.WithoutCancel(ctx), run.ID)
	return run, nil
}

func (m *Manager) uniqueRunIDLocked(base string) string {
	candidate := base
	for suffix := 2; ; suffix++ {
		used := false
		for _, run := range m.runs {
			if run.ID == candidate {
				used = true
				break
			}
		}
		if !used {
			return candidate
		}
		candidate = fmt.Sprintf("%s-%d", base, suffix)
	}
}

func (m *Manager) uniqueBackupIDLocked(base string) string {
	candidate := base
	for suffix := 2; ; suffix++ {
		used := false
		for _, run := range m.runs {
			if run.BackupID == candidate {
				used = true
				break
			}
		}
		if !used {
			return candidate
		}
		candidate = fmt.Sprintf("%s-%d", base, suffix)
	}
}

func (m *Manager) execute(ctx context.Context, id string) {
	defer m.clearReconciling(id)
	if err := m.update(id, func(run *Run) {
		now := m.now().UTC()
		run.State = StateRunning
		if run.StartedAt == nil {
			run.StartedAt = &now
		}
	}); err != nil {
		fmt.Fprintf(os.Stderr, "lifecycle operation %s aborted before side effects: %v\n", id, err)
		return
	}
	var err error
	m.mu.Lock()
	stored := m.findLocked(id)
	if stored == nil {
		m.mu.Unlock()
		return
	}
	run := *stored
	m.mu.Unlock()
	if (run.Action == ActionBackup || run.Action == ActionUpgrade) && run.BackupID == "" {
		m.mu.Lock()
		run.BackupID = m.uniqueBackupIDLocked(fmt.Sprintf("%s-%d", run.Service, run.CreatedAt.UTC().UnixNano()))
		m.mu.Unlock()
		if err := m.update(id, func(target *Run) { target.BackupID = run.BackupID }); err != nil {
			fmt.Fprintf(os.Stderr, "lifecycle operation %s could not persist recovered backupId: %v\n", id, err)
			return
		}
	}
	if _, profileErr := normalizeProfile(run.ProfileID); profileErr != nil {
		err = fmt.Errorf("durable lifecycle profile is invalid or missing: %w", profileErr)
	} else if !m.simulation && strings.TrimSpace(run.ExecutionNode) == "" {
		err = errors.New("durable lifecycle execution node is missing; refusing hostPath mutation after restart")
	} else {
		switch run.Action {
		case ActionBackup:
			err = m.performBackup(ctx, run.ID, run.Service, run.BackupID, run.ProfileID)
		case ActionRestore:
			err = m.performRestore(ctx, run.ID, run.Service, run.BackupID, run.ProfileID)
		case ActionUpgrade:
			run.PreviousImage, err = m.performUpgrade(ctx, id, run)
		case ActionUpgradeRecovery:
			err = m.performUpgradeRecovery(ctx, id, run)
		default:
			err = errors.New("unsupported lifecycle action")
		}
	}
	recoveryRequired := destructiveRecoveryRequired(err)
	if persistErr := m.update(id, func(target *Run) {
		finished := m.now().UTC()
		target.FinishedAt = &finished
		target.BackupID = run.BackupID
		target.PreviousImage = run.PreviousImage
		if err == nil && target.Action == ActionUpgradeRecovery {
			source := m.findLocked(target.SourceUpgradeRunID)
			if sourceErr := validateUpgradeRecoverySource(source, *target); sourceErr != nil {
				err = fmt.Errorf("finalize upgrade recovery authority: %w", sourceErr)
			} else {
				source.UpgradePhase = UpgradePhaseRecoveryCompleted
			}
		}
		if err != nil {
			target.State = StateFailed
			target.Error = err.Error()
			target.RecoveryRequired = recoveryRequired
		} else {
			target.State = StateSucceeded
			target.RecoveryRequired = false
			m.clearRecoveryBlockersLocked(*target)
		}
		m.active[target.Service] = false
	}); persistErr != nil {
		fmt.Fprintf(os.Stderr, "lifecycle operation %s completed but final state persistence failed: %v\n", id, persistErr)
	}
}

// Reconcile resumes durable operations that were queued or running when the
// installer process stopped. Every operation uses persisted identifiers so a
// restart continues the same logical mutation instead of creating a new run.
func (m *Manager) Reconcile(ctx context.Context) int {
	m.mu.Lock()
	ids := make([]string, 0)
	for _, run := range m.runs {
		if (run.State == StateQueued || run.State == StateRunning) && !m.reconciling[run.ID] {
			m.reconciling[run.ID] = true
			ids = append(ids, run.ID)
		}
	}
	m.mu.Unlock()
	for _, id := range ids {
		go m.execute(context.WithoutCancel(ctx), id)
	}
	return len(ids)
}

func (m *Manager) clearReconciling(id string) {
	m.mu.Lock()
	delete(m.reconciling, id)
	m.mu.Unlock()
}

func (m *Manager) executionNodeForRun(service, backupID string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.runs) - 1; i >= 0; i-- {
		run := m.runs[i]
		if run.Service == service && run.BackupID == backupID && (run.State == StateQueued || run.State == StateRunning) {
			return run.ExecutionNode
		}
	}
	return ""
}

func (m *Manager) resolveExecutionNode(ctx context.Context) (string, error) {
	if m.simulation {
		return "simulation-node", nil
	}
	host, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("resolve lifecycle execution node hostname: %w", err)
	}
	host = strings.ToLower(strings.TrimSpace(host))
	candidates := []string{host}
	if short := strings.Split(host, ".")[0]; short != "" && short != host {
		candidates = append(candidates, short)
	}
	var lastErr error
	for _, candidate := range candidates {
		raw, queryErr := m.kubectlOutput(ctx, "get", "node", candidate, "-o", "name")
		if queryErr == nil && strings.TrimSpace(string(raw)) != "" {
			return candidate, nil
		}
		if queryErr != nil {
			lastErr = queryErr
		}
	}
	if lastErr != nil {
		return "", fmt.Errorf("installer host %q is not a registered Kubernetes node: %w", host, lastErr)
	}
	return "", fmt.Errorf("installer host %q is not a registered Kubernetes node", host)
}

func (m *Manager) performBackup(ctx context.Context, operationID, service, id, profileID string) error {
	if !safeID(id) {
		return errors.New("backupId is invalid")
	}
	if meta, err := m.loadBackup(service, id); err == nil {
		if meta.ProfileID != "" && meta.ProfileID != profileID {
			return fmt.Errorf("existing backup profile %s does not match installed profile %s", meta.ProfileID, profileID)
		}
		if meta.ProfileID == "" && profileID == "production-standard-ha" {
			return errors.New("legacy lifecycle backup without durable profile cannot be reused for production-standard-ha; create a new backup")
		}
		if verifyErr := m.verifyBackupPayload(meta); verifyErr != nil {
			return fmt.Errorf("existing backup payload verification failed: %w", verifyErr)
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect existing backup: %w", err)
	}
	bundle, _, err := m.loadBundle()
	if err != nil {
		return err
	}
	dir := filepath.Join(m.backupDir, id)
	if err = os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if m.simulation {
		for name, payload := range simulatedBackupPayload(service) {
			if err = os.WriteFile(filepath.Join(dir, name), payload, 0o600); err != nil {
				return err
			}
		}
	} else {
		kind, name, replicas := workloadTarget(service, profileID)
		if err = m.quiesceWorkload(ctx, operationID, kind, name, service, replicas); err != nil {
			return err
		}
		jobName := lifecycleJobName("backup", operationID)
		manifest := backupJobManifest(service, id, jobName, operationID, m.backupDir, bundle, profileID, m.executionNodeForRun(service, id))
		if err = m.runJob(ctx, operationID, jobName, "backup-"+id, manifest); err != nil {
			resumeErr := m.resumeWorkload(context.WithoutCancel(ctx), operationID, kind, name, replicas)
			if resumeErr != nil {
				return errors.Join(err, fmt.Errorf("backup failed and %s could not be resumed: %w", service, resumeErr))
			}
			return err
		}
		if err = m.resumeWorkload(ctx, operationID, kind, name, replicas); err != nil {
			return fmt.Errorf("backup completed but %s could not be resumed: %w", service, err)
		}
	}
	files, err := collectBackupPayload(dir, service)
	if err != nil {
		return fmt.Errorf("validate completed backup payload: %w", err)
	}
	meta := BackupMetadata{ID: id, Service: service, ProfileID: profileID, CreatedAt: m.now().UTC(), Files: files}
	raw, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("encode backup metadata: %w", err)
	}
	if err = durablefile.Replace(filepath.Join(dir, "backup.json"), append(raw, '\n'), 0o700, 0o600); err != nil {
		return fmt.Errorf("durably commit backup metadata: %w", err)
	}
	return nil
}

func (m *Manager) validateBackupForRestore(service, id, profileID string) (BackupMetadata, error) {
	meta, err := m.loadBackup(service, id)
	if err != nil {
		return BackupMetadata{}, err
	}
	if err = m.verifyBackupPayload(meta); err != nil {
		return BackupMetadata{}, err
	}
	if meta.ProfileID != "" && meta.ProfileID != profileID {
		return BackupMetadata{}, fmt.Errorf("backup profile %s does not match installed profile %s", meta.ProfileID, profileID)
	}
	if meta.ProfileID == "" && profileID == "production-standard-ha" {
		return BackupMetadata{}, errors.New("legacy lifecycle backup without durable profile cannot be restored to production-standard-ha; create a new backup")
	}
	return meta, nil
}

func (m *Manager) restoreBackupWhileQuiesced(ctx context.Context, operationID, service, id, profileID string) error {
	if _, err := m.validateBackupForRestore(service, id, profileID); err != nil {
		return err
	}
	if m.simulation {
		return nil
	}
	bundle, _, err := m.loadBundle()
	if err != nil {
		return err
	}
	jobName := lifecycleJobName("restore", operationID)
	meta, err := m.validateBackupForRestore(service, id, profileID)
	if err != nil {
		return err
	}
	manifest := restoreJobManifest(service, id, jobName, operationID, m.backupDir, bundle, profileID, m.executionNodeForRun(service, id), meta)
	if err = m.runJob(ctx, operationID, jobName, "restore-"+id, manifest); err != nil {
		return fmt.Errorf("restore job failed; %s remains quiesced for safe retry: %w", service, err)
	}
	return nil
}

func (m *Manager) performRestore(ctx context.Context, operationID, service, id, profileID string) error {
	if _, err := m.validateBackupForRestore(service, id, profileID); err != nil {
		return err
	}
	if m.simulation {
		return nil
	}
	kind, name, replicas := workloadTarget(service, profileID)
	if err := m.quiesceWorkload(ctx, operationID, kind, name, service, replicas); err != nil {
		return err
	}
	if err := m.restoreBackupWhileQuiesced(ctx, operationID, service, id, profileID); err != nil {
		return requireDestructiveRecovery(err)
	}
	if err := m.resumeWorkload(ctx, operationID, kind, name, replicas); err != nil {
		return requireDestructiveRecovery(err)
	}
	return nil
}

func validateUpgradeRecoverySource(source *Run, recovery Run) error {
	if source == nil {
		return errors.New("source upgrade run is missing")
	}
	if source.Action != ActionUpgrade || source.State != StateFailed || source.UpgradePhase != UpgradePhaseRecoveryRequired {
		return errors.New("source upgrade is not failed in RECOVERY_REQUIRED state")
	}
	if source.ID != recovery.SourceUpgradeRunID || source.Service != recovery.Service || source.ProfileID != recovery.ProfileID || source.BackupID != recovery.BackupID || strings.TrimSpace(source.PreviousImage) != strings.TrimSpace(recovery.PreviousImage) || strings.TrimSpace(source.RequestedImage) != strings.TrimSpace(recovery.RequestedImage) {
		return errors.New("source upgrade authority no longer matches the recovery run")
	}
	return nil
}

func (m *Manager) performUpgradeRecovery(ctx context.Context, id string, run Run) error {
	if run.SourceUpgradeRunID == "" || run.BackupID == "" || !digestImage.MatchString(strings.TrimSpace(run.PreviousImage)) {
		return errors.New("upgrade recovery authority is incomplete")
	}
	if run.UpgradeRecoveryPhase == "" {
		return errors.New("legacy interrupted upgrade recovery lacks durable phase authority; automatic destructive replay is forbidden")
	}
	m.mu.Lock()
	source := m.findLocked(run.SourceUpgradeRunID)
	sourceErr := validateUpgradeRecoverySource(source, run)
	m.mu.Unlock()
	if sourceErr != nil {
		return fmt.Errorf("validate upgrade recovery source authority: %w", sourceErr)
	}
	previous := strings.TrimSpace(run.PreviousImage)
	requested := strings.TrimSpace(run.RequestedImage)

	if m.simulation {
		switch run.UpgradeRecoveryPhase {
		case UpgradeRecoveryPhaseRestorePending:
			if _, err := m.validateBackupForRestore(run.Service, run.BackupID, run.ProfileID); err != nil {
				return fmt.Errorf("validate upgrade recovery backup: %w", err)
			}
			if err := m.update(id, func(target *Run) { target.UpgradeRecoveryPhase = UpgradeRecoveryPhaseRestoreCompleted }); err != nil {
				return fmt.Errorf("persist completed upgrade recovery restore phase: %w", err)
			}
			fallthrough
		case UpgradeRecoveryPhaseRestoreCompleted:
			if err := m.update(id, func(target *Run) { target.UpgradeRecoveryPhase = UpgradeRecoveryPhaseResumeVerified }); err != nil {
				return fmt.Errorf("persist verified upgrade recovery resume phase: %w", err)
			}
			return nil
		case UpgradeRecoveryPhaseResumeVerified:
			return nil
		default:
			return fmt.Errorf("unsupported durable upgrade recovery phase %q", run.UpgradeRecoveryPhase)
		}
	}

	kind, name, replicas := workloadTarget(run.Service, run.ProfileID)
	options := m.workloadOptions(id, kind, name)
	if run.UpgradeRecoveryPhase == UpgradeRecoveryPhaseRestorePending {
		if _, err := m.validateBackupForRestore(run.Service, run.BackupID, run.ProfileID); err != nil {
			return fmt.Errorf("validate upgrade recovery backup: %w", err)
		}
		current, err := kubeworkload.CurrentImage(ctx, options, run.Service)
		if err != nil {
			return err
		}
		if current != previous && current != requested {
			return fmt.Errorf("upgrade recovery workload image drifted to %s; refusing destructive state restore", current)
		}
		if err = m.quiesceWorkload(ctx, id, kind, name, run.Service, replicas); err != nil {
			return err
		}
		// RESTORE_COMPLETED is persisted while writers are still quiesced. Once
		// this boundary is durable, reconciliation must never rewind the backup a
		// second time: the service may have resumed and accepted newer writes.
		if err = m.restoreBackupWhileQuiesced(ctx, id, run.Service, run.BackupID, run.ProfileID); err != nil {
			return requireDestructiveRecovery(err)
		}
		if err = m.update(id, func(target *Run) { target.UpgradeRecoveryPhase = UpgradeRecoveryPhaseRestoreCompleted }); err != nil {
			return requireDestructiveRecovery(fmt.Errorf("persist completed upgrade recovery restore phase: %w", err))
		}
		run.UpgradeRecoveryPhase = UpgradeRecoveryPhaseRestoreCompleted
	}

	if run.UpgradeRecoveryPhase == UpgradeRecoveryPhaseRestoreCompleted {
		current, err := kubeworkload.CurrentImage(ctx, options, run.Service)
		if err != nil {
			return requireDestructiveRecovery(err)
		}
		if current != previous && current != requested {
			return requireDestructiveRecovery(fmt.Errorf("upgrade recovery workload image drifted to %s after state restore; refusing automatic mutation", current))
		}
		if current != previous {
			if _, err = kubeworkload.SetImage(ctx, options, run.Service, previous); err != nil {
				return requireDestructiveRecovery(fmt.Errorf("restore previous image after backup rewind: %w", err))
			}
		}
		if err = m.resumeWorkload(ctx, id, kind, name, replicas); err != nil {
			return requireDestructiveRecovery(fmt.Errorf("resume previous version after backup rewind: %w", err))
		}
		if err = kubeworkload.VerifyImage(ctx, options, run.Service, previous); err != nil {
			return requireDestructiveRecovery(fmt.Errorf("previous version verification after backup rewind failed: %w", err))
		}
		if err = m.update(id, func(target *Run) { target.UpgradeRecoveryPhase = UpgradeRecoveryPhaseResumeVerified }); err != nil {
			return fmt.Errorf("persist verified upgrade recovery resume phase: %w", err)
		}
		return nil
	}

	if run.UpgradeRecoveryPhase == UpgradeRecoveryPhaseResumeVerified {
		current, err := kubeworkload.CurrentImage(ctx, options, run.Service)
		if err != nil {
			return err
		}
		if current != previous {
			return fmt.Errorf("completed upgrade recovery image drifted from %s to %s before final state persistence; automatic mutation is forbidden", previous, current)
		}
		if err = kubeworkload.VerifyImage(ctx, options, run.Service, previous); err != nil {
			return err
		}
		return kubeworkload.VerifyReplicas(ctx, options, replicas)
	}

	return fmt.Errorf("unsupported durable upgrade recovery phase %q", run.UpgradeRecoveryPhase)
}

func (m *Manager) performUpgrade(ctx context.Context, id string, run Run) (string, error) {
	if run.BackupID == "" {
		return "", errors.New("pre-upgrade backupId was not persisted")
	}
	if run.UpgradePhase == "" {
		return run.PreviousImage, errors.New("legacy interrupted upgrade lacks durable phase authority; automatic replay is forbidden")
	}
	if m.simulation {
		previous := run.PreviousImage
		switch run.UpgradePhase {
		case UpgradePhaseBackupPending:
			if err := m.performBackup(ctx, id, run.Service, run.BackupID, run.ProfileID); err != nil {
				return previous, fmt.Errorf("pre-upgrade backup: %w", err)
			}
			if previous == "" {
				previous = "simulated-old@sha256:" + strings.Repeat("a", 64)
			}
			if err := m.update(id, func(target *Run) {
				target.PreviousImage = previous
				target.UpgradePhase = UpgradePhaseApplyVerified
			}); err != nil {
				return "", err
			}
			return previous, nil
		case UpgradePhaseApplyPending:
			if previous == "" {
				return "", errors.New("simulated interrupted upgrade is missing durable previous image")
			}
			if err := m.update(id, func(target *Run) { target.UpgradePhase = UpgradePhaseApplyVerified }); err != nil {
				return previous, err
			}
			return previous, nil
		case UpgradePhaseApplyVerified:
			return previous, nil
		case UpgradePhaseRollbackPending:
			if err := m.update(id, func(target *Run) { target.UpgradePhase = UpgradePhaseRecoveryRequired }); err != nil {
				return previous, err
			}
			fallthrough
		case UpgradePhaseRecoveryRequired:
			failure := strings.TrimSpace(run.UpgradeFailure)
			if failure == "" {
				failure = "upgrade failed and explicit state-aware recovery is required"
			}
			return previous, errors.New(failure + "; explicit upgrade recovery is required")
		case UpgradePhaseRollbackCompleted:
			failure := strings.TrimSpace(run.UpgradeFailure)
			if failure == "" {
				failure = "legacy image-only rollback completed"
			}
			return previous, errors.New(failure + "; legacy image rollback does not prove persistent-state recovery")
		default:
			return previous, fmt.Errorf("unsupported durable upgrade phase %q", run.UpgradePhase)
		}
	}

	if run.UpgradePhase == UpgradePhaseRollbackPending {
		// Older releases could persist an image-only rollback intent. Do not replay
		// that mutation: stateful services may already have changed persistent
		// state, so rolling the image back without restoring the bound backup is
		// not a valid recovery operation. Convert the durable state fail-closed.
		if err := m.update(id, func(target *Run) { target.UpgradePhase = UpgradePhaseRecoveryRequired }); err != nil {
			return run.PreviousImage, fmt.Errorf("persist state-aware recovery requirement: %w", err)
		}
		run.UpgradePhase = UpgradePhaseRecoveryRequired
	}
	if run.UpgradePhase == UpgradePhaseRecoveryRequired {
		failure := strings.TrimSpace(run.UpgradeFailure)
		if failure == "" {
			failure = "upgrade failed and explicit state-aware recovery is required"
		}
		return run.PreviousImage, errors.New(failure + "; use the confirmation-bound upgrade recovery operation")
	}
	if run.UpgradePhase == UpgradePhaseRollbackCompleted {
		return run.PreviousImage, errors.New("legacy image-only rollback completed; persistent-state recovery was not proven")
	}
	if run.UpgradePhase == UpgradePhaseApplyVerified {
		return m.verifyCompletedUpgrade(ctx, id, run)
	}
	if run.UpgradePhase != UpgradePhaseBackupPending && run.UpgradePhase != UpgradePhaseApplyPending {
		return run.PreviousImage, fmt.Errorf("unsupported durable upgrade phase %q", run.UpgradePhase)
	}

	if run.UpgradePhase == UpgradePhaseBackupPending {
		if err := m.performBackup(ctx, id, run.Service, run.BackupID, run.ProfileID); err != nil {
			return run.PreviousImage, fmt.Errorf("pre-upgrade backup: %w", err)
		}
		kind, name := workload(run.Service)
		container := run.Service
		options := m.workloadOptions(id, kind, name)
		previous := strings.TrimSpace(run.PreviousImage)
		if previous == "" {
			currentImage, err := kubeworkload.CurrentImage(ctx, options, container)
			if err != nil {
				return "", err
			}
			previous = strings.TrimSpace(currentImage)
			if previous == "" || !digestImage.MatchString(previous) {
				return "", errors.New("current service image was not found or is not digest-pinned")
			}
			if previous == run.RequestedImage {
				return "", errors.New("cannot safely begin upgrade: requested image is already active before previous image was durably recorded")
			}
		}
		if err := m.update(id, func(target *Run) {
			target.PreviousImage = previous
			target.UpgradePhase = UpgradePhaseApplyPending
		}); err != nil {
			return "", err
		}
		run.PreviousImage = previous
		run.UpgradePhase = UpgradePhaseApplyPending
	}

	kind, name := workload(run.Service)
	container := run.Service
	options := m.workloadOptions(id, kind, name)
	previous := strings.TrimSpace(run.PreviousImage)
	if previous == "" || !digestImage.MatchString(previous) {
		return previous, errors.New("durable previous image is missing or is not digest-pinned")
	}
	current, err := kubeworkload.CurrentImage(ctx, options, container)
	if err != nil {
		return previous, err
	}
	if current != previous && current != run.RequestedImage {
		return previous, fmt.Errorf("upgrade workload image drifted to %s; refusing automatic mutation", current)
	}
	if current == previous {
		if _, err = kubeworkload.SetImage(ctx, options, container, run.RequestedImage); err != nil {
			return previous, err
		}
	}
	if err = m.kubectl(ctx, "rollout", "status", kind+"/"+name, "--timeout=10m"); err != nil {
		failure := "upgrade rollout failed: " + err.Error()
		if persistErr := m.update(id, func(target *Run) {
			target.UpgradePhase = UpgradePhaseRecoveryRequired
			target.UpgradeFailure = failure
		}); persistErr != nil {
			return previous, errors.Join(fmt.Errorf("upgrade rollout failed: %w", err), fmt.Errorf("persist state-aware recovery requirement: %w", persistErr))
		}
		return previous, errors.New(failure + "; automatic image-only rollback is unsafe for stateful services; explicit upgrade recovery is required")
	}
	if err = kubeworkload.VerifyImage(ctx, options, container, run.RequestedImage); err != nil {
		failure := "upgrade image verification failed: " + err.Error()
		if persistErr := m.update(id, func(target *Run) {
			target.UpgradePhase = UpgradePhaseRecoveryRequired
			target.UpgradeFailure = failure
		}); persistErr != nil {
			return previous, errors.Join(err, fmt.Errorf("persist state-aware recovery requirement: %w", persistErr))
		}
		return previous, errors.New(failure + "; automatic image-only rollback is unsafe for stateful services; explicit upgrade recovery is required")
	}
	if err = m.update(id, func(target *Run) { target.UpgradePhase = UpgradePhaseApplyVerified }); err != nil {
		return previous, fmt.Errorf("persist verified upgrade completion: %w", err)
	}
	return previous, nil
}

func (m *Manager) verifyCompletedUpgrade(ctx context.Context, id string, run Run) (string, error) {
	kind, name := workload(run.Service)
	options := m.workloadOptions(id, kind, name)
	current, err := kubeworkload.CurrentImage(ctx, options, run.Service)
	if err != nil {
		return run.PreviousImage, err
	}
	if current != run.RequestedImage {
		return run.PreviousImage, fmt.Errorf("verified upgrade image changed from %s to %s before final state persistence; automatic replay is forbidden", run.RequestedImage, current)
	}
	if err = kubeworkload.VerifyImage(ctx, options, run.Service, run.RequestedImage); err != nil {
		return run.PreviousImage, err
	}
	return run.PreviousImage, nil
}

func (m *Manager) reconcileUpgradeRollback(ctx context.Context, id string, run Run) (string, error) {
	previous := strings.TrimSpace(run.PreviousImage)
	if previous == "" || !digestImage.MatchString(previous) {
		return previous, errors.New("rollback authority is missing a digest-pinned previous image")
	}
	failure := strings.TrimSpace(run.UpgradeFailure)
	if failure == "" {
		failure = "upgrade failed before rollback completion was durably recorded"
	}
	if run.UpgradePhase == UpgradePhaseRollbackCompleted {
		return previous, errors.New(failure + "; previous image was already durably restored")
	}
	kind, name := workload(run.Service)
	options := m.workloadOptions(id, kind, name)
	current, err := kubeworkload.CurrentImage(ctx, options, run.Service)
	if err != nil {
		return previous, err
	}
	if current != previous && current != run.RequestedImage {
		return previous, fmt.Errorf("rollback workload image drifted to %s; refusing automatic mutation", current)
	}
	if current == run.RequestedImage {
		if _, err = kubeworkload.SetImage(ctx, options, run.Service, previous); err != nil {
			return previous, errors.Join(errors.New(failure), fmt.Errorf("restore previous image failed: %w", err))
		}
	}
	if err = m.kubectl(ctx, "rollout", "status", kind+"/"+name, "--timeout=10m"); err != nil {
		return previous, errors.Join(errors.New(failure), fmt.Errorf("previous image rollout did not recover: %w", err))
	}
	if err = kubeworkload.VerifyImage(ctx, options, run.Service, previous); err != nil {
		return previous, errors.Join(errors.New(failure), fmt.Errorf("restored workload image verification failed: %w", err))
	}
	if err = m.update(id, func(target *Run) { target.UpgradePhase = UpgradePhaseRollbackCompleted }); err != nil {
		return previous, errors.Join(errors.New(failure), fmt.Errorf("persist completed rollback authority: %w", err))
	}
	return previous, errors.New(failure + "; previous image was restored")
}

func (m *Manager) workloadOptions(operationID, kind, name string) kubeworkload.Options {
	return kubeworkload.Options{System: m.system, StateDir: m.stateDir, StateSubdir: "lifecycle", Kubeconfig: "/etc/rancher/rke2/rke2.yaml", Namespace: "platform-system", Owner: "lifecycle", OperationID: operationID, Kind: kind, Name: name}
}

func (m *Manager) quiesceWorkload(ctx context.Context, operationID, kind, name, service string, replicas int) error {
	options := m.workloadOptions(operationID, kind, name)
	if err := kubeworkload.Scale(ctx, options, 0); err != nil {
		return err
	}
	waitCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	selector := "app=platform-" + service
	for {
		raw, err := m.kubectlOutput(waitCtx, "get", "pods", "-l", selector, "--field-selector=status.phase!=Succeeded,status.phase!=Failed", "-o", "name")
		if err != nil {
			resumeErr := m.resumeWorkload(context.WithoutCancel(ctx), operationID, kind, name, replicas)
			baseErr := fmt.Errorf("observe %s writer shutdown: %w", service, err)
			if resumeErr != nil {
				return errors.Join(baseErr, fmt.Errorf("recover %s after quiesce observation failure: %w", service, resumeErr))
			}
			return baseErr
		}
		if strings.TrimSpace(string(raw)) == "" {
			return kubeworkload.VerifyReplicas(waitCtx, options, 0)
		}
		select {
		case <-waitCtx.Done():
			resumeErr := m.resumeWorkload(context.WithoutCancel(ctx), operationID, kind, name, replicas)
			baseErr := fmt.Errorf("wait for %s writer pods to terminate: %w", service, waitCtx.Err())
			if resumeErr != nil {
				return errors.Join(baseErr, fmt.Errorf("recover %s after quiesce timeout: %w", service, resumeErr))
			}
			return baseErr
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func (m *Manager) resumeWorkload(ctx context.Context, operationID, kind, name string, replicas int) error {
	options := m.workloadOptions(operationID, kind, name)
	if err := kubeworkload.Scale(ctx, options, replicas); err != nil {
		return err
	}
	if err := m.kubectl(ctx, "rollout", "status", kind+"/"+name, "--timeout=10m"); err != nil {
		return err
	}
	return kubeworkload.VerifyReplicas(ctx, options, replicas)
}

func lifecycleJobName(action, operationID string) string {
	suffix := strings.ToLower(strings.TrimSpace(operationID))
	if len(suffix) > 32 {
		suffix = suffix[len(suffix)-32:]
	}
	return action + "-" + suffix
}

func (m *Manager) runJob(ctx context.Context, operationID, name, legacyName, manifest string) error {
	return kubejob.Execute(ctx, kubejob.Options{
		System:      m.system,
		StateDir:    m.stateDir,
		StateSubdir: "lifecycle",
		Kubeconfig:  "/etc/rancher/rke2/rke2.yaml",
		Namespace:   "platform-system",
		Owner:       "lifecycle",
		OperationID: operationID,
		Name:        name,
		LegacyName:  legacyName,
		Manifest:    manifest,
		Timeout:     20 * time.Minute,
	})
}
func (m *Manager) kubectl(ctx context.Context, args ...string) error {
	all := append([]string{"--kubeconfig", "/etc/rancher/rke2/rke2.yaml", "-n", "platform-system"}, args...)
	return m.system.Run(ctx, "/var/lib/rancher/rke2/bin/kubectl", all, nil)
}
func (m *Manager) kubectlOutput(ctx context.Context, args ...string) ([]byte, error) {
	all := append([]string{"--kubeconfig", "/etc/rancher/rke2/rke2.yaml", "-n", "platform-system"}, args...)
	return m.system.Output(ctx, "/var/lib/rancher/rke2/bin/kubectl", all, nil)
}

func (m *Manager) loadBackup(service, id string) (BackupMetadata, error) {
	meta, err := m.readBackupMetadata(id)
	if err != nil {
		return meta, err
	}
	if meta.Service != service {
		return meta, errors.New("backup metadata does not match request")
	}
	return meta, nil
}

func (m *Manager) readBackupMetadata(id string) (BackupMetadata, error) {
	var meta BackupMetadata
	if !safeID(id) {
		return meta, errors.New("backupId is invalid")
	}
	dir := filepath.Join(m.backupDir, id)
	info, err := os.Lstat(dir)
	if err != nil {
		return meta, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return meta, errors.New("backup directory is not a real directory")
	}
	file, _, err := openRealRegularBackupFile(filepath.Join(dir, "backup.json"))
	if err != nil {
		return meta, fmt.Errorf("backup metadata is not a real regular file: %w", err)
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil {
		return meta, err
	}
	if len(raw) == 0 || len(raw) > 1<<20 {
		return meta, errors.New("backup metadata size is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&meta); err != nil {
		return meta, err
	}
	var trailing any
	if err = decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return meta, errors.New("backup metadata contains trailing JSON")
		}
		return meta, fmt.Errorf("decode backup metadata trailer: %w", err)
	}
	if meta.ID != id || !safeID(meta.ID) {
		return meta, errors.New("backup metadata does not match backup directory")
	}
	normalizedService, err := normalizeService(meta.Service)
	if err != nil || normalizedService != meta.Service {
		return meta, errors.New("backup metadata service is invalid")
	}
	if meta.ProfileID != "" {
		normalizedProfile, profileErr := normalizeProfile(meta.ProfileID)
		if profileErr != nil || normalizedProfile != meta.ProfileID {
			return meta, errors.New("backup metadata profile is invalid")
		}
	}
	if meta.CreatedAt.IsZero() {
		return meta, errors.New("backup metadata createdAt is required")
	}
	return meta, nil
}

func backupPayloadNames(service string) ([]string, error) {
	switch service {
	case "forgejo":
		return []string{"data.tar.gz", "database.dump"}, nil
	case "keycloak":
		return []string{"database.dump", "marker"}, nil
	case "zot":
		return []string{"data.tar.gz"}, nil
	default:
		return nil, fmt.Errorf("unsupported backup service %q", service)
	}
}

func simulatedBackupPayload(service string) map[string][]byte {
	switch service {
	case "forgejo":
		return map[string][]byte{
			"data.tar.gz":   []byte("simulated-forgejo-data"),
			"database.dump": []byte("simulated-forgejo-database"),
		}
	case "keycloak":
		return map[string][]byte{
			"database.dump": []byte("simulated-keycloak-database"),
			"marker":        []byte("service=keycloak\n"),
		}
	default:
		return map[string][]byte{"data.tar.gz": []byte("simulated-zot-data")}
	}
}

func collectBackupPayload(dir, service string) ([]BackupFile, error) {
	expected, err := backupPayloadNames(service)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, errors.New("backup directory is not a real directory")
	}
	expectedSet := make(map[string]struct{}, len(expected))
	for _, name := range expected {
		expectedSet[name] = struct{}{}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if _, ok := expectedSet[entry.Name()]; !ok {
			return nil, fmt.Errorf("backup directory contains unexpected entry %s", entry.Name())
		}
	}
	files := make([]BackupFile, 0, len(expected))
	for _, name := range expected {
		path := filepath.Join(dir, name)
		if err = syncBackupFile(path); err != nil {
			return nil, fmt.Errorf("durably commit backup file %s: %w", name, err)
		}
		digest, size, digestErr := fileDigest(path)
		if digestErr != nil {
			return nil, fmt.Errorf("verify backup file %s: %w", name, digestErr)
		}
		if size <= 0 {
			return nil, fmt.Errorf("backup file %s is empty", name)
		}
		files = append(files, BackupFile{Name: name, SHA256: digest, Size: size})
	}
	return files, nil
}

func (m *Manager) verifyBackupPayload(meta BackupMetadata) error {
	expected, err := backupPayloadNames(meta.Service)
	if err != nil {
		return err
	}
	if len(meta.Files) != len(expected) {
		return fmt.Errorf("backup payload file count mismatch: got %d want %d", len(meta.Files), len(expected))
	}
	dir := filepath.Join(m.backupDir, meta.ID)
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("backup directory is not a real directory")
	}
	expectedSet := make(map[string]struct{}, len(expected))
	for _, name := range expected {
		expectedSet[name] = struct{}{}
	}
	seen := make(map[string]struct{}, len(meta.Files))
	for _, file := range meta.Files {
		if _, ok := expectedSet[file.Name]; !ok {
			return fmt.Errorf("backup metadata contains unexpected file %q", file.Name)
		}
		if _, duplicate := seen[file.Name]; duplicate {
			return fmt.Errorf("backup metadata contains duplicate file %q", file.Name)
		}
		seen[file.Name] = struct{}{}
		if !backupDigest.MatchString(file.SHA256) || file.Size <= 0 {
			return fmt.Errorf("backup metadata for %s has invalid digest or size", file.Name)
		}
		digest, size, digestErr := fileDigest(filepath.Join(dir, file.Name))
		if digestErr != nil {
			return fmt.Errorf("backup file verification failed: %s: %w", file.Name, digestErr)
		}
		if digest != file.SHA256 || size != file.Size {
			return fmt.Errorf("backup file verification failed: %s", file.Name)
		}
	}
	for _, name := range expected {
		if _, ok := seen[name]; !ok {
			return fmt.Errorf("backup metadata is missing required file %s", name)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Name() == "backup.json" {
			continue
		}
		if _, ok := expectedSet[entry.Name()]; !ok {
			return fmt.Errorf("backup directory contains unexpected entry %s", entry.Name())
		}
	}
	return nil
}
func (m *Manager) update(id string, fn func(*Run)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if run := m.findLocked(id); run != nil {
		previousRuns := append([]Run(nil), m.runs...)
		previousActive := make(map[string]bool, len(m.active))
		for key, value := range m.active {
			previousActive[key] = value
		}
		fn(run)
		if err := m.saveLocked(); err != nil {
			m.runs = previousRuns
			m.active = previousActive
			return fmt.Errorf("persist lifecycle operation %s: %w", id, err)
		}
	}
	return nil
}
func (m *Manager) findLocked(id string) *Run {
	for i := range m.runs {
		if m.runs[i].ID == id {
			return &m.runs[i]
		}
	}
	return nil
}
func (m *Manager) saveLocked() error {
	raw, err := json.MarshalIndent(m.runs, "", "  ")
	if err != nil {
		return fmt.Errorf("encode lifecycle state: %w", err)
	}
	final := filepath.Join(m.stateDir, "lifecycle-runs.json")
	return durablefile.Replace(final, append(raw, '\n'), 0o700, 0o600)
}
func (m *Manager) load() error {
	raw, err := os.ReadFile(filepath.Join(m.stateDir, "lifecycle-runs.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err = json.Unmarshal(raw, &m.runs); err != nil {
		return err
	}
	seenRunIDs := map[string]struct{}{}
	seenProducedBackups := map[string]struct{}{}
	recoveryAuthorityByService := map[string]Run{}
	for _, run := range m.runs {
		if _, exists := seenRunIDs[run.ID]; exists {
			return fmt.Errorf("duplicate lifecycle run id %q in durable state", run.ID)
		}
		seenRunIDs[run.ID] = struct{}{}
		if run.RecoveryRequired {
			if run.State != StateFailed || (run.Action != ActionRestore && run.Action != ActionUpgradeRecovery) {
				return fmt.Errorf("lifecycle run %q has invalid recoveryRequired authority", run.ID)
			}
			if _, serviceErr := normalizeService(run.Service); serviceErr != nil {
				return fmt.Errorf("lifecycle recovery run %q has invalid service authority: %w", run.ID, serviceErr)
			}
			if _, profileErr := normalizeProfile(run.ProfileID); profileErr != nil {
				return fmt.Errorf("lifecycle recovery run %q has invalid profile authority: %w", run.ID, profileErr)
			}
			if !safeID(run.BackupID) {
				return fmt.Errorf("lifecycle recovery run %q has invalid backup authority", run.ID)
			}
			if run.Action == ActionUpgradeRecovery {
				if strings.TrimSpace(run.SourceUpgradeRunID) == "" || !digestImage.MatchString(strings.TrimSpace(run.PreviousImage)) {
					return fmt.Errorf("upgrade recovery run %q has incomplete source/image authority", run.ID)
				}
			}
			if prior, exists := recoveryAuthorityByService[run.Service]; exists {
				if !recoveryContinuationAllowed(prior, run) || !recoveryContinuationAllowed(run, prior) {
					return fmt.Errorf("lifecycle service %q has conflicting recoveryRequired authorities %q and %q", run.Service, prior.ID, run.ID)
				}
			} else {
				recoveryAuthorityByService[run.Service] = run
			}
		}
		if run.BackupID != "" && (run.Action == ActionBackup || run.Action == ActionUpgrade) {
			if _, exists := seenProducedBackups[run.BackupID]; exists {
				return fmt.Errorf("duplicate lifecycle produced backup id %q in durable state", run.BackupID)
			}
			seenProducedBackups[run.BackupID] = struct{}{}
		}
	}
	repairedLegacyRecovery := false
	for i := range m.runs {
		recovery := m.runs[i]
		if recovery.Action != ActionUpgradeRecovery || recovery.State != StateSucceeded || recovery.SourceUpgradeRunID == "" {
			continue
		}
		source := m.findLocked(recovery.SourceUpgradeRunID)
		if source == nil {
			return fmt.Errorf("successful upgrade recovery %q references missing source upgrade %q", recovery.ID, recovery.SourceUpgradeRunID)
		}
		if source.Action != ActionUpgrade || source.State != StateFailed || (source.UpgradePhase != UpgradePhaseRecoveryRequired && source.UpgradePhase != UpgradePhaseRecoveryCompleted) {
			return fmt.Errorf("successful upgrade recovery %q references incompatible source upgrade state", recovery.ID)
		}
		if source.Service != recovery.Service || source.ProfileID != recovery.ProfileID || source.BackupID != recovery.BackupID || strings.TrimSpace(source.PreviousImage) != strings.TrimSpace(recovery.PreviousImage) || strings.TrimSpace(source.RequestedImage) != strings.TrimSpace(recovery.RequestedImage) {
			return fmt.Errorf("successful upgrade recovery %q does not match source upgrade authority", recovery.ID)
		}
		if source.UpgradePhase == UpgradePhaseRecoveryRequired {
			source.UpgradePhase = UpgradePhaseRecoveryCompleted
			repairedLegacyRecovery = true
		}
	}
	if repairedLegacyRecovery {
		if err := m.saveLocked(); err != nil {
			return fmt.Errorf("persist legacy successful upgrade recovery authority repair: %w", err)
		}
	}
	for _, run := range m.runs {
		if run.State == StateQueued || run.State == StateRunning {
			m.active[run.Service] = true
		}
	}
	return nil
}
func normalizeService(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "forgejo", "zot", "keycloak":
		return value, nil
	default:
		return "", errors.New("service must be forgejo, zot or keycloak")
	}
}
func normalizeProfile(value string) (string, error) {
	value = strings.TrimSpace(value)
	switch value {
	case "evaluation-single-node", "production-standard-ha":
		return value, nil
	default:
		return "", errors.New("profileId must be evaluation-single-node or production-standard-ha")
	}
}
func safeID(value string) bool {
	if value == "" || strings.Contains(value, "..") || strings.ContainsAny(value, "/\\") {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}
func workload(service string) (string, string) {
	kind, name, _ := workloadTarget(service, "evaluation-single-node")
	return kind, name
}
func workloadTarget(service, profileID string) (string, string, int) {
	replicas := 1
	if service == "keycloak" && profileID == "production-standard-ha" {
		replicas = 2
	}
	switch service {
	case "forgejo":
		return "statefulset", "platform-forgejo", replicas
	case "keycloak":
		return "statefulset", "platform-keycloak", replicas
	default:
		return "deployment", "platform-zot", replicas
	}
}
func syncBackupFile(path string) error {
	file, _, err := openRealRegularBackupFile(path)
	if err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func fileDigest(path string) (string, int64, error) {
	file, _, err := openRealRegularBackupFile(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	hash := sha256.New()
	written, err := io.Copy(hash, file)
	if err != nil {
		return "", 0, err
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), written, nil
}

func openRealRegularBackupFile(path string) (*os.File, os.FileInfo, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, nil, errors.New("path is not a real regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	after, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) {
		_ = file.Close()
		return nil, nil, errors.New("path changed while opening or is not a real regular file")
	}
	return file, after, nil
}
