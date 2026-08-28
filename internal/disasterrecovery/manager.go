package disasterrecovery

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"platform.4so.io/factory/internal/bootstrap"
	"platform.4so.io/factory/internal/durablefile"
	"platform.4so.io/factory/internal/installation"
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
	stateDir, bundleDir string
	simulation          bool
	requireBundleLock   bool
	system              bootstrap.System
	now                 func() time.Time
	mu                  sync.Mutex
	runs                []Run
	active              bool
	reconciling         map[string]bool
}

var (
	disasterRecoveryComponents = []string{"postgresql", "platform-secrets", "agent-pki", "forgejo", "zot"}
	backupFormatIntegrityV2    = "sha256-sidecar-v2"
	safeBackupID               = regexp.MustCompile(`^[a-z0-9-]{3,96}$`)
	dns1123Label               = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$`)
)

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

func New(o Options) (*Manager, error) {
	if o.StateDir == "" || o.BundleDir == "" {
		return nil, errors.New("DR state and bundle directories are required")
	}
	if o.System == nil {
		o.System = bootstrap.LocalSystem{}
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	m := &Manager{stateDir: o.StateDir, bundleDir: o.BundleDir, simulation: o.Simulation, requireBundleLock: o.RequireBundleLock, system: o.System, now: o.Now, reconciling: map[string]bool{}}
	if err := m.load(); err != nil {
		return nil, fmt.Errorf("load disaster-recovery state: %w", err)
	}
	return m, nil
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
	if m.active {
		return true
	}
	for _, run := range m.runs {
		if run.State == StateFailed && run.RecoveryRequired {
			return true
		}
	}
	return false
}

func (m *Manager) recoveryBlockerLocked() *Run {
	for i := len(m.runs) - 1; i >= 0; i-- {
		run := &m.runs[i]
		if run.State == StateFailed && run.RecoveryRequired {
			return run
		}
	}
	return nil
}

func objectStorageAuthorityMatches(left, right installation.ServiceSpec) bool {
	return left.Mode == right.Mode &&
		strings.TrimSpace(left.Provider) == strings.TrimSpace(right.Provider) &&
		strings.TrimSpace(left.URL) == strings.TrimSpace(right.URL) &&
		strings.TrimSpace(left.Bucket) == strings.TrimSpace(right.Bucket) &&
		strings.Trim(left.Prefix, "/") == strings.Trim(right.Prefix, "/") &&
		strings.TrimSpace(left.Region) == strings.TrimSpace(right.Region)
}

func restoreRecoveryAuthorityMatches(blocker Run, candidate Run) bool {
	return blocker.Action == ActionRestore &&
		candidate.Action == ActionRestore &&
		blocker.BackupID != "" &&
		blocker.BackupID == candidate.BackupID &&
		blocker.ObjectPrefix != "" &&
		blocker.ObjectPrefix == candidate.ObjectPrefix &&
		blocker.ProfileID != "" &&
		blocker.ProfileID == candidate.ProfileID &&
		objectStorageAuthorityMatches(blocker.ObjectStorage, candidate.ObjectStorage)
}

func (m *Manager) clearRecoveryBlockersLocked(success Run) {
	for i := range m.runs {
		blocker := &m.runs[i]
		if blocker.State == StateFailed && blocker.RecoveryRequired && restoreRecoveryAuthorityMatches(*blocker, success) {
			blocker.RecoveryRequired = false
		}
	}
}
func (m *Manager) StartBackup(ctx context.Context, request installation.InstallRequest) (Run, error) {
	return m.start(ctx, request, ActionBackup, "")
}
func (m *Manager) StartRestore(ctx context.Context, request installation.InstallRequest, backupID string) (Run, error) {
	if !safeBackupID.MatchString(backupID) {
		return Run{}, errors.New("backupId is invalid")
	}
	return m.start(ctx, request, ActionRestore, backupID)
}
func (m *Manager) start(ctx context.Context, request installation.InstallRequest, action Action, backupID string) (Run, error) {
	if m.requireBundleLock {
		if _, err := bootstrap.InspectBundle(m.bundleDir, true); err != nil {
			return Run{}, fmt.Errorf("bundle admission: %w", err)
		}
	}
	if err := validateTarget(request); err != nil {
		return Run{}, err
	}
	prefix := strings.Trim(request.Services.ObjectStorage.Prefix, "/")
	if prefix == "" {
		prefix = "4so-platform-factory"
	}
	candidate := Run{Action: action, BackupID: backupID, ObjectStorage: request.Services.ObjectStorage, ProfileID: request.ProfileID}
	if backupID != "" {
		candidate.ObjectPrefix = prefix + "/" + backupID
	}

	var restoreTargets []RestoreTargetIdentity
	var completedComponents []string
	m.mu.Lock()
	if m.active {
		m.mu.Unlock()
		return Run{}, errors.New("a disaster-recovery operation is already active")
	}
	if blocker := m.recoveryBlockerLocked(); blocker != nil {
		if !restoreRecoveryAuthorityMatches(*blocker, candidate) {
			m.mu.Unlock()
			return Run{}, fmt.Errorf("disaster-recovery restore %s requires recovery with the exact backup/profile/object-storage authority before %s can start", blocker.ID, action)
		}
		restoreTargets = append([]RestoreTargetIdentity(nil), blocker.RestoreTargets...)
		completedComponents = append([]string(nil), blocker.CompletedComponents...)
	}
	m.mu.Unlock()

	if action == ActionRestore && restoreTargets == nil {
		var err error
		restoreTargets, err = m.captureRestoreTargets(ctx)
		if err != nil {
			return Run{}, fmt.Errorf("bind disaster-recovery restore targets before mutation: %w", err)
		}
	}

	m.mu.Lock()
	if m.active {
		m.mu.Unlock()
		return Run{}, errors.New("a disaster-recovery operation is already active")
	}
	if blocker := m.recoveryBlockerLocked(); blocker != nil {
		if !restoreRecoveryAuthorityMatches(*blocker, candidate) {
			m.mu.Unlock()
			return Run{}, fmt.Errorf("disaster-recovery restore %s requires recovery with the exact backup/profile/object-storage authority before %s can start", blocker.ID, action)
		}
		// Continue from the durable destructive-recovery authority. Re-capturing
		// identities or replaying components already completed by the failed run
		// would turn a retry into a new restore rather than a continuation.
		restoreTargets = append([]RestoreTargetIdentity(nil), blocker.RestoreTargets...)
		completedComponents = append([]string(nil), blocker.CompletedComponents...)
	}
	now := m.now().UTC()
	if backupID == "" {
		backupID = m.uniqueBackupIDLocked(fmt.Sprintf("appliance-%s", now.Format("20060102t150405z")))
		candidate.BackupID = backupID
		candidate.ObjectPrefix = prefix + "/" + backupID
	}
	backupFormat := ""
	if action == ActionBackup {
		backupFormat = backupFormatIntegrityV2
	}
	runID := m.uniqueRunIDLocked(fmt.Sprintf("dr-%s-%d", action, now.UnixNano()))
	run := Run{ID: runID, Action: action, State: StateQueued, BackupID: backupID, ObjectPrefix: prefix + "/" + backupID, ObjectStorage: request.Services.ObjectStorage, ProfileID: request.ProfileID, BackupFormat: backupFormat, CompletedComponents: completedComponents, RestoreTargets: restoreTargets, CreatedAt: now}
	m.runs = append(m.runs, run)
	m.active = true
	if err := m.saveLocked(); err != nil {
		m.runs = m.runs[:len(m.runs)-1]
		m.active = false
		m.mu.Unlock()
		return Run{}, fmt.Errorf("persist queued disaster-recovery operation: %w", err)
	}
	m.mu.Unlock()
	go m.execute(context.WithoutCancel(ctx), run.ID, request)
	return run, nil
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

func validateTarget(request installation.InstallRequest) error {
	if request.ProfileID != "production-standard-ha" && request.ProfileID != "evaluation-single-node" {
		return errors.New("supported installation profile is required for disaster recovery")
	}
	obj := request.Services.ObjectStorage
	if obj.Mode != installation.ServiceModeExternal || !strings.HasPrefix(obj.URL, "https://") || obj.Bucket == "" {
		return errors.New("external HTTPS S3-compatible object storage with bucket is required")
	}
	if !strings.HasPrefix(obj.CredentialRef, "external-secret://") {
		return errors.New("credentialRef must be external-secret://platform-system/<valid-kubernetes-secret>")
	}
	ref := strings.TrimPrefix(obj.CredentialRef, "external-secret://")
	parts := strings.Split(ref, "/")
	if len(parts) != 2 || parts[0] != "platform-system" || !validDNS1123Subdomain(parts[1]) {
		return errors.New("credentialRef must be external-secret://platform-system/<valid-kubernetes-secret>")
	}
	return nil
}

func validDNS1123Subdomain(value string) bool {
	if value == "" || len(value) > 253 {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || !dns1123Label.MatchString(label) {
			return false
		}
	}
	return true
}

type restoreSecretSnapshot struct {
	Metadata struct {
		UID             string            `json:"uid"`
		ResourceVersion string            `json:"resourceVersion"`
		Labels          map[string]string `json:"labels"`
	} `json:"metadata"`
	Type string            `json:"type"`
	Data map[string]string `json:"data"`
}

type restoreTargetRequirement struct {
	Namespace, Name, SecretType string
	RequiredKeys                []string
	RequiredLabels              map[string]string
}

var restoreTargetRequirements = []restoreTargetRequirement{
	{Namespace: "platform-system", Name: "platform-internal-services", SecretType: "Opaque", RequiredKeys: []string{"forgejo-admin-password", "identity-admin-password", "identity-admin-email", "session-secret", "catalog-signing-key"}},
	{Namespace: "platform-system", Name: "platform-ingress-tls", SecretType: "kubernetes.io/tls", RequiredKeys: []string{"tls.crt", "tls.key", "ca.crt"}},
	{Namespace: "platform-gitops", Name: "platform-internal-git", RequiredKeys: []string{"type", "url", "username", "password"}, RequiredLabels: map[string]string{"argocd.argoproj.io/secret-type": "repository"}},
	{Namespace: "platform-system", Name: "platform-agent-mtls", SecretType: "Opaque", RequiredKeys: []string{"client-ca.crt", "client-ca.key", "tls.crt", "tls.key"}},
}

func (m *Manager) captureRestoreTargets(ctx context.Context) ([]RestoreTargetIdentity, error) {
	out := make([]RestoreTargetIdentity, 0, len(restoreTargetRequirements))
	if m.simulation {
		for i, requirement := range restoreTargetRequirements {
			out = append(out, RestoreTargetIdentity{Namespace: requirement.Namespace, Name: requirement.Name, UID: fmt.Sprintf("simulation-uid-%d", i+1), ResourceVersion: "1"})
		}
		return out, nil
	}
	for _, requirement := range restoreTargetRequirements {
		raw, err := m.kubectlOutputNamespace(ctx, requirement.Namespace, "get", "secret/"+requirement.Name, "-o", "json")
		if err != nil {
			return nil, fmt.Errorf("inspect Secret %s/%s: %w", requirement.Namespace, requirement.Name, err)
		}
		var snapshot restoreSecretSnapshot
		if err = json.Unmarshal(raw, &snapshot); err != nil {
			return nil, fmt.Errorf("decode Secret %s/%s: %w", requirement.Namespace, requirement.Name, err)
		}
		if strings.TrimSpace(snapshot.Metadata.UID) == "" || strings.TrimSpace(snapshot.Metadata.ResourceVersion) == "" {
			return nil, fmt.Errorf("Secret %s/%s is missing UID/resourceVersion identity", requirement.Namespace, requirement.Name)
		}
		if requirement.SecretType != "" && snapshot.Type != requirement.SecretType {
			return nil, fmt.Errorf("Secret %s/%s type %q does not match product authority type %q", requirement.Namespace, requirement.Name, snapshot.Type, requirement.SecretType)
		}
		for _, key := range requirement.RequiredKeys {
			if strings.TrimSpace(snapshot.Data[key]) == "" {
				return nil, fmt.Errorf("Secret %s/%s is missing required product authority key %s", requirement.Namespace, requirement.Name, key)
			}
		}
		for key, expected := range requirement.RequiredLabels {
			if snapshot.Metadata.Labels[key] != expected {
				return nil, fmt.Errorf("Secret %s/%s ownership label %s=%q does not match %q", requirement.Namespace, requirement.Name, key, snapshot.Metadata.Labels[key], expected)
			}
		}
		out = append(out, RestoreTargetIdentity{Namespace: requirement.Namespace, Name: requirement.Name, UID: snapshot.Metadata.UID, ResourceVersion: snapshot.Metadata.ResourceVersion})
	}
	return out, nil
}

func validateRestoreTargets(run Run) error {
	if len(run.RestoreTargets) != len(restoreTargetRequirements) {
		return errors.New("durable restore target identities are missing; automatic legacy restore replay is forbidden")
	}
	seen := map[string]struct{}{}
	for _, target := range run.RestoreTargets {
		key := target.Namespace + "/" + target.Name
		if strings.TrimSpace(target.Namespace) == "" || strings.TrimSpace(target.Name) == "" || strings.TrimSpace(target.UID) == "" || strings.TrimSpace(target.ResourceVersion) == "" {
			return fmt.Errorf("durable restore target %s is incomplete", key)
		}
		if _, exists := seen[key]; exists {
			return fmt.Errorf("duplicate durable restore target %s", key)
		}
		seen[key] = struct{}{}
	}
	for _, requirement := range restoreTargetRequirements {
		if _, exists := seen[requirement.Namespace+"/"+requirement.Name]; !exists {
			return fmt.Errorf("durable restore target %s/%s is missing", requirement.Namespace, requirement.Name)
		}
	}
	return nil
}

func restoreTarget(run Run, namespace, name string) (RestoreTargetIdentity, error) {
	for _, target := range run.RestoreTargets {
		if target.Namespace == namespace && target.Name == name {
			if strings.TrimSpace(target.UID) == "" || strings.TrimSpace(target.ResourceVersion) == "" {
				return RestoreTargetIdentity{}, fmt.Errorf("durable restore target %s/%s is incomplete", namespace, name)
			}
			return target, nil
		}
	}
	return RestoreTargetIdentity{}, fmt.Errorf("durable restore target %s/%s is missing", namespace, name)
}

func (m *Manager) execute(ctx context.Context, id string, request installation.InstallRequest) {
	defer m.clearReconciling(id)
	persisted := m.get(id)
	if persisted == nil {
		return
	}
	if strings.TrimSpace(persisted.ObjectStorage.URL) != "" {
		request.Services.ObjectStorage = persisted.ObjectStorage
	} else if strings.TrimSpace(request.Services.ObjectStorage.URL) != "" {
		if err := m.update(id, func(r *Run) { r.ObjectStorage = request.Services.ObjectStorage }); err != nil {
			fmt.Fprintf(os.Stderr, "disaster-recovery operation %s could not persist recovery target: %v\n", id, err)
			return
		}
	}
	if strings.TrimSpace(persisted.ProfileID) != "" {
		request.ProfileID = persisted.ProfileID
	} else if strings.TrimSpace(request.ProfileID) != "" {
		if err := m.update(id, func(r *Run) { r.ProfileID = request.ProfileID }); err != nil {
			fmt.Fprintf(os.Stderr, "disaster-recovery operation %s could not persist installation profile: %v\n", id, err)
			return
		}
	}
	if err := validateTarget(request); err != nil {
		_ = m.update(id, func(r *Run) {
			n := m.now().UTC()
			r.State = StateFailed
			r.Error = "reconcile target unavailable: " + err.Error()
			r.FinishedAt = &n
			m.active = false
		})
		return
	}
	if err := m.update(id, func(r *Run) {
		n := m.now().UTC()
		r.State = StateRunning
		if r.StartedAt == nil {
			r.StartedAt = &n
		}
		r.Error = ""
	}); err != nil {
		fmt.Fprintf(os.Stderr, "disaster-recovery operation %s aborted before side effects: %v\n", id, err)
		return
	}
	var err error
	if m.simulation {
		time.Sleep(5 * time.Millisecond)
	} else if action := m.action(id); action == ActionBackup {
		err = m.backup(ctx, id, request)
	} else {
		err = m.restore(ctx, id, request)
	}
	recoveryRequired := destructiveRecoveryRequired(err)
	if persistErr := m.update(id, func(r *Run) {
		n := m.now().UTC()
		r.FinishedAt = &n
		if err != nil {
			r.State = StateFailed
			r.Error = err.Error()
			r.RecoveryRequired = recoveryRequired
		} else {
			r.State = StateSucceeded
			r.RecoveryRequired = false
			if r.Action == ActionRestore {
				m.clearRecoveryBlockersLocked(*r)
			}
		}
		m.active = false
	}); persistErr != nil {
		fmt.Fprintf(os.Stderr, "disaster-recovery operation %s completed but final state persistence failed: %v\n", id, persistErr)
	}
}
func (m *Manager) action(id string) Action {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.runs {
		if r.ID == id {
			return r.Action
		}
	}
	return ""
}
func containsComponent(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}

func (m *Manager) markComponentCompleted(id, component string) error {
	return m.update(id, func(r *Run) {
		if !containsComponent(r.CompletedComponents, component) {
			r.CompletedComponents = append(r.CompletedComponents, component)
		}
	})
}

// Reconcile resumes a durable DR operation after process restart. The persisted
// object-storage contract is authoritative; currentRequest is only a migration
// fallback for runs written by an older release.
func (m *Manager) Reconcile(ctx context.Context, currentRequest installation.InstallRequest) int {
	m.mu.Lock()
	ids := make([]string, 0, 1)
	for _, run := range m.runs {
		if (run.State == StateQueued || run.State == StateRunning) && !m.reconciling[run.ID] {
			m.reconciling[run.ID] = true
			ids = append(ids, run.ID)
		}
	}
	m.mu.Unlock()
	for _, id := range ids {
		go m.execute(context.WithoutCancel(ctx), id, currentRequest)
	}
	return len(ids)
}

func (m *Manager) clearReconciling(id string) {
	m.mu.Lock()
	delete(m.reconciling, id)
	m.mu.Unlock()
}

type workloadReplicaTarget struct {
	kind     string
	name     string
	replicas int
}

func workloadTargets(request installation.InstallRequest) []workloadReplicaTarget {
	apiReplicas, keycloakReplicas := 1, 1
	if request.ProfileID == "production-standard-ha" {
		apiReplicas, keycloakReplicas = 3, 2
	}
	return []workloadReplicaTarget{
		{kind: "deployment", name: "platform-api", replicas: apiReplicas},
		{kind: "statefulset", name: "platform-keycloak", replicas: keycloakReplicas},
		{kind: "statefulset", name: "platform-forgejo", replicas: 1},
		{kind: "deployment", name: "platform-zot", replicas: 1},
	}
}

func (m *Manager) workloadOptions(operationID string, target workloadReplicaTarget) kubeworkload.Options {
	return kubeworkload.Options{System: m.system, StateDir: m.stateDir, StateSubdir: "disaster-recovery", Kubeconfig: "/etc/rancher/rke2/rke2.yaml", Namespace: "platform-system", Owner: "disaster-recovery", OperationID: operationID, Kind: target.kind, Name: target.name}
}

func (m *Manager) resumeWorkloadTargets(ctx context.Context, operationID string, targets []workloadReplicaTarget) error {
	var errs []error
	for _, target := range targets {
		resource := target.kind + "/" + target.name
		if err := kubeworkload.Scale(ctx, m.workloadOptions(operationID, target), target.replicas); err != nil {
			errs = append(errs, fmt.Errorf("scale %s to %d replicas: %w", resource, target.replicas, err))
		}
	}
	for _, target := range targets {
		if target.replicas == 0 {
			continue
		}
		resource := target.kind + "/" + target.name
		if err := m.kubectl(ctx, "rollout", "status", resource, "--timeout=10m"); err != nil {
			errs = append(errs, fmt.Errorf("rollout %s after disaster-recovery quiesce: %w", resource, err))
			continue
		}
		if err := kubeworkload.VerifyReplicas(ctx, m.workloadOptions(operationID, target), target.replicas); err != nil {
			errs = append(errs, fmt.Errorf("verify %s replicas after disaster-recovery resume: %w", resource, err))
		}
	}
	return errors.Join(errs...)
}

func (m *Manager) resumeWorkloads(ctx context.Context, operationID string, request installation.InstallRequest) error {
	return m.resumeWorkloadTargets(ctx, operationID, workloadTargets(request))
}

func (m *Manager) installerExecutionNode(ctx context.Context) (string, error) {
	if m.simulation {
		return "simulation-node", nil
	}
	host, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("resolve disaster-recovery installer node hostname: %w", err)
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

func (m *Manager) backupWorkloadNode(ctx context.Context, component string) (string, error) {
	app := "platform-" + component
	raw, err := m.kubectlOutput(ctx, "get", "pods", "-l", "app="+app, "-o", "jsonpath={.items[0].spec.nodeName}")
	if err != nil {
		return "", fmt.Errorf("resolve %s backup node: %w", component, err)
	}
	node := strings.TrimSpace(string(raw))
	if node == "" || strings.ContainsAny(node, "\r\n\t ") {
		return "", fmt.Errorf("resolve %s backup node: running workload node is unavailable", component)
	}
	return node, nil
}

func (m *Manager) ensureBackupWorkloadNodes(ctx context.Context, id string, run *Run) (*Run, error) {
	if strings.TrimSpace(run.AuthorityBackupNode) == "" {
		node, err := m.installerExecutionNode(ctx)
		if err != nil {
			return nil, err
		}
		if err = m.update(id, func(target *Run) { target.AuthorityBackupNode = node }); err != nil {
			return nil, err
		}
		run = m.get(id)
		if run == nil {
			return nil, errors.New("DR run disappeared while persisting installer authority placement")
		}
	}
	for _, component := range []string{"forgejo", "zot"} {
		current := run.ForgejoBackupNode
		if component == "zot" {
			current = run.ZotBackupNode
		}
		if strings.TrimSpace(current) != "" {
			continue
		}
		node, err := m.backupWorkloadNode(ctx, component)
		if err != nil {
			return nil, err
		}
		if err = m.update(id, func(target *Run) {
			if component == "forgejo" {
				target.ForgejoBackupNode = node
			} else {
				target.ZotBackupNode = node
			}
		}); err != nil {
			return nil, err
		}
		run = m.get(id)
		if run == nil {
			return nil, errors.New("DR run disappeared while persisting backup workload placement")
		}
	}
	return run, nil
}

func (m *Manager) waitForWorkloadQuiesced(ctx context.Context, operationID string, target workloadReplicaTarget) error {
	waitCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	selector := "app=" + target.name
	for {
		raw, err := m.kubectlOutput(waitCtx, "get", "pods", "-l", selector, "--field-selector=status.phase!=Succeeded,status.phase!=Failed", "-o", "name")
		if err != nil {
			return fmt.Errorf("observe %s shutdown: %w", target.kind+"/"+target.name, err)
		}
		if strings.TrimSpace(string(raw)) == "" {
			return kubeworkload.VerifyReplicas(waitCtx, m.workloadOptions(operationID, target), 0)
		}
		select {
		case <-waitCtx.Done():
			return fmt.Errorf("wait for %s pods to terminate: %w", target.kind+"/"+target.name, waitCtx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func (m *Manager) quiesceWorkloads(ctx context.Context, operationID string, request installation.InstallRequest) error {
	targets := workloadTargets(request)
	quiesced := make([]workloadReplicaTarget, 0, len(targets))
	for _, target := range targets {
		resource := target.kind + "/" + target.name
		if err := kubeworkload.Scale(ctx, m.workloadOptions(operationID, target), 0); err != nil {
			recoverErr := m.resumeWorkloadTargets(context.WithoutCancel(ctx), operationID, quiesced)
			baseErr := fmt.Errorf("quiesce %s before disaster-recovery operation: %w", resource, err)
			if recoverErr != nil {
				return errors.Join(baseErr, fmt.Errorf("recover workloads after quiesce failure: %w", recoverErr))
			}
			return baseErr
		}
		quiesced = append(quiesced, target)
		if err := m.waitForWorkloadQuiesced(ctx, operationID, target); err != nil {
			recoverErr := m.resumeWorkloadTargets(context.WithoutCancel(ctx), operationID, quiesced)
			baseErr := fmt.Errorf("quiesce %s before disaster-recovery operation: %w", resource, err)
			if recoverErr != nil {
				return errors.Join(baseErr, fmt.Errorf("recover workloads after quiesce failure: %w", recoverErr))
			}
			return baseErr
		}
	}
	return nil
}

func (m *Manager) withBackupQuiesced(ctx context.Context, operationID string, request installation.InstallRequest, operation func() error) (err error) {
	if err = m.quiesceWorkloads(ctx, operationID, request); err != nil {
		return err
	}
	defer func() {
		if resumeErr := m.resumeWorkloads(context.WithoutCancel(ctx), operationID, request); resumeErr != nil {
			wrapped := fmt.Errorf("resume platform workloads after disaster-recovery backup: %w", resumeErr)
			if err != nil {
				err = errors.Join(err, wrapped)
			} else {
				err = wrapped
			}
		}
	}()
	return operation()
}

func (m *Manager) withRestoreQuiesced(ctx context.Context, operationID string, request installation.InstallRequest, operation func() error) error {
	if err := m.quiesceWorkloads(ctx, operationID, request); err != nil {
		return err
	}
	if err := operation(); err != nil {
		return requireDestructiveRecovery(fmt.Errorf("restore failed; platform workloads remain quiesced for safe retry: %w", err))
	}
	if err := m.resumeWorkloads(ctx, operationID, request); err != nil {
		return requireDestructiveRecovery(fmt.Errorf("restored appliance data but could not resume all platform workloads: %w", err))
	}
	return nil
}

func backupNodeForComponent(run Run, component string) string {
	if component == "platform-secrets" {
		return run.AuthorityBackupNode
	}
	if component == "forgejo" {
		return run.ForgejoBackupNode
	}
	if component == "zot" {
		return run.ZotBackupNode
	}
	return ""
}

func (m *Manager) ensureCurrentBackupFormat(id string, run *Run) (*Run, error) {
	if run == nil {
		return nil, errors.New("DR run not found")
	}
	if run.BackupFormat == backupFormatIntegrityV2 {
		return run, nil
	}
	if err := m.update(id, func(target *Run) {
		target.BackupFormat = backupFormatIntegrityV2
		target.CompletedComponents = nil
	}); err != nil {
		return nil, fmt.Errorf("migrate interrupted backup to current integrity format: %w", err)
	}
	updated := m.get(id)
	if updated == nil {
		return nil, errors.New("DR run disappeared while migrating backup format")
	}
	return updated, nil
}

func (m *Manager) backup(ctx context.Context, id string, request installation.InstallRequest) error {
	bundle, _, err := m.loadBundle()
	if err != nil {
		return err
	}
	run := m.get(id)
	if run == nil {
		return errors.New("DR run not found")
	}
	run, err = m.ensureCurrentBackupFormat(id, run)
	if err != nil {
		return err
	}
	run, err = m.ensureBackupWorkloadNodes(ctx, id, run)
	if err != nil {
		return err
	}
	return m.withBackupQuiesced(ctx, run.ID, request, func() error {
		for _, component := range disasterRecoveryComponents {
			if containsComponent(run.CompletedComponents, component) {
				continue
			}
			manifest := backupManifest(component, *run, request, bundle, backupNodeForComponent(*run, component))
			if err = m.runJob(ctx, run.ID, drBackupJobName(component, *run), "dr-backup-"+component+"-"+shortID(run.BackupID), manifest); err != nil {
				return fmt.Errorf("backup %s: %w", component, err)
			}
			if err = m.markComponentCompleted(id, component); err != nil {
				return err
			}
			run = m.get(id)
			if run == nil {
				return errors.New("DR run disappeared during backup")
			}
		}
		if !containsComponent(run.CompletedComponents, "commit") {
			if err = m.runJob(ctx, run.ID, drBackupCommitJobName(*run), "dr-backup-commit-"+shortID(run.BackupID), backupCommitManifest(*run, request, bundle)); err != nil {
				return fmt.Errorf("commit complete backup: %w", err)
			}
			if err = m.markComponentCompleted(id, "commit"); err != nil {
				return err
			}
		}
		return nil
	})
}

func (m *Manager) restore(ctx context.Context, id string, request installation.InstallRequest) error {
	bundle, _, err := m.loadBundle()
	if err != nil {
		return err
	}
	run := m.get(id)
	if run == nil {
		return errors.New("DR run not found")
	}
	if err = validateRestoreTargets(*run); err != nil {
		return err
	}
	if err = m.runJob(ctx, run.ID, drRestorePreflightJobName(*run), "dr-restore-preflight-"+shortID(run.BackupID), restorePreflightManifest(*run, request, bundle)); err != nil {
		return fmt.Errorf("restore backup preflight: backup is incomplete, legacy, or inaccessible: %w", err)
	}
	return m.withRestoreQuiesced(ctx, run.ID, request, func() error {
		for _, component := range disasterRecoveryComponents {
			if containsComponent(run.CompletedComponents, component) {
				continue
			}
			manifest := restoreManifest(component, *run, request, bundle)
			if err = m.runJob(ctx, run.ID, drRestoreJobName(component, *run), "dr-restore-"+component+"-"+shortID(run.BackupID), manifest); err != nil {
				return fmt.Errorf("restore %s: %w", component, err)
			}
			if component == "platform-secrets" {
				if err = m.syncRestoredPlatformAuthority(ctx, *run); err != nil {
					return fmt.Errorf("mirror restored platform authority into installer state: %w", err)
				}
			}
			if component == "agent-pki" {
				if err = m.syncRestoredAgentAuthority(ctx, *run); err != nil {
					return fmt.Errorf("mirror restored agent authority into installer state: %w", err)
				}
			}
			if err = m.markComponentCompleted(id, component); err != nil {
				return err
			}
			run = m.get(id)
			if run == nil {
				return errors.New("DR run disappeared during restore")
			}
		}
		internalServices, targetErr := restoreTarget(*run, "platform-system", "platform-internal-services")
		if targetErr != nil {
			return targetErr
		}
		if err = m.removeSecretKeyWithIdentity(ctx, "platform-system", "platform-internal-services", "gitops-signing-key", internalServices.UID); err != nil {
			return fmt.Errorf("remove transient GitOps signing authority after durable restore completion: %w", err)
		}
		return nil
	})
}

func (m *Manager) readBoundSecret(ctx context.Context, namespace, secret, expectedUID string) (restoreSecretSnapshot, error) {
	raw, err := m.kubectlOutputNamespace(ctx, namespace, "get", "secret/"+secret, "-o", "json")
	if err != nil {
		return restoreSecretSnapshot{}, fmt.Errorf("read Secret %s/%s: %w", namespace, secret, err)
	}
	var current restoreSecretSnapshot
	if err = json.Unmarshal(raw, &current); err != nil {
		return current, fmt.Errorf("decode Secret %s/%s: %w", namespace, secret, err)
	}
	if strings.TrimSpace(current.Metadata.UID) == "" || strings.TrimSpace(current.Metadata.ResourceVersion) == "" {
		return current, fmt.Errorf("Secret %s/%s is missing UID/resourceVersion identity", namespace, secret)
	}
	if current.Metadata.UID != expectedUID {
		return current, fmt.Errorf("Secret %s/%s UID changed from %s to %s during restore; refusing same-name replacement", namespace, secret, expectedUID, current.Metadata.UID)
	}
	return current, nil
}

func (m *Manager) mirrorSecretKey(ctx context.Context, namespace, secret, key, destination string, mode os.FileMode, expectedUID string) error {
	current, err := m.readBoundSecret(ctx, namespace, secret, expectedUID)
	if err != nil {
		return err
	}
	encoded := strings.TrimSpace(current.Data[key])
	if encoded == "" {
		return fmt.Errorf("read %s/%s: secret data key %s is empty", namespace, secret, key)
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return fmt.Errorf("decode %s/%s key %s: %w", namespace, secret, key, err)
	}
	if len(decoded) == 0 {
		return fmt.Errorf("decode %s/%s key %s: secret data is empty", namespace, secret, key)
	}
	if err = m.system.WriteFile(destination, decoded, mode); err != nil {
		return fmt.Errorf("write restored installer authority %s: %w", destination, err)
	}
	return nil
}

func (m *Manager) syncRestoredPlatformAuthority(ctx context.Context, run Run) error {
	internal, err := restoreTarget(run, "platform-system", "platform-internal-services")
	if err != nil {
		return err
	}
	ingress, err := restoreTarget(run, "platform-system", "platform-ingress-tls")
	if err != nil {
		return err
	}
	items := []struct {
		namespace, secret, key, destination, uid string
		mode                                     os.FileMode
	}{
		{"platform-system", "platform-internal-services", "forgejo-admin-password", "/var/lib/4so-platform-installer/secrets/forgejo-admin-password", internal.UID, 0o600},
		{"platform-system", "platform-internal-services", "identity-admin-password", "/var/lib/4so-platform-installer/secrets/identity-admin-password", internal.UID, 0o600},
		{"platform-system", "platform-internal-services", "session-secret", "/var/lib/4so-platform-installer/secrets/session-secret", internal.UID, 0o600},
		{"platform-system", "platform-internal-services", "catalog-signing-key", "/var/lib/4so-platform-installer/secrets/catalog-signing-key", internal.UID, 0o600},
		{"platform-system", "platform-internal-services", "gitops-signing-key", "/var/lib/4so-platform-installer/secrets/gitops-signing-key", internal.UID, 0o600},
		{"platform-system", "platform-ingress-tls", "ca.crt", "/var/lib/4so-platform-installer/secrets/platform-ca.crt", ingress.UID, 0o644},
		{"platform-system", "platform-ingress-tls", "tls.crt", "/var/lib/4so-platform-installer/secrets/platform-tls.crt", ingress.UID, 0o600},
		{"platform-system", "platform-ingress-tls", "tls.key", "/var/lib/4so-platform-installer/secrets/platform-tls.key", ingress.UID, 0o600},
	}
	for _, item := range items {
		if err := m.mirrorSecretKey(ctx, item.namespace, item.secret, item.key, item.destination, item.mode, item.uid); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) removeSecretKeyWithIdentity(ctx context.Context, namespace, secret, key, expectedUID string) error {
	current, err := m.readBoundSecret(ctx, namespace, secret, expectedUID)
	if err != nil {
		return fmt.Errorf("inspect Secret %s/%s before cleanup: %w", namespace, secret, err)
	}
	if _, exists := current.Data[key]; !exists {
		return nil
	}
	patch, err := json.Marshal([]map[string]any{
		{"op": "test", "path": "/metadata/uid", "value": expectedUID},
		{"op": "test", "path": "/metadata/resourceVersion", "value": current.Metadata.ResourceVersion},
		{"op": "remove", "path": "/data/" + strings.ReplaceAll(strings.ReplaceAll(key, "~", "~0"), "/", "~1")},
	})
	if err != nil {
		return fmt.Errorf("encode Secret %s/%s cleanup patch: %w", namespace, secret, err)
	}
	if err = m.kubectlNamespace(ctx, namespace, "patch", "secret/"+secret, "--type=json", "-p", string(patch)); err != nil {
		return fmt.Errorf("identity-fenced Secret %s/%s cleanup: %w", namespace, secret, err)
	}
	verified, err := m.readBoundSecret(ctx, namespace, secret, expectedUID)
	if err != nil {
		return err
	}
	if _, exists := verified.Data[key]; exists {
		return fmt.Errorf("Secret %s/%s cleanup returned success but key %s is still present", namespace, secret, key)
	}
	return nil
}

func (m *Manager) syncRestoredAgentAuthority(ctx context.Context, run Run) error {
	agent, err := restoreTarget(run, "platform-system", "platform-agent-mtls")
	if err != nil {
		return err
	}
	for _, item := range []struct {
		key, destination string
		mode             os.FileMode
	}{
		{"client-ca.crt", "/var/lib/4so-platform-installer/secrets/agent-ca.crt", 0o644},
		{"client-ca.key", "/var/lib/4so-platform-installer/secrets/agent-ca.key", 0o600},
	} {
		if err := m.mirrorSecretKey(ctx, "platform-system", "platform-agent-mtls", item.key, item.destination, item.mode, agent.UID); err != nil {
			return err
		}
	}
	return nil
}

func shortID(v string) string {
	v = strings.ToLower(v)
	v = strings.ReplaceAll(v, "_", "-")
	if len(v) > 32 {
		return v[len(v)-32:]
	}
	return v
}
func (m *Manager) runJob(ctx context.Context, operationID, name, legacyName, manifest string) error {
	return kubejob.Execute(ctx, kubejob.Options{
		System:      m.system,
		StateDir:    m.stateDir,
		StateSubdir: "disaster-recovery",
		Kubeconfig:  "/etc/rancher/rke2/rke2.yaml",
		Namespace:   "platform-system",
		Owner:       "disaster-recovery",
		OperationID: operationID,
		Name:        name,
		LegacyName:  legacyName,
		Manifest:    manifest,
		Timeout:     30 * time.Minute,
	})
}
func (m *Manager) kubectl(ctx context.Context, args ...string) error {
	return m.kubectlNamespace(ctx, "platform-system", args...)
}
func (m *Manager) kubectlNamespace(ctx context.Context, namespace string, args ...string) error {
	all := append([]string{"--kubeconfig", "/etc/rancher/rke2/rke2.yaml", "-n", namespace}, args...)
	return m.system.Run(ctx, "/var/lib/rancher/rke2/bin/kubectl", all, nil)
}
func (m *Manager) kubectlOutput(ctx context.Context, args ...string) ([]byte, error) {
	return m.kubectlOutputNamespace(ctx, "platform-system", args...)
}
func (m *Manager) kubectlOutputNamespace(ctx context.Context, namespace string, args ...string) ([]byte, error) {
	all := append([]string{"--kubeconfig", "/etc/rancher/rke2/rke2.yaml", "-n", namespace}, args...)
	return m.system.Output(ctx, "/var/lib/rancher/rke2/bin/kubectl", all, nil)
}
func (m *Manager) get(id string) *Run {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.runs {
		if m.runs[i].ID == id {
			v := m.runs[i]
			return &v
		}
	}
	return nil
}
func (m *Manager) update(id string, fn func(*Run)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	previousRuns := append([]Run(nil), m.runs...)
	previousActive := m.active
	found := false
	for i := range m.runs {
		if m.runs[i].ID == id {
			fn(&m.runs[i])
			found = true
			break
		}
	}
	if !found {
		return nil
	}
	if err := m.saveLocked(); err != nil {
		m.runs = previousRuns
		m.active = previousActive
		return fmt.Errorf("persist disaster-recovery operation %s: %w", id, err)
	}
	return nil
}
func validateRestoreProgress(run Run) error {
	if run.Action != ActionRestore {
		return nil
	}
	if len(run.CompletedComponents) > len(disasterRecoveryComponents) {
		return errors.New("restore completedComponents exceeds the restore component sequence")
	}
	for i, component := range run.CompletedComponents {
		if component != disasterRecoveryComponents[i] {
			return fmt.Errorf("restore completedComponents is not a durable prefix: index %d is %q, want %q", i, component, disasterRecoveryComponents[i])
		}
	}
	return nil
}

func validateRestoreRecoveryAuthority(run Run) error {
	if run.State != StateFailed || run.Action != ActionRestore || !run.RecoveryRequired {
		return errors.New("recoveryRequired must belong to a failed restore")
	}
	if !safeBackupID.MatchString(run.BackupID) {
		return errors.New("recovery restore has invalid backup authority")
	}
	if err := validateTarget(installation.InstallRequest{ProfileID: run.ProfileID, Services: installation.ServicesSpec{ObjectStorage: run.ObjectStorage}}); err != nil {
		return fmt.Errorf("recovery restore target authority is invalid: %w", err)
	}
	prefix := strings.Trim(run.ObjectStorage.Prefix, "/")
	if prefix == "" {
		prefix = "4so-platform-factory"
	}
	if run.ObjectPrefix != prefix+"/"+run.BackupID {
		return errors.New("recovery restore object prefix does not match its exact backup/object-storage authority")
	}
	if err := validateRestoreTargets(run); err != nil {
		return fmt.Errorf("recovery restore target identities are invalid: %w", err)
	}
	return validateRestoreProgress(run)
}

func (m *Manager) saveLocked() error {
	raw, err := json.MarshalIndent(m.runs, "", "  ")
	if err != nil {
		return fmt.Errorf("encode disaster-recovery state: %w", err)
	}
	return durablefile.Replace(filepath.Join(m.stateDir, "disaster-recovery-runs.json"), append(raw, '\n'), 0o700, 0o600)
}
func (m *Manager) load() error {
	raw, err := os.ReadFile(filepath.Join(m.stateDir, "disaster-recovery-runs.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err = json.Unmarshal(raw, &m.runs); err != nil {
		return err
	}
	var recoveryAuthority *Run
	for _, run := range m.runs {
		if run.Action == ActionRestore {
			if err := validateRestoreProgress(run); err != nil {
				return fmt.Errorf("disaster-recovery run %q has invalid durable restore progress: %w", run.ID, err)
			}
		}
		if run.RecoveryRequired {
			if err := validateRestoreRecoveryAuthority(run); err != nil {
				return fmt.Errorf("disaster-recovery run %q has invalid recoveryRequired authority: %w", run.ID, err)
			}
			if recoveryAuthority != nil && (!restoreRecoveryAuthorityMatches(*recoveryAuthority, run) || !restoreRecoveryAuthorityMatches(run, *recoveryAuthority)) {
				return fmt.Errorf("disaster-recovery state has conflicting recoveryRequired authorities %q and %q", recoveryAuthority.ID, run.ID)
			}
			if recoveryAuthority == nil {
				copyRun := run
				recoveryAuthority = &copyRun
			}
		}
		if run.State == StateQueued || run.State == StateRunning {
			m.active = true
		}
	}
	return nil
}
