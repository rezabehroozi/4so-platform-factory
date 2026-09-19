package bootstrap

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"platform.4so.io/factory/internal/durablefile"
	"platform.4so.io/factory/internal/installation"
)

type RunnerOptions struct {
	Version           string
	BundleDir         string
	StateDir          string
	Simulation        bool
	RequireBundleLock bool
	System            System
	Now               func() time.Time
	TLSKeyGenerator   TLSKeyGenerator
}

type Runner struct {
	version           string
	bundleDir         string
	stateDir          string
	simulation        bool
	requireBundleLock bool
	system            System
	now               func() time.Time
	tlsKeyGenerator   TLSKeyGenerator
	journal           *Journal
	resetJournal      *ResetJournal
	mu                sync.Mutex
	active            bool
}

type interruptedStepPolicy string

const (
	interruptedReplaySafe    interruptedStepPolicy = "REPLAY_SAFE"
	interruptedVerifyRKE2    interruptedStepPolicy = "VERIFY_RKE2"
	interruptedReconcileGit  interruptedStepPolicy = "RECONCILE_GIT_REVISION"
	interruptedOutcomePrefix                       = "INTERRUPTED_OUTCOME_UNCERTAIN: "
)

var bootstrapInterruptedPolicies = map[string]interruptedStepPolicy{
	"preflight":                   interruptedReplaySafe,
	"prepare-host":                interruptedReplaySafe,
	"stage-bundle":                interruptedReplaySafe,
	"configure-rke2":              interruptedReplaySafe,
	"install-rke2":                interruptedVerifyRKE2,
	"verify-ha-quorum":            interruptedReplaySafe,
	"prepare-storage-devices":     interruptedReplaySafe,
	"deploy-replicated-storage":   interruptedReplaySafe,
	"deploy-postgresql-operator":  interruptedReplaySafe,
	"deploy-foundation":           interruptedReplaySafe,
	"deploy-internal-git":         interruptedReplaySafe,
	"deploy-oci-registry":         interruptedReplaySafe,
	"seed-offline-registry":       interruptedReplaySafe,
	"deploy-identity":             interruptedReplaySafe,
	"configure-secure-exposure":   interruptedReplaySafe,
	"bootstrap-repository":        interruptedReplaySafe,
	"deploy-gitops-controller":    interruptedReplaySafe,
	"publish-signed-revision":     interruptedReconcileGit,
	"verify-gitops-handover":      interruptedReplaySafe,
	"deploy-fleet-hub":            interruptedReplaySafe,
	"verify-fleet-hub":            interruptedReplaySafe,
	"configure-off-node-backup":   interruptedReplaySafe,
	"verify-off-node-backup":      interruptedReplaySafe,
	"verify-embedded-services":    interruptedReplaySafe,
	"verify-runtime":              interruptedReplaySafe,
	"verify-ha-services":          interruptedReplaySafe,
	"revoke-bootstrap-credential": interruptedReplaySafe,
}

var bootstrapSteps = []struct{ key, title string }{
	{"preflight", "Validate the local Linux host and digest-locked appliance bundle"},
	{"prepare-host", "Create appliance directories, bootstrap identity and TLS material"},
	{"stage-bundle", "Stage RKE2 and workload image artifacts"},
	{"configure-rke2", "Write the single-node RKE2 configuration"},
	{"install-rke2", "Install and start the RKE2 management node or three-node HA cluster"},
	{"verify-ha-quorum", "Verify the three-node management quorum when HA is selected"},
	{"prepare-storage-devices", "Prepare explicitly admitted dedicated storage devices on every HA node"},
	{"deploy-replicated-storage", "Deploy Longhorn, bind only 4SO-owned data disks, and verify the product-owned replicated StorageClass"},
	{"deploy-postgresql-operator", "Deploy the bundled PostgreSQL HA operator when HA is selected"},
	{"deploy-foundation", "Deploy PostgreSQL and the 4SO control plane"},
	{"deploy-internal-git", "Deploy managed Forgejo"},
	{"deploy-oci-registry", "Deploy the managed zot OCI registry"},
	{"seed-offline-registry", "Verify disconnected image availability on every management node"},
	{"deploy-identity", "Deploy managed Keycloak and initialize the platform administrator"},
	{"configure-secure-exposure", "Expose the appliance through TLS ingress"},
	{"bootstrap-repository", "Create and seed the internal desired-state repository"},
	{"deploy-gitops-controller", "Deploy the bundled Argo CD GitOps controller"},
	{"publish-signed-revision", "Publish the product-signed initial desired-state revision"},
	{"verify-gitops-handover", "Verify Argo CD reconciliation and revision digest equality"},
	{"deploy-fleet-hub", "Deploy the bundled Open Cluster Management hub"},
	{"verify-fleet-hub", "Verify the fleet registration control plane"},
	{"configure-off-node-backup", "Configure the external S3-compatible disaster-recovery target"},
	{"verify-off-node-backup", "Verify credentialed S3 write, read-back integrity and delete semantics"},
	{"verify-embedded-services", "Verify Git, registry and identity health"},
	{"verify-runtime", "Verify authenticated PostgreSQL-backed API persistence across restart"},
	{"verify-ha-services", "Verify HA database and control-plane service availability"},
	{"revoke-bootstrap-credential", "Revoke the installer bootstrap credential from the running control plane"},
}

func bootstrapStepsForBundle(bundle BundleManifest, milestone, startStep string) []struct{ key, title string } {
	steps := make([]struct{ key, title string }, 0, len(bootstrapSteps))
	stopAfter := ""
	switch strings.TrimSpace(milestone) {
	case "rke2-quorum":
		stopAfter = "verify-ha-quorum"
	case "ha-storage":
		stopAfter = "deploy-replicated-storage"
	case "", "full":
	default:
		stopAfter = ""
	}
	started := strings.TrimSpace(startStep) == ""
	for _, item := range bootstrapSteps {
		if !started {
			if item.key != strings.TrimSpace(startStep) {
				continue
			}
			started = true
		}
		if (item.key == "deploy-fleet-hub" || item.key == "verify-fleet-hub") && strings.TrimSpace(bundle.Spec.Workloads.OCMManifest.Path) == "" {
			continue
		}
		steps = append(steps, item)
		if stopAfter != "" && item.key == stopAfter {
			break
		}
	}
	return steps
}

func NewRunner(options RunnerOptions) (*Runner, error) {
	if strings.TrimSpace(options.Version) == "" {
		return nil, fmt.Errorf("runner version is required")
	}
	if strings.TrimSpace(options.BundleDir) == "" || strings.TrimSpace(options.StateDir) == "" {
		return nil, fmt.Errorf("bundle and state directories are required")
	}
	if options.System == nil {
		options.System = LocalSystem{}
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.TLSKeyGenerator == nil {
		options.TLSKeyGenerator = ProductionTLSKeyGenerator
		if options.Simulation {
			// Simulation validates lifecycle semantics and artifact handling, not RSA
			// entropy cost. Production remains pinned to RSA-3072.
			options.TLSKeyGenerator = SimulationTLSKeyGenerator
		}
	}
	return &Runner{version: options.Version, bundleDir: options.BundleDir, stateDir: options.StateDir, simulation: options.Simulation, requireBundleLock: options.RequireBundleLock, system: options.System, now: options.Now, tlsKeyGenerator: options.TLSKeyGenerator, journal: NewJournal(options.StateDir), resetJournal: NewResetJournal(options.StateDir)}, nil
}

func (r *Runner) Status() (*Run, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.journal.Load()
}

func (r *Runner) BundleStatus() (BundleAdmissionStatus, error) {
	return InspectBundle(r.bundleDir, r.requireBundleLock)
}

func (r *Runner) Plan(request installation.InstallRequest) (installation.InstallationPlan, string, error) {
	plan, err := installation.CreateBootstrapPlan(request)
	if err != nil {
		return installation.InstallationPlan{}, "", err
	}
	admission, bundleErr := InspectBundleForMilestone(r.bundleDir, r.requireBundleLock, request.ExecutionMilestone)
	bundleDigest := admission.BundleDigest
	if bundleErr != nil {
		plan.Blockers = append(plan.Blockers, bundleErr.Error())
		plan.Status = "planning-only"
		plan.Executable = false
	}
	return plan, bundleDigest, nil
}

func (r *Runner) Start(ctx context.Context, request installation.InstallRequest) (Run, error) {
	if err := r.beginExecution(); err != nil {
		return Run{}, err
	}
	defer r.endExecution()
	current, err := r.journal.Load()
	if err != nil {
		return Run{}, err
	}
	if r.system.Exists(bootstrapCredentialRevokedPath) {
		return Run{}, errors.New("bootstrap credential is durably revoked; perform an explicit reset before starting another installation")
	}
	if current != nil && current.State != RunSucceeded {
		return Run{}, fmt.Errorf("bootstrap run %s is %s and must be resumed before a new start", current.ID, current.State)
	}
	plan, bundleDigest, err := r.PlanUnlocked(request)
	if err != nil {
		return Run{}, err
	}
	if !plan.Executable {
		return Run{}, fmt.Errorf("bootstrap plan is not executable: %s", strings.Join(plan.Blockers, "; "))
	}
	request = plan.EffectiveRequest
	if err := r.prepareCloneSafety(ctx, request); err != nil {
		return Run{}, fmt.Errorf("prepare cloned host identity: %w", err)
	}
	if err := r.prepareTimeSynchronization(ctx, request.Connectivity); err != nil {
		return Run{}, err
	}
	if err := r.prepareHAPeerTimeSynchronization(ctx, request); err != nil {
		return Run{}, err
	}
	preflight, err := r.preflightUnlocked(ctx, request)
	if err != nil {
		return Run{}, err
	}
	if !preflight.Passed() {
		return Run{}, fmt.Errorf("appliance preflight is blocked; inspect report %s", preflight.ID)
	}
	now := r.now().UTC()
	run := Run{
		ID: "bootstrap-" + strings.TrimPrefix(plan.SpecDigest, "sha256:")[:20], Version: r.version,
		State: RunPending, Request: request, SpecDigest: plan.SpecDigest, BundleDigest: bundleDigest, PreflightDigest: preflight.Digest,
		CreatedAt: now, UpdatedAt: now, Simulation: r.simulation,
	}
	bundle, _, err := LoadBundleForMilestone(r.bundleDir, request.ExecutionMilestone)
	if err != nil {
		return Run{}, err
	}
	for _, item := range bootstrapStepsForBundle(bundle, request.ExecutionMilestone, request.ExecutionStartStep) {
		run.Steps = append(run.Steps, Step{Key: item.key, Title: item.title, State: StepPending})
	}
	if err = r.journal.Save(run); err != nil {
		return Run{}, err
	}
	return r.executeUnlocked(ctx, run)
}

func (r *Runner) Resume(ctx context.Context) (Run, error) {
	if err := r.beginExecution(); err != nil {
		return Run{}, err
	}
	defer r.endExecution()
	run, err := r.journal.Load()
	if err != nil {
		return Run{}, err
	}
	if run == nil {
		return Run{}, fmt.Errorf("no bootstrap run exists")
	}
	if run.State == RunSucceeded {
		return *run, nil
	}
	plan, currentBundleDigest, err := r.PlanUnlocked(run.Request)
	if err != nil {
		return *run, err
	}
	if plan.SpecDigest != run.SpecDigest {
		return *run, fmt.Errorf("persisted bootstrap request no longer matches its accepted spec digest: accepted %s observed %s", run.SpecDigest, plan.SpecDigest)
	}
	if !plan.Executable {
		return *run, fmt.Errorf("persisted bootstrap request is no longer executable: %s", strings.Join(plan.Blockers, "; "))
	}
	if currentBundleDigest != run.BundleDigest {
		return *run, fmt.Errorf("appliance bundle changed after bootstrap was accepted: accepted %s observed %s", run.BundleDigest, currentBundleDigest)
	}
	// Persist the exact normalized request used by the planner before any resumed
	// side effect. This keeps Plan, Preflight, Resume, and execution on one SoT.
	run.Request = plan.EffectiveRequest
	if err = r.journal.Save(*run); err != nil {
		return *run, err
	}
	if !bootstrapStepSucceeded(*run, "preflight") {
		if err = r.prepareCloneSafety(ctx, run.Request); err != nil {
			return *run, fmt.Errorf("prepare cloned host identity: %w", err)
		}
		if err = r.prepareTimeSynchronization(ctx, run.Request.Connectivity); err != nil {
			return *run, err
		}
		if err = r.prepareHAPeerTimeSynchronization(ctx, run.Request); err != nil {
			return *run, err
		}
		preflight, preflightErr := r.preflightUnlocked(ctx, run.Request)
		if preflightErr != nil {
			return *run, preflightErr
		}
		if !preflight.Passed() {
			return *run, fmt.Errorf("appliance preflight is blocked; inspect report %s", preflight.ID)
		}
		run.PreflightDigest = preflight.Digest
		for i := range run.Steps {
			if run.Steps[i].Key != "preflight" || run.Steps[i].State == StepSucceeded {
				continue
			}
			finished := r.now().UTC()
			run.Steps[i].State = StepSucceeded
			run.Steps[i].Error = ""
			run.Steps[i].FinishedAt = &finished
			run.UpdatedAt = finished
			break
		}
		if err = r.journal.Save(*run); err != nil {
			return *run, err
		}
	} else if strings.TrimSpace(run.PreflightDigest) == "" {
		return *run, fmt.Errorf("persisted successful preflight is missing its evidence digest")
	}
	if err = r.reconcileInterruptedBootstrapStep(ctx, run); err != nil {
		return *run, err
	}
	return r.executeUnlocked(ctx, *run)
}

func (r *Runner) reconcileInterruptedBootstrapStep(ctx context.Context, run *Run) error {
	interrupted := -1
	for i := range run.Steps {
		step := run.Steps[i]
		if step.State == StepRunning || (step.State == StepFailed && strings.HasPrefix(step.Error, interruptedOutcomePrefix)) {
			if interrupted >= 0 {
				return fmt.Errorf("bootstrap journal has multiple interrupted steps: %s and %s", run.Steps[interrupted].Key, step.Key)
			}
			interrupted = i
		}
	}
	if interrupted < 0 {
		return nil
	}
	step := &run.Steps[interrupted]
	policy, known := bootstrapInterruptedPolicies[step.Key]
	if !known {
		return r.persistInterruptedOutcome(run, interrupted, fmt.Errorf("bootstrap step %s has no interrupted-execution recovery policy", step.Key))
	}
	switch policy {
	case interruptedReplaySafe:
		// Every replayable mutating step is explicitly owner-classified here.
		// Unknown future steps fail closed instead of inheriting replay authority.
		step.State = StepFailed
		step.Error = "interrupted execution detected; owner policy permits idempotent reconciliation replay"
		step.FinishedAt = nil
		run.State = RunFailed
		run.LastError = step.Key + ": interrupted execution will be reconciled by its idempotent owner step"
		run.UpdatedAt = r.now().UTC()
		return r.journal.Save(*run)
	case interruptedVerifyRKE2:
		if err := r.reconcileInterruptedRKE2(ctx, *run); err != nil {
			return r.persistInterruptedOutcome(run, interrupted, err)
		}
	case interruptedReconcileGit:
		recovered, err := r.reconcileInterruptedPublishedRevision(ctx, *run)
		if err != nil {
			return r.persistInterruptedOutcome(run, interrupted, err)
		}
		if !recovered {
			return r.persistInterruptedOutcome(run, interrupted, errors.New("published revision outcome is not present in durable Git authority; automatic republish is forbidden"))
		}
	default:
		return r.persistInterruptedOutcome(run, interrupted, fmt.Errorf("unsupported interrupted recovery policy %q", policy))
	}
	now := r.now().UTC()
	step.State = StepSucceeded
	step.Error = ""
	step.FinishedAt = &now
	run.State = RunRunning
	run.LastError = ""
	run.UpdatedAt = now
	return r.journal.Save(*run)
}

func (r *Runner) persistInterruptedOutcome(run *Run, index int, cause error) error {
	now := r.now().UTC()
	run.Steps[index].State = StepFailed
	run.Steps[index].Error = interruptedOutcomePrefix + cause.Error()
	run.Steps[index].FinishedAt = &now
	run.State = RunFailed
	run.LastError = run.Steps[index].Key + ": " + run.Steps[index].Error
	run.UpdatedAt = now
	if err := r.journal.Save(*run); err != nil {
		return fmt.Errorf("%w; persist interrupted bootstrap state: %v", cause, err)
	}
	return fmt.Errorf("%s", run.LastError)
}

func (r *Runner) reconcileInterruptedRKE2(ctx context.Context, run Run) error {
	if !r.system.Exists("/etc/rancher/rke2/rke2.yaml") {
		return errors.New("RKE2 kubeconfig is absent; install outcome is uncertain and installer replay is forbidden")
	}
	if err := r.system.Run(ctx, "systemctl", []string{"is-active", "--quiet", "rke2-server"}, nil); err != nil {
		return fmt.Errorf("RKE2 service is not provably active: %w", err)
	}
	if run.Request.ProfileID == "production-standard-ha" {
		if err := r.verifyHAQuorum(ctx, run); err != nil {
			return fmt.Errorf("RKE2 HA install outcome is not a proven three-node Ready quorum: %w", err)
		}
	}
	return nil
}

func bootstrapStepSucceeded(run Run, key string) bool {
	for _, step := range run.Steps {
		if step.Key == key {
			return step.State == StepSucceeded
		}
	}
	return false
}

func (r *Runner) beginExecution() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active {
		return fmt.Errorf("a bootstrap execution is already active")
	}
	r.active = true
	return nil
}

func (r *Runner) endExecution() {
	r.mu.Lock()
	r.active = false
	r.mu.Unlock()
}

func (r *Runner) PlanUnlocked(request installation.InstallRequest) (installation.InstallationPlan, string, error) {
	plan, err := installation.CreateBootstrapPlan(request)
	if err != nil {
		return installation.InstallationPlan{}, "", err
	}
	admission, bundleErr := InspectBundle(r.bundleDir, r.requireBundleLock)
	bundleDigest := admission.BundleDigest
	if bundleErr != nil {
		plan.Blockers = append(plan.Blockers, bundleErr.Error())
		plan.Status = "planning-only"
		plan.Executable = false
	}
	return plan, bundleDigest, nil
}

func (r *Runner) executeUnlocked(ctx context.Context, run Run) (Run, error) {
	run.State = RunRunning
	run.LastError = ""
	run.UpdatedAt = r.now().UTC()
	if err := r.journal.Save(run); err != nil {
		return run, err
	}
	for index := range run.Steps {
		if run.Steps[index].State == StepSucceeded || run.Steps[index].State == StepSkipped {
			continue
		}
		started := r.now().UTC()
		run.Steps[index].State = StepRunning
		run.Steps[index].Attempt++
		run.Steps[index].StartedAt = &started
		run.Steps[index].Error = ""
		run.UpdatedAt = started
		if err := r.journal.Save(run); err != nil {
			return run, err
		}
		err := r.executeStep(ctx, run.Steps[index].Key, run)
		finished := r.now().UTC()
		run.Steps[index].FinishedAt = &finished
		run.UpdatedAt = finished
		if err != nil {
			run.Steps[index].State = StepFailed
			run.Steps[index].Error = err.Error()
			run.State = RunFailed
			run.LastError = fmt.Sprintf("%s: %v", run.Steps[index].Key, err)
			if saveErr := r.journal.Save(run); saveErr != nil {
				return run, fmt.Errorf("%w; persist failed bootstrap state: %v", err, saveErr)
			}
			return run, err
		}
		run.Steps[index].State = StepSucceeded
		if err := r.journal.Save(run); err != nil {
			return run, err
		}
	}
	run.State = RunSucceeded
	run.UpdatedAt = r.now().UTC()
	if err := r.journal.Save(run); err != nil {
		return run, err
	}
	return run, nil
}

func (r *Runner) executeStep(ctx context.Context, key string, run Run) error {
	admission, err := InspectBundleForMilestone(r.bundleDir, r.requireBundleLock, run.Request.ExecutionMilestone)
	if err != nil {
		return err
	}
	if admission.BundleDigest != run.BundleDigest {
		return fmt.Errorf("appliance bundle changed after plan: planned %s observed %s", run.BundleDigest, admission.BundleDigest)
	}
	bundle, _, err := LoadBundleForMilestone(r.bundleDir, run.Request.ExecutionMilestone)
	if err != nil {
		return err
	}
	switch key {
	case "preflight":
		return r.preflight(ctx, run, bundle)
	case "prepare-host":
		return r.prepareHost(run)
	case "stage-bundle":
		return r.stageBundle(bundle)
	case "configure-rke2":
		return r.configureRKE2(run)
	case "install-rke2":
		return r.installRKE2(ctx, run)
	case "verify-ha-quorum":
		return r.verifyHAQuorum(ctx, run)
	case "prepare-storage-devices":
		return r.prepareHAStorageDevices(ctx, run)
	case "deploy-replicated-storage":
		return r.deployReplicatedStorage(ctx, run, bundle)
	case "deploy-postgresql-operator":
		return r.deployPostgreSQLOperator(ctx, run, bundle)
	case "deploy-foundation":
		return r.deployFoundation(ctx, run, bundle)
	case "deploy-internal-git":
		return r.deployInternalGit(ctx, run, bundle)
	case "deploy-oci-registry":
		return r.deployOCIRegistry(ctx, run, bundle)
	case "seed-offline-registry":
		return r.verifyOfflineImages(ctx, run, bundle)
	case "deploy-identity":
		return r.deployIdentity(ctx, run, bundle)
	case "configure-secure-exposure":
		return r.configureSecureExposure(ctx, run)
	case "bootstrap-repository":
		return r.bootstrapRepository(ctx, run, bundle)
	case "deploy-gitops-controller":
		return r.deployGitOpsController(ctx, run, bundle)
	case "publish-signed-revision":
		return r.publishSignedRevision(ctx, run, bundle)
	case "verify-gitops-handover":
		return r.verifyGitOpsHandover(ctx)
	case "deploy-fleet-hub":
		return r.deployFleetHub(ctx, bundle)
	case "verify-fleet-hub":
		return r.verifyFleetHub(ctx)
	case "configure-off-node-backup":
		return r.configureOffNodeBackup(ctx, run, bundle)
	case "verify-off-node-backup":
		return r.verifyOffNodeBackup(ctx, run, bundle)
	case "verify-embedded-services":
		return r.verifyEmbeddedServices(ctx, bundle)
	case "verify-runtime":
		return r.verifyRuntime(ctx, bundle, run.ID)
	case "verify-ha-services":
		return r.verifyHAServices(ctx, run)
	case "revoke-bootstrap-credential":
		return r.revokeBootstrapCredential(ctx, run.ID)
	default:
		return fmt.Errorf("unknown bootstrap step %q", key)
	}
}

const (
	bootstrapObjectOwnerAnnotation = "platform.4so.io/bootstrap-owner"
	bootstrapObjectOwnerValue      = "4so-platform-installer"
	bootstrapRestartAnnotation     = "platform.4so.io/bootstrap-restart"
)

type bootstrapObjectIdentity struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
	UID  string `json:"uid"`
}

type bootstrapObjectSnapshot struct {
	Metadata struct {
		UID             string            `json:"uid"`
		ResourceVersion string            `json:"resourceVersion"`
		Annotations     map[string]string `json:"annotations"`
	} `json:"metadata"`
	Spec struct {
		Template struct {
			Metadata struct {
				Annotations map[string]string `json:"annotations"`
			} `json:"metadata"`
			Spec struct {
				Containers []struct {
					Name string `json:"name"`
					Env  []struct {
						Name string `json:"name"`
					} `json:"env"`
				} `json:"containers"`
			} `json:"spec"`
		} `json:"template"`
	} `json:"spec"`
	Data map[string]string `json:"data"`
}

func (r *Runner) bootstrapObjectIdentityPath(runID, kind, name string) string {
	return filepath.Join(r.stateDir, "bootstrap-object-identities", runID, kind+"-"+name+".json")
}

func (r *Runner) bootstrapObjectIdentityExists(runID, kind, name string) (bool, error) {
	path := r.bootstrapObjectIdentityPath(runID, kind, name)
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, fmt.Errorf("inspect durable bootstrap object identity: %w", err)
}

func (r *Runner) verifyFoundationMaterializationBoundary(ctx context.Context, runID string) error {
	deploymentBound, err := r.bootstrapObjectIdentityExists(runID, "deployment", "platform-api")
	if err != nil {
		return err
	}
	secretBound, err := r.bootstrapObjectIdentityExists(runID, "secret", "platform-internal-services")
	if err != nil {
		return err
	}
	if deploymentBound != secretBound {
		return errors.New("foundation materialization has only a partial durable object identity set; automatic replay is forbidden")
	}
	if deploymentBound {
		if _, err = r.bindBootstrapObject(ctx, runID, "deployment", "platform-api"); err != nil {
			return fmt.Errorf("verify previously materialized platform-api identity: %w", err)
		}
		if _, err = r.bindBootstrapObject(ctx, runID, "secret", "platform-internal-services"); err != nil {
			return fmt.Errorf("verify previously materialized platform-internal-services identity: %w", err)
		}
		return nil
	}

	// The first foundation materialization is only valid in a namespace that does
	// not already exist. This prevents RKE2's static-manifest controller from
	// silently applying our ownership marker onto a pre-existing same-name
	// resource and turning a foreign object into an apparent first-bind owner.
	kubectl := "/var/lib/rancher/rke2/bin/kubectl"
	raw, err := r.system.Output(ctx, kubectl, []string{"--kubeconfig", "/etc/rancher/rke2/rke2.yaml", "get", "namespace/platform-system", "--ignore-not-found", "-o", "name"}, nil)
	if err != nil {
		return fmt.Errorf("inspect foundation namespace before first materialization: %w", err)
	}
	if strings.TrimSpace(string(raw)) != "" {
		return errors.New("platform-system already exists before first foundation materialization; refusing implicit adoption")
	}
	return nil
}

func (r *Runner) bindBootstrapObject(ctx context.Context, runID, kind, name string) (bootstrapObjectSnapshot, error) {
	var snapshot bootstrapObjectSnapshot
	if strings.TrimSpace(runID) == "" || strings.ContainsAny(runID, `/\`) {
		return snapshot, errors.New("bootstrap run identity is unsafe for durable object fencing")
	}
	kubectl := "/var/lib/rancher/rke2/bin/kubectl"
	args := []string{"--kubeconfig", "/etc/rancher/rke2/rke2.yaml", "-n", "platform-system", "get", kind + "/" + name, "-o", "json"}
	raw, err := r.system.Output(ctx, kubectl, args, nil)
	if err != nil {
		return snapshot, fmt.Errorf("inspect bootstrap-owned %s/%s: %w", kind, name, err)
	}
	if err = json.Unmarshal(raw, &snapshot); err != nil {
		return snapshot, fmt.Errorf("decode bootstrap-owned %s/%s: %w", kind, name, err)
	}
	if strings.TrimSpace(snapshot.Metadata.UID) == "" || strings.TrimSpace(snapshot.Metadata.ResourceVersion) == "" {
		return snapshot, fmt.Errorf("bootstrap-owned %s/%s is missing UID/resourceVersion", kind, name)
	}
	if snapshot.Metadata.Annotations[bootstrapObjectOwnerAnnotation] != bootstrapObjectOwnerValue {
		return snapshot, fmt.Errorf("bootstrap-owned %s/%s is missing product ownership annotation; refusing first-bind adoption", kind, name)
	}
	path := r.bootstrapObjectIdentityPath(runID, kind, name)
	storedRaw, readErr := os.ReadFile(path)
	if readErr == nil {
		var stored bootstrapObjectIdentity
		if err = json.Unmarshal(storedRaw, &stored); err != nil {
			return snapshot, fmt.Errorf("decode durable bootstrap object identity: %w", err)
		}
		if stored.Kind != kind || stored.Name != name || stored.UID != snapshot.Metadata.UID {
			return snapshot, fmt.Errorf("bootstrap-owned %s/%s UID changed from %s to %s; refusing same-name replacement", kind, name, stored.UID, snapshot.Metadata.UID)
		}
		return snapshot, nil
	}
	if !os.IsNotExist(readErr) {
		return snapshot, fmt.Errorf("read durable bootstrap object identity: %w", readErr)
	}
	stored := bootstrapObjectIdentity{Kind: kind, Name: name, UID: snapshot.Metadata.UID}
	encoded, _ := json.MarshalIndent(stored, "", "  ")
	if err = durablefile.Replace(path, append(encoded, '\n'), 0o700, 0o600); err != nil {
		return snapshot, fmt.Errorf("persist bootstrap object UID before mutation: %w", err)
	}
	return snapshot, nil
}

const (
	foundationManifestPath = "/var/lib/rancher/rke2/server/manifests/4so-platform-foundation.yaml"
	bootstrapCredentialRevokedPath = "/var/lib/4so-platform-installer/bootstrap-credential.revoked"
	bootstrapCredentialRevokedAuthority = "INSTALLER_BOOTSTRAP_CREDENTIAL_REVOKED_V1"
)

func (r *Runner) persistBootstrapCredentialRevocationTombstone() error {
	if err := r.system.WriteFile(bootstrapCredentialRevokedPath, []byte(bootstrapCredentialRevokedAuthority+"\n"), 0o600); err != nil {
		return fmt.Errorf("persist bootstrap credential revocation tombstone: %w", err)
	}
	return nil
}

func sanitizeBootstrapCredentialManifest(raw []byte) ([]byte, error) {
	text := string(raw)
	for _, block := range []string{
		`            - name: PLATFORM_FACTORY_BOOTSTRAP_TOKEN
              valueFrom:
                secretKeyRef:
                  name: platform-internal-services
                  key: bootstrap-token
`,
		`            - name: PLATFORM_FACTORY_BOOTSTRAP_TOKEN
              valueFrom: {secretKeyRef: {name: platform-internal-services, key: bootstrap-token}}
`,
	} {
		text = strings.ReplaceAll(text, block, "")
	}
	lines := strings.Split(text, "\n")
	filtered := lines[:0]
	for _, line := range lines {
		if strings.HasPrefix(line, "  bootstrap-token:") {
			continue
		}
		filtered = append(filtered, line)
	}
	text = strings.Join(filtered, "\n")
	if strings.Contains(text, "PLATFORM_FACTORY_BOOTSTRAP_TOKEN") || strings.Contains(text, "bootstrap-token") {
		return nil, errors.New("foundation manifest still contains bootstrap credential material after sanitization")
	}
	if strings.TrimSpace(text) == "" {
		return nil, errors.New("foundation manifest became empty while revoking bootstrap credential")
	}
	return []byte(text), nil
}

func (r *Runner) persistBootstrapCredentialRevocation() error {
	raw, err := r.readFile(foundationManifestPath)
	if err != nil {
		return fmt.Errorf("read authoritative foundation manifest before bootstrap credential revocation: %w", err)
	}
	sanitized, err := sanitizeBootstrapCredentialManifest(raw)
	if err != nil {
		return err
	}
	if err = r.system.WriteFile(foundationManifestPath, sanitized, 0o600); err != nil {
		return fmt.Errorf("persist bootstrap credential revocation in authoritative foundation manifest: %w", err)
	}
	return nil
}

func (r *Runner) revokeBootstrapCredential(ctx context.Context, runID string) error {
	if r.simulation {
		return r.persistBootstrapCredentialRevocationTombstone()
	}
	// Remove the credential from the durable RKE2 desired-state source before
	// mutating live objects. Otherwise a reboot/reconciliation can resurrect a
	// credential that the live API objects already report as revoked.
	if err := r.persistBootstrapCredentialRevocation(); err != nil {
		return err
	}
	kubectl := "/var/lib/rancher/rke2/bin/kubectl"
	kc := "/etc/rancher/rke2/rke2.yaml"
	args := []string{"--kubeconfig", kc, "-n", "platform-system"}
	deployment, err := r.bindBootstrapObject(ctx, runID, "deployment", "platform-api")
	if err != nil {
		return err
	}
	containerIndex, envIndex := -1, -1
	for i, container := range deployment.Spec.Template.Spec.Containers {
		if container.Name != "api" {
			continue
		}
		containerIndex = i
		for j, env := range container.Env {
			if env.Name == "PLATFORM_FACTORY_BOOTSTRAP_TOKEN" {
				envIndex = j
				break
			}
		}
		break
	}
	if containerIndex < 0 {
		return errors.New("platform-api container is missing while revoking bootstrap credential")
	}
	if envIndex >= 0 {
		patchOps := []map[string]any{
			{"op": "test", "path": "/metadata/uid", "value": deployment.Metadata.UID},
			{"op": "test", "path": "/metadata/resourceVersion", "value": deployment.Metadata.ResourceVersion},
			{"op": "test", "path": fmt.Sprintf("/spec/template/spec/containers/%d/name", containerIndex), "value": "api"},
			{"op": "test", "path": fmt.Sprintf("/spec/template/spec/containers/%d/env/%d/name", containerIndex, envIndex), "value": "PLATFORM_FACTORY_BOOTSTRAP_TOKEN"},
			{"op": "remove", "path": fmt.Sprintf("/spec/template/spec/containers/%d/env/%d", containerIndex, envIndex)},
		}
		patchRaw, _ := json.Marshal(patchOps)
		if err = r.system.Run(ctx, kubectl, append(append([]string{}, args...), "patch", "deployment/platform-api", "--type=json", "-p", string(patchRaw)), nil); err != nil {
			return fmt.Errorf("remove bootstrap token from API deployment: %w", err)
		}
	}
	secret, err := r.bindBootstrapObject(ctx, runID, "secret", "platform-internal-services")
	if err != nil {
		return err
	}
	if _, present := secret.Data["bootstrap-token"]; present {
		patchOps := []map[string]any{
			{"op": "test", "path": "/metadata/uid", "value": secret.Metadata.UID},
			{"op": "test", "path": "/metadata/resourceVersion", "value": secret.Metadata.ResourceVersion},
			{"op": "remove", "path": "/data/bootstrap-token"},
		}
		patchRaw, _ := json.Marshal(patchOps)
		if err = r.system.Run(ctx, kubectl, append(append([]string{}, args...), "patch", "secret/platform-internal-services", "--type=json", "-p", string(patchRaw)), nil); err != nil {
			return fmt.Errorf("remove bootstrap token from Secret: %w", err)
		}
	}
	verifiedSecret, err := r.bindBootstrapObject(ctx, runID, "secret", "platform-internal-services")
	if err != nil {
		return err
	}
	if _, present := verifiedSecret.Data["bootstrap-token"]; present {
		return errors.New("bootstrap token remains configured in platform-internal-services")
	}
	if err = r.system.Run(ctx, kubectl, append(append([]string{}, args...), "rollout", "status", "deployment/platform-api", "--timeout=10m"), nil); err != nil {
		return fmt.Errorf("wait for bootstrap credential revocation rollout: %w", err)
	}
	verified, err := r.bindBootstrapObject(ctx, runID, "deployment", "platform-api")
	if err != nil {
		return err
	}
	for _, container := range verified.Spec.Template.Spec.Containers {
		if container.Name == "api" {
			for _, env := range container.Env {
				if env.Name == "PLATFORM_FACTORY_BOOTSTRAP_TOKEN" {
					return fmt.Errorf("bootstrap token remains configured on platform-api")
				}
			}
			if err = r.persistBootstrapCredentialRevocationTombstone(); err != nil {
				return err
			}
			remover, ok := r.system.(interface{ Remove(string) error })
			if !ok {
				return errors.New("bootstrap system does not support removal of revoked credentials")
			}
			if err = remover.Remove("/var/lib/4so-platform-installer/secrets/bootstrap-token"); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("remove revoked bootstrap credential from installer state: %w", err)
			}
			return nil
		}
	}
	return errors.New("platform-api container disappeared while verifying bootstrap credential revocation")
}

func (r *Runner) preflight(ctx context.Context, run Run, _ BundleManifest) error {
	report, err := r.preflightUnlocked(ctx, run.Request)
	if err != nil {
		return err
	}
	if !report.Passed() {
		return fmt.Errorf("appliance preflight is blocked; inspect report %s", report.ID)
	}
	if strings.TrimSpace(run.PreflightDigest) != "" && report.Digest != run.PreflightDigest {
		return fmt.Errorf("appliance preflight changed after execution was accepted: planned %s observed %s", run.PreflightDigest, report.Digest)
	}
	return nil
}

func (r *Runner) prepareHost(run Run) error {
	if r.system.Exists(bootstrapCredentialRevokedPath) {
		return errors.New("bootstrap credential is durably revoked; reset is required before preparing a new installation")
	}
	for path, mode := range map[string]os.FileMode{
		"/etc/rancher/rke2":                             0o700,
		"/var/lib/rancher/rke2/agent/images":            0o700,
		"/var/lib/rancher/rke2/server/manifests":        0o700,
		"/var/lib/4so-platform-installer/bundle/rke2":   0o700,
		"/var/lib/4so-platform-installer/bundle/gitops": 0o700,
		"/var/lib/4so-platform-installer/bundle/fleet":  0o700,
		"/var/lib/4so-platform-installer/secrets":       0o700,
		"/var/lib/4so-platform-installer/backups":       0o700,
		"/var/lib/4so-platform-installer/lifecycle":     0o700,
	} {
		if err := r.system.MkdirAll(path, mode); err != nil {
			return err
		}
	}
	for _, item := range []struct {
		path string
		size int
	}{
		{"/var/lib/4so-platform-installer/secrets/rke2-token", 32},
		{"/var/lib/4so-platform-installer/secrets/postgres-password", 32},
		{"/var/lib/4so-platform-installer/secrets/keycloak-db-password", 32},
		{"/var/lib/4so-platform-installer/secrets/forgejo-db-password", 32},
		{"/var/lib/4so-platform-installer/secrets/forgejo-admin-password", 32},
		{"/var/lib/4so-platform-installer/secrets/identity-admin-password", 32},
		{"/var/lib/4so-platform-installer/secrets/session-secret", 48},
		{"/var/lib/4so-platform-installer/secrets/bootstrap-token", 48},
	} {
		if !r.system.Exists(item.path) {
			value, err := randomSecret(item.size)
			if err != nil {
				return err
			}
			if err = r.system.WriteFile(item.path, []byte(value+"\n"), 0o600); err != nil {
				return err
			}
		}
	}
	if err := ensureTLSMaterial(r.system, run.Request.Network.PublicEndpoint, run.Request.Network.DNSZone, r.tlsKeyGenerator); err != nil {
		return err
	}
	if err := ensureAgentPKI(r.system); err != nil {
		return err
	}
	if err := r.ensureGitOpsSigningKey(); err != nil {
		return err
	}
	if err := r.ensureCatalogSigningKey(); err != nil {
		return err
	}
	requestRaw, _ := json.MarshalIndent(run.Request, "", "  ")
	return r.system.WriteFile("/var/lib/4so-platform-installer/install-request.json", append(requestRaw, '\n'), 0o600)
}

func (r *Runner) stageBundle(bundle BundleManifest) error {
	installerSource, _ := safeBundlePath(r.bundleDir, bundle.Spec.RKE2.Installer.Path)
	if err := r.system.CopyFile(installerSource, "/var/lib/4so-platform-installer/bundle/rke2/install.sh", 0o700); err != nil {
		return err
	}
	for _, artifact := range bundle.Spec.RKE2.InstallArtifacts {
		source, _ := safeBundlePath(r.bundleDir, artifact.Path)
		destination := filepath.Join("/var/lib/4so-platform-installer/bundle/rke2", filepath.Base(artifact.Path))
		if err := r.system.CopyFile(source, destination, 0o600); err != nil {
			return err
		}
	}
	archives := append([]Artifact(nil), bundle.Spec.RKE2.ImageArchives...)
	archives = append(archives, bundle.Spec.Workloads.ImageArchives...)
	for _, artifact := range archives {
		source, _ := safeBundlePath(r.bundleDir, artifact.Path)
		destination := filepath.Join("/var/lib/rancher/rke2/agent/images", filepath.Base(artifact.Path))
		if err := r.system.CopyFile(source, destination, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func (r *Runner) configureRKE2(run Run) error {
	endpoint, err := url.Parse(run.Request.Network.PublicEndpoint)
	if err != nil {
		return err
	}
	accessAddresses := run.Request.Infrastructure.NodeAddresses
	clusterAddresses := effectiveClusterNodeAddresses(run.Request)
	if len(accessAddresses) == 0 || len(clusterAddresses) == 0 {
		return errors.New("RKE2 configuration requires at least one management node address")
	}
	nodeAddress := clusterAddresses[0]
	tokenRaw, err := r.readSecret("/var/lib/4so-platform-installer/secrets/rke2-token")
	if err != nil {
		return err
	}
	config := fmt.Sprintf("write-kubeconfig-mode: \"0600\"\nnode-ip: %s\ntoken: %s\ntls-san:\n  - %s\n  - %s\n  - %s\n", yamlScalar(nodeAddress), yamlScalar(tokenRaw), yamlScalar(endpoint.Hostname()), yamlScalar(accessAddresses[0]), yamlScalar(nodeAddress))
	if run.Request.ProfileID == "production-standard-ha" {
		config += "etcd-expose-metrics: true\n"
		if iface := strings.TrimSpace(run.Request.Infrastructure.ClusterInterface); iface != "" {
			canalConfig := fmt.Sprintf("apiVersion: helm.cattle.io/v1\nkind: HelmChartConfig\nmetadata:\n  name: rke2-canal\n  namespace: kube-system\nspec:\n  valuesContent: |-\n    flannel:\n      iface: %s\n", yamlScalar(iface))
			if err := r.system.WriteFile("/var/lib/rancher/rke2/server/manifests/rke2-canal-config.yaml", []byte(canalConfig), 0o600); err != nil {
				return err
			}
		}
		for index, peer := range accessAddresses[1:] {
			clusterPeer := peer
			if index+1 < len(clusterAddresses) {
				clusterPeer = clusterAddresses[index+1]
			}
			peerConfig := fmt.Sprintf("server: https://%s:9345\nwrite-kubeconfig-mode: \"0600\"\nnode-ip: %s\ntoken: %s\ntls-san:\n  - %s\n  - %s\n  - %s\n", nodeAddress, clusterPeer, yamlScalar(tokenRaw), yamlScalar(endpoint.Hostname()), yamlScalar(peer), yamlScalar(clusterPeer))
			path := filepath.Join(r.stateDir, "ha-nodes", peer, "config.yaml")
			if err := writePrivateFile(path, []byte(peerConfig)); err != nil {
				return err
			}
		}
	}
	return r.system.WriteFile("/etc/rancher/rke2/config.yaml", []byte(config), 0o600)
}

func (r *Runner) installRKE2(ctx context.Context, run Run) error {
	env := map[string]string{
		"INSTALL_RKE2_ARTIFACT_PATH": "/var/lib/4so-platform-installer/bundle/rke2",
		"INSTALL_RKE2_SKIP_DOWNLOAD": "true",
		"INSTALL_RKE2_TYPE":          "server",
	}
	if err := r.system.Run(ctx, "/bin/sh", []string{"/var/lib/4so-platform-installer/bundle/rke2/install.sh"}, env); err != nil {
		return err
	}
	if err := r.system.Run(ctx, "systemctl", []string{"enable", "--now", "rke2-server"}, nil); err != nil {
		return err
	}
	if run.Request.ProfileID == "production-standard-ha" {
		if err := r.joinHAControllerNodes(ctx, run); err != nil {
			return err
		}
	}
	return waitUntil(ctx, 2*time.Second, 5*time.Minute, func() error {
		if !r.system.Exists("/etc/rancher/rke2/rke2.yaml") {
			return fmt.Errorf("RKE2 kubeconfig is not ready")
		}
		return nil
	})
}

func (r *Runner) deployFoundation(ctx context.Context, run Run, bundle BundleManifest) error {
	password, err := r.readSecret("/var/lib/4so-platform-installer/secrets/postgres-password")
	if err != nil {
		return err
	}
	forgejoPassword, err := r.readSecret("/var/lib/4so-platform-installer/secrets/forgejo-admin-password")
	if err != nil {
		return err
	}
	keycloakDBPassword, err := r.readSecret("/var/lib/4so-platform-installer/secrets/keycloak-db-password")
	if err != nil {
		return err
	}
	forgejoDBPassword, err := r.readSecret("/var/lib/4so-platform-installer/secrets/forgejo-db-password")
	if err != nil {
		return err
	}
	identityPassword, err := r.readSecret("/var/lib/4so-platform-installer/secrets/identity-admin-password")
	if err != nil {
		return err
	}
	sessionSecret, err := r.readSecret("/var/lib/4so-platform-installer/secrets/session-secret")
	if err != nil {
		return err
	}
	bootstrapToken, err := r.readSecret("/var/lib/4so-platform-installer/secrets/bootstrap-token")
	if err != nil {
		return err
	}
	catalogSigningKey, err := r.readSecret(catalogSigningKeyPath)
	if err != nil {
		return err
	}
	caPEM, err := r.readFile(tlsCAPath)
	if err != nil {
		return err
	}
	tlsCertPEM, err := r.readFile(tlsCertPath)
	if err != nil {
		return err
	}
	tlsKeyPEM, err := r.readFile(tlsKeyPath)
	if err != nil {
		return err
	}
	agentCAPEM, err := r.readFile(agentCACertPath)
	if err != nil {
		return err
	}
	agentCAKeyPEM, err := r.readFile(agentCAKeyPath)
	if err != nil {
		return err
	}
	manifest := foundationManifest(bundle, password, keycloakDBPassword, forgejoDBPassword, forgejoPassword, identityPassword, sessionSecret, bootstrapToken, catalogSigningKey, caPEM, tlsCertPEM, tlsKeyPEM, agentCAPEM, agentCAKeyPEM, run.Request)
	if !r.simulation {
		if err = r.verifyFoundationMaterializationBoundary(ctx, run.ID); err != nil {
			return err
		}
	}
	if err = r.system.WriteFile("/var/lib/rancher/rke2/server/manifests/4so-platform-foundation.yaml", []byte(manifest), 0o600); err != nil {
		return err
	}
	if r.simulation {
		return nil
	}
	kubectl := "/var/lib/rancher/rke2/bin/kubectl"
	kubeconfig := "/etc/rancher/rke2/rke2.yaml"
	checks := [][]string{{"--kubeconfig", kubeconfig, "-n", "platform-system", "rollout", "status", "deployment/platform-api", "--timeout=10m"}}
	if run.Request.ProfileID == "production-standard-ha" {
		checks = append([][]string{{"--kubeconfig", kubeconfig, "-n", "platform-system", "wait", "--for=condition=Ready", "cluster/platform-postgresql", "--timeout=15m"}}, checks...)
	} else {
		checks = append([][]string{{"--kubeconfig", kubeconfig, "-n", "platform-system", "rollout", "status", "statefulset/platform-postgresql", "--timeout=10m"}}, checks...)
	}
	for _, args := range checks {
		if err = r.system.Run(ctx, kubectl, args, nil); err != nil {
			return err
		}
	}
	if _, err = r.bindBootstrapObject(ctx, run.ID, "deployment", "platform-api"); err != nil {
		return fmt.Errorf("bind materialized platform-api identity: %w", err)
	}
	if _, err = r.bindBootstrapObject(ctx, run.ID, "secret", "platform-internal-services"); err != nil {
		return fmt.Errorf("bind materialized platform-internal-services identity: %w", err)
	}
	return nil
}

func forgejoAdminBootstrapCommand() string {
	return `set -eu
command -v su-exec >/dev/null 2>&1 || { echo "Forgejo image is missing su-exec; refusing root admin CLI execution" >&2; exit 1; }
if su-exec git forgejo admin user list | grep -Eq '(^|[[:space:]])platform-admin([[:space:]]|$)'; then
  su-exec git forgejo admin user change-password --username platform-admin --password "$(cat /run/secrets/platform/admin-password)"
else
  su-exec git forgejo admin user create --admin --username platform-admin --password "$(cat /run/secrets/platform/admin-password)" --email "$(cat /run/secrets/platform/admin-email)" --must-change-password=false
fi`
}

func (r *Runner) deployInternalGit(ctx context.Context, run Run, bundle BundleManifest) error {
	if err := r.waitHADatabase(ctx, run, "platform-forgejo-database"); err != nil {
		return err
	}
	if err := r.reconcileLegacyHAServiceDatabaseOwnership(ctx, run, "forgejo", "forgejo", "platform-forgejo"); err != nil {
		return err
	}
	manifest := forgejoManifest(bundle, run.Request)
	if err := r.system.WriteFile("/var/lib/rancher/rke2/server/manifests/4so-platform-forgejo.yaml", []byte(manifest), 0o600); err != nil {
		return err
	}
	if r.simulation {
		return nil
	}
	kubectl := "/var/lib/rancher/rke2/bin/kubectl"
	kubeconfig := "/etc/rancher/rke2/rke2.yaml"
	if err := r.system.Run(ctx, kubectl, []string{"--kubeconfig", kubeconfig, "-n", "platform-system", "rollout", "status", "statefulset/platform-forgejo", "--timeout=10m"}, nil); err != nil {
		return err
	}
	adminCommand := forgejoAdminBootstrapCommand()
	if err := r.system.Run(ctx, kubectl, []string{"--kubeconfig", kubeconfig, "-n", "platform-system", "exec", "statefulset/platform-forgejo", "--", "/bin/sh", "-ec", adminCommand}, nil); err != nil {
		return fmt.Errorf("initialize Forgejo administrator: %w", err)
	}
	return nil
}

func (r *Runner) deployOCIRegistry(ctx context.Context, run Run, bundle BundleManifest) error {
	manifest := zotManifest(bundle, run.Request)
	if err := r.system.WriteFile("/var/lib/rancher/rke2/server/manifests/4so-platform-zot.yaml", []byte(manifest), 0o600); err != nil {
		return err
	}
	if r.simulation {
		return nil
	}
	kubectl := "/var/lib/rancher/rke2/bin/kubectl"
	kubeconfig := "/etc/rancher/rke2/rke2.yaml"
	return r.system.Run(ctx, kubectl, []string{"--kubeconfig", kubeconfig, "-n", "platform-system", "rollout", "status", "deployment/platform-zot", "--timeout=10m"}, nil)
}

func (r *Runner) verifyEmbeddedServices(ctx context.Context, bundle BundleManifest) error {
	checks := map[string]string{
		"Forgejo":  "http://platform-forgejo:3000/api/v1/version",
		"zot":      "http://platform-zot:5000/v2/",
		"Keycloak": "http://platform-keycloak:8080/realms/platform/.well-known/openid-configuration",
	}
	for name, endpoint := range checks {
		if err := waitUntil(ctx, 2*time.Second, 5*time.Minute, func() error {
			_, probeErr := r.clusterHTTP(ctx, bundle, "GET", endpoint, nil, nil)
			return probeErr
		}); err != nil {
			return fmt.Errorf("%s health verification: %w", name, err)
		}
	}
	bootstrapToken, err := r.readSecret("/var/lib/4so-platform-installer/secrets/bootstrap-token")
	if err != nil {
		return err
	}
	output, err := r.clusterHTTP(ctx, bundle, "GET", "http://platform-api:8080/api/v1/system-services", nil, map[string]string{"X-Platform-Bootstrap-Token": bootstrapToken})
	if err != nil {
		return err
	}
	var statuses []struct {
		Name    string `json:"name"`
		Healthy bool   `json:"healthy"`
	}
	if err = json.Unmarshal(output, &statuses); err != nil {
		return fmt.Errorf("decode system service status: %w", err)
	}
	if len(statuses) != 4 {
		return fmt.Errorf("expected four managed system services, got %d", len(statuses))
	}
	for _, status := range statuses {
		if !status.Healthy {
			return fmt.Errorf("managed service %s is not healthy", status.Name)
		}
	}
	return nil
}

func (r *Runner) restartBootstrapDeployment(ctx context.Context, runID, name string) error {
	deployment, err := r.bindBootstrapObject(ctx, runID, "deployment", name)
	if err != nil {
		return err
	}
	stamp := r.now().UTC().Format(time.RFC3339Nano)
	patchOps := []map[string]any{
		{"op": "test", "path": "/metadata/uid", "value": deployment.Metadata.UID},
		{"op": "test", "path": "/metadata/resourceVersion", "value": deployment.Metadata.ResourceVersion},
		{"op": "test", "path": "/metadata/annotations/platform.4so.io~1bootstrap-owner", "value": bootstrapObjectOwnerValue},
		{"op": "add", "path": "/spec/template/metadata/annotations/platform.4so.io~1bootstrap-restart", "value": stamp},
	}
	patchRaw, _ := json.Marshal(patchOps)
	kubectl := "/var/lib/rancher/rke2/bin/kubectl"
	kubeconfig := "/etc/rancher/rke2/rke2.yaml"
	if err = r.system.Run(ctx, kubectl, []string{"--kubeconfig", kubeconfig, "-n", "platform-system", "patch", "deployment/" + name, "--type=json", "-p", string(patchRaw)}, nil); err != nil {
		return fmt.Errorf("identity-fenced restart of deployment/%s: %w", name, err)
	}
	if err = r.system.Run(ctx, kubectl, []string{"--kubeconfig", kubeconfig, "-n", "platform-system", "rollout", "status", "deployment/" + name, "--timeout=5m"}, nil); err != nil {
		return err
	}
	verified, err := r.bindBootstrapObject(ctx, runID, "deployment", name)
	if err != nil {
		return err
	}
	if verified.Spec.Template.Metadata.Annotations[bootstrapRestartAnnotation] != stamp {
		return fmt.Errorf("deployment/%s restart postcondition drifted before verification", name)
	}
	return nil
}

func (r *Runner) verifyRuntime(ctx context.Context, bundle BundleManifest, runID string) error {
	bootstrapToken, err := r.readSecret("/var/lib/4so-platform-installer/secrets/bootstrap-token")
	if err != nil {
		return err
	}
	headers := map[string]string{"X-Platform-Bootstrap-Token": bootstrapToken, "X-Actor-ID": "bootstrap-installer"}
	if err = waitUntil(ctx, 2*time.Second, 5*time.Minute, func() error {
		_, probeErr := r.clusterHTTP(ctx, bundle, "GET", "http://platform-api:8080/readyz", nil, headers)
		return probeErr
	}); err != nil {
		return err
	}
	exists, err := r.bootstrapOrganizationExists(ctx, bundle, headers)
	if err != nil {
		return err
	}
	if !exists {
		payload := []byte(`{"name":"bootstrap","displayName":"Bootstrap Organization"}`)
		if _, err = r.clusterHTTP(ctx, bundle, "POST", "http://platform-api:8080/api/v1/organizations", payload, map[string]string{"Content-Type": "application/json", "X-Platform-Bootstrap-Token": bootstrapToken, "X-Actor-ID": "bootstrap-installer"}); err != nil {
			return err
		}
	}
	orgID, err := r.bootstrapOrganizationID(ctx, bundle, headers)
	if err != nil {
		return err
	}
	projectExists, err := r.bootstrapProjectExists(ctx, bundle, headers, orgID)
	if err != nil {
		return err
	}
	if !projectExists {
		payload, _ := json.Marshal(map[string]string{"organizationId": orgID, "name": "platform", "displayName": "Platform"})
		if _, err = r.clusterHTTP(ctx, bundle, "POST", "http://platform-api:8080/api/v1/projects", payload, map[string]string{"Content-Type": "application/json", "X-Platform-Bootstrap-Token": bootstrapToken, "X-Actor-ID": "bootstrap-installer"}); err != nil {
			return err
		}
	}
	if err = r.ensureBootstrapOIDCGroupMapping(ctx, bundle, headers); err != nil {
		return err
	}
	if !r.simulation {
		if err = r.restartBootstrapDeployment(ctx, runID, "platform-api"); err != nil {
			return err
		}
	}
	exists, err = r.bootstrapOrganizationExists(ctx, bundle, headers)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("bootstrap organization did not persist after API restart")
	}
	orgID, err = r.bootstrapOrganizationID(ctx, bundle, headers)
	if err != nil {
		return err
	}
	projectExists, err = r.bootstrapProjectExists(ctx, bundle, headers, orgID)
	if err != nil {
		return err
	}
	if !projectExists {
		return fmt.Errorf("bootstrap platform project did not persist after API restart")
	}
	if err = r.ensureBootstrapOIDCGroupMapping(ctx, bundle, headers); err != nil {
		return fmt.Errorf("bootstrap OIDC group mapping did not persist after API restart: %w", err)
	}
	return nil
}

func (r *Runner) ensureBootstrapOIDCGroupMapping(ctx context.Context, bundle BundleManifest, headers map[string]string) error {
	if r.simulation {
		return nil
	}
	out, err := r.clusterHTTP(ctx, bundle, "GET", "http://platform-api:8080/api/v1/identity/group-mappings?state=ACTIVE", nil, headers)
	if err != nil {
		return err
	}
	var mappings []struct {
		Group       string `json:"group"`
		ProductRole string `json:"productRole"`
		State       string `json:"state"`
	}
	if err = json.Unmarshal(out, &mappings); err != nil {
		return fmt.Errorf("decode OIDC group mappings: %w", err)
	}
	for _, m := range mappings {
		if m.Group == "platform-admins" && m.ProductRole == "platform-admin" && m.State == "ACTIVE" {
			return nil
		}
	}
	payload, _ := json.Marshal(map[string]string{"group": "platform-admins", "productRole": "platform-admin"})
	_, err = r.clusterHTTP(ctx, bundle, "POST", "http://platform-api:8080/api/v1/identity/group-mappings", payload, map[string]string{"Content-Type": "application/json", "X-Platform-Bootstrap-Token": headers["X-Platform-Bootstrap-Token"], "X-Actor-ID": "bootstrap-installer"})
	return err
}

func (r *Runner) bootstrapOrganizationID(ctx context.Context, bundle BundleManifest, headers map[string]string) (string, error) {
	output, err := r.clusterHTTP(ctx, bundle, "GET", "http://platform-api:8080/api/v1/organizations", nil, headers)
	if err != nil {
		return "", err
	}
	var organizations []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err = json.Unmarshal(output, &organizations); err != nil {
		return "", fmt.Errorf("decode organization response: %w", err)
	}
	for _, organization := range organizations {
		if organization.Name == "bootstrap" {
			return organization.ID, nil
		}
	}
	if r.simulation {
		return "org_simulated", nil
	}
	return "", fmt.Errorf("bootstrap organization is missing")
}

func (r *Runner) bootstrapProjectExists(ctx context.Context, bundle BundleManifest, headers map[string]string, orgID string) (bool, error) {
	output, err := r.clusterHTTP(ctx, bundle, "GET", "http://platform-api:8080/api/v1/projects?organizationId="+url.QueryEscape(orgID), nil, headers)
	if err != nil {
		return false, err
	}
	var projects []struct {
		Name string `json:"name"`
	}
	if err = json.Unmarshal(output, &projects); err != nil {
		return false, fmt.Errorf("decode project response: %w", err)
	}
	for _, project := range projects {
		if project.Name == "platform" {
			return true, nil
		}
	}
	if r.simulation {
		return true, nil
	}
	return false, nil
}

func (r *Runner) bootstrapOrganizationExists(ctx context.Context, bundle BundleManifest, headers map[string]string) (bool, error) {
	output, err := r.clusterHTTP(ctx, bundle, "GET", "http://platform-api:8080/api/v1/organizations", nil, headers)
	if err != nil {
		return false, err
	}
	var organizations []struct {
		Name string `json:"name"`
	}
	if err = json.Unmarshal(output, &organizations); err != nil {
		return false, fmt.Errorf("decode organization verification response: %w", err)
	}
	for _, organization := range organizations {
		if organization.Name == "bootstrap" {
			return true, nil
		}
	}
	if r.simulation {
		return true, nil
	}
	return false, nil
}

func (r *Runner) readFile(path string) ([]byte, error) {
	if mapped, ok := r.system.(interface{ path(string) string }); ok {
		return os.ReadFile(mapped.path(path))
	}
	return os.ReadFile(path)
}

func (r *Runner) readSecret(path string) (string, error) {
	if mapped, ok := r.system.(interface{ path(string) string }); ok {
		raw, err := os.ReadFile(mapped.path(path))
		return strings.TrimSpace(string(raw)), err
	}
	raw, err := os.ReadFile(path)
	return strings.TrimSpace(string(raw)), err
}

func randomSecret(bytes int) (string, error) {
	raw := make([]byte, bytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func yamlScalar(value string) string {
	return strconv.Quote(value)
}

func waitUntil(ctx context.Context, interval, timeout time.Duration, check func() error) error {
	deadlineCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var last error
	for {
		if err := check(); err == nil {
			return nil
		} else {
			last = err
		}
		timer := time.NewTimer(interval)
		select {
		case <-deadlineCtx.Done():
			timer.Stop()
			return fmt.Errorf("timeout: %w", last)
		case <-timer.C:
		}
	}
}

func foundationManifest(bundle BundleManifest, password, keycloakDBPassword, forgejoDBPassword, forgejoPassword, identityPassword, sessionSecret, bootstrapToken, catalogSigningKey string, caPEM, tlsCertPEM, tlsKeyPEM, agentCAPEM, agentCAKeyPEM []byte, request installation.InstallRequest) string {
	if request.ProfileID == "production-standard-ha" {
		return foundationManifestHA(bundle, password, keycloakDBPassword, forgejoDBPassword, forgejoPassword, identityPassword, sessionSecret, bootstrapToken, catalogSigningKey, caPEM, tlsCertPEM, tlsKeyPEM, agentCAPEM, agentCAKeyPEM, request)
	}
	encodedPassword := base64.StdEncoding.EncodeToString([]byte(password))
	dsn := fmt.Sprintf("postgresql://platform:%s@platform-postgresql:5432/platform_factory?sslmode=disable", url.QueryEscape(password))
	encodedDSN := base64.StdEncoding.EncodeToString([]byte(dsn))
	encodedForgejoPassword := base64.StdEncoding.EncodeToString([]byte(forgejoPassword))
	encodedIdentityPassword := base64.StdEncoding.EncodeToString([]byte(identityPassword))
	encodedAdminEmail := base64.StdEncoding.EncodeToString([]byte(request.Services.Identity.AdminEmail))
	encodedSession := base64.StdEncoding.EncodeToString([]byte(sessionSecret))
	encodedBootstrap := base64.StdEncoding.EncodeToString([]byte(bootstrapToken))
	encodedCatalogSigningKey := base64.StdEncoding.EncodeToString([]byte(catalogSigningKey))
	encodedCA := base64.StdEncoding.EncodeToString(caPEM)
	encodedTLSCert := base64.StdEncoding.EncodeToString(tlsCertPEM)
	encodedTLSKey := base64.StdEncoding.EncodeToString(tlsKeyPEM)
	encodedAgentCA := base64.StdEncoding.EncodeToString(agentCAPEM)
	encodedAgentCAKey := base64.StdEncoding.EncodeToString(agentCAKeyPEM)
	agentPublicURL := "https://agent." + strings.TrimSpace(request.Network.DNSZone)
	issuer := "https://auth." + request.Network.DNSZone + "/realms/platform"
	redirect := strings.TrimRight(request.Network.PublicEndpoint, "/") + "/auth/callback"
	return fmt.Sprintf(`apiVersion: v1
kind: Namespace
metadata:
  name: platform-system
---
apiVersion: v1
kind: Secret
metadata:
  name: platform-database
  namespace: platform-system
type: Opaque
data:
  password: %s
  dsn: %s
---
apiVersion: v1
kind: Secret
metadata:
  name: platform-internal-services
  namespace: platform-system
  annotations:
    platform.4so.io/bootstrap-owner: "4so-platform-installer"
type: Opaque
data:
  forgejo-admin-password: %s
  identity-admin-password: %s
  identity-admin-email: %s
  session-secret: %s
  bootstrap-token: %s
  catalog-signing-key: %s
---
apiVersion: v1
kind: Secret
metadata:
  name: platform-agent-mtls
  namespace: platform-system
type: Opaque
data:
  client-ca.crt: %s
  client-ca.key: %s
  tls.crt: %s
  tls.key: %s
---
apiVersion: v1
kind: Service
metadata:
  name: platform-postgresql
  namespace: platform-system
spec:
  selector:
    app: platform-postgresql
  ports:
    - name: postgresql
      port: 5432
      targetPort: 5432
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: platform-postgresql
  namespace: platform-system
spec:
  serviceName: platform-postgresql
  replicas: 1
  selector:
    matchLabels:
      app: platform-postgresql
  template:
    metadata:
      labels:
        app: platform-postgresql
    spec:
      containers:
        - name: postgresql
          image: %s
          imagePullPolicy: IfNotPresent
          env:
            - name: POSTGRES_USER
              value: platform
            - name: POSTGRES_DB
              value: platform_factory
            - name: POSTGRES_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: platform-database
                  key: password
          ports:
            - containerPort: 5432
          readinessProbe:
            exec:
              command: ["pg_isready", "-U", "platform", "-d", "platform_factory"]
            initialDelaySeconds: 5
            periodSeconds: 5
          volumeMounts:
            - name: data
              mountPath: /var/lib/postgresql/data
  volumeClaimTemplates:
    - metadata:
        name: data
      spec:
        accessModes: ["ReadWriteOnce"]
        storageClassName: local-path
        resources:
          requests:
            storage: 20Gi
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: platform-api
  namespace: platform-system
  annotations:
    platform.4so.io/bootstrap-owner: "4so-platform-installer"
spec:
  replicas: 1
  selector:
    matchLabels:
      app: platform-api
  template:
    metadata:
      labels:
        app: platform-api
      annotations:
        platform.4so.io/bootstrap-restart: "initial"
    spec:
      terminationGracePeriodSeconds: 75
      containers:
        - name: api
          image: %s
          imagePullPolicy: IfNotPresent
          env:
            - name: PLATFORM_FACTORY_LISTEN
              value: 0.0.0.0:8080
            - {name: PLATFORM_FACTORY_SOURCE_RELEASE_DIGEST, value: %s}
            - name: PLATFORM_FACTORY_POSTGRES_DSN
              valueFrom:
                secretKeyRef:
                  name: platform-database
                  key: dsn
            - {name: PLATFORM_FACTORY_POSTGRES_MIGRATION_MODE, value: "rolling"}
            - name: PLATFORM_FACTORY_POSTGRES_MAX_OPEN_CONNS
              value: "20"
            - name: PLATFORM_FACTORY_POSTGRES_MAX_IDLE_CONNS
              value: "5"
            - name: PLATFORM_FACTORY_INTERNAL_GIT_URL
              value: http://platform-forgejo:3000
            - name: PLATFORM_FACTORY_INTERNAL_GIT_USERNAME
              value: platform-admin
            - name: PLATFORM_FACTORY_INTERNAL_GIT_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: platform-internal-services
                  key: forgejo-admin-password
            - name: PLATFORM_FACTORY_INTERNAL_GIT_BOOTSTRAP
              value: "true"
            - name: PLATFORM_FACTORY_INTERNAL_REGISTRY_URL
              value: http://platform-zot:5000
            - name: PLATFORM_FACTORY_INTERNAL_IDENTITY_URL
              value: http://platform-keycloak:8080
            - name: PLATFORM_FACTORY_INTERNAL_GITOPS_URL
              value: http://argocd-server.platform-gitops.svc.cluster.local
            - name: PLATFORM_FACTORY_INTERNAL_GITOPS_TOKEN
              valueFrom:
                secretKeyRef:
                  name: platform-internal-services
                  key: argocd-observer-token
                  optional: true
            - name: PLATFORM_FACTORY_OIDC_ENABLED
              value: "true"
            - name: PLATFORM_FACTORY_OIDC_ISSUER
              value: %s
            - name: PLATFORM_FACTORY_OIDC_INTERNAL_BASE
              value: http://platform-keycloak:8080
            - name: PLATFORM_FACTORY_OIDC_CLIENT_ID
              value: platform-console
            - name: PLATFORM_FACTORY_OIDC_REDIRECT_URL
              value: %s
            - name: PLATFORM_FACTORY_SESSION_SECRET
              valueFrom:
                secretKeyRef:
                  name: platform-internal-services
                  key: session-secret
            - name: PLATFORM_FACTORY_BOOTSTRAP_TOKEN
              valueFrom:
                secretKeyRef:
                  name: platform-internal-services
                  key: bootstrap-token
            - name: PLATFORM_FACTORY_CATALOG_SIGNING_PRIVATE_KEY_B64
              valueFrom:
                secretKeyRef:
                  name: platform-internal-services
                  key: catalog-signing-key
            - name: PLATFORM_FACTORY_FLEET_AGENT_IMAGE
              value: %s
            - name: PLATFORM_FACTORY_RUNTIME_PROBE_IMAGE
              value: %s
            - name: PLATFORM_FACTORY_PUBLIC_URL
              value: %s
            - name: PLATFORM_FACTORY_AGENT_PUBLIC_URL
              value: %s
            - name: PLATFORM_FACTORY_PUBLIC_CA_PEM_B64
              value: %s
            - name: PLATFORM_FACTORY_AGENT_MTLS_REQUIRED
              value: "true"
            - name: PLATFORM_FACTORY_AGENT_LISTEN
              value: "0.0.0.0:8443"
            - name: PLATFORM_FACTORY_AGENT_CA_CERT_FILE
              value: /etc/4so-agent-mtls/client-ca.crt
            - name: PLATFORM_FACTORY_AGENT_CA_KEY_FILE
              value: /etc/4so-agent-mtls/client-ca.key
            - name: PLATFORM_FACTORY_AGENT_TLS_CERT_FILE
              value: /etc/4so-agent-mtls/tls.crt
            - name: PLATFORM_FACTORY_AGENT_TLS_KEY_FILE
              value: /etc/4so-agent-mtls/tls.key
          ports:
            - containerPort: 8080
            - containerPort: 8443
          resources:
            requests:
              cpu: 250m
              memory: 256Mi
            limits:
              cpu: "2"
              memory: 1Gi
          volumeMounts:
            - name: agent-mtls
              mountPath: /etc/4so-agent-mtls
              readOnly: true
            - name: identity-admin
              mountPath: /run/secrets/platform
              readOnly: true
          
          readinessProbe:
            httpGet:
              path: /readyz
              port: 8080
            initialDelaySeconds: 5
            periodSeconds: 5
          startupProbe:
            httpGet:
              path: /readyz
              port: 8080
            periodSeconds: 5
            failureThreshold: 24
          livenessProbe:
            httpGet:
              path: /healthz
              port: 8080
            periodSeconds: 15
            timeoutSeconds: 3
            failureThreshold: 4
      volumes:
        - name: agent-mtls
          secret:
            secretName: platform-agent-mtls
            defaultMode: 0400
        - name: identity-admin
          secret:
            secretName: platform-internal-services
            defaultMode: 0400
            items:
              - key: identity-admin-password
                path: identity-admin-password
---
apiVersion: v1
kind: Service
metadata:
  name: platform-api
  namespace: platform-system
spec:
  selector:
    app: platform-api
  ports:
    - name: http
      port: 8080
      targetPort: 8080
    - name: agent-mtls
      port: 8443
      targetPort: 8443
`, encodedPassword, encodedDSN, encodedForgejoPassword, encodedIdentityPassword, encodedAdminEmail, encodedSession, encodedBootstrap, encodedCatalogSigningKey, encodedAgentCA, encodedAgentCAKey, encodedTLSCert, encodedTLSKey, bundle.Spec.Workloads.PostgreSQLImage, bundle.Spec.Workloads.PlatformAPIImage, yamlScalar(bundle.Metadata.SourceReleaseDigest), yamlScalar(issuer), yamlScalar(redirect), yamlScalar(bundle.Spec.Workloads.FleetAgentImage), yamlScalar(bundle.Spec.Workloads.RuntimeProbeImage), yamlScalar(strings.TrimRight(request.Network.PublicEndpoint, "/")), yamlScalar(agentPublicURL), yamlScalar(encodedCA))
}

func forgejoManifest(bundle BundleManifest, request installation.InstallRequest) string {
	rootURL := "https://git." + strings.TrimSpace(request.Network.DNSZone) + "/"
	dbInit := `
      initContainers:
        - name: initialize-database
          image: %s
          imagePullPolicy: IfNotPresent
          env:
            - name: PGPASSWORD
              valueFrom:
                secretKeyRef:
                  name: platform-database
                  key: password
          command: ["/bin/sh", "-ec"]
          args:
            - >-
              until pg_isready -h platform-postgresql -U platform -d postgres; do sleep 2; done;
              psql -h platform-postgresql -U platform -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='forgejo'" | grep -q 1 ||
              createdb -h platform-postgresql -U platform forgejo`
	dbUser := "platform"
	dbSecret := "platform-database"
	if request.ProfileID == "production-standard-ha" {
		dbInit = ""
		dbUser = "forgejo"
		dbSecret = "platform-forgejo-db"
	}
	storageClass := request.Infrastructure.StorageClass
	if storageClass == "" {
		storageClass = "local-path"
	}
	return fmt.Sprintf(`apiVersion: v1
kind: Service
metadata:
  name: platform-forgejo
  namespace: platform-system
spec:
  selector:
    app: platform-forgejo
  ports:
    - name: http
      port: 3000
      targetPort: 3000
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: platform-forgejo
  namespace: platform-system
spec:
  serviceName: platform-forgejo
  replicas: 1
  selector:
    matchLabels:
      app: platform-forgejo
  template:
    metadata:
      labels:
        app: platform-forgejo
    spec:%s
      containers:
        - name: forgejo
          image: %s
          imagePullPolicy: IfNotPresent
          env:
            - name: USER_UID
              value: "1000"
            - name: USER_GID
              value: "1000"
            - name: FORGEJO__database__DB_TYPE
              value: postgres
            - name: FORGEJO__database__HOST
              value: platform-postgresql:5432
            - name: FORGEJO__database__NAME
              value: forgejo
            - name: FORGEJO__database__USER
              value: %s
            - name: FORGEJO__database__PASSWD
              valueFrom:
                secretKeyRef:
                  name: %s
                  key: password
            - name: FORGEJO__database__SSL_MODE
              value: disable
            - name: FORGEJO__server__ROOT_URL
              value: %s
            - name: FORGEJO__server__HTTP_PORT
              value: "3000"
            - name: FORGEJO__server__DISABLE_SSH
              value: "true"
            - name: FORGEJO__service__DISABLE_REGISTRATION
              value: "true"
            - name: FORGEJO__security__INSTALL_LOCK
              value: "true"
            - name: FORGEJO__repository__DEFAULT_BRANCH
              value: main
          ports:
            - containerPort: 3000
          readinessProbe:
            httpGet:
              path: /api/v1/version
              port: 3000
            initialDelaySeconds: 10
            periodSeconds: 5
          volumeMounts:
            - name: data
              mountPath: /data
            - name: internal-services
              mountPath: /run/secrets/platform
              readOnly: true
      volumes:
        - name: internal-services
          secret:
            secretName: platform-internal-services
            items:
              - key: forgejo-admin-password
                path: admin-password
              - key: identity-admin-email
                path: admin-email
  volumeClaimTemplates:
    - metadata:
        name: data
      spec:
        accessModes: ["ReadWriteOnce"]
        storageClassName: %s
        resources:
          requests:
            storage: 10Gi
`, fmt.Sprintf(dbInit, bundle.Spec.Workloads.PostgreSQLImage), bundle.Spec.Workloads.ForgejoImage, yamlScalar(dbUser), yamlScalar(dbSecret), yamlScalar(rootURL), yamlScalar(storageClass))
}

func zotManifest(bundle BundleManifest, request installation.InstallRequest) string {
	storageClass := request.Infrastructure.StorageClass
	if storageClass == "" {
		storageClass = "local-path"
	}
	return fmt.Sprintf(`apiVersion: v1
kind: ConfigMap
metadata:
  name: platform-zot-config
  namespace: platform-system
data:
  config.json: |
    {
      "distSpecVersion": "1.1.0",
      "storage": {"rootDirectory": "/var/lib/registry", "commit": true, "dedupe": true, "gc": true},
      "http": {"address": "0.0.0.0", "port": "5000", "compat": ["docker2s2"]},
      "log": {"level": "info"},
      "extensions": {"ui": {"enable": false}}
    }
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: platform-zot-data
  namespace: platform-system
spec:
  accessModes: ["ReadWriteOnce"]
  storageClassName: %s
  resources:
    requests:
      storage: 20Gi
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: platform-zot
  namespace: platform-system
spec:
  replicas: 1
  strategy:
    type: Recreate
  selector:
    matchLabels:
      app: platform-zot
  template:
    metadata:
      labels:
        app: platform-zot
    spec:
      containers:
        - name: zot
          image: %s
          imagePullPolicy: IfNotPresent
          args: ["serve", "/etc/zot/config.json"]
          ports:
            - containerPort: 5000
          readinessProbe:
            httpGet:
              path: /v2/
              port: 5000
            initialDelaySeconds: 5
            periodSeconds: 5
          volumeMounts:
            - name: config
              mountPath: /etc/zot
              readOnly: true
            - name: data
              mountPath: /var/lib/registry
      volumes:
        - name: config
          configMap:
            name: platform-zot-config
        - name: data
          persistentVolumeClaim:
            claimName: platform-zot-data
---
apiVersion: v1
kind: Service
metadata:
  name: platform-zot
  namespace: platform-system
spec:
  selector:
    app: platform-zot
  ports:
    - name: http
      port: 5000
      targetPort: 5000
`, yamlScalar(storageClass), bundle.Spec.Workloads.ZotImage)
}

func runDigest(request installation.InstallRequest) string {
	raw, _ := json.Marshal(request)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// CACertificate returns the bootstrap CA generated for the evaluation Appliance.
func (r *Runner) CACertificate() ([]byte, error) { return r.readFile(tlsCAPath) }
