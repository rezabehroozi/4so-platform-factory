package hostdeployment

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"platform.4so.io/factory/internal/bootstrap"
	"platform.4so.io/factory/internal/installeraccess"
)

const (
	APIVersion           = "platform.4so.io/v1alpha1"
	Kind                 = "InstallerHostDeployment"
	StateKind            = "InstallerHostDeploymentState"
	ConfirmationDeploy   = "DEPLOY"
	ConfirmationRollback = "ROLLBACK"
	ConfirmationRecover  = "RECOVER"
)

type AdmissionPolicy struct {
	AllowDowngrade bool `json:"allowDowngrade"`
}

type Spec struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"metadata"`
	Spec struct {
		InstallerBinary   string `json:"installerBinary"`
		BundleDirectory   string `json:"bundleDirectory"`
		Listen            string `json:"listen"`
		ExecutionEnabled  bool   `json:"executionEnabled"`
		AllowInsecureHTTP bool   `json:"allowInsecureHttp"`
		TLS               struct {
			CertificateFile string `json:"certificateFile,omitempty"`
			PrivateKeyFile  string `json:"privateKeyFile,omitempty"`
		} `json:"tls"`
		Health struct {
			Path                 string `json:"path,omitempty"`
			ServerName           string `json:"serverName,omitempty"`
			TimeoutSeconds       int    `json:"timeoutSeconds,omitempty"`
			IntervalMilliseconds int    `json:"intervalMilliseconds,omitempty"`
		} `json:"health"`
		Admission *AdmissionPolicy `json:"admission"`
		Service   struct {
			Enable bool `json:"enable"`
			Start  bool `json:"start"`
		} `json:"service"`
	} `json:"spec"`
}

type Action struct {
	Type   string `json:"type"`
	Path   string `json:"path,omitempty"`
	Detail string `json:"detail"`
}

type Paths struct {
	Binary          string `json:"binary"`
	Bundle          string `json:"bundle"`
	Environment     string `json:"environment"`
	Unit            string `json:"unit"`
	TLSCertificate  string `json:"tlsCertificate,omitempty"`
	TLSPrivateKey   string `json:"tlsPrivateKey,omitempty"`
	State           string `json:"state"`
	BackupDirectory string `json:"backupDirectory"`
	Lock            string `json:"lock,omitempty"`
}

type Plan struct {
	SchemaVersion          int                             `json:"schemaVersion"`
	DeploymentID           string                          `json:"deploymentId"`
	Name                   string                          `json:"name"`
	Version                string                          `json:"version"`
	Root                   string                          `json:"root"`
	SpecDigest             string                          `json:"specDigest"`
	InstallerBinaryDigest  string                          `json:"installerBinaryDigest"`
	InstallerBinaryVersion string                          `json:"installerBinaryVersion"`
	Bundle                 bootstrap.BundleAdmissionStatus `json:"bundle"`
	Transport              installeraccess.TransportStatus `json:"transport"`
	Paths                  Paths                           `json:"paths"`
	EnvironmentDigest      string                          `json:"environmentDigest"`
	UnitDigest             string                          `json:"unitDigest"`
	TLSCertificateDigest   string                          `json:"tlsCertificateDigest,omitempty"`
	TLSPrivateKeyDigest    string                          `json:"tlsPrivateKeyDigest,omitempty"`
	Service                ServiceIntent                   `json:"service"`
	Health                 HealthPlan                      `json:"health"`
	Admission              HostAdmissionReport             `json:"admission"`
	Actions                []Action                        `json:"actions"`
	Confirmation           string                          `json:"confirmation"`
}

type PreviousState struct {
	BinaryExisted         bool   `json:"binaryExisted"`
	EnvironmentExisted    bool   `json:"environmentExisted"`
	UnitExisted           bool   `json:"unitExisted"`
	TLSCertificateExisted bool   `json:"tlsCertificateExisted"`
	TLSPrivateKeyExisted  bool   `json:"tlsPrivateKeyExisted"`
	BundleExisted         bool   `json:"bundleExisted"`
	BundleBackupPath      string `json:"bundleBackupPath,omitempty"`
	ServiceWasActive      bool   `json:"serviceWasActive"`
	ServiceWasEnabled     bool   `json:"serviceWasEnabled"`
}

type State struct {
	APIVersion       string        `json:"apiVersion"`
	Kind             string        `json:"kind"`
	SchemaVersion    int           `json:"schemaVersion"`
	Status           string        `json:"status"`
	Plan             Plan          `json:"plan"`
	Previous         PreviousState `json:"previous"`
	Activated        bool          `json:"activated"`
	AppliedAt        time.Time     `json:"appliedAt"`
	RolledBackAt     time.Time     `json:"rolledBackAt,omitempty"`
	StateDigest      string        `json:"stateDigest"`
	BackupPrepared   bool          `json:"backupPrepared,omitempty"`
	CurrentStep      string        `json:"currentStep,omitempty"`
	CompletedSteps   []string      `json:"completedSteps,omitempty"`
	LastError        string        `json:"lastError,omitempty"`
	RecoveryRequired bool          `json:"recoveryRequired,omitempty"`
	RecoveredAt      time.Time     `json:"recoveredAt,omitempty"`
	Readiness        HealthStatus  `json:"readiness,omitempty"`
}

type VerifyResult struct {
	Valid                 bool         `json:"valid"`
	Status                string       `json:"status"`
	DeploymentID          string       `json:"deploymentId"`
	Version               string       `json:"version"`
	BundleDigest          string       `json:"bundleDigest"`
	LockDigest            string       `json:"lockDigest"`
	InstallerBinaryDigest string       `json:"installerBinaryDigest"`
	EnvironmentDigest     string       `json:"environmentDigest"`
	UnitDigest            string       `json:"unitDigest"`
	ServiceActive         bool         `json:"serviceActive"`
	ServiceEnabled        bool         `json:"serviceEnabled"`
	StagedOnly            bool         `json:"stagedOnly"`
	JournalSchemaVersion  int          `json:"journalSchemaVersion"`
	CompletedSteps        []string     `json:"completedSteps,omitempty"`
	RecoveryRequired      bool         `json:"recoveryRequired"`
	ServiceEnableExpected bool         `json:"serviceEnableExpected"`
	ServiceStartExpected  bool         `json:"serviceStartExpected"`
	Readiness             HealthStatus `json:"readiness,omitempty"`
	AdmissionReady        bool         `json:"admissionReady"`
	AdmissionDigest       string       `json:"admissionDigest"`
}

type CommandRunner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

type LocalCommandRunner struct{}

func (LocalCommandRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("run %s: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

type Options struct {
	Root            string
	Runner          CommandRunner
	Now             func() time.Time
	AfterCheckpoint func(string) error
	HealthProbe     func(context.Context, HealthPlan, string, func() time.Time) (HealthStatus, error)
}

func LoadSpec(path string) (Spec, []byte, error) {
	var spec Spec
	raw, err := os.ReadFile(path)
	if err != nil {
		return spec, nil, fmt.Errorf("read deployment spec: %w", err)
	}
	if err := decodeStrict(raw, &spec); err != nil {
		return spec, nil, fmt.Errorf("decode deployment spec: %w", err)
	}
	if err := validateSpec(spec); err != nil {
		return spec, nil, err
	}
	return spec, raw, nil
}

func BuildPlan(specPath string, options Options) (Plan, error) {
	spec, raw, err := LoadSpec(specPath)
	if err != nil {
		return Plan{}, err
	}
	root, err := normalizeRoot(options.Root)
	if err != nil {
		return Plan{}, err
	}
	installerPath, err := filepath.Abs(spec.Spec.InstallerBinary)
	if err != nil {
		return Plan{}, err
	}
	bundlePath, err := filepath.Abs(spec.Spec.BundleDirectory)
	if err != nil {
		return Plan{}, err
	}
	if err := validateRegularFile(installerPath, true); err != nil {
		return Plan{}, fmt.Errorf("installer binary: %w", err)
	}
	binaryVersion, err := readBinaryVersion(installerPath)
	if err != nil {
		return Plan{}, err
	}
	if binaryVersion != spec.Metadata.Version {
		return Plan{}, fmt.Errorf("installer binary version %q does not match deployment version %q", binaryVersion, spec.Metadata.Version)
	}
	binaryDigest, err := fileDigest(installerPath)
	if err != nil {
		return Plan{}, err
	}
	bundle, err := bootstrap.InspectBundle(bundlePath, true)
	if err != nil {
		return Plan{}, fmt.Errorf("verify source bundle: %w", err)
	}
	if bundle.Version != spec.Metadata.Version {
		return Plan{}, fmt.Errorf("bundle version %q does not match deployment version %q", bundle.Version, spec.Metadata.Version)
	}
	certSource, keySource := strings.TrimSpace(spec.Spec.TLS.CertificateFile), strings.TrimSpace(spec.Spec.TLS.PrivateKeyFile)
	if certSource != "" {
		certSource, err = filepath.Abs(certSource)
		if err != nil {
			return Plan{}, err
		}
	}
	if keySource != "" {
		keySource, err = filepath.Abs(keySource)
		if err != nil {
			return Plan{}, err
		}
	}
	if certSource != "" {
		if err = validateRegularFile(certSource, false); err != nil {
			return Plan{}, fmt.Errorf("TLS certificate: %w", err)
		}
	}
	if keySource != "" {
		if err = validatePrivateKeyFile(keySource); err != nil {
			return Plan{}, err
		}
	}
	transport, err := installeraccess.ValidateTransport(spec.Spec.Listen, certSource, keySource, spec.Spec.AllowInsecureHTTP, now(options))
	if err != nil {
		return Plan{}, fmt.Errorf("validate deployment transport: %w", err)
	}
	specDigest := digest(raw)
	id := "hostdep-" + strings.TrimPrefix(specDigest, "sha256:")[:16]
	paths := deploymentPaths(root, id, certSource != "")
	health, err := buildHealthPlan(spec, paths.TLSCertificate)
	if err != nil {
		return Plan{}, fmt.Errorf("build installer readiness contract: %w", err)
	}
	env := renderEnvironment(spec)
	unit := renderUnit()
	plan := Plan{
		SchemaVersion: 3, DeploymentID: id, Name: spec.Metadata.Name, Version: spec.Metadata.Version, Root: root,
		SpecDigest: specDigest, InstallerBinaryDigest: binaryDigest, InstallerBinaryVersion: binaryVersion,
		Bundle: bundle, Transport: transport, Paths: paths, EnvironmentDigest: digest(env), UnitDigest: digest(unit), Confirmation: ConfirmationDeploy,
		Service: ServiceIntent{Enable: spec.Spec.Service.Enable, Start: spec.Spec.Service.Start}, Health: health,
	}
	if certSource != "" {
		plan.TLSCertificateDigest, err = fileDigest(certSource)
		if err != nil {
			return Plan{}, fmt.Errorf("digest TLS certificate: %w", err)
		}
		plan.TLSPrivateKeyDigest, err = fileDigest(keySource)
		if err != nil {
			return Plan{}, fmt.Errorf("digest TLS private key: %w", err)
		}
	}
	plan.Admission = buildHostAdmission(spec, plan, options)
	plan.Actions = []Action{
		{Type: "admission", Detail: "require host architecture, systemd, path safety, version transition and filesystem capacity checks"},
		{Type: "transaction-lock", Path: paths.Lock, Detail: "hold one exclusive deployment transaction lock"},
		{Type: "transaction-journal", Path: paths.State, Detail: "persist crash-recovery journal before host mutation"},
		{Type: "copy", Path: paths.Binary, Detail: "install verified platform-installer binary atomically"},
		{Type: "replace-directory", Path: paths.Bundle, Detail: "install sealed bundle using same-filesystem atomic swap"},
		{Type: "write", Path: paths.Environment, Detail: "write installer environment without bootstrap-token value"},
		{Type: "write", Path: paths.Unit, Detail: "write systemd service contract"},
	}
	if certSource != "" {
		plan.Actions = append(plan.Actions, Action{Type: "copy", Path: paths.TLSCertificate, Detail: "install TLS certificate"}, Action{Type: "copy-private", Path: paths.TLSPrivateKey, Detail: "install TLS private key with mode 0600"})
	}
	if spec.Spec.Service.Enable {
		plan.Actions = append(plan.Actions, Action{Type: "systemd", Detail: "daemon-reload and enable service"})
	}
	if spec.Spec.Service.Start {
		plan.Actions = append(plan.Actions,
			Action{Type: "systemd", Detail: "restart service and require active state"},
			Action{Type: "readiness", Path: plan.Health.URL, Detail: "require version-bound installer health response before committing deployment"},
		)
	}
	return plan, nil
}

func Apply(ctx context.Context, specPath, confirmation string, options Options) (State, error) {
	if confirmation != ConfirmationDeploy {
		return State{}, errors.New("confirmation must be exactly DEPLOY")
	}
	plan, err := BuildPlan(specPath, options)
	if err != nil {
		return State{}, err
	}
	if !plan.Admission.Ready {
		return State{}, fmt.Errorf("installer host admission blocked: %s", admissionBlockedSummary(plan.Admission))
	}
	if plan.Root == "/" && os.Geteuid() != 0 {
		return State{}, errors.New("installer host deployment requires root privileges")
	}
	lock, err := acquireDeploymentLock(plan.Paths.Lock)
	if err != nil {
		return State{}, err
	}
	defer lock.Close()
	if err = rejectUnfinishedTransaction(plan.Paths.State); err != nil {
		return State{}, err
	}
	spec, _, err := LoadSpec(specPath)
	if err != nil {
		return State{}, err
	}
	runner := options.Runner
	if runner == nil {
		runner = LocalCommandRunner{}
	}
	state := State{
		APIVersion: APIVersion, Kind: StateKind, SchemaVersion: 4, Status: "PREPARED",
		Plan: plan, AppliedAt: now(options).UTC(), CurrentStep: "prepare-backups",
	}
	if err = os.MkdirAll(filepath.Dir(plan.Paths.State), 0o700); err != nil {
		return State{}, err
	}
	if err = os.Chmod(filepath.Dir(plan.Paths.State), 0o700); err != nil {
		return State{}, err
	}
	if plan.Root == "/" {
		state.Previous.ServiceWasActive = systemctlBool(ctx, runner, "is-active", "--quiet", "4so-platform-installer.service")
		state.Previous.ServiceWasEnabled = systemctlBool(ctx, runner, "is-enabled", "--quiet", "4so-platform-installer.service")
	}
	if err = prepareBackups(plan, &state.Previous); err != nil {
		return State{}, err
	}
	state.BackupPrepared = true
	state.CompletedSteps = append(state.CompletedSteps, "backups-prepared")
	state.CurrentStep = "binary-install"
	if err = persistCheckpoint(plan.Paths.State, &state); err != nil {
		return State{}, err
	}
	if err = callCheckpointHook(options, "backups-prepared"); err != nil {
		return state, err
	}
	state.Status = "APPLYING"
	if err = persistCheckpoint(plan.Paths.State, &state); err != nil {
		return State{}, err
	}

	fail := func(cause error) (State, error) {
		state.Status = "RECOVERY_REQUIRED"
		state.RecoveryRequired = true
		state.LastError = cause.Error()
		checkpointErr := persistCheckpoint(plan.Paths.State, &state)
		if restoreErr := restorePrevious(ctx, &state, runner); restoreErr != nil {
			state.LastError = cause.Error() + "; automatic recovery failed: " + restoreErr.Error()
			finalCheckpointErr := persistCheckpoint(plan.Paths.State, &state)
			return state, errors.Join(cause, fmt.Errorf("automatic recovery failed: %w", restoreErr), wrapCheckpointError("persist recovery-required state", checkpointErr), wrapCheckpointError("persist failed-recovery state", finalCheckpointErr))
		}
		state.Status = "ROLLED_BACK"
		state.RecoveryRequired = false
		state.RecoveredAt = now(options).UTC()
		state.CurrentStep = ""
		finalCheckpointErr := persistCheckpoint(plan.Paths.State, &state)
		return state, errors.Join(cause, wrapCheckpointError("persist recovery-required state", checkpointErr), wrapCheckpointError("persist rolled-back state", finalCheckpointErr))
	}
	step := func(current, completed string, action func() error) error {
		state.CurrentStep = current
		if err := persistCheckpoint(plan.Paths.State, &state); err != nil {
			return err
		}
		if err := action(); err != nil {
			return err
		}
		state.CompletedSteps = append(state.CompletedSteps, completed)
		if err := persistCheckpoint(plan.Paths.State, &state); err != nil {
			return err
		}
		return callCheckpointHook(options, completed)
	}

	if err = step("binary-install", "binary-installed", func() error {
		return atomicCopyFile(spec.Spec.InstallerBinary, plan.Paths.Binary, 0o755)
	}); err != nil {
		if options.AfterCheckpoint != nil && isCheckpointInterruption(err) {
			return state, err
		}
		return fail(err)
	}
	if err = step("bundle-install", "bundle-installed", func() error {
		return replaceBundle(spec.Spec.BundleDirectory, plan.Paths.Bundle, plan.Paths.BackupDirectory, &state.Previous)
	}); err != nil {
		if options.AfterCheckpoint != nil && isCheckpointInterruption(err) {
			return state, err
		}
		return fail(err)
	}
	if err = step("environment-write", "environment-written", func() error {
		return writeAtomic(plan.Paths.Environment, renderEnvironment(spec), 0o600)
	}); err != nil {
		if options.AfterCheckpoint != nil && isCheckpointInterruption(err) {
			return state, err
		}
		return fail(err)
	}
	if strings.TrimSpace(spec.Spec.TLS.CertificateFile) != "" {
		if err = step("tls-install", "tls-installed", func() error {
			if err := atomicCopyFile(spec.Spec.TLS.CertificateFile, plan.Paths.TLSCertificate, 0o644); err != nil {
				return err
			}
			return atomicCopyFile(spec.Spec.TLS.PrivateKeyFile, plan.Paths.TLSPrivateKey, 0o600)
		}); err != nil {
			if options.AfterCheckpoint != nil && isCheckpointInterruption(err) {
				return state, err
			}
			return fail(err)
		}
	}
	if err = step("unit-write", "unit-written", func() error {
		return writeAtomic(plan.Paths.Unit, renderUnit(), 0o644)
	}); err != nil {
		if options.AfterCheckpoint != nil && isCheckpointInterruption(err) {
			return state, err
		}
		return fail(err)
	}
	if plan.Root == "/" {
		if err = step("systemd-activate", "systemd-activated", func() error {
			if _, err := runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
				return err
			}
			if spec.Spec.Service.Enable {
				if _, err := runner.Run(ctx, "systemctl", "enable", "4so-platform-installer.service"); err != nil {
					return err
				}
				if !systemctlBool(ctx, runner, "is-enabled", "--quiet", "4so-platform-installer.service") {
					return errors.New("installer service did not become enabled")
				}
			}
			if spec.Spec.Service.Start {
				if _, err := runner.Run(ctx, "systemctl", "restart", "4so-platform-installer.service"); err != nil {
					return err
				}
				if !systemctlBool(ctx, runner, "is-active", "--quiet", "4so-platform-installer.service") {
					return errors.New("installer service did not become active")
				}
				state.Activated = true
			}
			return nil
		}); err != nil {
			if options.AfterCheckpoint != nil && isCheckpointInterruption(err) {
				return state, err
			}
			return fail(err)
		}
		if spec.Spec.Service.Start {
			if err = step("readiness-probe", "health-ready", func() error {
				probe := options.HealthProbe
				if probe == nil {
					probe = probeHealth
				}
				status, probeErr := probe(ctx, plan.Health, plan.Version, func() time.Time { return now(options) })
				state.Readiness = status
				return probeErr
			}); err != nil {
				if options.AfterCheckpoint != nil && isCheckpointInterruption(err) {
					return state, err
				}
				return fail(err)
			}
		}
		state.Status = "APPLIED"
	} else {
		state.Status = "STAGED"
	}
	state.CurrentStep = ""
	state.RecoveryRequired = false
	state.LastError = ""
	if err = persistCheckpoint(plan.Paths.State, &state); err != nil {
		return fail(err)
	}
	return state, nil
}

func Verify(ctx context.Context, statePath string, options Options) (VerifyResult, error) {
	state, err := LoadState(statePath)
	if err != nil {
		return VerifyResult{}, err
	}
	if state.Status != "APPLIED" && state.Status != "STAGED" {
		return VerifyResult{}, fmt.Errorf("deployment state %q is not verifiable as active", state.Status)
	}
	if state.SchemaVersion >= 4 && (!state.Plan.Admission.Ready || state.Plan.Admission.Digest == "" || state.Plan.Admission.Digest != admissionDigest(state.Plan.Admission)) {
		return VerifyResult{}, errors.New("installer host admission evidence is missing or invalid")
	}
	binaryDigest, err := fileDigest(state.Plan.Paths.Binary)
	if err != nil {
		return VerifyResult{}, err
	}
	if binaryDigest != state.Plan.InstallerBinaryDigest {
		return VerifyResult{}, errors.New("deployed installer binary digest mismatch")
	}
	bundle, err := bootstrap.InspectBundle(state.Plan.Paths.Bundle, true)
	if err != nil {
		return VerifyResult{}, err
	}
	if bundle.BundleDigest != state.Plan.Bundle.BundleDigest || bundle.LockDigest != state.Plan.Bundle.LockDigest {
		return VerifyResult{}, errors.New("deployed bundle digest mismatch")
	}
	envDigest, err := fileDigest(state.Plan.Paths.Environment)
	if err != nil {
		return VerifyResult{}, err
	}
	if envDigest != state.Plan.EnvironmentDigest {
		return VerifyResult{}, errors.New("deployed environment digest mismatch")
	}
	unitDigest, err := fileDigest(state.Plan.Paths.Unit)
	if err != nil {
		return VerifyResult{}, err
	}
	if unitDigest != state.Plan.UnitDigest {
		return VerifyResult{}, errors.New("deployed systemd unit digest mismatch")
	}
	if state.Plan.TLSCertificateDigest != "" {
		certDigest, e := fileDigest(state.Plan.Paths.TLSCertificate)
		if e != nil {
			return VerifyResult{}, e
		}
		keyDigest, e := fileDigest(state.Plan.Paths.TLSPrivateKey)
		if e != nil {
			return VerifyResult{}, e
		}
		if certDigest != state.Plan.TLSCertificateDigest || keyDigest != state.Plan.TLSPrivateKeyDigest {
			return VerifyResult{}, errors.New("deployed TLS material digest mismatch")
		}
		if e = validatePrivateKeyFile(state.Plan.Paths.TLSPrivateKey); e != nil {
			return VerifyResult{}, e
		}
	}
	runner := options.Runner
	if runner == nil {
		runner = LocalCommandRunner{}
	}
	result := VerifyResult{Valid: true, Status: state.Status, DeploymentID: state.Plan.DeploymentID, Version: state.Plan.Version, BundleDigest: bundle.BundleDigest, LockDigest: bundle.LockDigest, InstallerBinaryDigest: binaryDigest, EnvironmentDigest: envDigest, UnitDigest: unitDigest, StagedOnly: state.Plan.Root != "/", JournalSchemaVersion: state.SchemaVersion, CompletedSteps: append([]string(nil), state.CompletedSteps...), RecoveryRequired: state.RecoveryRequired, ServiceEnableExpected: state.Plan.Service.Enable, ServiceStartExpected: state.Plan.Service.Start, Readiness: state.Readiness, AdmissionReady: state.Plan.Admission.Ready, AdmissionDigest: state.Plan.Admission.Digest}
	if state.Plan.Root == "/" {
		result.ServiceActive = systemctlBool(ctx, runner, "is-active", "--quiet", "4so-platform-installer.service")
		result.ServiceEnabled = systemctlBool(ctx, runner, "is-enabled", "--quiet", "4so-platform-installer.service")
		if state.Plan.Service.Enable && !result.ServiceEnabled {
			return VerifyResult{}, errors.New("installer service is not enabled as requested")
		}
		if state.Plan.Service.Start && !result.ServiceActive {
			return VerifyResult{}, errors.New("installer service is not active as requested")
		}
		if state.SchemaVersion >= 3 && state.Plan.Service.Start {
			probe := options.HealthProbe
			if probe == nil {
				probe = probeHealth
			}
			status, probeErr := probe(ctx, state.Plan.Health, state.Plan.Version, func() time.Time { return now(options) })
			result.Readiness = status
			if probeErr != nil {
				return VerifyResult{}, probeErr
			}
		}
	}
	return result, nil
}

func Rollback(ctx context.Context, statePath, confirmation string, options Options) (State, error) {
	if confirmation != ConfirmationRollback {
		return State{}, errors.New("confirmation must be exactly ROLLBACK")
	}
	state, err := LoadState(statePath)
	if err != nil {
		return State{}, err
	}
	if state.Status != "APPLIED" && state.Status != "STAGED" {
		return State{}, fmt.Errorf("deployment state %q cannot be rolled back", state.Status)
	}
	if state.Plan.Root == "/" && os.Geteuid() != 0 {
		return State{}, errors.New("installer host rollback requires root privileges")
	}
	lockPath := state.Plan.Paths.Lock
	if lockPath == "" {
		lockPath = filepath.Join(filepath.Dir(statePath), "host-deployment.lock")
	}
	lock, err := acquireDeploymentLock(lockPath)
	if err != nil {
		return State{}, err
	}
	defer lock.Close()
	runner := options.Runner
	if runner == nil {
		runner = LocalCommandRunner{}
	}
	if err = restorePrevious(ctx, &state, runner); err != nil {
		return State{}, err
	}
	state.Status = "ROLLED_BACK"
	state.RolledBackAt = now(options).UTC()
	state.Activated = false
	state.RecoveryRequired = false
	state.CurrentStep = ""
	if err = persistCheckpoint(state.Plan.Paths.State, &state); err != nil {
		return State{}, err
	}
	return state, nil
}

func Recover(ctx context.Context, statePath, confirmation string, options Options) (State, error) {
	if confirmation != ConfirmationRecover {
		return State{}, errors.New("confirmation must be exactly RECOVER")
	}
	state, err := LoadState(statePath)
	if err != nil {
		return State{}, err
	}
	switch state.Status {
	case "PREPARED", "APPLYING", "RECOVERY_REQUIRED":
	default:
		return State{}, fmt.Errorf("deployment state %q does not require recovery", state.Status)
	}
	if !state.BackupPrepared {
		return State{}, errors.New("deployment transaction has no prepared backup journal")
	}
	if state.Plan.Root == "/" && os.Geteuid() != 0 {
		return State{}, errors.New("installer host recovery requires root privileges")
	}
	lockPath := state.Plan.Paths.Lock
	if lockPath == "" {
		lockPath = filepath.Join(filepath.Dir(statePath), "host-deployment.lock")
	}
	lock, err := acquireDeploymentLock(lockPath)
	if err != nil {
		return State{}, err
	}
	defer lock.Close()
	runner := options.Runner
	if runner == nil {
		runner = LocalCommandRunner{}
	}
	if err = restorePrevious(ctx, &state, runner); err != nil {
		state.Status = "RECOVERY_REQUIRED"
		state.RecoveryRequired = true
		state.LastError = err.Error()
		persistErr := persistCheckpoint(state.Plan.Paths.State, &state)
		return State{}, errors.Join(err, wrapCheckpointError("persist recovery-required state", persistErr))
	}
	state.Status = "RECOVERED"
	state.Activated = false
	state.RecoveryRequired = false
	state.CurrentStep = ""
	state.RecoveredAt = now(options).UTC()
	state.CompletedSteps = append(state.CompletedSteps, "transaction-recovered")
	if err = persistCheckpoint(state.Plan.Paths.State, &state); err != nil {
		return State{}, err
	}
	return state, nil
}

func wrapCheckpointError(action string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", action, err)
}

func LoadState(path string) (State, error) {
	var state State
	raw, err := os.ReadFile(path)
	if err != nil {
		return state, err
	}
	if err = decodeStrict(raw, &state); err != nil {
		return state, err
	}
	if state.APIVersion != APIVersion || state.Kind != StateKind || (state.SchemaVersion != 1 && state.SchemaVersion != 2 && state.SchemaVersion != 3 && state.SchemaVersion != 4) {
		return state, errors.New("unsupported installer host deployment state")
	}
	if state.StateDigest == "" || state.StateDigest != stateDigest(state) {
		return state, errors.New("installer host deployment state integrity mismatch")
	}
	return state, nil
}

func validateSpec(spec Spec) error {
	if spec.APIVersion != APIVersion || spec.Kind != Kind {
		return errors.New("unsupported installer host deployment contract")
	}
	if strings.TrimSpace(spec.Metadata.Name) == "" || strings.TrimSpace(spec.Metadata.Version) == "" {
		return errors.New("deployment name and version are required")
	}
	if strings.TrimSpace(spec.Spec.InstallerBinary) == "" || strings.TrimSpace(spec.Spec.BundleDirectory) == "" || strings.TrimSpace(spec.Spec.Listen) == "" {
		return errors.New("installerBinary, bundleDirectory and listen are required")
	}
	if spec.Spec.Service.Start && !spec.Spec.Service.Enable {
		return errors.New("service.start requires service.enable")
	}
	if spec.Spec.Admission == nil {
		return errors.New("spec.admission is required")
	}
	if (strings.TrimSpace(spec.Spec.TLS.CertificateFile) == "") != (strings.TrimSpace(spec.Spec.TLS.PrivateKeyFile) == "") {
		return errors.New("TLS certificateFile and privateKeyFile must be provided together")
	}
	if spec.Spec.Health.TimeoutSeconds < 0 || spec.Spec.Health.IntervalMilliseconds < 0 {
		return errors.New("health timeout and interval cannot be negative")
	}
	return nil
}

func normalizeRoot(value string) (string, error) {
	if strings.TrimSpace(value) == "" {
		value = "/"
	}
	root, err := filepath.Abs(value)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return "", errors.New("deployment root must be an existing directory")
	}
	return filepath.Clean(root), nil
}

func deploymentPaths(root, id string, tlsEnabled bool) Paths {
	join := func(path string) string {
		if root == "/" {
			return path
		}
		return filepath.Join(root, strings.TrimPrefix(path, "/"))
	}
	p := Paths{Binary: join("/usr/local/bin/platform-installer"), Bundle: join("/opt/4so-platform-factory/bundle"), Environment: join("/etc/4so-platform-factory/installer.env"), Unit: join("/etc/systemd/system/4so-platform-installer.service"), State: join("/var/lib/4so-platform-installer/host-deployment.json"), BackupDirectory: join("/var/lib/4so-platform-installer/host-deployment-backups/" + id), Lock: join("/var/lib/4so-platform-installer/host-deployment.lock")}
	if tlsEnabled {
		p.TLSCertificate = join("/etc/4so-platform-factory/tls/installer.crt")
		p.TLSPrivateKey = join("/etc/4so-platform-factory/tls/installer.key")
	}
	return p
}

func renderEnvironment(spec Spec) []byte {
	lines := []string{
		"PLATFORM_INSTALLER_LISTEN=" + spec.Spec.Listen,
		"PLATFORM_INSTALLER_BUNDLE_DIR=/opt/4so-platform-factory/bundle",
		"PLATFORM_INSTALLER_STATE_DIR=/var/lib/4so-platform-installer",
		fmt.Sprintf("PLATFORM_INSTALLER_ALLOW_EXECUTION=%t", spec.Spec.ExecutionEnabled),
		fmt.Sprintf("PLATFORM_INSTALLER_ALLOW_INSECURE_HTTP=%t", spec.Spec.AllowInsecureHTTP),
	}
	if strings.TrimSpace(spec.Spec.TLS.CertificateFile) != "" {
		lines = append(lines,
			"PLATFORM_INSTALLER_TLS_CERT_FILE=/etc/4so-platform-factory/tls/installer.crt",
			"PLATFORM_INSTALLER_TLS_KEY_FILE=/etc/4so-platform-factory/tls/installer.key",
		)
	}
	sort.Strings(lines)
	return []byte(strings.Join(lines, "\n") + "\n")
}

func renderUnit() []byte {
	return []byte(`[Unit]
Description=4SO Platform Factory Bootstrap Installer
After=network-online.target
Wants=network-online.target
ConditionPathExists=/opt/4so-platform-factory/bundle/bundle.json

[Service]
Type=simple
User=root
Group=root
UMask=0077
EnvironmentFile=/etc/4so-platform-factory/installer.env
ExecStart=/usr/local/bin/platform-installer
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=full
ReadWritePaths=/etc/rancher /var/lib/rancher /var/lib/4so-platform-installer /opt/4so-platform-factory /usr/local/bin /usr/local/lib/systemd/system /etc/systemd/system /opt/rke2
CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER CAP_NET_BIND_SERVICE CAP_SETGID CAP_SETUID CAP_SYS_ADMIN

[Install]
WantedBy=multi-user.target
`)
}

func prepareBackups(plan Plan, previous *PreviousState) error {
	if err := os.MkdirAll(plan.Paths.BackupDirectory, 0o700); err != nil {
		return err
	}
	type entry struct {
		source, name string
		mode         fs.FileMode
		existed      *bool
	}
	entries := []entry{{plan.Paths.Binary, "platform-installer", 0o755, &previous.BinaryExisted}, {plan.Paths.Environment, "installer.env", 0o600, &previous.EnvironmentExisted}, {plan.Paths.Unit, "4so-platform-installer.service", 0o644, &previous.UnitExisted}}
	if plan.Paths.TLSCertificate != "" {
		entries = append(entries, entry{plan.Paths.TLSCertificate, "installer.crt", 0o644, &previous.TLSCertificateExisted}, entry{plan.Paths.TLSPrivateKey, "installer.key", 0o600, &previous.TLSPrivateKeyExisted})
	}
	for _, e := range entries {
		info, err := os.Lstat(e.source)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("existing destination %s must be a regular non-symlink file", e.source)
		}
		*e.existed = true
		if err = atomicCopyFile(e.source, filepath.Join(plan.Paths.BackupDirectory, e.name), e.mode); err != nil {
			return err
		}
	}
	if info, err := os.Lstat(plan.Paths.Bundle); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("existing bundle destination must be a non-symlink directory")
		}
		previous.BundleExisted = true
		previous.BundleBackupPath = filepath.Join(filepath.Dir(plan.Paths.Bundle), ".bundle-previous-"+filepath.Base(plan.Paths.BackupDirectory))
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func replaceBundle(source, destination, backupDir string, previous *PreviousState) error {
	sourceAbs, err := filepath.Abs(source)
	if err != nil {
		return fmt.Errorf("resolve source bundle path: %w", err)
	}
	destinationAbs, err := filepath.Abs(destination)
	if err != nil {
		return fmt.Errorf("resolve destination bundle path: %w", err)
	}
	if sourceAbs == destinationAbs {
		return errors.New("source bundle must differ from deployed bundle destination")
	}
	parent := filepath.Dir(destination)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return err
	}
	stage, err := os.MkdirTemp(parent, ".bundle-stage-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	if err = copyTree(source, stage); err != nil {
		return err
	}
	if _, err = bootstrap.InspectBundle(stage, true); err != nil {
		return fmt.Errorf("verify staged bundle: %w", err)
	}
	backup := previous.BundleBackupPath
	if backup == "" {
		backup = filepath.Join(parent, ".bundle-previous-"+filepath.Base(backupDir))
	}
	if err = os.RemoveAll(backup); err != nil {
		return fmt.Errorf("remove stale bundle backup: %w", err)
	}
	if previous.BundleExisted {
		if err = os.Rename(destination, backup); err != nil {
			return err
		}
		previous.BundleBackupPath = backup
		if err = syncDirectoryPath(parent); err != nil {
			return fmt.Errorf("durably record previous bundle before activation: %w", err)
		}
	}
	if err = os.Rename(stage, destination); err != nil {
		if previous.BundleBackupPath != "" {
			if restoreErr := os.Rename(previous.BundleBackupPath, destination); restoreErr != nil {
				return errors.Join(err, fmt.Errorf("restore original bundle after activation failure: %w", restoreErr))
			}
		}
		return err
	}
	if err = syncDirectoryPath(parent); err != nil {
		return fmt.Errorf("durably activate staged bundle: %w", err)
	}
	return nil
}

func restorePrevious(ctx context.Context, state *State, runner CommandRunner) error {
	p := state.Plan.Paths
	if state.Plan.Root == "/" {
		if _, err := runner.Run(ctx, "systemctl", "stop", "4so-platform-installer.service"); err != nil {
			return fmt.Errorf("stop installer service before recovery: %w", err)
		}
	}
	restore := func(existed bool, backupName, destination string, mode fs.FileMode) error {
		if existed {
			return atomicCopyFile(filepath.Join(p.BackupDirectory, backupName), destination, mode)
		}
		if err := os.Remove(destination); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
		return syncDirectoryPath(filepath.Dir(destination))
	}
	if err := restore(state.Previous.BinaryExisted, "platform-installer", p.Binary, 0o755); err != nil {
		return err
	}
	if err := restore(state.Previous.EnvironmentExisted, "installer.env", p.Environment, 0o600); err != nil {
		return err
	}
	if err := restore(state.Previous.UnitExisted, "4so-platform-installer.service", p.Unit, 0o644); err != nil {
		return err
	}
	if p.TLSCertificate != "" {
		if err := restore(state.Previous.TLSCertificateExisted, "installer.crt", p.TLSCertificate, 0o644); err != nil {
			return err
		}
		if err := restore(state.Previous.TLSPrivateKeyExisted, "installer.key", p.TLSPrivateKey, 0o600); err != nil {
			return err
		}
	}
	if state.Previous.BundleExisted {
		backupExists := false
		if state.Previous.BundleBackupPath != "" {
			if info, statErr := os.Lstat(state.Previous.BundleBackupPath); statErr == nil {
				if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
					return errors.New("bundle recovery backup is not a safe directory")
				}
				backupExists = true
			} else if !errors.Is(statErr, os.ErrNotExist) {
				return statErr
			}
		}
		if backupExists {
			if err := os.RemoveAll(p.Bundle); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			if err := os.Rename(state.Previous.BundleBackupPath, p.Bundle); err != nil {
				return err
			}
		} else {
			if info, statErr := os.Lstat(p.Bundle); statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return errors.New("original bundle is unavailable and no recovery backup exists")
			}
		}
	} else if err := os.RemoveAll(p.Bundle); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := syncDirectoryIfExists(filepath.Dir(p.Bundle)); err != nil {
		return fmt.Errorf("durably restore bundle directory state: %w", err)
	}
	if state.Plan.Root == "/" {
		if _, err := runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
			return err
		}
		if !state.Previous.ServiceWasEnabled {
			if _, err := runner.Run(ctx, "systemctl", "disable", "4so-platform-installer.service"); err != nil {
				return fmt.Errorf("restore installer disabled state: %w", err)
			}
		}
		if state.Previous.ServiceWasEnabled {
			if _, err := runner.Run(ctx, "systemctl", "enable", "4so-platform-installer.service"); err != nil {
				return fmt.Errorf("restore installer enabled state: %w", err)
			}
		}
		if state.Previous.ServiceWasActive {
			if _, err := runner.Run(ctx, "systemctl", "restart", "4so-platform-installer.service"); err != nil {
				return err
			}
		}
	}
	return nil
}

func copyTree(source, destination string) error {
	sourceAbs, err := filepath.Abs(source)
	if err != nil {
		return err
	}
	return filepath.WalkDir(sourceAbs, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(sourceAbs, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, rel)
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("source contains symlink %s", rel)
		}
		if entry.IsDir() {
			return os.MkdirAll(target, info.Mode().Perm())
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("source contains non-regular file %s", rel)
		}
		return atomicCopyFile(path, target, info.Mode().Perm())
	})
}

func validateRegularFile(path string, executable bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 {
		return errors.New("must be a non-empty regular non-symlink file")
	}
	if executable && info.Mode().Perm()&0o111 == 0 {
		return errors.New("must be executable")
	}
	return nil
}

func validatePrivateKeyFile(path string) error {
	if err := validateRegularFile(path, false); err != nil {
		return fmt.Errorf("TLS private key: %w", err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("TLS private key permissions must not allow group/other access: got %04o", info.Mode().Perm())
	}
	return nil
}

func readBinaryVersion(path string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "--version").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("read installer binary version: %w: %s", err, strings.TrimSpace(string(out)))
	}
	value := strings.TrimSpace(string(out))
	if value == "" || strings.ContainsAny(value, "\r\n\x00") {
		return "", errors.New("installer binary returned an invalid version")
	}
	return value, nil
}

func syncDirectoryIfExists(path string) error {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("sync target %s is not a directory", path)
	}
	return syncDirectoryPath(path)
}

func syncDirectoryPath(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	if err = directory.Sync(); err != nil {
		_ = directory.Close()
		return err
	}
	return directory.Close()
}

func atomicCopyFile(source, destination string, mode fs.FileMode) error {
	raw, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	return writeAtomic(destination, raw, mode)
}
func writeAtomic(path string, raw []byte, mode fs.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".deploy-")
	if err != nil {
		return err
	}
	name := temp.Name()
	defer os.Remove(name)
	if err = temp.Chmod(mode); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err = temp.Write(raw); err != nil {
		_ = temp.Close()
		return err
	}
	if err = temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err = temp.Close(); err != nil {
		return err
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	if err = os.Chmod(path, mode); err != nil {
		return err
	}
	return syncDirectoryPath(filepath.Dir(path))
}

type deploymentLock struct {
	file *os.File
}

func acquireDeploymentLock(path string) (*deploymentLock, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("deployment lock path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err = file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, errors.New("another installer host deployment transaction is active")
		}
		return nil, err
	}
	return &deploymentLock{file: file}, nil
}

func (lock *deploymentLock) Close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	unlockErr := syscall.Flock(int(lock.file.Fd()), syscall.LOCK_UN)
	closeErr := lock.file.Close()
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}

type checkpointInterruption struct {
	cause error
}

func (e checkpointInterruption) Error() string { return e.cause.Error() }
func (e checkpointInterruption) Unwrap() error { return e.cause }

func callCheckpointHook(options Options, step string) error {
	if options.AfterCheckpoint == nil {
		return nil
	}
	if err := options.AfterCheckpoint(step); err != nil {
		return checkpointInterruption{cause: err}
	}
	return nil
}

func isCheckpointInterruption(err error) bool {
	var target checkpointInterruption
	return errors.As(err, &target)
}

func persistCheckpoint(path string, state *State) error {
	state.StateDigest = stateDigest(*state)
	return writeState(path, *state)
}

func rejectUnfinishedTransaction(path string) error {
	state, err := LoadState(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("existing deployment state must be repaired before apply: %w", err)
	}
	switch state.Status {
	case "PREPARED", "APPLYING", "RECOVERY_REQUIRED":
		return fmt.Errorf("unfinished installer host deployment transaction %s requires explicit RECOVER", state.Plan.DeploymentID)
	default:
		return nil
	}
}

func writeState(path string, state State) error {
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(path, append(raw, '\n'), 0o600)
}
func fileDigest(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return digest(raw), nil
}
func digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func stateDigest(state State) string {
	state.StateDigest = ""
	raw, _ := json.Marshal(state)
	return digest(raw)
}
func now(options Options) time.Time {
	if options.Now != nil {
		return options.Now()
	}
	return time.Now()
}
func decodeStrict(raw []byte, target any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}
func systemctlBool(ctx context.Context, runner CommandRunner, args ...string) bool {
	_, err := runner.Run(ctx, "systemctl", args...)
	return err == nil
}
