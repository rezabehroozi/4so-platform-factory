package remotebootstrap

import (
	"archive/tar"
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"debug/elf"
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
	"platform.4so.io/factory/internal/durablefile"
	"platform.4so.io/factory/internal/hostdeployment"
)

const (
	APIVersion              = "platform.4so.io/v1alpha1"
	Kind                    = "InstallerRemoteBootstrap"
	ConfirmationDeploy      = "DEPLOY"
	ConfirmationRollback    = "ROLLBACK"
	ConfirmationRecover     = "RECOVER"
	StageManifestSchema     = 1
	ExpectedBundleAuthority = "REMOTE_BOOTSTRAP_EXPECTED_BUNDLE_AUTHORITY_V1"
	remoteCleanupTimeout    = 15 * time.Second
)

type Spec struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"metadata"`
	Spec struct {
		Target struct {
			Host           string `json:"host"`
			User           string `json:"user"`
			IdentityFile   string `json:"identityFile"`
			KnownHostsFile string `json:"knownHostsFile"`
			Root           string `json:"root,omitempty"`
		} `json:"target"`
		PlatformctlBinary string `json:"platformctlBinary"`
		DeploymentSpec    string `json:"deploymentSpec"`
		ExpectedBundle    struct {
			BundleDigest string `json:"bundleDigest"`
			LockDigest   string `json:"lockDigest"`
		} `json:"expectedBundle"`
	} `json:"spec"`
}

type HostTrust struct {
	Host        string `json:"host"`
	KeyType     string `json:"keyType"`
	Fingerprint string `json:"fingerprint"`
}

type RemoteTarget struct {
	Host         string      `json:"host"`
	User         string      `json:"user"`
	Root         string      `json:"root"`
	Architecture string      `json:"architecture"`
	Trust        []HostTrust `json:"trust"`
}

type Prepared struct {
	SchemaVersion          int                                `json:"schemaVersion"`
	Name                   string                             `json:"name"`
	Version                string                             `json:"version"`
	Target                 RemoteTarget                       `json:"target"`
	StageDirectory         string                             `json:"stageDirectory"`
	StageManifestDigest    string                             `json:"stageManifestDigest"`
	DeploymentSpecDigest   string                             `json:"deploymentSpecDigest"`
	BundleBindingAuthority string                             `json:"bundleBindingAuthority"`
	Admission              hostdeployment.HostAdmissionReport `json:"admission"`
	Plan                   hostdeployment.Plan                `json:"plan"`
}

type Result struct {
	Prepared Prepared             `json:"prepared"`
	State    hostdeployment.State `json:"state"`
}

type StageManifestEntry struct {
	Path   string `json:"path"`
	Mode   uint32 `json:"mode"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type StageManifest struct {
	SchemaVersion int                  `json:"schemaVersion"`
	Entries       []StageManifestEntry `json:"entries"`
	Digest        string               `json:"digest"`
}

type Runner interface {
	Run(context.Context, io.Reader, string, ...string) ([]byte, error)
}

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, stdin io.Reader, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = stdin
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("run %s: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

type Options struct {
	Runner    Runner
	SSHBinary string
	Now       func() time.Time
}

type loadedSpec struct {
	Config             Spec
	Deployment         hostdeployment.Spec
	Platformctl        string
	DeploymentSpecPath string
	InstallerBinary    string
	BundleDirectory    string
	TLSCertificate     string
	TLSPrivateKey      string
	IdentityFile       string
	KnownHostsFile     string
	Root               string
	Host               string
	User               string
	Trust              []HostTrust
	StageDirectory     string
}

func LoadSpec(path string) (Spec, error) {
	var spec Spec
	raw, err := os.ReadFile(path)
	if err != nil {
		return spec, fmt.Errorf("read remote bootstrap spec: %w", err)
	}
	if err = decodeStrict(raw, &spec); err != nil {
		return spec, fmt.Errorf("decode remote bootstrap spec: %w", err)
	}
	if spec.APIVersion != APIVersion || spec.Kind != Kind {
		return spec, fmt.Errorf("remote bootstrap type must be %s %s", APIVersion, Kind)
	}
	if strings.TrimSpace(spec.Metadata.Name) == "" || strings.TrimSpace(spec.Metadata.Version) == "" {
		return spec, errors.New("metadata.name and metadata.version are required")
	}
	if err = bootstrap.ValidateSSHHost(spec.Spec.Target.Host); err != nil {
		return spec, err
	}
	spec.Spec.Target.User = bootstrap.NormalizeSSHUser(spec.Spec.Target.User)
	if err = bootstrap.ValidateSSHUser(spec.Spec.Target.User); err != nil {
		return spec, err
	}
	if spec.Spec.Target.User != "root" {
		return spec, errors.New("remote installer bootstrap requires SSH user root; sudo/password elevation is not supported")
	}
	if strings.TrimSpace(spec.Spec.PlatformctlBinary) == "" || strings.TrimSpace(spec.Spec.DeploymentSpec) == "" {
		return spec, errors.New("platformctlBinary and deploymentSpec are required")
	}
	if !canonicalSHA256(spec.Spec.ExpectedBundle.BundleDigest) || !canonicalSHA256(spec.Spec.ExpectedBundle.LockDigest) {
		return spec, errors.New("expectedBundle.bundleDigest and expectedBundle.lockDigest must be canonical sha256 digests")
	}
	if strings.TrimSpace(spec.Spec.Target.IdentityFile) == "" || strings.TrimSpace(spec.Spec.Target.KnownHostsFile) == "" {
		return spec, errors.New("identityFile and knownHostsFile are required")
	}
	root := strings.TrimSpace(spec.Spec.Target.Root)
	if root == "" {
		root = "/"
	}
	if err = validateRemoteRoot(root); err != nil {
		return spec, err
	}
	spec.Spec.Target.Root = root
	return spec, nil
}

func Prepare(ctx context.Context, specPath string, options Options) (prepared Prepared, retErr error) {
	loaded, err := loadAndValidate(specPath)
	if err != nil {
		return Prepared{}, err
	}
	loaded, err = isolateRemoteStage(loaded)
	if err != nil {
		return Prepared{}, err
	}
	runner := options.Runner
	if runner == nil {
		runner = ExecRunner{}
	}
	sshBinary := options.SSHBinary
	if strings.TrimSpace(sshBinary) == "" {
		sshBinary = "ssh"
	}
	arch, err := remoteArchitecture(ctx, runner, sshBinary, loaded)
	if err != nil {
		return Prepared{}, err
	}
	localArch, err := executableArchitecture(loaded.Platformctl)
	if err != nil {
		return Prepared{}, fmt.Errorf("inspect platformctl architecture: %w", err)
	}
	if normalizeArchitecture(arch) != localArch {
		return Prepared{}, fmt.Errorf("remote architecture %q does not match platformctl architecture %q", arch, localArch)
	}
	controlPath, cleanup, err := stageControlBinary(ctx, runner, sshBinary, loaded)
	if err != nil {
		return Prepared{}, err
	}
	defer func() {
		if cleanupErr := cleanup(); cleanupErr != nil {
			retErr = errors.Join(retErr, fmt.Errorf("cleanup remote platformctl: %w", cleanupErr))
		}
	}()
	manifest, archive, remoteSpecDigest, err := buildStageArchive(loaded)
	if err != nil {
		return Prepared{}, err
	}
	defer cleanupStageArchive(archive)
	defer func() {
		if cleanupErr := cleanupRemoteStage(runner, sshBinary, loaded, controlPath); cleanupErr != nil {
			retErr = errors.Join(retErr, fmt.Errorf("cleanup remote bootstrap stage: %w", cleanupErr))
		}
	}()
	if err = receiveStage(ctx, runner, sshBinary, loaded, controlPath, manifest, archive); err != nil {
		return Prepared{}, err
	}
	admissionRaw, err := runRemotePlatformctl(ctx, runner, sshBinary, loaded, controlPath, "installer-host", "preflight", "--spec", remoteDeploymentSpecPath(loaded), "--root", loaded.Root)
	if err != nil {
		return Prepared{}, err
	}
	var admission hostdeployment.HostAdmissionReport
	if err = decodeStrict(admissionRaw, &admission); err != nil {
		return Prepared{}, fmt.Errorf("decode remote host admission: %w", err)
	}
	planRaw, err := runRemotePlatformctl(ctx, runner, sshBinary, loaded, controlPath, "installer-host", "plan", "--spec", remoteDeploymentSpecPath(loaded), "--root", loaded.Root)
	if err != nil {
		return Prepared{}, err
	}
	var plan hostdeployment.Plan
	if err = decodeStrict(planRaw, &plan); err != nil {
		return Prepared{}, fmt.Errorf("decode remote deployment plan: %w", err)
	}
	if err = enforceExpectedBundleBinding(loaded.Config, plan.Bundle); err != nil {
		return Prepared{}, fmt.Errorf("staged remote bundle binding: %w", err)
	}
	prepared = Prepared{
		SchemaVersion: 2, Name: loaded.Config.Metadata.Name, Version: loaded.Config.Metadata.Version,
		Target:         RemoteTarget{Host: loaded.Host, User: loaded.User, Root: loaded.Root, Architecture: normalizeArchitecture(arch), Trust: loaded.Trust},
		StageDirectory: loaded.StageDirectory, StageManifestDigest: manifest.Digest, DeploymentSpecDigest: remoteSpecDigest, BundleBindingAuthority: ExpectedBundleAuthority,
		Admission: admission, Plan: plan,
	}
	return prepared, nil
}

func Apply(ctx context.Context, specPath, confirmation string, options Options) (result Result, retErr error) {
	if confirmation != ConfirmationDeploy {
		return Result{}, errors.New("confirmation must be exactly DEPLOY")
	}
	loaded, err := loadAndValidate(specPath)
	if err != nil {
		return Result{}, err
	}
	loaded, err = isolateRemoteStage(loaded)
	if err != nil {
		return Result{}, err
	}
	runner := options.Runner
	if runner == nil {
		runner = ExecRunner{}
	}
	sshBinary := options.SSHBinary
	if strings.TrimSpace(sshBinary) == "" {
		sshBinary = "ssh"
	}
	arch, err := remoteArchitecture(ctx, runner, sshBinary, loaded)
	if err != nil {
		return Result{}, err
	}
	localArch, err := executableArchitecture(loaded.Platformctl)
	if err != nil {
		return Result{}, err
	}
	if normalizeArchitecture(arch) != localArch {
		return Result{}, fmt.Errorf("remote architecture %q does not match platformctl architecture %q", arch, localArch)
	}
	controlPath, cleanup, err := stageControlBinary(ctx, runner, sshBinary, loaded)
	if err != nil {
		return Result{}, err
	}
	defer func() {
		if cleanupErr := cleanup(); cleanupErr != nil {
			retErr = errors.Join(retErr, fmt.Errorf("cleanup remote platformctl: %w", cleanupErr))
		}
	}()
	manifest, archive, remoteSpecDigest, err := buildStageArchive(loaded)
	if err != nil {
		return Result{}, err
	}
	defer cleanupStageArchive(archive)
	defer func() {
		if cleanupErr := cleanupRemoteStage(runner, sshBinary, loaded, controlPath); cleanupErr != nil {
			retErr = errors.Join(retErr, fmt.Errorf("cleanup remote bootstrap stage: %w", cleanupErr))
		}
	}()
	if err = receiveStage(ctx, runner, sshBinary, loaded, controlPath, manifest, archive); err != nil {
		return Result{}, err
	}
	verifyRaw, err := runRemotePlatformctl(ctx, runner, sshBinary, loaded, controlPath, "installer-remote", "verify-stage", "--dir", loaded.StageDirectory, "--manifest-digest", manifest.Digest)
	if err != nil {
		return Result{}, err
	}
	var verified StageManifest
	if err = decodeStrict(verifyRaw, &verified); err != nil {
		return Result{}, fmt.Errorf("decode remote stage verification: %w", err)
	}
	if verified.Digest != manifest.Digest {
		return Result{}, errors.New("remote staged payload digest changed before deployment")
	}
	admissionRaw, err := runRemotePlatformctl(ctx, runner, sshBinary, loaded, controlPath, "installer-host", "preflight", "--spec", remoteDeploymentSpecPath(loaded), "--root", loaded.Root)
	if err != nil {
		return Result{}, err
	}
	var admission hostdeployment.HostAdmissionReport
	if err = decodeStrict(admissionRaw, &admission); err != nil {
		return Result{}, err
	}
	if !admission.Ready {
		return Result{}, errors.New("remote installer host admission is blocked")
	}
	planRaw, err := runRemotePlatformctl(ctx, runner, sshBinary, loaded, controlPath, "installer-host", "plan", "--spec", remoteDeploymentSpecPath(loaded), "--root", loaded.Root)
	if err != nil {
		return Result{}, err
	}
	var plan hostdeployment.Plan
	if err = decodeStrict(planRaw, &plan); err != nil {
		return Result{}, err
	}
	if err = enforceExpectedBundleBinding(loaded.Config, plan.Bundle); err != nil {
		return Result{}, fmt.Errorf("staged remote bundle binding: %w", err)
	}
	if plan.SpecDigest != remoteSpecDigest {
		return Result{}, errors.New("remote deployment spec digest does not match locally staged spec")
	}
	stateRaw, err := runRemotePlatformctl(ctx, runner, sshBinary, loaded, controlPath, "installer-host", "apply", "--spec", remoteDeploymentSpecPath(loaded), "--root", loaded.Root, "--confirmation", ConfirmationDeploy)
	if err != nil {
		return Result{}, err
	}
	var state hostdeployment.State
	if err = decodeStrict(stateRaw, &state); err != nil {
		return Result{}, fmt.Errorf("decode remote deployment state: %w", err)
	}
	if err = enforceExpectedBundleBinding(loaded.Config, state.Plan.Bundle); err != nil {
		return Result{}, fmt.Errorf("applied remote bundle binding: %w", err)
	}
	prepared := Prepared{SchemaVersion: 2, Name: loaded.Config.Metadata.Name, Version: loaded.Config.Metadata.Version, Target: RemoteTarget{Host: loaded.Host, User: loaded.User, Root: loaded.Root, Architecture: normalizeArchitecture(arch), Trust: loaded.Trust}, StageDirectory: loaded.StageDirectory, StageManifestDigest: manifest.Digest, DeploymentSpecDigest: remoteSpecDigest, BundleBindingAuthority: ExpectedBundleAuthority, Admission: admission, Plan: plan}
	result = Result{Prepared: prepared, State: state}
	return result, nil
}

func Status(ctx context.Context, specPath string, options Options) (hostdeployment.State, error) {
	raw, err := runControl(ctx, specPath, options, "status")
	if err != nil {
		return hostdeployment.State{}, err
	}
	var state hostdeployment.State
	if err = decodeStrict(raw, &state); err != nil {
		return state, err
	}
	loaded, loadErr := loadAndValidate(specPath)
	if loadErr != nil {
		return state, loadErr
	}
	if err = enforceExpectedBundleBinding(loaded.Config, state.Plan.Bundle); err != nil {
		return state, fmt.Errorf("remote deployment state bundle binding: %w", err)
	}
	return state, nil
}

func Verify(ctx context.Context, specPath string, options Options) (hostdeployment.VerifyResult, error) {
	raw, err := runControl(ctx, specPath, options, "verify")
	if err != nil {
		return hostdeployment.VerifyResult{}, err
	}
	var result hostdeployment.VerifyResult
	if err = decodeStrict(raw, &result); err != nil {
		return result, err
	}
	loaded, loadErr := loadAndValidate(specPath)
	if loadErr != nil {
		return result, loadErr
	}
	if result.BundleDigest != loaded.Config.Spec.ExpectedBundle.BundleDigest || result.LockDigest != loaded.Config.Spec.ExpectedBundle.LockDigest {
		return result, errors.New("remote verify result does not match expected bundle binding")
	}
	return result, nil
}

func Rollback(ctx context.Context, specPath, confirmation string, options Options) (hostdeployment.State, error) {
	if confirmation != ConfirmationRollback {
		return hostdeployment.State{}, errors.New("confirmation must be exactly ROLLBACK")
	}
	raw, err := runControl(ctx, specPath, options, "rollback", "--confirmation", ConfirmationRollback)
	if err != nil {
		return hostdeployment.State{}, err
	}
	var state hostdeployment.State
	if err = decodeStrict(raw, &state); err != nil {
		return state, err
	}
	loaded, loadErr := loadAndValidate(specPath)
	if loadErr != nil {
		return state, loadErr
	}
	if err = enforceExpectedBundleBinding(loaded.Config, state.Plan.Bundle); err != nil {
		return state, fmt.Errorf("remote rollback state bundle binding: %w", err)
	}
	return state, nil
}

func Recover(ctx context.Context, specPath, confirmation string, options Options) (hostdeployment.State, error) {
	if confirmation != ConfirmationRecover {
		return hostdeployment.State{}, errors.New("confirmation must be exactly RECOVER")
	}
	raw, err := runControl(ctx, specPath, options, "recover", "--confirmation", ConfirmationRecover)
	if err != nil {
		return hostdeployment.State{}, err
	}
	var state hostdeployment.State
	if err = decodeStrict(raw, &state); err != nil {
		return state, err
	}
	loaded, loadErr := loadAndValidate(specPath)
	if loadErr != nil {
		return state, loadErr
	}
	if err = enforceExpectedBundleBinding(loaded.Config, state.Plan.Bundle); err != nil {
		return state, fmt.Errorf("remote recovery state bundle binding: %w", err)
	}
	return state, nil
}

func runControl(ctx context.Context, specPath string, options Options, subcommand string, extra ...string) (raw []byte, retErr error) {
	loaded, err := loadAndValidate(specPath)
	if err != nil {
		return nil, err
	}
	runner := options.Runner
	if runner == nil {
		runner = ExecRunner{}
	}
	sshBinary := options.SSHBinary
	if strings.TrimSpace(sshBinary) == "" {
		sshBinary = "ssh"
	}
	arch, err := remoteArchitecture(ctx, runner, sshBinary, loaded)
	if err != nil {
		return nil, err
	}
	localArch, err := executableArchitecture(loaded.Platformctl)
	if err != nil {
		return nil, err
	}
	if normalizeArchitecture(arch) != localArch {
		return nil, fmt.Errorf("remote architecture %q does not match platformctl architecture %q", arch, localArch)
	}
	controlPath, cleanup, err := stageControlBinary(ctx, runner, sshBinary, loaded)
	if err != nil {
		return nil, err
	}
	defer func() {
		if cleanupErr := cleanup(); cleanupErr != nil {
			retErr = errors.Join(retErr, fmt.Errorf("cleanup remote platformctl: %w", cleanupErr))
		}
	}()
	args := []string{"installer-host", subcommand, "--root", loaded.Root}
	args = append(args, extra...)
	raw, retErr = runRemotePlatformctl(ctx, runner, sshBinary, loaded, controlPath, args...)
	return raw, retErr
}

func loadAndValidate(specPath string) (loadedSpec, error) {
	config, err := LoadSpec(specPath)
	if err != nil {
		return loadedSpec{}, err
	}
	base := filepath.Dir(specPath)
	abs := func(p string) (string, error) {
		if !filepath.IsAbs(p) {
			p = filepath.Join(base, p)
		}
		return filepath.Abs(p)
	}
	platformctl, err := abs(config.Spec.PlatformctlBinary)
	if err != nil {
		return loadedSpec{}, err
	}
	deploymentPath, err := abs(config.Spec.DeploymentSpec)
	if err != nil {
		return loadedSpec{}, err
	}
	identity, err := abs(config.Spec.Target.IdentityFile)
	if err != nil {
		return loadedSpec{}, err
	}
	known, err := abs(config.Spec.Target.KnownHostsFile)
	if err != nil {
		return loadedSpec{}, err
	}
	if err = validatePrivateFile(identity, "SSH identity"); err != nil {
		return loadedSpec{}, err
	}
	if err = validatePrivateFile(known, "known_hosts"); err != nil {
		return loadedSpec{}, err
	}
	trustRaw, err := os.ReadFile(known)
	if err != nil {
		return loadedSpec{}, err
	}
	entries, _, err := bootstrap.ParseSSHKnownHosts(trustRaw)
	if err != nil {
		return loadedSpec{}, err
	}
	canonical := strings.ToLower(strings.TrimSuffix(strings.Trim(config.Spec.Target.Host, "[]"), "."))
	var trust []HostTrust
	for _, entry := range entries {
		if strings.ToLower(strings.TrimSuffix(entry.Host, ".")) == canonical {
			trust = append(trust, HostTrust{Host: entry.Host, KeyType: entry.KeyType, Fingerprint: entry.Fingerprint})
		}
	}
	if len(trust) == 0 {
		return loadedSpec{}, fmt.Errorf("remote SSH host %s has no pinned host key", config.Spec.Target.Host)
	}
	if err = validateExecutable(platformctl, "platformctl binary"); err != nil {
		return loadedSpec{}, err
	}
	ctlVersion, err := runVersion(platformctl, "version")
	if err != nil {
		return loadedSpec{}, err
	}
	if ctlVersion != config.Metadata.Version {
		return loadedSpec{}, fmt.Errorf("platformctl version %q does not match remote bootstrap version %q", ctlVersion, config.Metadata.Version)
	}
	deployment, _, err := hostdeployment.LoadSpec(deploymentPath)
	if err != nil {
		return loadedSpec{}, err
	}
	if deployment.Metadata.Version != config.Metadata.Version {
		return loadedSpec{}, fmt.Errorf("deployment version %q does not match remote bootstrap version %q", deployment.Metadata.Version, config.Metadata.Version)
	}
	deploymentBase := filepath.Dir(deploymentPath)
	installer, err := absFrom(deploymentBase, deployment.Spec.InstallerBinary)
	if err != nil {
		return loadedSpec{}, err
	}
	bundle, err := absFrom(deploymentBase, deployment.Spec.BundleDirectory)
	if err != nil {
		return loadedSpec{}, err
	}
	// Deployment source paths are resolved relative to the deployment specification.
	deployment.Spec.InstallerBinary = installer
	deployment.Spec.BundleDirectory = bundle
	if err = validateExecutable(installer, "platform-installer binary"); err != nil {
		return loadedSpec{}, err
	}
	installerVersion, err := runVersion(installer, "--version")
	if err != nil {
		return loadedSpec{}, err
	}
	if installerVersion != config.Metadata.Version {
		return loadedSpec{}, fmt.Errorf("platform-installer version %q does not match remote bootstrap version %q", installerVersion, config.Metadata.Version)
	}
	bundleStatus, err := bootstrap.InspectBundle(bundle, true)
	if err != nil {
		return loadedSpec{}, fmt.Errorf("verify source bundle: %w", err)
	}
	if bundleStatus.Version != config.Metadata.Version {
		return loadedSpec{}, fmt.Errorf("bundle version %q does not match remote bootstrap version %q", bundleStatus.Version, config.Metadata.Version)
	}
	if err = enforceExpectedBundleBinding(config, bundleStatus); err != nil {
		return loadedSpec{}, err
	}
	cert, key := "", ""
	if strings.TrimSpace(deployment.Spec.TLS.CertificateFile) != "" {
		cert, err = absFrom(deploymentBase, deployment.Spec.TLS.CertificateFile)
		if err != nil {
			return loadedSpec{}, err
		}
		deployment.Spec.TLS.CertificateFile = cert
		if err = validateRegular(cert, false); err != nil {
			return loadedSpec{}, err
		}
	}
	if strings.TrimSpace(deployment.Spec.TLS.PrivateKeyFile) != "" {
		key, err = absFrom(deploymentBase, deployment.Spec.TLS.PrivateKeyFile)
		if err != nil {
			return loadedSpec{}, err
		}
		deployment.Spec.TLS.PrivateKeyFile = key
		if err = validatePrivateFile(key, "TLS private key"); err != nil {
			return loadedSpec{}, err
		}
	}
	root := config.Spec.Target.Root
	hashInput := config.Metadata.Version + "\n" + config.Spec.Target.Host + "\n" + root + "\n" + bundleStatus.BundleDigest + "\n" + installerVersion
	sum := sha256.Sum256([]byte(hashInput))
	id := hex.EncodeToString(sum[:])[:20]
	stage := filepath.Join(root, "var/lib/4so-platform-installer/remote-bootstrap", id)
	return loadedSpec{Config: config, Deployment: deployment, Platformctl: platformctl, DeploymentSpecPath: deploymentPath, InstallerBinary: installer, BundleDirectory: bundle, TLSCertificate: cert, TLSPrivateKey: key, IdentityFile: identity, KnownHostsFile: known, Root: root, Host: config.Spec.Target.Host, User: config.Spec.Target.User, Trust: trust, StageDirectory: stage}, nil
}

func absFrom(base, p string) (string, error) {
	if filepath.IsAbs(p) {
		return filepath.Abs(p)
	}
	return filepath.Abs(filepath.Join(base, p))
}

func canonicalSHA256(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && value == strings.ToLower(value)
}

func enforceExpectedBundleBinding(config Spec, status bootstrap.BundleAdmissionStatus) error {
	expected := config.Spec.ExpectedBundle
	if status.BundleDigest != expected.BundleDigest || status.LockDigest != expected.LockDigest {
		return fmt.Errorf("bundle binding mismatch: expected bundle=%s lock=%s got bundle=%s lock=%s", expected.BundleDigest, expected.LockDigest, status.BundleDigest, status.LockDigest)
	}
	return nil
}

func validateRemoteRoot(root string) error {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return fmt.Errorf("target root %q must be a clean absolute path", root)
	}
	if strings.Contains(root, "..") || strings.ContainsAny(root, "\x00\r\n\t'\"`$;&|<>") {
		return fmt.Errorf("target root %q contains unsafe characters", root)
	}
	return nil
}

func validateRegular(path string, executable bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s must be a regular file", path)
	}
	if executable && info.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("%s must be executable", path)
	}
	return nil
}
func validateExecutable(path, label string) error {
	if err := validateRegular(path, true); err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	return nil
}
func validatePrivateFile(path, label string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s must be a regular file", label)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s permissions must not grant group/world access", label)
	}
	return nil
}
func runVersion(path, arg string) (string, error) {
	out, err := exec.Command(path, arg).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("read version from %s: %w: %s", path, err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

func executableArchitecture(path string) (string, error) {
	f, err := elf.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	switch f.FileHeader.Machine {
	case elf.EM_X86_64:
		return "amd64", nil
	case elf.EM_AARCH64:
		return "arm64", nil
	default:
		return "", fmt.Errorf("unsupported ELF architecture %s", f.FileHeader.Machine)
	}
}
func normalizeArchitecture(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "x86_64", "amd64":
		return "amd64"
	case "aarch64", "arm64":
		return "arm64"
	default:
		return strings.ToLower(strings.TrimSpace(v))
	}
}

func remoteArchitecture(ctx context.Context, runner Runner, sshBinary string, loaded loadedSpec) (string, error) {
	out, err := runSSH(ctx, runner, sshBinary, loaded, nil, "printf '%s %s %s\\n' \"$(uname -s)\" \"$(uname -m)\" \"$(id -u)\"")
	if err != nil {
		return "", err
	}
	fields := strings.Fields(string(out))
	if len(fields) != 3 {
		return "", fmt.Errorf("unexpected remote host probe output %q", strings.TrimSpace(string(out)))
	}
	if fields[0] != "Linux" {
		return "", fmt.Errorf("remote installer bootstrap requires Linux, got %q", fields[0])
	}
	if fields[2] != "0" {
		return "", fmt.Errorf("remote installer bootstrap requires root SSH execution, got uid %q", fields[2])
	}
	return fields[1], nil
}

func sshArgs(loaded loadedSpec) []string {
	return []string{"-i", loaded.IdentityFile, "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no", "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + loaded.KnownHostsFile, "-o", "GlobalKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR", loaded.User + "@" + loaded.Host}
}
func runSSH(ctx context.Context, runner Runner, sshBinary string, loaded loadedSpec, stdin io.Reader, command string) ([]byte, error) {
	args := append(sshArgs(loaded), command)
	return runner.Run(ctx, stdin, sshBinary, args...)
}

func newRemoteOperationID() (string, error) {
	var raw [12]byte
	if _, err := cryptorand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate remote bootstrap operation identity: %w", err)
	}
	return hex.EncodeToString(raw[:]), nil
}

func isolateRemoteStage(loaded loadedSpec) (loadedSpec, error) {
	operationID, err := newRemoteOperationID()
	if err != nil {
		return loadedSpec{}, err
	}
	loaded.StageDirectory = loaded.StageDirectory + "-" + operationID
	return loaded, nil
}

func stageControlBinary(ctx context.Context, runner Runner, sshBinary string, loaded loadedSpec) (string, func() error, error) {
	digest, err := fileSHA(loaded.Platformctl)
	if err != nil {
		return "", func() error { return nil }, err
	}
	operationID, err := newRemoteOperationID()
	if err != nil {
		return "", func() error { return nil }, err
	}
	path := "/tmp/.4so-platformctl-" + strings.TrimPrefix(digest, "sha256:")[:20] + "-" + operationID
	f, err := os.Open(loaded.Platformctl)
	if err != nil {
		return "", func() error { return nil }, err
	}
	defer f.Close()
	command := "umask 077; cat > " + shellQuote(path) + " && chmod 0700 " + shellQuote(path)
	if _, err = runSSH(ctx, runner, sshBinary, loaded, f, command); err != nil {
		cleanupErr := removeRemoteControlBinary(runner, sshBinary, loaded, path)
		return "", func() error { return nil }, errors.Join(fmt.Errorf("stage remote platformctl: %w", err), cleanupErr)
	}
	cleanup := func() error {
		return removeRemoteControlBinary(runner, sshBinary, loaded, path)
	}
	return path, cleanup, nil
}

func removeRemoteControlBinary(runner Runner, sshBinary string, loaded loadedSpec, path string) error {
	ctx, cancel := context.WithTimeout(context.Background(), remoteCleanupTimeout)
	defer cancel()
	if _, err := runSSH(ctx, runner, sshBinary, loaded, nil, "rm -f -- "+shellQuote(path)); err != nil {
		return fmt.Errorf("remove staged remote platformctl: %w", err)
	}
	return nil
}

func runRemotePlatformctl(ctx context.Context, runner Runner, sshBinary string, loaded loadedSpec, controlPath string, args ...string) ([]byte, error) {
	parts := []string{shellQuote(controlPath)}
	for _, arg := range args {
		parts = append(parts, shellQuote(arg))
	}
	return runSSH(ctx, runner, sshBinary, loaded, nil, strings.Join(parts, " "))
}

func cleanupRemoteStage(runner Runner, sshBinary string, loaded loadedSpec, controlPath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), remoteCleanupTimeout)
	defer cancel()
	if _, err := runRemotePlatformctl(ctx, runner, sshBinary, loaded, controlPath, "installer-remote", "remove-stage", "--dir", loaded.StageDirectory); err != nil {
		return err
	}
	return nil
}
func remoteDeploymentSpecPath(loaded loadedSpec) string {
	return filepath.Join(loaded.StageDirectory, "deployment.json")
}

func buildStageArchive(loaded loadedSpec) (StageManifest, *os.File, string, error) {
	remoteSpec := loaded.Deployment
	remoteSpec.Spec.InstallerBinary = filepath.Join(loaded.StageDirectory, "platform-installer")
	remoteSpec.Spec.BundleDirectory = filepath.Join(loaded.StageDirectory, "bundle")
	if loaded.TLSCertificate != "" {
		remoteSpec.Spec.TLS.CertificateFile = filepath.Join(loaded.StageDirectory, "tls.crt")
	}
	if loaded.TLSPrivateKey != "" {
		remoteSpec.Spec.TLS.PrivateKeyFile = filepath.Join(loaded.StageDirectory, "tls.key")
	}
	specRaw, err := json.MarshalIndent(remoteSpec, "", "  ")
	if err != nil {
		return StageManifest{}, nil, "", err
	}
	specRaw = append(specRaw, '\n')
	entries := map[string]stageSource{"deployment.json": {data: specRaw, mode: 0o600}, "platform-installer": {path: loaded.InstallerBinary, mode: 0o755}}
	if loaded.TLSCertificate != "" {
		entries["tls.crt"] = stageSource{path: loaded.TLSCertificate, mode: 0o644}
	}
	if loaded.TLSPrivateKey != "" {
		entries["tls.key"] = stageSource{path: loaded.TLSPrivateKey, mode: 0o600}
	}
	err = filepath.WalkDir(loaded.BundleDirectory, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("bundle stage source %s must be a regular non-symlink file", path)
		}
		rel, err := filepath.Rel(loaded.BundleDirectory, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if err = validateRelative(rel); err != nil {
			return err
		}
		mode := uint32(0o644)
		if info.Mode().Perm()&0o111 != 0 {
			mode = 0o755
		}
		entries["bundle/"+rel] = stageSource{path: path, mode: mode}
		return nil
	})
	if err != nil {
		return StageManifest{}, nil, "", err
	}
	archive, err := os.CreateTemp("", "4so-platform-remote-stage-*.tar")
	if err != nil {
		return StageManifest{}, nil, "", err
	}
	if err = archive.Chmod(0o600); err != nil {
		cleanupStageArchive(archive)
		return StageManifest{}, nil, "", err
	}
	manifest, err := writeArchive(entries, archive)
	if err != nil {
		cleanupStageArchive(archive)
		return StageManifest{}, nil, "", err
	}
	if err = archive.Sync(); err != nil {
		cleanupStageArchive(archive)
		return StageManifest{}, nil, "", err
	}
	if _, err = archive.Seek(0, io.SeekStart); err != nil {
		cleanupStageArchive(archive)
		return StageManifest{}, nil, "", err
	}
	return manifest, archive, digest(specRaw), nil
}

type stageSource struct {
	path string
	data []byte
	mode uint32
}

func openStageSource(path string) (*os.File, os.FileInfo, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("stage source %s must be a regular non-symlink file", path)
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, err
	}
	opened, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		_ = file.Close()
		return nil, nil, fmt.Errorf("stage source %s changed while opening", path)
	}
	return file, opened, nil
}

func stageSourceUnchanged(before, after os.FileInfo) bool {
	return os.SameFile(before, after) && before.Size() == after.Size() && before.ModTime().Equal(after.ModTime())
}

func writeArchive(sources map[string]stageSource, output io.Writer) (StageManifest, error) {
	names := make([]string, 0, len(sources))
	for n := range sources {
		if err := validateRelative(n); err != nil {
			return StageManifest{}, err
		}
		names = append(names, n)
	}
	sort.Strings(names)
	var manifest StageManifest
	manifest.SchemaVersion = StageManifestSchema
	tw := tar.NewWriter(output)
	for _, name := range names {
		src := sources[name]
		var size int64
		var file *os.File
		var opened os.FileInfo
		if src.path != "" {
			var err error
			file, opened, err = openStageSource(src.path)
			if err != nil {
				_ = tw.Close()
				return manifest, err
			}
			size = opened.Size()
		} else {
			size = int64(len(src.data))
		}
		hdr := &tar.Header{Name: name, Mode: int64(src.mode), Size: size, Typeflag: tar.TypeReg, ModTime: time.Unix(0, 0)}
		if err := tw.WriteHeader(hdr); err != nil {
			if file != nil {
				_ = file.Close()
			}
			_ = tw.Close()
			return manifest, err
		}
		h := sha256.New()
		writer := io.MultiWriter(tw, h)
		if file != nil {
			written, err := io.CopyN(writer, file, size)
			if err != nil || written != size {
				_ = file.Close()
				_ = tw.Close()
				if err == nil {
					err = io.ErrUnexpectedEOF
				}
				return manifest, fmt.Errorf("read stage source %s: %w", src.path, err)
			}
			var extra [1]byte
			n, readErr := file.Read(extra[:])
			after, statErr := file.Stat()
			closeErr := file.Close()
			if statErr != nil {
				_ = tw.Close()
				return manifest, statErr
			}
			if closeErr != nil {
				_ = tw.Close()
				return manifest, closeErr
			}
			if n != 0 || (readErr != nil && !errors.Is(readErr, io.EOF)) || !stageSourceUnchanged(opened, after) {
				_ = tw.Close()
				return manifest, fmt.Errorf("stage source %s changed while snapshotting", src.path)
			}
		} else {
			if _, err := writer.Write(src.data); err != nil {
				_ = tw.Close()
				return manifest, err
			}
		}
		manifest.Entries = append(manifest.Entries, StageManifestEntry{Path: name, Mode: src.mode, Size: size, SHA256: "sha256:" + hex.EncodeToString(h.Sum(nil))})
	}
	if err := tw.Close(); err != nil {
		return manifest, err
	}
	manifest.Digest = manifestDigest(manifest.Entries)
	return manifest, nil
}

func makeArchive(sources map[string]stageSource) (StageManifest, []byte, error) {
	var buf bytes.Buffer
	manifest, err := writeArchive(sources, &buf)
	if err != nil {
		return manifest, nil, err
	}
	return manifest, buf.Bytes(), nil
}

func cleanupStageArchive(archive *os.File) {
	if archive == nil {
		return
	}
	name := archive.Name()
	_ = archive.Close()
	_ = os.Remove(name)
}

func receiveStage(ctx context.Context, runner Runner, sshBinary string, loaded loadedSpec, controlPath string, manifest StageManifest, archive io.Reader) error {
	_, err := runSSH(ctx, runner, sshBinary, loaded, archive, shellQuote(controlPath)+" installer-remote receive-stage --dir "+shellQuote(loaded.StageDirectory)+" --manifest-digest "+shellQuote(manifest.Digest))
	return err
}

func ReceiveStage(destination, expectedDigest string, input io.Reader) (StageManifest, error) {
	if err := validateStageDestination(destination); err != nil {
		return StageManifest{}, err
	}
	parent := filepath.Dir(destination)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return StageManifest{}, err
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		return StageManifest{}, err
	}
	if err := recoverInterruptedStageSwap(destination); err != nil {
		return StageManifest{}, err
	}
	incoming, err := os.MkdirTemp(parent, "."+filepath.Base(destination)+".*.incoming")
	if err != nil {
		return StageManifest{}, err
	}
	defer os.RemoveAll(incoming)
	if err = os.Chmod(incoming, 0o700); err != nil {
		return StageManifest{}, err
	}
	tr := tar.NewReader(io.LimitReader(input, 64<<30))
	var entries []StageManifestEntry
	seen := map[string]bool{}
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return StageManifest{}, err
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			return StageManifest{}, fmt.Errorf("stage archive entry %s is not a regular file", hdr.Name)
		}
		name := filepath.ToSlash(hdr.Name)
		if err = validateRelative(name); err != nil {
			return StageManifest{}, err
		}
		if seen[name] {
			return StageManifest{}, fmt.Errorf("duplicate stage archive entry %s", name)
		}
		seen[name] = true
		if hdr.Size < 0 || hdr.Size > 32<<30 {
			return StageManifest{}, fmt.Errorf("stage archive entry %s has invalid size", name)
		}
		mode := uint32(hdr.Mode) & 0o755
		if mode&0o022 != 0 {
			return StageManifest{}, fmt.Errorf("stage archive entry %s is group/world writable", name)
		}
		target := filepath.Join(incoming, filepath.FromSlash(name))
		if err = os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return StageManifest{}, err
		}
		tmp, err := os.OpenFile(target+".tmp", os.O_CREATE|os.O_EXCL|os.O_WRONLY, os.FileMode(mode))
		if err != nil {
			return StageManifest{}, err
		}
		h := sha256.New()
		written, copyErr := io.CopyN(io.MultiWriter(tmp, h), tr, hdr.Size)
		syncErr := tmp.Sync()
		closeErr := tmp.Close()
		if copyErr != nil {
			return StageManifest{}, copyErr
		}
		if syncErr != nil {
			return StageManifest{}, syncErr
		}
		if closeErr != nil {
			return StageManifest{}, closeErr
		}
		if written != hdr.Size {
			return StageManifest{}, fmt.Errorf("short stage archive entry %s", name)
		}
		if err = os.Rename(target+".tmp", target); err != nil {
			return StageManifest{}, err
		}
		if err = syncDirectory(filepath.Dir(target)); err != nil {
			return StageManifest{}, err
		}
		entries = append(entries, StageManifestEntry{Path: name, Mode: mode, Size: hdr.Size, SHA256: "sha256:" + hex.EncodeToString(h.Sum(nil))})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	manifest := StageManifest{SchemaVersion: StageManifestSchema, Entries: entries}
	manifest.Digest = manifestDigest(entries)
	if manifest.Digest != expectedDigest {
		return StageManifest{}, fmt.Errorf("stage manifest digest %s does not match expected %s", manifest.Digest, expectedDigest)
	}
	raw, _ := json.MarshalIndent(manifest, "", "  ")
	raw = append(raw, '\n')
	if err = writePrivate(filepath.Join(incoming, "stage-manifest.json"), raw, 0o600); err != nil {
		return StageManifest{}, err
	}
	if err = syncTreeDirectories(incoming); err != nil {
		return StageManifest{}, err
	}
	if err = replaceStageDirectory(destination, incoming); err != nil {
		return StageManifest{}, err
	}
	return manifest, nil
}

func VerifyStage(destination, expectedDigest string) (StageManifest, error) {
	if err := validateStageDestination(destination); err != nil {
		return StageManifest{}, err
	}
	if err := recoverInterruptedStageSwap(destination); err != nil {
		return StageManifest{}, err
	}
	raw, err := os.ReadFile(filepath.Join(destination, "stage-manifest.json"))
	if err != nil {
		return StageManifest{}, err
	}
	var manifest StageManifest
	if err = decodeStrict(raw, &manifest); err != nil {
		return manifest, err
	}
	if manifest.SchemaVersion != StageManifestSchema {
		return manifest, fmt.Errorf("unsupported stage manifest schema %d", manifest.SchemaVersion)
	}
	if manifest.Digest != expectedDigest {
		return manifest, fmt.Errorf("stage manifest digest %s does not match expected %s", manifest.Digest, expectedDigest)
	}
	if manifestDigest(manifest.Entries) != manifest.Digest {
		return manifest, errors.New("stage manifest content digest is invalid")
	}
	expected := map[string]StageManifestEntry{}
	for _, e := range manifest.Entries {
		if err = validateRelative(e.Path); err != nil {
			return manifest, err
		}
		expected[e.Path] = e
	}
	seen := map[string]bool{}
	err = filepath.WalkDir(destination, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == destination {
			return nil
		}
		rel, _ := filepath.Rel(destination, path)
		rel = filepath.ToSlash(rel)
		if rel == "stage-manifest.json" {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("stage entry %s is not a regular file", rel)
		}
		want, ok := expected[rel]
		if !ok {
			return fmt.Errorf("unindexed stage file %s", rel)
		}
		seen[rel] = true
		if uint32(info.Mode().Perm()) != want.Mode {
			return fmt.Errorf("stage file %s mode changed", rel)
		}
		if info.Size() != want.Size {
			return fmt.Errorf("stage file %s size changed", rel)
		}
		got, err := fileSHA(path)
		if err != nil {
			return err
		}
		if got != want.SHA256 {
			return fmt.Errorf("stage file %s digest changed", rel)
		}
		return nil
	})
	if err != nil {
		return manifest, err
	}
	for path := range expected {
		if !seen[path] {
			return manifest, fmt.Errorf("stage file %s is missing", path)
		}
	}
	return manifest, nil
}

func RemoveStage(destination string) error {
	if err := validateStageDestination(destination); err != nil {
		return err
	}
	parent := filepath.Dir(destination)
	paths := []string{destination, stageBackupPath(destination)}
	entries, err := os.ReadDir(parent)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	prefix := "." + filepath.Base(destination) + "."
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, prefix) && strings.HasSuffix(name, ".incoming") {
			paths = append(paths, filepath.Join(parent, name))
		}
	}
	for _, path := range paths {
		if err := os.RemoveAll(path); err != nil {
			return err
		}
	}
	if _, err := os.Stat(parent); err == nil {
		return syncDirectory(parent)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func validateStageDestination(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("stage directory %q must be a clean absolute path", path)
	}
	if !strings.Contains(filepath.ToSlash(path), "/var/lib/4so-platform-installer/remote-bootstrap/") {
		return fmt.Errorf("stage directory %q is outside the remote-bootstrap authority", path)
	}
	if err := rejectSymlinkAncestors(filepath.Dir(path)); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("stage directory %q must not be a symlink", path)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func rejectSymlinkAncestors(path string) error {
	current := filepath.Clean(path)
	for {
		info, err := os.Lstat(current)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("remote bootstrap stage path contains symlink ancestor %q", current)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	return nil
}
func validateRelative(path string) error {
	if path == "" || strings.HasPrefix(path, "/") || filepath.Clean(filepath.FromSlash(path)) != filepath.FromSlash(path) || strings.Contains(path, "\\") || strings.HasPrefix(path, "../") || path == ".." {
		return fmt.Errorf("unsafe stage path %q", path)
	}
	return nil
}
func manifestDigest(entries []StageManifestEntry) string {
	copyEntries := append([]StageManifestEntry(nil), entries...)
	sort.Slice(copyEntries, func(i, j int) bool { return copyEntries[i].Path < copyEntries[j].Path })
	raw, _ := json.Marshal(copyEntries)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func fileSHA(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }
func writePrivate(path string, data []byte, mode os.FileMode) error {
	return durablefile.Replace(path, data, 0o700, mode)
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	if err = dir.Sync(); err != nil {
		_ = dir.Close()
		return err
	}
	return dir.Close()
}

func syncTreeDirectories(root string) error {
	var directories []string
	if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			directories = append(directories, path)
		}
		return nil
	}); err != nil {
		return err
	}
	sort.Slice(directories, func(i, j int) bool {
		return strings.Count(directories[i], string(os.PathSeparator)) > strings.Count(directories[j], string(os.PathSeparator))
	})
	for _, directory := range directories {
		if err := syncDirectory(directory); err != nil {
			return err
		}
	}
	return nil
}

func stageBackupPath(destination string) string { return destination + ".previous" }

func recoverInterruptedStageSwap(destination string) error {
	backup := stageBackupPath(destination)
	_, destinationErr := os.Lstat(destination)
	_, backupErr := os.Lstat(backup)
	destinationExists := destinationErr == nil
	backupExists := backupErr == nil
	if destinationErr != nil && !errors.Is(destinationErr, os.ErrNotExist) {
		return destinationErr
	}
	if backupErr != nil && !errors.Is(backupErr, os.ErrNotExist) {
		return backupErr
	}
	parent := filepath.Dir(destination)
	switch {
	case !destinationExists && backupExists:
		if err := os.Rename(backup, destination); err != nil {
			return fmt.Errorf("recover interrupted remote stage: %w", err)
		}
		return syncDirectory(parent)
	case destinationExists && backupExists:
		if err := os.RemoveAll(backup); err != nil {
			return fmt.Errorf("remove completed remote stage backup: %w", err)
		}
		return syncDirectory(parent)
	default:
		return nil
	}
}

func replaceStageDirectory(destination, incoming string) error {
	parent := filepath.Dir(destination)
	backup := stageBackupPath(destination)
	if err := os.RemoveAll(backup); err != nil {
		return err
	}
	hadDestination := true
	if _, err := os.Lstat(destination); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		hadDestination = false
	}
	if hadDestination {
		if err := os.Rename(destination, backup); err != nil {
			return err
		}
		if err := syncDirectory(parent); err != nil {
			_ = os.Rename(backup, destination)
			_ = syncDirectory(parent)
			return err
		}
	}
	if err := os.Rename(incoming, destination); err != nil {
		if hadDestination {
			_ = os.Rename(backup, destination)
			_ = syncDirectory(parent)
		}
		return err
	}
	if err := syncDirectory(parent); err != nil {
		if hadDestination {
			_ = os.RemoveAll(destination)
			_ = os.Rename(backup, destination)
			_ = syncDirectory(parent)
		}
		return err
	}
	if hadDestination {
		if err := os.RemoveAll(backup); err != nil {
			return err
		}
		if err := syncDirectory(parent); err != nil {
			return err
		}
	}
	return nil
}
func decodeStrict(raw []byte, out any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}
