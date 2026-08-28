package bootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"platform.4so.io/factory/internal/durablefile"
	"platform.4so.io/factory/internal/installation"
)

const (
	PreflightAPIVersion = "platform.4so.io/v1alpha1"
	PreflightKind       = "AppliancePreflightReport"
	PreflightSchema     = 1
	PreflightPassed     = "PASSED"
	PreflightBlocked    = "BLOCKED"
	CheckPassed         = "PASSED"
	CheckBlocked        = "BLOCKED"
	CheckSkipped        = "SKIPPED"
)

type PreflightCheck struct {
	Key    string `json:"key"`
	Title  string `json:"title"`
	State  string `json:"state"`
	Detail string `json:"detail"`
}

type PreflightReport struct {
	APIVersion    string           `json:"apiVersion"`
	Kind          string           `json:"kind"`
	SchemaVersion int              `json:"schemaVersion"`
	ID            string           `json:"id"`
	State         string           `json:"state"`
	Version       string           `json:"version"`
	ProfileID     string           `json:"profileId"`
	Connectivity  string           `json:"connectivity"`
	RequestDigest string           `json:"requestDigest"`
	BundleDigest  string           `json:"bundleDigest,omitempty"`
	Simulation    bool             `json:"simulation"`
	GeneratedAt   time.Time        `json:"generatedAt"`
	Checks        []PreflightCheck `json:"checks"`
	Digest        string           `json:"digest"`
}

type preflightDigestPayload struct {
	SchemaVersion int              `json:"schemaVersion"`
	Version       string           `json:"version"`
	ProfileID     string           `json:"profileId"`
	Connectivity  string           `json:"connectivity"`
	RequestDigest string           `json:"requestDigest"`
	BundleDigest  string           `json:"bundleDigest,omitempty"`
	Simulation    bool             `json:"simulation"`
	Checks        []PreflightCheck `json:"checks"`
}

func (p PreflightReport) Passed() bool { return p.State == PreflightPassed }

// Seal derives the aggregate state, evidence digest and deterministic report ID
// from the report checks. It is also used by independent test and tooling code
// to construct a report that the same verifier can validate.
func (p *PreflightReport) Seal() error {
	if p.GeneratedAt.IsZero() {
		p.GeneratedAt = time.Now().UTC()
	}
	p.State = PreflightPassed
	for _, check := range p.Checks {
		if check.State == CheckBlocked {
			p.State = PreflightBlocked
		}
	}
	digest, err := p.computeDigest()
	if err != nil {
		return err
	}
	p.Digest = digest
	p.ID = "preflight-" + strings.TrimPrefix(digest, "sha256:")[:20]
	return nil
}

func (p PreflightReport) computeDigest() (string, error) {
	payload := preflightDigestPayload{
		SchemaVersion: p.SchemaVersion,
		Version:       p.Version,
		ProfileID:     p.ProfileID,
		Connectivity:  p.Connectivity,
		RequestDigest: p.RequestDigest,
		BundleDigest:  p.BundleDigest,
		Simulation:    p.Simulation,
		Checks:        p.Checks,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func (p PreflightReport) Verify() error {
	if p.APIVersion != PreflightAPIVersion || p.Kind != PreflightKind || p.SchemaVersion != PreflightSchema {
		return errors.New("unsupported appliance preflight contract")
	}
	if p.State != PreflightPassed && p.State != PreflightBlocked {
		return fmt.Errorf("invalid preflight state %q", p.State)
	}
	if strings.TrimSpace(p.ID) == "" || strings.TrimSpace(p.Version) == "" || strings.TrimSpace(p.ProfileID) == "" || strings.TrimSpace(p.RequestDigest) == "" {
		return errors.New("preflight identity is incomplete")
	}
	if !digestPattern.MatchString(p.RequestDigest) {
		return errors.New("preflight requestDigest must be a lowercase sha256 digest")
	}
	if p.State == PreflightPassed && !digestPattern.MatchString(p.BundleDigest) {
		return errors.New("passing preflight requires a bundle digest")
	}
	if p.BundleDigest != "" && !digestPattern.MatchString(p.BundleDigest) {
		return errors.New("preflight bundleDigest must be a lowercase sha256 digest")
	}
	blocked := false
	for _, check := range p.Checks {
		if strings.TrimSpace(check.Key) == "" || strings.TrimSpace(check.Title) == "" || strings.TrimSpace(check.Detail) == "" {
			return errors.New("preflight check is incomplete")
		}
		switch check.State {
		case CheckPassed, CheckSkipped:
		case CheckBlocked:
			blocked = true
		default:
			return fmt.Errorf("invalid preflight check state %q", check.State)
		}
	}
	if (p.State == PreflightBlocked) != blocked {
		return errors.New("preflight state does not match check results")
	}
	computed, err := p.computeDigest()
	if err != nil {
		return err
	}
	if p.Digest != computed {
		return errors.New("preflight digest mismatch")
	}
	return nil
}

func (r *Runner) Preflight(ctx context.Context, request installation.InstallRequest) (PreflightReport, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active {
		return PreflightReport{}, fmt.Errorf("%w: bootstrap preflight cannot run while bootstrap execution is active", ErrBootstrapExecutionActive)
	}
	current, err := r.journal.Load()
	if err != nil {
		return PreflightReport{}, fmt.Errorf("load bootstrap journal before preflight: %w", err)
	}
	if current != nil && current.State != RunSucceeded {
		return PreflightReport{}, fmt.Errorf("%w: run %s is %s; use status/diagnostics or Resume instead", ErrPreflightEvidenceOwned, current.ID, current.State)
	}
	return r.preflightUnlocked(ctx, request)
}

func (r *Runner) PreflightStatus() (*PreflightReport, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	path := filepath.Join(r.stateDir, "preflight-report.json")
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	var report PreflightReport
	if err = decoder.Decode(&report); err != nil {
		return nil, fmt.Errorf("decode preflight report: %w", err)
	}
	var extra any
	if err = decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("preflight report has trailing data")
	}
	if err = report.Verify(); err != nil {
		return nil, fmt.Errorf("verify preflight report: %w", err)
	}
	return &report, nil
}

const canonicalLiveInstallerStateDir = "/var/lib/4so-platform-installer"

var kubernetesFreshInstallResidueBasePaths = []string{
	// RKE2 state is product-owned and must never be inherited by a new run.
	"/etc/rancher/rke2",
	"/var/lib/rancher/rke2",
	"/usr/local/bin/rke2",
	"/usr/bin/rke2",
	"/usr/local/bin/rke2-uninstall.sh",
	"/usr/local/bin/rke2-killall.sh",
	// Other Kubernetes distributions can leave kubelet/runtime state that
	// conflicts with the management-plane RKE2 runtime even when stopped.
	"/etc/rancher/k3s",
	"/var/lib/rancher/k3s",
	"/etc/kubernetes",
	"/var/lib/kubelet",
	"/usr/local/bin/k3s",
	"/usr/bin/k3s",
	"/usr/local/bin/kubelet",
	"/usr/bin/kubelet",
	"/usr/local/bin/kubeadm",
	"/usr/bin/kubeadm",
}

var kubernetesFreshInstallResidueUnits = []string{
	"rke2-server.service",
	"rke2-agent.service",
	"k3s.service",
	"k3s-agent.service",
	"kubelet.service",
}

var systemdUnitSearchFallbackDirectories = []string{
	"/etc/systemd/system.control",
	"/run/systemd/system.control",
	"/run/systemd/transient",
	"/run/systemd/generator.early",
	"/etc/systemd/system",
	"/etc/systemd/system.attached",
	"/run/systemd/system",
	"/run/systemd/system.attached",
	"/run/systemd/generator",
	"/usr/local/lib/systemd/system",
	"/usr/lib/systemd/system",
	"/lib/systemd/system",
	"/run/systemd/generator.late",
}

func (r *Runner) systemdUnitSearchDirectories(ctx context.Context) []string {
	seen := map[string]struct{}{}
	directories := make([]string, 0, len(systemdUnitSearchFallbackDirectories)+8)
	add := func(value string) {
		value = filepath.Clean(strings.TrimSpace(value))
		if !filepath.IsAbs(value) || value == "/" {
			return
		}
		if _, exists := seen[value]; exists {
			return
		}
		seen[value] = struct{}{}
		directories = append(directories, value)
	}
	for _, directory := range systemdUnitSearchFallbackDirectories {
		add(directory)
	}
	if raw, err := r.system.Output(ctx, "systemd-analyze", []string{"unit-paths"}, nil); err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			add(line)
		}
	}
	return directories
}

func (r *Runner) kubernetesFreshInstallResiduePaths(ctx context.Context) []string {
	paths := append([]string(nil), kubernetesFreshInstallResidueBasePaths...)
	for _, unit := range kubernetesFreshInstallResidueUnits {
		for _, directory := range r.systemdUnitSearchDirectories(ctx) {
			paths = append(paths, filepath.Join(directory, unit))
		}
	}
	return paths
}

func (r *Runner) existingKubernetesResidue(ctx context.Context) []string {
	paths := r.kubernetesFreshInstallResiduePaths(ctx)
	found := make([]string, 0, len(paths))
	seen := map[string]struct{}{}
	add := func(value string) {
		if _, exists := seen[value]; exists {
			return
		}
		seen[value] = struct{}{}
		found = append(found, value)
	}
	for _, path := range paths {
		if r.system.Exists(path) {
			add(path)
		}
	}
	// On a live local host, systemd itself is the final authority for generated,
	// transient and distribution-specific unit lookup paths. Filesystem scanning
	// above remains as a fail-closed fallback when the manager is offline.
	if r.usesLocalHostFilesystem() {
		for _, unit := range kubernetesFreshInstallResidueUnits {
			if err := r.system.Run(ctx, "systemctl", []string{"cat", unit}, nil); err == nil {
				add("systemd-unit:" + unit)
			}
		}
	}
	return found
}

func (r *Runner) verifySystemdOperational(ctx context.Context) error {
	if r.usesLocalHostFilesystem() && !r.system.Exists("/run/systemd/system") {
		return errors.New("systemd is installed but not running: /run/systemd/system is unavailable")
	}
	if err := r.system.Run(ctx, "systemctl", []string{"show", "--property=Version", "--value"}, nil); err != nil {
		return fmt.Errorf("systemd manager is not operational: %w", err)
	}
	return nil
}

func (r *Runner) usesLocalHostFilesystem() bool {
	switch r.system.(type) {
	case LocalSystem, *LocalSystem:
		return true
	default:
		return false
	}
}

func (r *Runner) existingBootstrapAuthorityResidue() []string {
	// These are generated by prepare-host/bootstrap and are not operator input.
	// SSH identity/known-hosts and the installer-access token are deliberately
	// excluded because they are valid inputs to a fresh bootstrap preflight.
	relative := []string{
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
		"bundle/rke2",
		"bundle/gitops",
		"bundle/fleet",
		"install-request.json",
		"gitops-handover.json",
		"bootstrap-object-identities",
		"ha-nodes",
		"lifecycle-runs.json",
		"disaster-recovery-runs.json",
		"lifecycle",
		"disaster-recovery",
	}
	found := make([]string, 0, len(relative))
	for _, item := range relative {
		path := filepath.Join(r.stateDir, item)
		if r.system.Exists(path) {
			found = append(found, path)
		}
	}
	return found
}

func uniqueNodeAddresses(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		key := strings.ToLower(strings.TrimSuffix(value, "."))
		if ip := net.ParseIP(strings.Trim(value, "[]")); ip != nil {
			key = ip.String()
		}
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			return false
		}
		seen[key] = struct{}{}
	}
	return true
}

func (r *Runner) preflightUnlocked(ctx context.Context, request installation.InstallRequest) (PreflightReport, error) {
	plan, planErr := installation.CreateBootstrapPlan(request)
	if planErr == nil {
		request = plan.EffectiveRequest
	}
	report := PreflightReport{
		APIVersion: PreflightAPIVersion, Kind: PreflightKind, SchemaVersion: PreflightSchema,
		State: PreflightPassed, Version: r.version, ProfileID: strings.TrimSpace(request.ProfileID),
		Connectivity: string(request.Connectivity), Simulation: r.simulation, GeneratedAt: r.now().UTC(),
	}
	if planErr == nil {
		report.RequestDigest = plan.SpecDigest
	}
	add := func(key, title, state, detail string) {
		report.Checks = append(report.Checks, PreflightCheck{Key: key, Title: title, State: state, Detail: detail})
		if state == CheckBlocked {
			report.State = PreflightBlocked
		}
	}
	if planErr != nil {
		add("installation-plan", "Validate installation request", CheckBlocked, planErr.Error())
	} else if !plan.Executable {
		add("installation-plan", "Validate installation request", CheckBlocked, "plan is not executable: "+strings.Join(plan.Blockers, "; "))
	} else {
		add("installation-plan", "Validate installation request", CheckPassed, "request is supported and the generated plan is executable")
	}
	admission, bundleErr := InspectBundle(r.bundleDir, r.requireBundleLock)
	if bundleErr != nil {
		add("bundle-admission", "Verify sealed appliance bundle", CheckBlocked, bundleErr.Error())
	} else {
		report.BundleDigest = admission.BundleDigest
		add("bundle-admission", "Verify sealed appliance bundle", CheckPassed, "bundle manifest, lock, exact index, files and digests are valid")
	}
	if request.ProfileID != "evaluation-single-node" && request.ProfileID != "production-standard-ha" {
		add("profile", "Validate executable deployment profile", CheckBlocked, fmt.Sprintf("version %s executes evaluation-single-node and production-standard-ha", r.version))
	} else {
		add("profile", "Validate executable deployment profile", CheckPassed, "selected profile is implemented by this installer")
	}
	if !r.system.IsRoot() {
		add("root", "Verify privileged installer execution", CheckBlocked, "bootstrap installer must run as root")
	} else {
		add("root", "Verify privileged installer execution", CheckPassed, "installer has root privileges")
	}
	nodeCount := len(request.Infrastructure.NodeAddresses)
	addressesValid := true
	for _, host := range request.Infrastructure.NodeAddresses {
		if err := validateSSHHost(host); err != nil {
			add("host-addresses", "Validate management node addresses", CheckBlocked, err.Error())
			addressesValid = false
			break
		}
	}
	if addressesValid && !uniqueNodeAddresses(request.Infrastructure.NodeAddresses) {
		add("host-addresses", "Validate management node addresses", CheckBlocked, "management node addresses must be unique")
		addressesValid = false
	}
	if addressesValid {
		add("host-addresses", "Validate management node addresses", CheckPassed, "all management node addresses are explicit, unique IP addresses or DNS hostnames")
	}
	switch request.ProfileID {
	case "evaluation-single-node":
		if nodeCount != 1 {
			add("topology", "Validate management topology", CheckBlocked, "evaluation bootstrap requires exactly one management node")
		} else {
			add("topology", "Validate management topology", CheckPassed, "exactly one management node is configured")
		}
	case "production-standard-ha":
		if nodeCount != 3 {
			add("topology", "Validate management topology", CheckBlocked, "HA bootstrap requires exactly three management nodes")
		} else {
			add("topology", "Validate management topology", CheckPassed, "exactly three management nodes are configured")
		}
		if err := r.validateSSHIdentity(request.Infrastructure.CredentialRef, request.Infrastructure.SSHUser); err != nil {
			add("ssh-credential", "Validate restricted HA SSH credential", CheckBlocked, err.Error())
		} else {
			add("ssh-credential", "Validate restricted HA SSH credential", CheckPassed, "HA SSH private key reference, user and permissions are valid")
		}
		peers := []string{}
		if len(request.Infrastructure.NodeAddresses) > 1 {
			peers = request.Infrastructure.NodeAddresses[1:]
		}
		if err := r.validateSSHHostTrust(peers); err != nil {
			add("ssh-host-trust", "Validate pinned HA SSH host keys", CheckBlocked, err.Error())
		} else {
			add("ssh-host-trust", "Validate pinned HA SSH host keys", CheckPassed, "every remote HA peer has an explicitly pinned host key")
		}
		if r.simulation {
			add("ssh-client", "Verify OpenSSH client availability", CheckSkipped, "simulation mode does not execute the SSH client check")
			for index, peer := range peers {
				add(fmt.Sprintf("ha-peer-%d", index+1), "Verify HA peer readiness", CheckSkipped, "simulation mode does not execute remote readiness checks for "+peer)
			}
		} else if _, err := r.system.Output(ctx, "ssh", []string{"-V"}, nil); err != nil {
			add("ssh-client", "Verify OpenSSH client availability", CheckBlocked, err.Error())
		} else {
			add("ssh-client", "Verify OpenSSH client availability", CheckPassed, "OpenSSH client is available; SCP is not required")
			probeRun := Run{Request: request}
			for index, peer := range peers {
				if _, err := r.system.Output(ctx, "ssh", r.sshArgs(probeRun, peer, haPeerPreflightCommand()), nil); err != nil {
					add(fmt.Sprintf("ha-peer-%d", index+1), "Verify HA peer readiness", CheckBlocked, fmt.Sprintf("%s: %v", peer, err))
				} else {
					add(fmt.Sprintf("ha-peer-%d", index+1), "Verify HA peer readiness", CheckPassed, peer+": pinned SSH connectivity, Linux/root/systemd readiness, clean Kubernetes runtime state and required free ports verified")
				}
			}
		}
	default:
		add("topology", "Validate management topology", CheckBlocked, "unsupported profile topology")
	}
	if request.Connectivity == installation.ConnectivityDisconnected {
		if bundleErr != nil || !admission.Verified {
			add("disconnected", "Validate disconnected installation assets", CheckBlocked, "disconnected installation requires a complete admitted bundle")
		} else {
			bundle, _, err := LoadBundle(r.bundleDir)
			if err != nil || !bundle.Spec.Airgap.Complete {
				add("disconnected", "Validate disconnected installation assets", CheckBlocked, "bundle does not declare a complete air-gap set")
			} else {
				add("disconnected", "Validate disconnected installation assets", CheckPassed, "complete air-gap bundle is available locally")
			}
		}
	} else {
		add("disconnected", "Validate disconnected installation assets", CheckSkipped, "connectivity mode does not require disconnected admission")
	}
	if bundleErr == nil && admission.Version != r.version {
		add("version", "Match installer and bundle versions", CheckBlocked, fmt.Sprintf("bundle version %s does not match installer version %s", admission.Version, r.version))
	} else if bundleErr == nil {
		add("version", "Match installer and bundle versions", CheckPassed, "installer and bundle versions match")
	} else {
		add("version", "Match installer and bundle versions", CheckBlocked, "bundle version cannot be trusted until admission passes")
	}
	if r.simulation {
		add("state-directory", "Validate canonical installer state authority", CheckSkipped, "simulation mode uses an isolated state root")
		add("existing-installer-state", "Detect stale installer-owned bootstrap authority", CheckSkipped, "simulation mode uses an isolated filesystem")
		add("systemd", "Verify systemd availability", CheckSkipped, "simulation mode does not execute the host systemd check")
		add("existing-kubernetes", "Detect conflicting Kubernetes runtime residue", CheckSkipped, "simulation mode uses an isolated filesystem")
		for _, port := range []string{"80", "443", "6443", "9345"} {
			add("port-"+port, "Verify local port "+port, CheckSkipped, "simulation mode does not reserve host ports")
		}
	} else {
		if r.usesLocalHostFilesystem() && filepath.Clean(r.stateDir) != canonicalLiveInstallerStateDir {
			add("state-directory", "Validate canonical installer state authority", CheckBlocked, "live bootstrap requires state directory "+canonicalLiveInstallerStateDir+"; alternate state roots would split the durable journal from product-owned host credentials and runtime state")
		} else if r.usesLocalHostFilesystem() {
			add("state-directory", "Validate canonical installer state authority", CheckPassed, "live bootstrap journal, credentials and host-owned runtime state share one canonical state root")
		} else {
			add("state-directory", "Validate canonical installer state authority", CheckSkipped, "non-local test/system adapter owns filesystem path translation")
		}
		if residue := r.existingBootstrapAuthorityResidue(); len(residue) > 0 {
			add("existing-installer-state", "Detect stale installer-owned bootstrap authority", CheckBlocked, "generated bootstrap state is present without a resumable owning run ("+strings.Join(residue, ", ")+"); do not reuse stale credentials in a new installation")
		} else {
			add("existing-installer-state", "Detect stale installer-owned bootstrap authority", CheckPassed, "no generated bootstrap credentials or state from a previous installation were found")
		}
		if err := r.verifySystemdOperational(ctx); err != nil {
			add("systemd", "Verify systemd runtime readiness", CheckBlocked, err.Error())
		} else {
			add("systemd", "Verify systemd runtime readiness", CheckPassed, "systemd manager is installed, running and reachable")
		}
		if residue := r.existingKubernetesResidue(ctx); len(residue) > 0 {
			add("existing-kubernetes", "Detect conflicting Kubernetes runtime residue", CheckBlocked, "Kubernetes runtime residue is present on a fresh-install host ("+strings.Join(residue, ", ")+"); use the persisted Resume path or explicitly reset the host before starting a new installation")
		} else {
			add("existing-kubernetes", "Detect conflicting Kubernetes runtime residue", CheckPassed, "no conflicting RKE2, K3s or kubelet/kubeadm state, binary or systemd unit was found")
		}
		for _, port := range []string{"80", "443", "6443", "9345"} {
			listener, listenErr := net.Listen("tcp", ":"+port)
			if listenErr != nil {
				add("port-"+port, "Verify local port "+port, CheckBlocked, "required local port is unavailable: "+listenErr.Error())
				continue
			}
			_ = listener.Close()
			add("port-"+port, "Verify local port "+port, CheckPassed, "required local port is available")
		}
	}
	if strings.TrimSpace(report.RequestDigest) == "" {
		report.RequestDigest = "sha256:" + strings.Repeat("0", 64)
	}
	if err := report.Seal(); err != nil {
		return report, err
	}
	if err := r.writePreflightReport(report); err != nil {
		return report, err
	}
	return report, nil
}

func haPeerPreflightCommand() string {
	return `set -eu; test "$(uname -s)" = Linux; test "$(id -u)" = 0; command -v systemctl >/dev/null 2>&1; test -d /run/systemd/system; systemctl show --property=Version --value >/dev/null 2>&1; for p in /etc/rancher/rke2 /var/lib/rancher/rke2 /usr/local/bin/rke2 /usr/bin/rke2 /usr/local/bin/rke2-uninstall.sh /usr/local/bin/rke2-killall.sh /etc/rancher/k3s /var/lib/rancher/k3s /etc/kubernetes /var/lib/kubelet /usr/local/bin/k3s /usr/bin/k3s /usr/local/bin/kubelet /usr/bin/kubelet /usr/local/bin/kubeadm /usr/bin/kubeadm; do if [ -e "$p" ]; then echo "Kubernetes runtime residue is present: $p" >&2; exit 12; fi; done; for u in rke2-server.service rke2-agent.service k3s.service k3s-agent.service kubelet.service; do if systemctl cat "$u" >/dev/null 2>&1; then echo "Kubernetes systemd unit is already installed: $u" >&2; exit 12; fi; done; command -v ss >/dev/null 2>&1; listeners="$(ss -H -ltn | awk '{print $4}')"; for p in 80 443 6443 9345; do if printf '%s\n' "$listeners" | grep -Eq "(^|:)$p$"; then echo "required port $p is already in use" >&2; exit 13; fi; done`
}

func (r *Runner) writePreflightReport(report PreflightReport) error {
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return durablefile.Replace(filepath.Join(r.stateDir, "preflight-report.json"), append(raw, '\n'), 0o700, 0o600)
}
