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
	"net/url"
	"os"
	"path/filepath"
	"strconv"
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

func (r *Runner) verifyTimeSynchronization(ctx context.Context) error {
	raw, err := r.system.Output(ctx, "timedatectl", []string{"show", "--property=NTPSynchronized", "--value"}, nil)
	if err != nil {
		return fmt.Errorf("time synchronization status is unavailable: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(string(raw)), "yes") {
		return errors.New("host clock is not NTP-synchronized; correct time synchronization before bootstrap")
	}
	return nil
}

const managedChronySourcesPath = "/etc/chrony/sources.d/4so-time.sources"

var managedChronySources = strings.Join([]string{
	"server time.windows.com iburst",
	"server time.apple.com iburst",
	"server time.facebook.com iburst",
	"server rolex.ripe.net iburst",
	"server time.nist.gov iburst",
	"server ntp.nict.jp iburst",
	"server 162.159.200.1 iburst",
	"server 162.159.200.123 iburst",
	"pool 0.pool.ntp.org iburst maxsources 2",
	"pool 1.pool.ntp.org iburst maxsources 2",
	"server time.google.com iburst noselect",
	"server time.cloudflare.com iburst noselect",
	"server ntp.ubuntu.com iburst noselect",
}, "\n") + "\n"

func (r *Runner) ensureTimeSynchronization(ctx context.Context) error {
	if err := r.verifyTimeSynchronization(ctx); err == nil {
		return nil
	}
	if !r.system.IsRoot() {
		return errors.New("time synchronization repair requires root privileges")
	}
	if _, err := r.system.Output(ctx, "chronyc", []string{"tracking"}, nil); err != nil {
		if err := r.installChrony(ctx); err != nil {
			return fmt.Errorf("install chrony: %w", err)
		}
	}
	if err := r.system.MkdirAll(filepath.Dir(managedChronySourcesPath), 0o755); err != nil {
		return fmt.Errorf("create chrony sources directory: %w", err)
	}
	if err := r.system.WriteFile(managedChronySourcesPath, []byte(managedChronySources), 0o644); err != nil {
		return fmt.Errorf("write managed chrony sources: %w", err)
	}
	if err := r.enableChrony(ctx); err != nil {
		return err
	}
	if _, err := r.system.Output(ctx, "chronyc", []string{"reload", "sources"}, nil); err != nil {
		return fmt.Errorf("reload chrony sources: %w", err)
	}
	_, _ = r.system.Output(ctx, "chronyc", []string{"burst", "4/4"}, nil)
	_, _ = r.system.Output(ctx, "chronyc", []string{"makestep"}, nil)
	_, _ = r.system.Output(ctx, "chronyc", []string{"waitsync", "30", "0.1"}, nil)
	if err := r.verifyTimeSynchronization(ctx); err != nil {
		tracking, _ := r.system.Output(ctx, "chronyc", []string{"tracking"}, nil)
		sources, _ := r.system.Output(ctx, "chronyc", []string{"sources", "-n"}, nil)
		return fmt.Errorf("time synchronization repair did not converge: %w; tracking=%q sources=%q", err, strings.TrimSpace(string(tracking)), strings.TrimSpace(string(sources)))
	}
	return nil
}

func (r *Runner) installChrony(ctx context.Context) error {
	switch {
	case r.system.Exists("/usr/bin/apt-get"):
		env := map[string]string{"DEBIAN_FRONTEND": "noninteractive"}
		if err := r.system.Run(ctx, "apt-get", []string{"update"}, env); err != nil {
			return err
		}
		return r.system.Run(ctx, "apt-get", []string{"install", "-y", "chrony"}, env)
	case r.system.Exists("/usr/bin/dnf"):
		return r.system.Run(ctx, "dnf", []string{"install", "-y", "chrony"}, nil)
	case r.system.Exists("/usr/bin/yum"):
		return r.system.Run(ctx, "yum", []string{"install", "-y", "chrony"}, nil)
	default:
		return errors.New("chrony is unavailable and no supported package manager was found")
	}
}

func (r *Runner) enableChrony(ctx context.Context) error {
	if err := r.system.Run(ctx, "systemctl", []string{"enable", "--now", "chrony"}, nil); err == nil {
		return nil
	}
	if err := r.system.Run(ctx, "systemctl", []string{"enable", "--now", "chronyd"}, nil); err != nil {
		return fmt.Errorf("enable chrony service: %w", err)
	}
	return nil
}

func (r *Runner) prepareTimeSynchronization(ctx context.Context, connectivity installation.ConnectivityMode) error {
	if r.simulation {
		return nil
	}
	if connectivity == installation.ConnectivityDisconnected {
		if err := r.verifyTimeSynchronization(ctx); err != nil {
			return fmt.Errorf("disconnected installation requires reachable local NTP: %w", err)
		}
		return nil
	}
	if err := r.ensureTimeSynchronization(ctx); err != nil {
		return fmt.Errorf("repair host time synchronization: %w", err)
	}
	return nil
}
func verifyTCPEndpointReachability(ctx context.Context, rawURL string) error {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsed.Hostname() == "" {
		return fmt.Errorf("invalid service endpoint %q", rawURL)
	}
	host := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		switch strings.ToLower(parsed.Scheme) {
		case "https":
			port = "443"
		case "http":
			port = "80"
		default:
			return fmt.Errorf("service endpoint %q requires an explicit TCP port", rawURL)
		}
	}
	if _, err := strconv.Atoi(port); err != nil {
		return fmt.Errorf("service endpoint %q has invalid port %q", rawURL, port)
	}
	probeCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	if net.ParseIP(host) == nil {
		if _, err := net.DefaultResolver.LookupHost(probeCtx, host); err != nil {
			return fmt.Errorf("resolve %s: %w", host, err)
		}
	}
	conn, err := (&net.Dialer{Timeout: 4 * time.Second}).DialContext(probeCtx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return fmt.Errorf("connect to %s: %w", net.JoinHostPort(host, port), err)
	}
	_ = conn.Close()
	return nil
}

type hostCapacity struct {
	VCPU        int
	MemoryGiB   int
	DiskGiB     int
	FreeDiskGiB int
}

func parsePositiveInt(raw []byte, name string) (int, error) {
	value, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("%s probe returned invalid value %q", name, strings.TrimSpace(string(raw)))
	}
	return value, nil
}

func (r *Runner) probeHostCapacity(ctx context.Context) (hostCapacity, error) {
	var capacity hostCapacity
	cpuRaw, err := r.system.Output(ctx, "getconf", []string{"_NPROCESSORS_ONLN"}, nil)
	if err != nil {
		return capacity, fmt.Errorf("probe online CPUs: %w", err)
	}
	if capacity.VCPU, err = parsePositiveInt(cpuRaw, "CPU"); err != nil {
		return capacity, err
	}
	memRaw, err := r.system.Output(ctx, "cat", []string{"/proc/meminfo"}, nil)
	if err != nil {
		return capacity, fmt.Errorf("probe memory: %w", err)
	}
	for _, line := range strings.Split(string(memRaw), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "MemTotal:" {
			kib, parseErr := strconv.ParseInt(fields[1], 10, 64)
			if parseErr != nil || kib <= 0 {
				return capacity, errors.New("MemTotal is invalid")
			}
			capacity.MemoryGiB = int(kib / (1024 * 1024))
			if capacity.MemoryGiB == 0 {
				capacity.MemoryGiB = 1
			}
			break
		}
	}
	if capacity.MemoryGiB == 0 {
		return capacity, errors.New("MemTotal is unavailable")
	}
	diskRaw, err := r.system.Output(ctx, "df", []string{"-Pk", "/var/lib"}, nil)
	if err != nil {
		return capacity, fmt.Errorf("probe /var/lib filesystem capacity: %w", err)
	}
	lines := strings.Split(strings.TrimSpace(string(diskRaw)), "\n")
	if len(lines) < 2 {
		return capacity, errors.New("df capacity output is incomplete")
	}
	fields := strings.Fields(lines[len(lines)-1])
	if len(fields) < 4 {
		return capacity, errors.New("df capacity output is malformed")
	}
	totalKiB, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil || totalKiB <= 0 {
		return capacity, errors.New("filesystem total capacity is invalid")
	}
	freeKiB, err := strconv.ParseInt(fields[3], 10, 64)
	if err != nil || freeKiB < 0 {
		return capacity, errors.New("filesystem free capacity is invalid")
	}
	capacity.DiskGiB = int(totalKiB / (1024 * 1024))
	capacity.FreeDiskGiB = int(freeKiB / (1024 * 1024))
	return capacity, nil
}

func enforceSizing(capacity hostCapacity, sizing installation.ApplianceSizing) error {
	var failures []string
	if capacity.VCPU < sizing.MinimumVCPU {
		failures = append(failures, fmt.Sprintf("vCPU %d < required %d", capacity.VCPU, sizing.MinimumVCPU))
	}
	if capacity.MemoryGiB < sizing.MinimumMemoryGiB {
		failures = append(failures, fmt.Sprintf("memory %d GiB < required %d GiB", capacity.MemoryGiB, sizing.MinimumMemoryGiB))
	}
	if capacity.DiskGiB < sizing.MinimumDiskGiB {
		failures = append(failures, fmt.Sprintf("/var/lib filesystem %d GiB < required %d GiB", capacity.DiskGiB, sizing.MinimumDiskGiB))
	}
	if capacity.FreeDiskGiB < sizing.MinimumFreeDiskGiB {
		failures = append(failures, fmt.Sprintf("/var/lib free space %d GiB < required %d GiB", capacity.FreeDiskGiB, sizing.MinimumFreeDiskGiB))
	}
	if len(failures) > 0 {
		return errors.New(strings.Join(failures, "; "))
	}
	return nil
}

func (r *Runner) verifyFilesystemLocality(ctx context.Context) (string, error) {
	raw, err := r.system.Output(ctx, "findmnt", []string{"-n", "-o", "FSTYPE", "-T", "/var/lib"}, nil)
	if err != nil {
		return "", fmt.Errorf("inspect /var/lib filesystem: %w", err)
	}
	fsType := strings.ToLower(strings.TrimSpace(string(raw)))
	if fsType == "" {
		return "", errors.New("/var/lib filesystem type is unavailable")
	}
	switch fsType {
	case "nfs", "nfs4", "cifs", "smb3", "9p", "fuse.sshfs", "ceph", "glusterfs":
		return fsType, fmt.Errorf("/var/lib uses network/distributed filesystem %s; management runtime state requires local block-backed storage", fsType)
	}
	return fsType, nil
}

func (r *Runner) verifyDefaultRoute(ctx context.Context) (string, error) {
	raw, err := r.system.Output(ctx, "ip", []string{"-4", "route", "show", "default"}, nil)
	if err != nil {
		return "", fmt.Errorf("inspect IPv4 default route: %w", err)
	}
	line := strings.TrimSpace(strings.Split(string(raw), "\n")[0])
	if line == "" || !strings.HasPrefix(line, "default") {
		return "", errors.New("no IPv4 default route is available")
	}
	fields := strings.Fields(line)
	device := ""
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "dev" {
			device = fields[i+1]
			break
		}
	}
	if device == "" {
		return "", errors.New("default route has no device")
	}
	linkRaw, err := r.system.Output(ctx, "ip", []string{"-o", "link", "show", "dev", device}, nil)
	if err != nil {
		return "", fmt.Errorf("inspect default-route interface %s: %w", device, err)
	}
	mtu := "unknown"
	linkFields := strings.Fields(string(linkRaw))
	for i := 0; i+1 < len(linkFields); i++ {
		if linkFields[i] == "mtu" {
			mtu = linkFields[i+1]
			break
		}
	}
	return fmt.Sprintf("default route uses %s with MTU %s", device, mtu), nil
}

func noProxyCovers(token, host string) bool {
	token = strings.TrimSpace(strings.ToLower(token))
	host = strings.Trim(strings.TrimSpace(strings.ToLower(host)), "[]")
	if token == "*" || token == host {
		return true
	}
	if strings.HasPrefix(token, ".") && strings.HasSuffix(host, token) {
		return true
	}
	if _, network, err := net.ParseCIDR(token); err == nil {
		if ip := net.ParseIP(host); ip != nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

func verifyProxyBypass(request installation.InstallRequest) (string, error) {
	proxy := strings.TrimSpace(os.Getenv("HTTPS_PROXY"))
	if proxy == "" {
		proxy = strings.TrimSpace(os.Getenv("https_proxy"))
	}
	if proxy == "" {
		proxy = strings.TrimSpace(os.Getenv("HTTP_PROXY"))
	}
	if proxy == "" {
		proxy = strings.TrimSpace(os.Getenv("http_proxy"))
	}
	if proxy == "" {
		return "", nil
	}
	noProxy := os.Getenv("NO_PROXY")
	if strings.TrimSpace(noProxy) == "" {
		noProxy = os.Getenv("no_proxy")
	}
	tokens := strings.Split(noProxy, ",")
	required := []string{"localhost", "127.0.0.1"}
	required = append(required, request.Infrastructure.NodeAddresses...)
	if endpoint, err := url.Parse(request.Network.PublicEndpoint); err == nil && endpoint.Hostname() != "" {
		required = append(required, endpoint.Hostname())
	}
	var missing []string
	for _, host := range required {
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}
		covered := false
		for _, token := range tokens {
			if noProxyCovers(token, host) {
				covered = true
				break
			}
		}
		if !covered {
			missing = append(missing, host)
		}
	}
	if len(missing) > 0 {
		return proxy, fmt.Errorf("proxy is configured but NO_PROXY does not cover management-local endpoints: %s", strings.Join(missing, ", "))
	}
	return proxy, nil
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

func effectiveClusterNodeAddresses(request installation.InstallRequest) []string {
	if len(request.Infrastructure.ClusterNodeAddresses) == len(request.Infrastructure.NodeAddresses) && len(request.Infrastructure.ClusterNodeAddresses) > 0 {
		return request.Infrastructure.ClusterNodeAddresses
	}
	return request.Infrastructure.NodeAddresses
}

func (r *Runner) verifyLocalClusterNetwork(ctx context.Context, request installation.InstallRequest) (string, error) {
	addresses := effectiveClusterNodeAddresses(request)
	if len(addresses) == 0 {
		return "", errors.New("no management cluster address is configured")
	}
	expected := strings.Trim(strings.TrimSpace(addresses[0]), "[]")
	if net.ParseIP(expected) == nil {
		return "", fmt.Errorf("local cluster address %q is not a literal IP address", expected)
	}
	args := []string{"-4", "-o", "addr", "show"}
	iface := strings.TrimSpace(request.Infrastructure.ClusterInterface)
	if iface != "" {
		args = append(args, "dev", iface)
	}
	raw, err := r.system.Output(ctx, "ip", args, nil)
	if err != nil {
		return "", fmt.Errorf("inspect cluster network: %w", err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		if iface != "" && fields[1] != iface {
			continue
		}
		for _, field := range fields {
			address := strings.SplitN(field, "/", 2)[0]
			if address != expected {
				continue
			}
			if iface == "" {
				return "cluster address " + expected + " is already assigned; installer will not mutate host networking", nil
			}
			return "cluster address " + expected + " is already assigned to interface " + iface + "; installer will not mutate host networking", nil
		}
	}
	if iface != "" {
		return "", fmt.Errorf("cluster address %s is not assigned to interface %s; installer will not assign or invent east-west IP addresses", expected, iface)
	}
	return "", fmt.Errorf("cluster address %s is not assigned to this host; installer will not assign or invent east-west IP addresses", expected)
}

func clusterPeerProbeCommand(clusterAddress, clusterInterface string) string {
	clusterAddress = strings.Trim(strings.TrimSpace(clusterAddress), "[]")
	clusterInterface = strings.TrimSpace(clusterInterface)
	if clusterAddress == "" {
		return ""
	}
	if clusterInterface != "" {
		return "; ip link show dev " + haShellQuote(clusterInterface) + " >/dev/null 2>&1 || { echo " + haShellQuote("cluster interface is missing: "+clusterInterface) + " >&2; exit 16; }; ip -4 -o addr show dev " + haShellQuote(clusterInterface) + " | awk '{print $4}' | cut -d/ -f1 | grep -Fxq " + haShellQuote(clusterAddress) + " || { echo " + haShellQuote("cluster address "+clusterAddress+" is not assigned to interface "+clusterInterface) + " >&2; exit 16; }"
	}
	return "; ip -4 -o addr show | awk '{print $4}' | cut -d/ -f1 | grep -Fxq " + haShellQuote(clusterAddress) + " || { echo " + haShellQuote("cluster address "+clusterAddress+" is not assigned") + " >&2; exit 16; }"
}

func (r *Runner) preflightUnlocked(ctx context.Context, request installation.InstallRequest) (PreflightReport, error) {
	plan, planErr := installation.CreateBootstrapPlan(request)
	if planErr == nil {
		request = plan.EffectiveRequest
	}
	sizing := installation.ApplianceSizing{}
	if planErr == nil {
		sizing = plan.Profile.Sizing
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
		clusterAddresses := effectiveClusterNodeAddresses(request)
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
				clusterAddress := ""
				if index+1 < len(clusterAddresses) {
					clusterAddress = clusterAddresses[index+1]
				}
				command := haPeerPreflightCommand(sizing) + clusterPeerProbeCommand(clusterAddress, request.Infrastructure.ClusterInterface)
				if _, err := r.system.Output(ctx, "ssh", r.sshArgs(probeRun, peer, command), nil); err != nil {
					add(fmt.Sprintf("ha-peer-%d", index+1), "Verify HA peer readiness", CheckBlocked, fmt.Sprintf("%s: %v", peer, err))
				} else {
					add(fmt.Sprintf("ha-peer-%d", index+1), "Verify HA peer readiness", CheckPassed, peer+": pinned SSH connectivity, Linux/root/systemd/NTP readiness, clean Kubernetes runtime state and required free ports verified")
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
		add("clone-identity", "Verify unique cloned-host identity", CheckSkipped, "simulation mode does not inspect host identity")
		add("time-sync", "Verify host time synchronization", CheckSkipped, "simulation mode does not execute the host NTP synchronization check")
		add("host-sizing", "Verify appliance CPU, memory and disk sizing", CheckSkipped, "simulation mode does not inspect physical host capacity")
		add("filesystem", "Verify local runtime filesystem", CheckSkipped, "simulation mode does not inspect the host filesystem type")
		add("default-route", "Verify management network route and MTU evidence", CheckSkipped, "simulation mode does not inspect the host network route")
		if request.ProfileID == "production-standard-ha" {
			add("cluster-network", "Verify HA east-west cluster address", CheckSkipped, "simulation mode does not inspect host interface/address assignment")
		}
		add("proxy-bypass", "Verify proxy bypass for management-local endpoints", CheckSkipped, "simulation mode does not inherit host proxy admission")
		if request.Services.ObjectStorage.Mode == installation.ServiceModeExternal {
			add("object-storage-reachability", "Verify external object storage endpoint reachability", CheckSkipped, "simulation mode does not execute DNS/TCP endpoint probes")
		}
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
		if err := r.verifyCloneSafety(ctx, request); err != nil {
			add("clone-identity", "Verify unique cloned-host identity", CheckBlocked, err.Error())
		} else {
			add("clone-identity", "Verify unique cloned-host identity", CheckPassed, "hostname, machine-id, DMI UUID, SSH host key and MAC identity are unique across the management topology")
		}
		if err := r.verifyTimeSynchronization(ctx); err != nil {
			add("time-sync", "Verify host time synchronization", CheckBlocked, err.Error())
		} else {
			add("time-sync", "Verify host time synchronization", CheckPassed, "host clock is synchronized before certificates, leases and distributed control-plane state are created")
		}
		if request.ProfileID == "production-standard-ha" {
			if detail, err := r.verifyLocalClusterNetwork(ctx, request); err != nil {
				add("cluster-network", "Verify HA east-west cluster address", CheckBlocked, err.Error())
			} else {
				add("cluster-network", "Verify HA east-west cluster address", CheckPassed, detail)
			}
		}
		if capacity, err := r.probeHostCapacity(ctx); err != nil {
			add("host-sizing", "Verify appliance CPU, memory and disk sizing", CheckBlocked, err.Error())
		} else if err := enforceSizing(capacity, sizing); err != nil {
			add("host-sizing", "Verify appliance CPU, memory and disk sizing", CheckBlocked, err.Error())
		} else {
			add("host-sizing", "Verify appliance CPU, memory and disk sizing", CheckPassed, fmt.Sprintf("observed %d vCPU, %d GiB memory, %d GiB /var/lib filesystem with %d GiB free; source baseline minimum is %d vCPU, %d GiB memory, %d GiB disk with %d GiB free", capacity.VCPU, capacity.MemoryGiB, capacity.DiskGiB, capacity.FreeDiskGiB, sizing.MinimumVCPU, sizing.MinimumMemoryGiB, sizing.MinimumDiskGiB, sizing.MinimumFreeDiskGiB))
		}
		if fsType, err := r.verifyFilesystemLocality(ctx); err != nil {
			add("filesystem", "Verify local runtime filesystem", CheckBlocked, err.Error())
		} else {
			add("filesystem", "Verify local runtime filesystem", CheckPassed, "/var/lib is backed by local filesystem type "+fsType)
		}
		if detail, err := r.verifyDefaultRoute(ctx); err != nil {
			add("default-route", "Verify management network route and MTU evidence", CheckBlocked, err.Error())
		} else {
			add("default-route", "Verify management network route and MTU evidence", CheckPassed, detail)
		}
		if proxy, err := verifyProxyBypass(request); err != nil {
			add("proxy-bypass", "Verify proxy bypass for management-local endpoints", CheckBlocked, err.Error())
		} else if proxy == "" {
			add("proxy-bypass", "Verify proxy bypass for management-local endpoints", CheckSkipped, "installer process has no HTTP(S) proxy configured")
		} else {
			add("proxy-bypass", "Verify proxy bypass for management-local endpoints", CheckPassed, "configured proxy has NO_PROXY coverage for loopback, management nodes and the product endpoint")
		}
		if request.Services.ObjectStorage.Mode == installation.ServiceModeExternal {
			if err := verifyTCPEndpointReachability(ctx, request.Services.ObjectStorage.URL); err != nil {
				add("object-storage-reachability", "Verify external object storage endpoint reachability", CheckBlocked, err.Error())
			} else {
				add("object-storage-reachability", "Verify external object storage endpoint reachability", CheckPassed, "endpoint DNS and TCP connectivity are available before bootstrap mutation; credentialed read/write certification remains a lifecycle gate")
			}
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

func haPeerPreflightCommand(sizing installation.ApplianceSizing) string {
	return fmt.Sprintf(`set -eu; test "$(uname -s)" = Linux; test "$(id -u)" = 0; command -v systemctl >/dev/null 2>&1; test -d /run/systemd/system; systemctl show --property=Version --value >/dev/null 2>&1; command -v timedatectl >/dev/null 2>&1; test "$(timedatectl show --property=NTPSynchronized --value)" = yes; cpu="$(getconf _NPROCESSORS_ONLN)"; mem_kib="$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)"; set -- $(df -Pk /var/lib | tail -1); disk_kib="$2"; free_kib="$4"; test "$cpu" -ge %d || { echo "vCPU $cpu below required %d" >&2; exit 14; }; test "$mem_kib" -ge %d || { echo "memory below required %d GiB" >&2; exit 14; }; test "$disk_kib" -ge %d || { echo "/var/lib filesystem below required %d GiB" >&2; exit 14; }; test "$free_kib" -ge %d || { echo "/var/lib free space below required %d GiB" >&2; exit 14; }; command -v findmnt >/dev/null 2>&1; fs="$(findmnt -n -o FSTYPE -T /var/lib)"; case "$fs" in nfs|nfs4|cifs|smb3|9p|fuse.sshfs|ceph|glusterfs) echo "/var/lib uses unsupported network/distributed filesystem $fs" >&2; exit 15;; esac; command -v ip >/dev/null 2>&1; ip -4 route show default | grep -q '^default '; for p in /etc/rancher/rke2 /var/lib/rancher/rke2 /usr/local/bin/rke2 /usr/bin/rke2 /usr/local/bin/rke2-uninstall.sh /usr/local/bin/rke2-killall.sh /etc/rancher/k3s /var/lib/rancher/k3s /etc/kubernetes /var/lib/kubelet /usr/local/bin/k3s /usr/bin/k3s /usr/local/bin/kubelet /usr/bin/kubelet /usr/local/bin/kubeadm /usr/bin/kubeadm; do if [ -e "$p" ]; then echo "Kubernetes runtime residue is present: $p" >&2; exit 12; fi; done; for u in rke2-server.service rke2-agent.service k3s.service k3s-agent.service kubelet.service; do if systemctl cat "$u" >/dev/null 2>&1; then echo "Kubernetes systemd unit is already installed: $u" >&2; exit 12; fi; done; command -v ss >/dev/null 2>&1; listeners="$(ss -H -ltn | awk '{print $4}')"; for p in 80 443 6443 9345; do if printf '%%s\n' "$listeners" | grep -Eq "(^|:)$p$"; then echo "required port $p is already in use" >&2; exit 13; fi; done`, sizing.MinimumVCPU, sizing.MinimumVCPU, sizing.MinimumMemoryGiB*1024*1024, sizing.MinimumMemoryGiB, sizing.MinimumDiskGiB*1024*1024, sizing.MinimumDiskGiB, sizing.MinimumFreeDiskGiB*1024*1024, sizing.MinimumFreeDiskGiB)
}

func (r *Runner) writePreflightReport(report PreflightReport) error {
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return durablefile.Replace(filepath.Join(r.stateDir, "preflight-report.json"), append(raw, '\n'), 0o700, 0o600)
}
