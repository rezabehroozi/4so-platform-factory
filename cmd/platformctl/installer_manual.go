package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"platform.4so.io/factory/internal/hostdeployment"
	"platform.4so.io/factory/internal/releaseartifact"
)

const (
	installerGuidedManualWorkflowAuthority = "INSTALLER_GUIDED_MANUAL_WORKFLOW_V1"
	installerManualExactReleaseAuthority   = "INSTALLER_MANUAL_EXACT_RELEASE_BINDING_V1"
	installerManualRemoteHandoffAuthority  = "INSTALLER_MANUAL_REMOTE_HANDOFF_V1"
	installerManualPreflightGuidanceAuthority = "INSTALLER_MANUAL_PREFLIGHT_GUIDANCE_V1"
	installerManualMachineNextActionAuthority  = "INSTALLER_MANUAL_MACHINE_NEXT_ACTION_V1"
)

// installer-manual is the human-oriented owner path for placing the Bootstrap
// Installer on a host. It intentionally composes the same hostdeployment
// authority as installer-host; it does not invent a second install engine.
func installerManualCommand(args []string) {
	if len(args) < 1 {
		usage()
		os.Exit(2)
	}
	switch args[0] {
	case "help", "--help", "-h":
		usage()
		return
	case "preflight", "plan", "install":
		installerManualPrepare(args[0], args[1:])
	case "status":
		installerHostStatus(args[1:])
	case "verify":
		installerHostVerify(args[1:])
	case "recover":
		installerHostRecover(args[1:])
	case "rollback":
		installerHostRollback(args[1:])
	default:
		usage()
		os.Exit(2)
	}
}

type manualInstallerAccess struct {
	Mode              string `json:"mode"`
	LoopbackOnly      bool   `json:"loopbackOnly"`
	WorkstationURL    string `json:"workstationUrl,omitempty"`
	SSHForwardCommand string `json:"sshForwardCommand,omitempty"`
	Note              string `json:"note"`
}

type manualInstallerPreflightResult struct {
	hostdeployment.HostAdmissionReport
	Authority                  string `json:"authority"`
	ExactReleaseAuthority      string `json:"exactReleaseAuthority"`
	PreflightGuidanceAuthority string `json:"preflightGuidanceAuthority"`
	ManualInstall              bool   `json:"manualInstall"`
	SourceReleaseDigest        string `json:"sourceReleaseDigest,omitempty"`
	MachineNextActionAuthority string   `json:"machineNextActionAuthority"`
	NextActionCode             string   `json:"nextActionCode"`
	NextCommand                []string `json:"nextCommand,omitempty"`
	NextAction                 string   `json:"nextAction"`
}

func newManualInstallerPreflightResult(admission hostdeployment.HostAdmissionReport, releaseDigest string) manualInstallerPreflightResult {
	nextActionCode := "RESOLVE_HOST_ADMISSION"
	nextAction := "resolve the reported host admission blockers, then rerun preflight; no host mutation has occurred"
	if admission.Ready {
		nextActionCode = "REVIEW_PLAN"
		nextAction = "review installer-manual plan next; no host mutation has occurred"
	}
	return manualInstallerPreflightResult{
		HostAdmissionReport:        admission,
		Authority:                  installerGuidedManualWorkflowAuthority,
		ExactReleaseAuthority:      installerManualExactReleaseAuthority,
		PreflightGuidanceAuthority: installerManualPreflightGuidanceAuthority,
		ManualInstall:              true,
		SourceReleaseDigest:        releaseDigest,
		MachineNextActionAuthority: installerManualMachineNextActionAuthority,
		NextActionCode:             nextActionCode,
		NextAction:                 nextAction,
	}
}

type manualInstallerInputs struct {
	InstallerBinary   string
	BundleDirectory   string
	ReleaseArtifact   string
	Listen            string
	TLSCertificate    string
	TLSPrivateKey     string
	ExecutionEnabled  bool
	AllowInsecureHTTP bool
	AllowDowngrade    bool
	Root              string
	OutputSpec        string
	Confirmation      string
	Timeout           time.Duration
}

func manualInstallerContinuationCommand(input manualInstallerInputs, mode string, forceExecution bool) []string {
	executable, err := os.Executable()
	if err != nil || strings.TrimSpace(executable) == "" {
		executable = "platformctl"
	}
	command := []string{executable, "installer-manual", mode,
		"--installer-binary", strings.TrimSpace(input.InstallerBinary),
		"--bundle-dir", strings.TrimSpace(input.BundleDirectory),
		"--listen", strings.TrimSpace(input.Listen),
		"--root", strings.TrimSpace(input.Root),
		"--timeout", input.Timeout.String(),
	}
	if value := strings.TrimSpace(input.ReleaseArtifact); value != "" {
		command = append(command, "--release-artifact", value)
	}
	if value := strings.TrimSpace(input.TLSCertificate); value != "" {
		command = append(command, "--tls-cert", value)
	}
	if value := strings.TrimSpace(input.TLSPrivateKey); value != "" {
		command = append(command, "--tls-key", value)
	}
	if input.AllowInsecureHTTP {
		command = append(command, "--allow-insecure-http")
	}
	if input.AllowDowngrade {
		command = append(command, "--allow-downgrade")
	}
	if input.ExecutionEnabled || forceExecution {
		command = append(command, "--enable-execution")
	}
	if mode == "install" {
		command = append(command, "--confirmation", hostdeployment.ConfirmationDeploy)
	}
	return command
}

func installerManualPrepare(mode string, args []string) {
	fs := flag.NewFlagSet("installer-manual "+mode, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	input := manualInstallerInputs{}
	fs.StringVar(&input.InstallerBinary, "installer-binary", defaultSiblingInstallerBinary(), "platform-installer binary; defaults to the sibling of the running platformctl")
	fs.StringVar(&input.BundleDirectory, "bundle-dir", "", "verified appliance bundle directory")
	fs.StringVar(&input.ReleaseArtifact, "release-artifact", strings.TrimSpace(os.Getenv("PLATFORM_FACTORY_RELEASE_ARTIFACT")), "exact release ZIP; required for a live host unless PLATFORM_FACTORY_RELEASE_ARTIFACT is set")
	fs.StringVar(&input.Listen, "listen", "127.0.0.1:9080", "Bootstrap Installer listen address")
	fs.StringVar(&input.TLSCertificate, "tls-cert", "", "TLS certificate for non-loopback Installer access")
	fs.StringVar(&input.TLSPrivateKey, "tls-key", "", "private TLS key for non-loopback Installer access")
	fs.BoolVar(&input.ExecutionEnabled, "enable-execution", false, "allow Bootstrap Installer mutations after host deployment")
	fs.BoolVar(&input.AllowInsecureHTTP, "allow-insecure-http", false, "explicitly allow insecure HTTP where transport policy permits it")
	fs.BoolVar(&input.AllowDowngrade, "allow-downgrade", false, "explicitly admit an Installer downgrade")
	fs.StringVar(&input.Root, "root", "/", "target filesystem root; use / for a live host")
	fs.StringVar(&input.OutputSpec, "out-spec", "", "optional path to retain the generated strict deployment spec")
	fs.StringVar(&input.Confirmation, "confirmation", "", "install requires exactly DEPLOY")
	fs.DurationVar(&input.Timeout, "timeout", 2*time.Minute, "host deployment/verification timeout")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage()
			return
		}
		usage()
		os.Exit(2)
	}
	if fs.NArg() != 0 || strings.TrimSpace(input.BundleDirectory) == "" || input.Timeout <= 0 {
		fatal(errors.New("installer-manual requires --bundle-dir; use --help for the remaining optional inputs"))
	}
	if input.Root == "/" && strings.TrimSpace(input.ReleaseArtifact) == "" {
		fatal(errors.New("live installer-manual requires --release-artifact or PLATFORM_FACTORY_RELEASE_ARTIFACT for exact-release binding"))
	}
	if mode == "install" && input.Confirmation != hostdeployment.ConfirmationDeploy {
		fatal(errors.New("installer-manual install requires --confirmation DEPLOY"))
	}
	spec, err := buildManualInstallerSpec(input)
	if err != nil {
		fatal(err)
	}
	specPath, cleanup, err := materializeManualInstallerSpec(spec, input.OutputSpec)
	if err != nil {
		fatal(err)
	}
	defer cleanup()

	plan, err := hostdeployment.BuildPlan(specPath, hostdeployment.Options{Root: input.Root})
	if err != nil {
		fatal(err)
	}
	releaseDigest := ""
	if strings.TrimSpace(input.ReleaseArtifact) != "" {
		releaseDigest, err = verifyManualInstallerExactRelease(input.ReleaseArtifact, plan)
		if err != nil {
			fatal(err)
		}
	}
	if mode == "preflight" {
		result := newManualInstallerPreflightResult(plan.Admission, releaseDigest)
		if plan.Admission.Ready {
			result.NextCommand = manualInstallerContinuationCommand(input, "plan", false)
		} else {
			result.NextCommand = manualInstallerContinuationCommand(input, "preflight", false)
		}
		printJSON(result)
		if !plan.Admission.Ready {
			os.Exit(1)
		}
		return
	}
	if mode == "plan" {
		nextActionCode := "RUN_INSTALL"
		nextAction := "review admission/actions; run the exact nextCommand to enable browser appliance mutation"
		nextCommand := manualInstallerContinuationCommand(input, "install", true)
		if !plan.Admission.Ready {
			nextActionCode = "RESOLVE_HOST_ADMISSION"
			nextAction = "resolve the reported host admission blockers, then rerun the exact preflight nextCommand"
			nextCommand = manualInstallerContinuationCommand(input, "preflight", false)
		}
		printJSON(map[string]any{
			"authority":     installerGuidedManualWorkflowAuthority,
			"exactReleaseAuthority": installerManualExactReleaseAuthority,
			"machineNextActionAuthority": installerManualMachineNextActionAuthority,
			"manualInstall": true,
			"plan":          plan,
			"specPath":      retainedSpecPath(input.OutputSpec),
			"sourceReleaseDigest": releaseDigest,
			"nextActionCode": nextActionCode,
			"nextCommand":    nextCommand,
			"nextAction":    nextAction,
		})
		if !plan.Admission.Ready {
			os.Exit(1)
		}
		return
	}
	if !plan.Admission.Ready {
		printJSON(map[string]any{"authority": installerGuidedManualWorkflowAuthority, "exactReleaseAuthority": installerManualExactReleaseAuthority, "remoteHandoffAuthority": installerManualRemoteHandoffAuthority, "machineNextActionAuthority": installerManualMachineNextActionAuthority, "manualInstall": true, "plan": plan, "status": "BLOCKED", "nextActionCode": "RESOLVE_HOST_ADMISSION", "nextCommand": manualInstallerContinuationCommand(input, "preflight", false), "nextAction": "resolve host admission blockers and rerun the exact preflight nextCommand"})
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), input.Timeout)
	defer cancel()
	state, err := hostdeployment.Apply(ctx, specPath, input.Confirmation, hostdeployment.Options{Root: input.Root})
	if err != nil {
		fatal(err)
	}
	verification, err := hostdeployment.Verify(ctx, state.Plan.Paths.State, hostdeployment.Options{})
	if err != nil {
		fatal(fmt.Errorf("post-install verification: %w", err))
	}
	tokenFile := filepath.Join(filepath.Dir(state.Plan.Paths.State), "bootstrap-token")
	live := state.Plan.Root == "/"
	status := "STAGED"
	installerURL := ""
	bootstrapTokenFile := ""
	access := manualInstallerAccess{Mode: "staged", Note: "No live Installer transport exists for a staged --root deployment."}
	nextActions := []string{"copy the staged files to the intended live root or rerun installer-manual against --root / before using the browser Installer"}
	nextActionCode := "COMPLETE_STAGED_DEPLOYMENT"
	var nextCommand []string
	if live {
		status = "READY"
		nextActionCode = "OPEN_BROWSER_INSTALLER"
		installerURL = manualInstallerConsoleURL(plan.Health.URL)
		bootstrapTokenFile = tokenFile
		access = manualInstallerAccessPlan(plan)
		nextActions = []string{
			"read the private bootstrap token from bootstrapTokenFile",
			"open installerUrl and authenticate with that token",
			"create or load the installation request, run preflight, review the plan, then explicitly start installation",
			"from the extracted exact release, use install.sh status/verify/recover/rollback (or platformctl installer-manual directly) for host-deployment continuation",
		}
		if !input.ExecutionEnabled {
			nextActionCode = "ENABLE_EXECUTION"
			nextCommand = manualInstallerContinuationCommand(input, "install", true)
			nextActions = append([]string{"host deployment is ready but Bootstrap mutation is disabled; rerun the exact nextCommand with execution enabled before starting appliance installation"}, nextActions...)
		}
	}
	printJSON(map[string]any{
		"authority":          installerGuidedManualWorkflowAuthority,
		"exactReleaseAuthority": installerManualExactReleaseAuthority,
		"remoteHandoffAuthority": installerManualRemoteHandoffAuthority,
		"machineNextActionAuthority": installerManualMachineNextActionAuthority,
		"manualInstall":      true,
		"status":             status,
		"plan":               plan,
		"deployment":         state,
		"verification":       verification,
		"installerUrl":       installerURL,
		"healthUrl":          plan.Health.URL,
		"access":             access,
		"bootstrapTokenFile": bootstrapTokenFile,
		"executionEnabled":   input.ExecutionEnabled,
		"sourceReleaseDigest": releaseDigest,
		"specPath":           retainedSpecPath(input.OutputSpec),
		"nextActionCode":     nextActionCode,
		"nextCommand":        nextCommand,
		"nextActions":        nextActions,
	})
}

func verifyManualInstallerExactRelease(path string, plan hostdeployment.Plan) (string, error) {
	release, err := releaseartifact.Inspect(path, version)
	if err != nil {
		return "", fmt.Errorf("inspect exact release artifact: %w", err)
	}
	bindRunningPlatformctlToExactRelease(release)
	expectedInstallerDigest, err := release.FileDigest(releaseartifact.InstallerBinaryPath)
	if err != nil {
		return "", fmt.Errorf("inspect exact release installer binary: %w", err)
	}
	if plan.InstallerBinaryDigest != expectedInstallerDigest {
		return "", errors.New("manual installer binary digest does not match bin/linux-amd64/platform-installer in the exact release")
	}
	if strings.TrimSpace(plan.Bundle.SourceReleaseDigest) == "" {
		return "", errors.New("manual installer bundle is not bound to a source release digest")
	}
	if !strings.EqualFold(strings.TrimSpace(plan.Bundle.SourceReleaseDigest), strings.TrimSpace(release.Digest)) {
		return "", errors.New("manual installer bundle sourceReleaseDigest does not match the exact release ZIP")
	}
	return release.Digest, nil
}

func buildManualInstallerSpec(input manualInstallerInputs) (hostdeployment.Spec, error) {
	if strings.TrimSpace(input.InstallerBinary) == "" {
		return hostdeployment.Spec{}, errors.New("platform-installer binary could not be inferred; pass --installer-binary")
	}
	cert, key := strings.TrimSpace(input.TLSCertificate), strings.TrimSpace(input.TLSPrivateKey)
	if (cert == "") != (key == "") {
		return hostdeployment.Spec{}, errors.New("--tls-cert and --tls-key must be supplied together")
	}
	spec := hostdeployment.Spec{APIVersion: hostdeployment.APIVersion, Kind: hostdeployment.Kind}
	spec.Metadata.Name = "manual-installer"
	spec.Metadata.Version = version
	spec.Spec.InstallerBinary = strings.TrimSpace(input.InstallerBinary)
	spec.Spec.BundleDirectory = strings.TrimSpace(input.BundleDirectory)
	spec.Spec.Listen = strings.TrimSpace(input.Listen)
	spec.Spec.ExecutionEnabled = input.ExecutionEnabled
	spec.Spec.AllowInsecureHTTP = input.AllowInsecureHTTP
	spec.Spec.TLS.CertificateFile = cert
	spec.Spec.TLS.PrivateKeyFile = key
	spec.Spec.Admission = &hostdeployment.AdmissionPolicy{AllowDowngrade: input.AllowDowngrade}
	spec.Spec.Service.Enable = true
	spec.Spec.Service.Start = true
	return spec, nil
}

func materializeManualInstallerSpec(spec hostdeployment.Spec, output string) (string, func(), error) {
	raw, err := json.MarshalIndent(spec, "", "  ")
	if err != nil {
		return "", func() {}, err
	}
	raw = append(raw, '\n')
	if strings.TrimSpace(output) != "" {
		absolute, err := filepath.Abs(output)
		if err != nil {
			return "", func() {}, err
		}
		if _, err = os.Lstat(absolute); err == nil {
			return "", func() {}, fmt.Errorf("out-spec %s already exists; refusing to overwrite", absolute)
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", func() {}, err
		}
		if err = os.MkdirAll(filepath.Dir(absolute), 0o750); err != nil {
			return "", func() {}, err
		}
		if err = os.WriteFile(absolute, raw, 0o600); err != nil {
			return "", func() {}, err
		}
		return absolute, func() {}, nil
	}
	file, err := os.CreateTemp("", "4so-installer-manual-*.json")
	if err != nil {
		return "", func() {}, err
	}
	path := file.Name()
	cleanup := func() { _ = os.Remove(path) }
	if err = file.Chmod(0o600); err != nil {
		_ = file.Close()
		cleanup()
		return "", func() {}, err
	}
	if _, err = file.Write(raw); err != nil {
		_ = file.Close()
		cleanup()
		return "", func() {}, err
	}
	if err = file.Sync(); err != nil {
		_ = file.Close()
		cleanup()
		return "", func() {}, err
	}
	if err = file.Close(); err != nil {
		cleanup()
		return "", func() {}, err
	}
	return path, cleanup, nil
}

func defaultSiblingInstallerBinary() string {
	executable, err := os.Executable()
	if err != nil {
		return ""
	}
	candidate := filepath.Join(filepath.Dir(executable), "platform-installer")
	info, err := os.Stat(candidate)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&0o111 == 0 {
		return ""
	}
	return candidate
}

func manualInstallerAccessPlan(plan hostdeployment.Plan) manualInstallerAccess {
	consoleURL := manualInstallerConsoleURL(plan.Health.URL)
	access := manualInstallerAccess{
		Mode:         plan.Transport.Mode,
		LoopbackOnly: plan.Transport.LoopbackOnly,
		WorkstationURL: consoleURL,
		Note:         "Use the verified Installer endpoint and the private bootstrap token file returned by this command.",
	}
	if !plan.Transport.LoopbackOnly {
		if plan.Transport.InsecureOverride {
			access.Note = "Direct Installer access is using the explicitly admitted insecure HTTP override; migrate to TLS before normal remote operation."
		}
		return access
	}
	parsed, err := url.Parse(consoleURL)
	if err != nil {
		return access
	}
	port := parsed.Port()
	if port == "" {
		if parsed.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	parsed.Host = net.JoinHostPort("127.0.0.1", port)
	access.WorkstationURL = strings.TrimRight(parsed.String(), "/")
	access.SSHForwardCommand = fmt.Sprintf("ssh -N -L %s:127.0.0.1:%s <user>@<installer-host>", port, port)
	access.Note = "Installer is loopback-only by default. From the operator workstation, keep this SSH tunnel open, then open workstationUrl; the Installer itself remains unexposed on the network."
	return access
}

func manualInstallerConsoleURL(healthURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(healthURL))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	parsed.Path = "/"
	parsed.RawPath = ""
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return strings.TrimRight(parsed.String(), "/")
}

func retainedSpecPath(value string) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	absolute, err := filepath.Abs(value)
	if err != nil {
		return value
	}
	return absolute
}
