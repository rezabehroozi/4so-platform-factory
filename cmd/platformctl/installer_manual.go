package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"platform.4so.io/factory/internal/hostdeployment"
)

const installerGuidedManualWorkflowAuthority = "INSTALLER_GUIDED_MANUAL_WORKFLOW_V1"

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

type manualInstallerInputs struct {
	InstallerBinary   string
	BundleDirectory   string
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

func installerManualPrepare(mode string, args []string) {
	fs := flag.NewFlagSet("installer-manual "+mode, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	input := manualInstallerInputs{}
	fs.StringVar(&input.InstallerBinary, "installer-binary", defaultSiblingInstallerBinary(), "platform-installer binary; defaults to the sibling of the running platformctl")
	fs.StringVar(&input.BundleDirectory, "bundle-dir", "", "verified appliance bundle directory")
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
	if mode == "preflight" {
		printJSON(plan.Admission)
		if !plan.Admission.Ready {
			os.Exit(1)
		}
		return
	}
	if mode == "plan" {
		printJSON(map[string]any{
			"authority":     installerGuidedManualWorkflowAuthority,
			"manualInstall": true,
			"plan":          plan,
			"specPath":      retainedSpecPath(input.OutputSpec),
			"nextAction":    "review admission/actions; rerun installer-manual install with --confirmation DEPLOY",
		})
		if !plan.Admission.Ready {
			os.Exit(1)
		}
		return
	}
	if !plan.Admission.Ready {
		printJSON(map[string]any{"authority": installerGuidedManualWorkflowAuthority, "manualInstall": true, "plan": plan, "status": "BLOCKED", "nextAction": "resolve host admission blockers and rerun preflight"})
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
	printJSON(map[string]any{
		"authority":          installerGuidedManualWorkflowAuthority,
		"manualInstall":      true,
		"status":             "READY",
		"plan":               plan,
		"deployment":         state,
		"verification":       verification,
		"installerUrl":       manualInstallerConsoleURL(plan.Health.URL),
		"healthUrl":          plan.Health.URL,
		"bootstrapTokenFile": tokenFile,
		"executionEnabled":   input.ExecutionEnabled,
		"specPath":           retainedSpecPath(input.OutputSpec),
		"nextActions": []string{
			"read the private bootstrap token from bootstrapTokenFile",
			"open installerUrl and authenticate with that token",
			"create or load the installation request, run preflight, review the plan, then explicitly start installation",
			"use installer-manual status/verify/recover/rollback for host-deployment recovery",
		},
	})
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
