package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"platform.4so.io/factory/internal/buildinfo"
	"strings"
	"time"

	"platform.4so.io/factory/catalog"
	"platform.4so.io/factory/internal/agentpki"
	bp "platform.4so.io/factory/internal/blueprint"
	"platform.4so.io/factory/internal/bootstrap"
	"platform.4so.io/factory/internal/bundlebuilder"
	"platform.4so.io/factory/internal/domain"
	"platform.4so.io/factory/internal/durablefile"
	"platform.4so.io/factory/internal/evidence"
	"platform.4so.io/factory/internal/fieldevidence"
	"platform.4so.io/factory/internal/plan"
	"platform.4so.io/factory/internal/releaseartifact"
	"platform.4so.io/factory/internal/releasereadiness"
	"platform.4so.io/factory/internal/supportbundle"
	"platform.4so.io/factory/internal/targetmodel"
)

const (
	maxClosureReportBytes       = 2 << 20
	maxFieldEvidenceReportBytes = 4 << 20
)

var version = buildinfo.Version

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  platformctl validate -f blueprint.json
  platformctl plan -f blueprint.json
  platformctl release-readiness -f blueprint.json
  platformctl target-architecture
  platformctl compliance evaluate -f kubernetes-objects.json
  platformctl ai policy
  platformctl ai redact -f context.json
  platformctl ai diagnose -f failure-packet.json
  platformctl ai certify-provider --release-artifact RELEASE.zip --out ai-provider-certification.json --confirmation CERTIFY
  platformctl catalog-summary
  platformctl catalog-bundle assemble --component component.json --artifact upstream.bin --render-manifest resources.json --image-inventory images.json --licenses licenses.json --sbom sbom.spdx.json [--render-generation render-generation.json] --version VERSION [--source-type helm-chart|external-tagged-source-set] --source-url URL --source-revision REV --upstream-artifact-name NAME --artifact-digest sha256:HEX --bundle-key COMPONENT/VERSION --out bundle.zip
  platformctl catalog-bundle verify -f external-bundle.zip
  platformctl catalog-bundle install -f external-bundle.zip --repo-root DIR --confirmation IMPORT
  platformctl image-bundle assemble --oci-layout DIR --reference REGISTRY/REPO@sha256:DIGEST --out image-bundle.zip
  platformctl image-bundle verify -f image-bundle.zip
  platformctl image-bundle push -f image-bundle.zip --registry-url http://platform-zot:5000 --confirmation MIRROR
  platformctl agent-pki init --server-name HOST --out-cert FILE --out-key FILE --out-server-cert FILE --out-server-key FILE --confirmation INIT
  platformctl appliance-bundle build --spec build.json --staging DIR --out DIR --release-artifact RELEASE.zip
  platformctl appliance-bundle verify --dir DIR
  platformctl lab-storage verify --devices /dev/sdb,/dev/sdc,/dev/sdd
  platformctl lab-storage prepare --devices /dev/sdb,/dev/sdc,/dev/sdd --confirmation PREPARE-EMPTY-DISKS
  platformctl runtime-closure verify-report -f closure-report.json [--release-artifact RELEASE.zip]
  platformctl runtime-closure fetch-report --api-url https://platform.example --campaign-id ID --out report.json [--release-artifact RELEASE.zip] [--token-file FILE] [--ca-file FILE]
  platformctl field-evidence verify-report -f field-evidence.json --release-artifact RELEASE.zip
  platformctl field-evidence fetch-report --installer-url https://installer.example --out field-evidence.json [--token-file FILE] [--ca-file FILE]
	  platformctl field-diagnostics verify-report -f diagnostic.json
	  platformctl field-diagnostics fetch-report --installer-url https://installer.example --out diagnostic.json [--token-file FILE] [--ca-file FILE]
  platformctl field-campaign prepare --installer-url https://installer.example --request install.json --state campaign.json --release-artifact RELEASE.zip [--token-file FILE] [--ca-file FILE]
  platformctl field-campaign start --state campaign.json --confirmation INSTALL [--token-file FILE] [--ca-file FILE]
  platformctl field-campaign watch --state campaign.json [--poll-interval 5s] [--timeout 30m] [--token-file FILE] [--ca-file FILE]
  platformctl field-campaign resume --state campaign.json --confirmation RESUME [--token-file FILE] [--ca-file FILE]
  platformctl field-campaign collect --state campaign.json --out field-evidence.json --release-artifact RELEASE.zip [--token-file FILE] [--ca-file FILE]
	  platformctl field-campaign diagnose --state campaign.json --out diagnostic.json [--token-file FILE] [--ca-file FILE]
  platformctl field-campaign status --state campaign.json
  platformctl installer-access status --installer-url https://installer.example [--token-file FILE] [--ca-file FILE]
  platformctl installer-access rotate-token --installer-url https://installer.example --out-token-file FILE --confirmation ROTATE [--token-file FILE] [--ca-file FILE]
  platformctl installer-host preflight --spec deployment.json [--root /]
  platformctl installer-host plan --spec deployment.json [--root /]
  platformctl installer-host apply --spec deployment.json --confirmation DEPLOY [--root /]
  platformctl installer-host status [--state FILE] [--root /]
  platformctl installer-host verify [--state FILE] [--root /]
  platformctl installer-host rollback --confirmation ROLLBACK [--state FILE] [--root /]
  platformctl installer-host recover --confirmation RECOVER [--state FILE] [--root /]
  platformctl installer-remote preflight --spec remote-bootstrap.json
  platformctl installer-remote plan --spec remote-bootstrap.json
  platformctl installer-remote apply --spec remote-bootstrap.json --confirmation DEPLOY
  platformctl installer-remote status --spec remote-bootstrap.json
  platformctl installer-remote verify --spec remote-bootstrap.json
  platformctl installer-remote rollback --spec remote-bootstrap.json --confirmation ROLLBACK
  platformctl installer-remote recover --spec remote-bootstrap.json --confirmation RECOVER
  platformctl installer-remote export-access --spec remote-bootstrap.json --out-token-file FILE --confirmation EXPORT
  platformctl zero-to-ha handoff --remote-spec remote-bootstrap.json --installer-url https://installer.example --install-request install.json --campaign-state campaign.json --release-artifact RELEASE.zip --out-token-file installer.token --ha-identity-file id_ed25519 --ha-known-hosts-file known_hosts --confirmation HANDOFF [--ca-file FILE]
  platformctl zero-to-ha status --campaign-state campaign.json
  platformctl support-bundle verify -f support-bundle.zip`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "help", "--help", "-h":
		usage()
		return
	case "version", "--version":
		fmt.Println(version)
	case "catalog-summary":
		catalogSummary()
	case "catalog-bundle":
		catalogBundleCommand(os.Args[2:])
	case "image-bundle":
		imageBundleCommand(os.Args[2:])
	case "workload-oci":
		workloadOCICommand(os.Args[2:])
	case "agent-pki":
		agentPKICommand(os.Args[2:])
	case "validate", "plan":
		blueprintCommand(os.Args[1], os.Args[2:])
	case "release-readiness":
		releaseReadinessCommand(os.Args[2:])
	case "target-architecture":
		targetArchitectureCommand(os.Args[2:])
	case "compliance":
		complianceCommand(os.Args[2:])
	case "ai":
		aiCommand(os.Args[2:])
	case "runtime-closure":
		runtimeClosureCommand(os.Args[2:])
	case "field-evidence":
		fieldEvidenceCommand(os.Args[2:])
	case "field-diagnostics":
		fieldDiagnosticsCommand(os.Args[2:])
	case "field-campaign":
		fieldCampaignCommand(os.Args[2:])
	case "installer-access":
		installerAccessCommand(os.Args[2:])
	case "lab-storage":
		labStorageCommand(os.Args[2:])
	case "installer-host":
		installerHostCommand(os.Args[2:])
	case "installer-remote":
		installerRemoteCommand(os.Args[2:])
	case "zero-to-ha":
		zeroToHACommand(os.Args[2:])
	case "appliance-bundle":
		applianceBundleCommand(os.Args[2:])
	case "support-bundle":
		supportBundleCommand(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func labStorageCommand(args []string) {
	if len(args) == 0 || (args[0] != "verify" && args[0] != "prepare") {
		fatal(fmt.Errorf("lab-storage requires verify or prepare"))
	}
	action := args[0]
	fs := flag.NewFlagSet("lab-storage "+action, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	devicesRaw := fs.String("devices", "", "comma-separated canonical whole-disk /dev paths")
	confirmation := fs.String("confirmation", "", "must be PREPARE-EMPTY-DISKS for prepare")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
		fatal(fmt.Errorf("invalid lab-storage arguments"))
	}
	var devices []string
	for _, value := range strings.Split(*devicesRaw, ",") {
		if value = strings.TrimSpace(value); value != "" {
			devices = append(devices, value)
		}
	}
	if len(devices) == 0 {
		fatal(fmt.Errorf("lab-storage requires --devices"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	switch action {
	case "verify":
		if err := bootstrap.VerifyLocalHAStorageDevices(ctx, devices); err != nil {
			fatal(err)
		}
		fmt.Printf("LAB_STORAGE_VERIFY_PASS devices=%d\n", len(devices))
	case "prepare":
		if *confirmation != "PREPARE-EMPTY-DISKS" {
			fatal(fmt.Errorf("lab-storage prepare requires --confirmation PREPARE-EMPTY-DISKS"))
		}
		if err := bootstrap.PrepareLocalHAStorageDevices(ctx, devices); err != nil {
			fatal(err)
		}
		if err := bootstrap.VerifyLocalHAStorageDevices(ctx, devices); err != nil {
			fatal(fmt.Errorf("post-prepare verification: %w", err))
		}
		fmt.Printf("LAB_STORAGE_PREPARE_PASS devices=%d\n", len(devices))
	}
}

func agentPKICommand(args []string) {
	if len(args) == 0 || args[0] != "init" {
		usage()
		return
	}
	fs := flag.NewFlagSet("agent-pki init", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	serverName := fs.String("server-name", "", "agent TLS server DNS name or IP")
	certPath := fs.String("out-cert", "", "CA certificate output")
	keyPath := fs.String("out-key", "", "CA private-key output")
	serverCertPath := fs.String("out-server-cert", "", "agent listener certificate output")
	serverKeyPath := fs.String("out-server-key", "", "agent listener private-key output")
	confirmation := fs.String("confirmation", "", "must be INIT")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 || strings.TrimSpace(*serverName) == "" || strings.TrimSpace(*certPath) == "" || strings.TrimSpace(*keyPath) == "" || strings.TrimSpace(*serverCertPath) == "" || strings.TrimSpace(*serverKeyPath) == "" || *confirmation != "INIT" {
		fatal(fmt.Errorf("agent-pki init requires --server-name, CA/server output paths and --confirmation INIT"))
	}
	for _, path := range []string{*certPath, *keyPath, *serverCertPath, *serverKeyPath} {
		if _, err := os.Lstat(path); err == nil {
			fatal(fmt.Errorf("refusing to overwrite existing PKI file %s", path))
		}
	}
	cert, key, err := agentpki.GenerateCA("4SO Platform Factory Agent CA", time.Now().UTC(), 10*365*24*time.Hour)
	if err != nil {
		fatal(err)
	}
	signer, err := agentpki.NewSigner(cert, key, time.Now)
	if err != nil {
		fatal(err)
	}
	serverCert, serverKey, notAfter, err := signer.IssueServerCertificate(*serverName, 365*24*time.Hour)
	if err != nil {
		fatal(err)
	}
	if err = writeAtomicPrivate(*keyPath, key); err != nil {
		fatal(err)
	}
	if err = writeAtomicPrivate(*serverKeyPath, serverKey); err != nil {
		_ = os.Remove(*keyPath)
		fatal(err)
	}
	if err = os.MkdirAll(filepath.Dir(*certPath), 0o750); err != nil {
		fatal(err)
	}
	if err = os.WriteFile(*certPath, cert, 0o644); err != nil {
		fatal(err)
	}
	if err = os.MkdirAll(filepath.Dir(*serverCertPath), 0o750); err != nil {
		fatal(err)
	}
	if err = os.WriteFile(*serverCertPath, serverCert, 0o644); err != nil {
		fatal(err)
	}
	printJSON(map[string]any{"status": "created", "serverName": *serverName, "caCertificateFile": *certPath, "caPrivateKeyFile": *keyPath, "serverCertificateFile": *serverCertPath, "serverPrivateKeyFile": *serverKeyPath, "privateKeyMode": "0600", "serverCertificateNotAfter": notAfter, "next": "configure dedicated agent TLS listener and mTLS-required mode"})
}

func supportBundleCommand(args []string) {
	if len(args) == 0 || args[0] != "verify" {
		usage()
		return
	}
	fs := flag.NewFlagSet("support-bundle verify", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	path := fs.String("f", "", "support bundle zip")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 || strings.TrimSpace(*path) == "" {
		fatal(fmt.Errorf("support-bundle verify requires -f FILE"))
	}
	info, err := os.Stat(*path)
	if err != nil {
		fatal(err)
	}
	if info.Size() > 64<<20 {
		fatal(fmt.Errorf("support bundle exceeds 64 MiB verification limit"))
	}
	raw, err := os.ReadFile(*path)
	if err != nil {
		fatal(err)
	}
	report, err := supportbundle.Verify(raw)
	if err != nil {
		fatal(err)
	}
	printJSON(map[string]any{
		"valid":        report.Valid,
		"files":        report.FileCount,
		"redactions":   report.Redactions,
		"bundleDigest": report.Digest,
	})
}

func targetArchitectureCommand(args []string) {
	if len(args) != 0 {
		fatal(fmt.Errorf("target-architecture does not accept arguments"))
	}
	printJSON(targetmodel.ArchitectureModel())
}

func catalogSummary() {
	cs, err := catalog.Load()
	if err != nil {
		fatal(err)
	}
	printJSON(map[string]any{"componentCount": len(cs), "digest": catalog.Digest(cs)})
}

func blueprintCommand(cmd string, args []string) {
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	file := fs.String("f", "", "blueprint file (JSON)")
	if err := fs.Parse(args); err != nil || *file == "" || fs.NArg() != 0 {
		usage()
		os.Exit(2)
	}
	raw, err := os.ReadFile(*file)
	if err != nil {
		fatal(err)
	}
	var b domain.Blueprint
	if err = decodeStrict(raw, &b); err != nil {
		fatal(fmt.Errorf("blueprint must be strict JSON: %w", err))
	}
	cs, err := catalog.Load()
	if err != nil {
		fatal(err)
	}
	v := bp.Validate(b, cs)
	switch cmd {
	case "validate":
		printJSON(v)
		if !v.Valid {
			os.Exit(1)
		}
	case "plan":
		if !v.Valid {
			printJSON(v)
			os.Exit(1)
		}
		p, err := plan.Build(b, cs)
		if err != nil {
			fatal(err)
		}
		printJSON(p)
	}
}

func releaseReadinessCommand(args []string) {
	fs := flag.NewFlagSet("release-readiness", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	file := fs.String("f", "", "blueprint file (JSON)")
	if err := fs.Parse(args); err != nil || strings.TrimSpace(*file) == "" || fs.NArg() != 0 {
		usage()
		os.Exit(2)
	}
	raw, err := os.ReadFile(*file)
	if err != nil {
		fatal(err)
	}
	var b domain.Blueprint
	if err = decodeStrict(raw, &b); err != nil {
		fatal(fmt.Errorf("blueprint must be strict JSON: %w", err))
	}
	cs, err := catalog.Load()
	if err != nil {
		fatal(err)
	}
	v := bp.Validate(b, cs)
	if !v.Valid {
		printJSON(v)
		os.Exit(1)
	}
	p, err := plan.Build(b, cs)
	if err != nil {
		fatal(err)
	}
	admission, err := catalog.LoadUpstreamAdmission()
	if err != nil {
		fatal(err)
	}
	report, err := releasereadiness.Build(p, admission, cs)
	if err != nil {
		fatal(err)
	}
	printJSON(report)
}

func applianceBundleCommand(args []string) {
	if len(args) < 1 {
		usage()
		os.Exit(2)
	}
	switch args[0] {
	case "help", "--help", "-h":
		usage()
		return
	case "build":
		buildApplianceBundle(args[1:])
	case "verify":
		verifyApplianceBundle(args[1:])
	default:
		usage()
		os.Exit(2)
	}
}

func buildApplianceBundle(args []string) {
	fs := flag.NewFlagSet("appliance-bundle build", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	spec := fs.String("spec", "", "strict JSON bundle build specification")
	staging := fs.String("staging", "", "directory containing pre-staged artifacts")
	output := fs.String("out", "", "new empty output directory")
	releaseArtifact := fs.String("release-artifact", "", "exact 4SO Platform Factory release ZIP bound into the appliance bundle")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage()
			return
		}
		usage()
		os.Exit(2)
	}
	if strings.TrimSpace(*spec) == "" || strings.TrimSpace(*staging) == "" || strings.TrimSpace(*output) == "" || strings.TrimSpace(*releaseArtifact) == "" || fs.NArg() != 0 {
		usage()
		os.Exit(2)
	}
	buildSpec, _, err := bundlebuilder.LoadSpec(*spec)
	if err != nil {
		fatal(err)
	}
	release, err := releaseartifact.Inspect(*releaseArtifact, buildSpec.Metadata.Version)
	if err != nil {
		fatal(fmt.Errorf("inspect exact release artifact: %w", err))
	}
	bindRunningPlatformctlToExactRelease(release)
	if release.Digest != buildSpec.Metadata.SourceReleaseDigest {
		fatal(errors.New("build spec sourceReleaseDigest does not match the exact release artifact SHA-256"))
	}
	result, err := bundlebuilder.Build(*spec, *staging, *output)
	if err != nil {
		fatal(err)
	}
	printJSON(result)
}

func verifyApplianceBundle(args []string) {
	fs := flag.NewFlagSet("appliance-bundle verify", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dir := fs.String("dir", "", "appliance bundle directory")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage()
			return
		}
		usage()
		os.Exit(2)
	}
	if strings.TrimSpace(*dir) == "" || fs.NArg() != 0 {
		usage()
		os.Exit(2)
	}
	status, err := bootstrap.InspectBundle(*dir, true)
	if err != nil {
		fatal(err)
	}
	printJSON(status)
}

func fieldEvidenceCommand(args []string) {
	if len(args) < 1 {
		usage()
		os.Exit(2)
	}
	switch args[0] {
	case "help", "--help", "-h":
		usage()
		return
	case "verify-report":
		verifyFieldEvidenceReport(args[1:])
	case "fetch-report":
		fetchFieldEvidenceReport(args[1:])
	default:
		usage()
		os.Exit(2)
	}
}

func verifyFieldEvidenceReport(args []string) {
	fs := flag.NewFlagSet("field-evidence verify-report", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	file := fs.String("f", "", "field execution evidence report (JSON)")
	releaseArtifact := fs.String("release-artifact", "", "exact release ZIP whose SHA-256 must match the field evidence")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage()
			return
		}
		usage()
		os.Exit(2)
	}
	if strings.TrimSpace(*file) == "" || fs.NArg() != 0 {
		usage()
		os.Exit(2)
	}
	raw, err := readLimitedFile(*file, maxFieldEvidenceReportBytes)
	if err != nil {
		fatal(err)
	}
	result, err := fieldevidence.Verify(raw)
	if err != nil {
		fatal(err)
	}
	if strings.TrimSpace(result.ReleaseArtifactDigest) != "" {
		if strings.TrimSpace(*releaseArtifact) == "" {
			fatal(errors.New("field evidence is exact-release bound; --release-artifact is required for independent verification"))
		}
		release, inspectErr := releaseartifact.Inspect(*releaseArtifact, result.ProductVersion)
		if inspectErr != nil {
			fatal(fmt.Errorf("inspect exact release artifact: %w", inspectErr))
		}
		if release.Digest != result.ReleaseArtifactDigest {
			fatal(errors.New("field evidence releaseArtifactDigest does not match the supplied exact release ZIP"))
		}
		if strings.TrimSpace(result.InstallerBinaryDigest) != "" {
			expectedInstallerDigest, digestErr := release.FileDigest(releaseartifact.InstallerBinaryPath)
			if digestErr != nil {
				fatal(fmt.Errorf("inspect release installer binary digest: %w", digestErr))
			}
			if expectedInstallerDigest != result.InstallerBinaryDigest {
				fatal(errors.New("field evidence installerBinaryDigest does not match the platform-installer binary in the supplied exact release ZIP"))
			}
		}
	}
	printJSON(result)
}

func fetchFieldEvidenceReport(args []string) {
	fs := flag.NewFlagSet("field-evidence fetch-report", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	installerURL := fs.String("installer-url", "", "bootstrap installer base URL")
	output := fs.String("out", "", "output report path")
	tokenFile := fs.String("token-file", "", "file containing the bootstrap token; PLATFORM_INSTALLER_TOKEN is used when omitted")
	caFile := fs.String("ca-file", "", "PEM CA file for a private installer endpoint")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage()
			return
		}
		usage()
		os.Exit(2)
	}
	if strings.TrimSpace(*installerURL) == "" || strings.TrimSpace(*output) == "" || fs.NArg() != 0 {
		usage()
		os.Exit(2)
	}
	base, err := validateAPIURL(*installerURL)
	if err != nil {
		fatal(err)
	}
	token, err := namedAccessToken(*tokenFile, "PLATFORM_INSTALLER_TOKEN")
	if err != nil {
		fatal(err)
	}
	if strings.TrimSpace(token) == "" {
		fatal(errors.New("bootstrap token is required"))
	}
	client, err := closureHTTPClient(*caFile)
	if err != nil {
		fatal(err)
	}
	raw, result, err := downloadFieldEvidenceReport(client, base, token)
	if err != nil {
		fatal(err)
	}
	if err = writeAtomicPrivate(*output, raw); err != nil {
		fatal(err)
	}
	printJSON(map[string]any{"output": *output, "verification": result})
}

func downloadFieldEvidenceReport(client *http.Client, base *url.URL, token string) ([]byte, fieldevidence.Verification, error) {
	var result fieldevidence.Verification
	endpoint := strings.TrimRight(base.String(), "/") + "/api/v1/field-evidence/report"
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, result, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
	resp, err := client.Do(req)
	if err != nil {
		return nil, result, fmt.Errorf("fetch field evidence report: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxFieldEvidenceReportBytes+1))
	if err != nil {
		return nil, result, fmt.Errorf("read field evidence report: %w", err)
	}
	if len(raw) > maxFieldEvidenceReportBytes {
		return nil, result, errors.New("field evidence report exceeds 4 MiB")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, result, fmt.Errorf("installer returned %s: %s", resp.Status, strings.TrimSpace(string(raw)))
	}
	result, err = fieldevidence.Verify(raw)
	if err != nil {
		return nil, result, fmt.Errorf("downloaded field evidence failed independent verification: %w", err)
	}
	return raw, result, nil
}

func runtimeClosureCommand(args []string) {
	if len(args) < 1 {
		usage()
		os.Exit(2)
	}
	switch args[0] {
	case "help", "--help", "-h":
		usage()
		return
	case "verify-report":
		verifyClosureReport(args[1:])
	case "fetch-report":
		fetchClosureReport(args[1:])
	default:
		usage()
		os.Exit(2)
	}
}

func verifyClosureReport(args []string) {
	fs := flag.NewFlagSet("runtime-closure verify-report", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	file := fs.String("f", "", "runtime closure report (JSON)")
	releaseArtifact := fs.String("release-artifact", "", "exact release ZIP required for schema-v2 exact-release verification")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage()
			return
		}
		usage()
		os.Exit(2)
	}
	if strings.TrimSpace(*file) == "" || fs.NArg() != 0 {
		usage()
		os.Exit(2)
	}
	raw, err := readLimitedFile(*file, maxClosureReportBytes)
	if err != nil {
		fatal(err)
	}
	result, err := evidence.VerifyRuntimeClosureReport(raw)
	if err != nil {
		fatal(err)
	}
	if result.ExactReleaseBound {
		if strings.TrimSpace(*releaseArtifact) == "" {
			fatal(errors.New("schema-v2 runtime closure report requires --release-artifact for independent exact-release verification"))
		}
		release, inspectErr := releaseartifact.Inspect(*releaseArtifact, result.ProductVersion)
		if inspectErr != nil {
			fatal(inspectErr)
		}
		bindRunningPlatformctlToExactRelease(release)
		if verifyErr := verifyRuntimeClosureExactRelease(result, release); verifyErr != nil {
			fatal(verifyErr)
		}
	}
	printJSON(result)
}

func fetchClosureReport(args []string) {
	fs := flag.NewFlagSet("runtime-closure fetch-report", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	apiURL := fs.String("api-url", "", "platform API base URL")
	campaignID := fs.String("campaign-id", "", "runtime closure campaign ID")
	output := fs.String("out", "", "output report path")
	releaseArtifact := fs.String("release-artifact", "", "exact release ZIP required for schema-v2 exact-release verification")
	tokenFile := fs.String("token-file", "", "file containing a bearer token; PLATFORM_ACCESS_TOKEN is used when omitted")
	caFile := fs.String("ca-file", "", "PEM CA file for a private platform endpoint")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage()
			return
		}
		usage()
		os.Exit(2)
	}
	if strings.TrimSpace(*apiURL) == "" || strings.TrimSpace(*campaignID) == "" || strings.TrimSpace(*output) == "" || fs.NArg() != 0 {
		usage()
		os.Exit(2)
	}
	base, err := validateAPIURL(*apiURL)
	if err != nil {
		fatal(err)
	}
	token, err := accessToken(*tokenFile)
	if err != nil {
		fatal(err)
	}
	client, err := closureHTTPClient(*caFile)
	if err != nil {
		fatal(err)
	}
	raw, result, err := downloadClosureReport(client, base, *campaignID, token)
	if err != nil {
		fatal(err)
	}
	if result.ExactReleaseBound {
		if strings.TrimSpace(*releaseArtifact) == "" {
			fatal(errors.New("schema-v2 runtime closure report requires --release-artifact for independent exact-release verification"))
		}
		release, inspectErr := releaseartifact.Inspect(*releaseArtifact, result.ProductVersion)
		if inspectErr != nil {
			fatal(inspectErr)
		}
		bindRunningPlatformctlToExactRelease(release)
		if verifyErr := verifyRuntimeClosureExactRelease(result, release); verifyErr != nil {
			fatal(verifyErr)
		}
	}
	if err := writeAtomicPrivate(*output, raw); err != nil {
		fatal(err)
	}
	printJSON(map[string]any{"output": *output, "verification": result})
}

func downloadClosureReport(client *http.Client, base *url.URL, campaignID, token string) ([]byte, evidence.RuntimeClosureVerification, error) {
	var result evidence.RuntimeClosureVerification
	endpoint := strings.TrimRight(base.String(), "/") + "/api/v1/runtime-closure-campaigns/" + url.PathEscape(strings.TrimSpace(campaignID)) + "/report"
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, result, err
	}
	req.Header.Set("Accept", "application/json")
	if strings.TrimSpace(token) != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, result, fmt.Errorf("fetch runtime closure report: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxClosureReportBytes+1))
	if err != nil {
		return nil, result, fmt.Errorf("read runtime closure report: %w", err)
	}
	if len(raw) > maxClosureReportBytes {
		return nil, result, errors.New("runtime closure report exceeds 2 MiB")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, result, fmt.Errorf("platform API returned %s: %s", resp.Status, strings.TrimSpace(string(raw)))
	}
	result, err = evidence.VerifyRuntimeClosureReport(raw)
	if err != nil {
		return nil, result, fmt.Errorf("downloaded report failed independent verification: %w", err)
	}
	return raw, result, nil
}

func validateAPIURL(value string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("api-url must be an absolute URL without credentials, query or fragment")
	}
	if parsed.Scheme == "https" {
		return parsed, nil
	}
	host := parsed.Hostname()
	if parsed.Scheme == "http" && (host == "localhost" || net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback()) {
		return parsed, nil
	}
	return nil, errors.New("api-url must use HTTPS; HTTP is accepted only for a loopback endpoint")
}

func accessToken(file string) (string, error) {
	return namedAccessToken(file, "PLATFORM_ACCESS_TOKEN")
}

func namedAccessToken(file, environment string) (string, error) {
	if strings.TrimSpace(file) == "" {
		return strings.TrimSpace(os.Getenv(environment)), nil
	}
	raw, err := readPrivateTokenFile(file, 64<<10)
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(raw))
	if token == "" || strings.ContainsAny(token, "\r\n") {
		return "", errors.New("token file must contain exactly one non-empty token")
	}
	return token, nil
}

func closureHTTPClient(caFile string) (*http.Client, error) {
	return newClosureHTTPClient(caFile, nil, nil)
}

func readLimitedFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("file %s exceeds %d bytes", path, limit)
	}
	return raw, nil
}

func writeAtomicPrivate(path string, raw []byte) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	return durablefile.Replace(absolute, raw, 0o755, 0o600)
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

func printJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "ERROR", err)
	os.Exit(1)
}
