package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"platform.4so.io/factory/internal/bootstrap"
	"platform.4so.io/factory/internal/fieldcampaign"
	"platform.4so.io/factory/internal/fielddiagnostics"
	"platform.4so.io/factory/internal/fieldevidence"
	"platform.4so.io/factory/internal/installation"
	"platform.4so.io/factory/internal/releaseartifact"
)

const maxCampaignRequestBytes = 2 << 20

type fieldCampaignConnection struct {
	base   *url.URL
	client *http.Client
	token  string
}

type installerPlanResponse struct {
	Plan             installation.InstallationPlan `json:"plan"`
	BundleDigest     string                        `json:"bundleDigest"`
	ExecutionEnabled bool                          `json:"executionEnabled"`
}

type installerStatusResponse struct {
	ExecutionEnabled bool           `json:"executionEnabled"`
	BootstrapActive  bool           `json:"bootstrapActive"`
	Run              *bootstrap.Run `json:"run"`
}

func fieldCampaignCommand(args []string) {
	if len(args) < 1 {
		usage()
		os.Exit(2)
	}
	switch args[0] {
	case "help", "--help", "-h":
		usage()
		return
	case "prepare":
		fieldCampaignPrepareCommand(args[1:])
	case "start":
		fieldCampaignStartCommand(args[1:])
	case "watch":
		fieldCampaignWatchCommand(args[1:])
	case "resume":
		fieldCampaignResumeCommand(args[1:])
	case "collect":
		fieldCampaignCollectCommand(args[1:])
	case "diagnose":
		fieldCampaignDiagnoseCommand(args[1:])
	case "status":
		fieldCampaignStatusCommand(args[1:])
	default:
		usage()
		os.Exit(2)
	}
}

func fieldCampaignPrepareCommand(args []string) {
	fs := flag.NewFlagSet("field-campaign prepare", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	installerURL := fs.String("installer-url", "", "bootstrap installer base URL")
	requestPath := fs.String("request", "", "strict JSON installation request")
	statePath := fs.String("state", "", "new local campaign state path")
	releaseArtifact := fs.String("release-artifact", "", "exact 4SO Platform Factory release ZIP whose SHA-256 must match the appliance bundle source binding")
	tokenFile := fs.String("token-file", "", "file containing bootstrap token; PLATFORM_INSTALLER_TOKEN is used when omitted")
	caFile := fs.String("ca-file", "", "PEM CA file for a private installer endpoint")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage()
			return
		}
		usage()
		os.Exit(2)
	}
	if strings.TrimSpace(*installerURL) == "" || strings.TrimSpace(*requestPath) == "" || strings.TrimSpace(*statePath) == "" || strings.TrimSpace(*releaseArtifact) == "" || fs.NArg() != 0 {
		usage()
		os.Exit(2)
	}
	if _, err := os.Stat(*statePath); err == nil {
		fatal(errors.New("field campaign state already exists; use a new path or continue the existing campaign"))
	} else if !errors.Is(err, os.ErrNotExist) {
		fatal(err)
	}
	request, err := loadInstallationRequest(*requestPath)
	if err != nil {
		fatal(err)
	}
	release, err := releaseartifact.Inspect(*releaseArtifact, version)
	if err != nil {
		fatal(fmt.Errorf("inspect exact release artifact: %w", err))
	}
	platformctlBinaryDigest := bindRunningPlatformctlToExactRelease(release)
	installerBinaryDigest, err := release.FileDigest(releaseartifact.InstallerBinaryPath)
	if err != nil {
		fatal(fmt.Errorf("inspect release installer binary digest: %w", err))
	}
	connection, err := newFieldCampaignConnection(*installerURL, *tokenFile, *caFile)
	if err != nil {
		fatal(err)
	}
	campaign, err := prepareFieldCampaign(connection, request, release.Digest, installerBinaryDigest, platformctlBinaryDigest, time.Now().UTC())
	if err != nil {
		fatal(err)
	}
	if err = fieldcampaign.Save(*statePath, campaign); err != nil {
		fatal(err)
	}
	printJSON(map[string]any{"stateFile": *statePath, "campaign": campaign, "nextAction": "review the plan and run field-campaign start with --confirmation INSTALL"})
}

func fieldCampaignStartCommand(args []string) {
	fs, statePath, tokenFile, caFile := fieldCampaignStateFlags("field-campaign start")
	confirmation := fs.String("confirmation", "", "must be exactly INSTALL")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage()
			return
		}
		usage()
		os.Exit(2)
	}
	if strings.TrimSpace(*statePath) == "" || *confirmation != "INSTALL" || fs.NArg() != 0 {
		usage()
		os.Exit(2)
	}
	campaign, err := fieldcampaign.Load(*statePath)
	if err != nil {
		fatal(err)
	}
	bindRunningPlatformctlToFieldCampaign(campaign)
	connection, err := newFieldCampaignConnection(campaign.InstallerURL, *tokenFile, *caFile)
	if err != nil {
		fatal(err)
	}
	if err = startFieldCampaign(connection, &campaign, time.Now().UTC()); err != nil {
		fatal(err)
	}
	if err = fieldcampaign.Save(*statePath, campaign); err != nil {
		fatal(err)
	}
	printJSON(map[string]any{"stateFile": *statePath, "campaign": campaign, "nextAction": "run field-campaign watch"})
}

func fieldCampaignWatchCommand(args []string) {
	fs, statePath, tokenFile, caFile := fieldCampaignStateFlags("field-campaign watch")
	interval := fs.Duration("poll-interval", 5*time.Second, "status polling interval")
	timeout := fs.Duration("timeout", 30*time.Minute, "maximum watch duration")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage()
			return
		}
		usage()
		os.Exit(2)
	}
	if strings.TrimSpace(*statePath) == "" || fs.NArg() != 0 || *interval < 250*time.Millisecond || *interval > 5*time.Minute || *timeout <= 0 || *timeout > 24*time.Hour {
		usage()
		os.Exit(2)
	}
	campaign, err := fieldcampaign.Load(*statePath)
	if err != nil {
		fatal(err)
	}
	bindRunningPlatformctlToFieldCampaign(campaign)
	connection, err := newFieldCampaignConnection(campaign.InstallerURL, *tokenFile, *caFile)
	if err != nil {
		fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	if err = watchFieldCampaign(ctx, connection, &campaign, *interval, func(updated fieldcampaign.Campaign) error { return fieldcampaign.Save(*statePath, updated) }); err != nil {
		if saveErr := fieldcampaign.Save(*statePath, campaign); saveErr != nil {
			fatal(fmt.Errorf("%w; persist failed field-campaign state: %v", err, saveErr))
		}
		fatal(err)
	}
	if err = fieldcampaign.Save(*statePath, campaign); err != nil {
		fatal(err)
	}
	next := "collect independently verified field evidence"
	if campaign.State == fieldcampaign.StateFailed {
		next = "inspect lastError and use field-campaign resume with --confirmation RESUME after fixing the owning cause"
	} else if campaign.State == fieldcampaign.StateInterrupted {
		next = "resume the interrupted durable run with field-campaign resume --confirmation RESUME"
	}
	printJSON(map[string]any{"stateFile": *statePath, "campaign": campaign, "nextAction": next})
}

func fieldCampaignResumeCommand(args []string) {
	fs, statePath, tokenFile, caFile := fieldCampaignStateFlags("field-campaign resume")
	confirmation := fs.String("confirmation", "", "must be exactly RESUME")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage()
			return
		}
		usage()
		os.Exit(2)
	}
	if strings.TrimSpace(*statePath) == "" || *confirmation != "RESUME" || fs.NArg() != 0 {
		usage()
		os.Exit(2)
	}
	campaign, err := fieldcampaign.Load(*statePath)
	if err != nil {
		fatal(err)
	}
	bindRunningPlatformctlToFieldCampaign(campaign)
	connection, err := newFieldCampaignConnection(campaign.InstallerURL, *tokenFile, *caFile)
	if err != nil {
		fatal(err)
	}
	if err = resumeFieldCampaign(connection, &campaign, time.Now().UTC()); err != nil {
		fatal(err)
	}
	if err = fieldcampaign.Save(*statePath, campaign); err != nil {
		fatal(err)
	}
	printJSON(map[string]any{"stateFile": *statePath, "campaign": campaign, "nextAction": "run field-campaign watch"})
}

func fieldCampaignCollectCommand(args []string) {
	fs, statePath, tokenFile, caFile := fieldCampaignStateFlags("field-campaign collect")
	output := fs.String("out", "", "verified field evidence report output path")
	releaseArtifact := fs.String("release-artifact", "", "exact release ZIP required for schema v2 evidence collection")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage()
			return
		}
		usage()
		os.Exit(2)
	}
	if strings.TrimSpace(*statePath) == "" || strings.TrimSpace(*output) == "" || fs.NArg() != 0 {
		usage()
		os.Exit(2)
	}
	campaign, err := fieldcampaign.Load(*statePath)
	if err != nil {
		fatal(err)
	}
	if err = verifyCampaignReleaseArtifact(campaign, *releaseArtifact, version); err != nil {
		fatal(err)
	}
	if campaign.SchemaVersion != fieldcampaign.LegacySchemaVersion {
		release, inspectErr := releaseartifact.Inspect(*releaseArtifact, version)
		if inspectErr != nil {
			fatal(fmt.Errorf("inspect exact release artifact for field evidence collection: %w", inspectErr))
		}
		bindRunningPlatformctlToExactRelease(release)
	}
	connection, err := newFieldCampaignConnection(campaign.InstallerURL, *tokenFile, *caFile)
	if err != nil {
		fatal(err)
	}
	raw, verification, err := collectFieldCampaignEvidence(connection, &campaign, time.Now().UTC())
	if err != nil {
		fatal(err)
	}
	if err = writeAtomicPrivate(*output, raw); err != nil {
		fatal(err)
	}
	if err = fieldcampaign.Save(*statePath, campaign); err != nil {
		fatal(err)
	}
	printJSON(map[string]any{"stateFile": *statePath, "output": *output, "verification": verification, "campaign": campaign})
}

func verifyCampaignReleaseArtifact(campaign fieldcampaign.Campaign, path, expectedVersion string) error {
	if campaign.SchemaVersion == fieldcampaign.LegacySchemaVersion {
		return nil
	}
	if strings.TrimSpace(path) == "" {
		return errors.New("exact-SHA field evidence collection requires --release-artifact for re-verification")
	}
	release, err := releaseartifact.Inspect(path, expectedVersion)
	if err != nil {
		return fmt.Errorf("inspect exact release artifact: %w", err)
	}
	if release.Digest != campaign.ReleaseArtifactDigest {
		return errors.New("exact release artifact digest does not match the prepared field campaign")
	}
	if campaign.SchemaVersion >= fieldcampaign.RuntimeBindingSchemaVersion {
		expectedInstallerDigest, digestErr := release.FileDigest(releaseartifact.InstallerBinaryPath)
		if digestErr != nil {
			return fmt.Errorf("inspect release installer binary digest: %w", digestErr)
		}
		if expectedInstallerDigest != campaign.InstallerBinaryDigest {
			return errors.New("release installer binary digest does not match the prepared field campaign")
		}
	}
	if campaign.SchemaVersion >= fieldcampaign.PlatformctlBindingSchemaVersion {
		expectedPlatformctlDigest, digestErr := release.FileDigest(releaseartifact.PlatformctlBinaryPath)
		if digestErr != nil {
			return fmt.Errorf("inspect release platformctl binary digest: %w", digestErr)
		}
		if expectedPlatformctlDigest != campaign.PlatformctlBinaryDigest {
			return errors.New("release platformctl binary digest does not match the prepared field campaign")
		}
	}
	return nil
}

func fieldCampaignDiagnoseCommand(args []string) {
	fs, statePath, tokenFile, caFile := fieldCampaignStateFlags("field-campaign diagnose")
	output := fs.String("out", "", "verified diagnostic report output path")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage()
			return
		}
		usage()
		os.Exit(2)
	}
	if strings.TrimSpace(*statePath) == "" || strings.TrimSpace(*output) == "" || fs.NArg() != 0 {
		usage()
		os.Exit(2)
	}
	campaign, err := fieldcampaign.Load(*statePath)
	if err != nil {
		fatal(err)
	}
	bindRunningPlatformctlToFieldCampaign(campaign)
	if strings.TrimSpace(campaign.RunID) == "" {
		fatal(errors.New("field campaign has not observed an installation run"))
	}
	connection, err := newFieldCampaignConnection(campaign.InstallerURL, *tokenFile, *caFile)
	if err != nil {
		fatal(err)
	}
	raw, verification, err := downloadFieldDiagnosticReport(connection.client, connection.base, connection.token)
	if err != nil {
		fatal(err)
	}
	if verification.RunID != campaign.RunID || verification.RunState != campaign.RunState {
		fatal(errors.New("diagnostic report does not match campaign run identity and state"))
	}
	if err = writeAtomicPrivate(*output, raw); err != nil {
		fatal(err)
	}
	if err = campaign.Record("collect-diagnostics", "verified diagnostic report "+verification.ReportID+" recorded for owning layer "+verification.OwningLayer, time.Now().UTC()); err != nil {
		fatal(err)
	}
	if err = fieldcampaign.Save(*statePath, campaign); err != nil {
		fatal(err)
	}
	printJSON(map[string]any{"stateFile": *statePath, "output": *output, "verification": verification, "campaign": campaign, "nextAction": diagnosticNextAction(verification)})
}

func diagnosticNextAction(verification fielddiagnostics.Verification) string {
	if verification.RetryDisposition == "FIX_CAUSE_THEN_RESUME_SAME_RUN" {
		return "review the owning layer, fix the cause and use explicit RESUME on the same run"
	}
	if verification.RunState == string(bootstrap.RunSucceeded) {
		return "collect independently verified Field Execution Evidence"
	}
	return "continue observing the same run; do not start a second run"
}

func fieldCampaignStatusCommand(args []string) {
	fs := flag.NewFlagSet("field-campaign status", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	statePath := fs.String("state", "", "local campaign state path")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage()
			return
		}
		usage()
		os.Exit(2)
	}
	if strings.TrimSpace(*statePath) == "" || fs.NArg() != 0 {
		usage()
		os.Exit(2)
	}
	campaign, err := fieldcampaign.Load(*statePath)
	if err != nil {
		fatal(err)
	}
	printJSON(campaign)
}

func fieldCampaignStateFlags(name string) (*flag.FlagSet, *string, *string, *string) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	statePath := fs.String("state", "", "local campaign state path")
	tokenFile := fs.String("token-file", "", "file containing bootstrap token; PLATFORM_INSTALLER_TOKEN is used when omitted")
	caFile := fs.String("ca-file", "", "PEM CA file for a private installer endpoint")
	return fs, statePath, tokenFile, caFile
}

func loadInstallationRequest(path string) (installation.InstallRequest, error) {
	var request installation.InstallRequest
	raw, err := readLimitedFile(path, maxCampaignRequestBytes)
	if err != nil {
		return request, err
	}
	if err = decodeStrict(raw, &request); err != nil {
		return request, fmt.Errorf("installation request must be strict JSON: %w", err)
	}
	return request, nil
}

func newFieldCampaignConnection(installerURL, tokenFile, caFile string) (fieldCampaignConnection, error) {
	base, err := validateAPIURL(installerURL)
	if err != nil {
		return fieldCampaignConnection{}, err
	}
	token, err := namedAccessToken(tokenFile, "PLATFORM_INSTALLER_TOKEN")
	if err != nil {
		return fieldCampaignConnection{}, err
	}
	if strings.TrimSpace(token) == "" {
		return fieldCampaignConnection{}, errors.New("bootstrap token is required")
	}
	client, err := closureHTTPClient(caFile)
	if err != nil {
		return fieldCampaignConnection{}, err
	}
	return fieldCampaignConnection{base: base, client: client, token: token}, nil
}

func prepareFieldCampaign(connection fieldCampaignConnection, request installation.InstallRequest, releaseArtifactDigest, installerBinaryDigest, platformctlBinaryDigest string, now time.Time) (fieldcampaign.Campaign, error) {
	if err := verifyInstallerRuntimeBinding(connection, installerBinaryDigest); err != nil {
		return fieldcampaign.Campaign{}, err
	}
	bundle, planResponse, preflight, err := inspectInstallerForCampaign(connection, request)
	if err != nil {
		return fieldcampaign.Campaign{}, err
	}
	if strings.TrimSpace(bundle.SourceReleaseDigest) != strings.TrimSpace(releaseArtifactDigest) {
		return fieldcampaign.Campaign{}, errors.New("exact release artifact digest does not match the appliance bundle source release binding")
	}
	return fieldcampaign.New(connection.base.String(), request, planResponse.Plan.SpecDigest, bundle.BundleDigest, releaseArtifactDigest, installerBinaryDigest, platformctlBinaryDigest, planResponse.Plan.ID, preflight.Digest, planResponse.ExecutionEnabled, now)
}

func verifyInstallerRuntimeBinding(connection fieldCampaignConnection, expectedDigest string) error {
	if strings.TrimSpace(expectedDigest) == "" {
		return errors.New("expected installer binary digest is required for runtime binding")
	}
	status, err := fetchInstallerAccessStatus(connection.client, connection.base, connection.token)
	if err != nil {
		return fmt.Errorf("verify running installer identity: %w", err)
	}
	if strings.TrimSpace(status.InstallerBinaryDigest) != strings.TrimSpace(expectedDigest) {
		return errors.New("running platform-installer binary digest does not match the exact release artifact")
	}
	return nil
}

func inspectInstallerForCampaign(connection fieldCampaignConnection, request installation.InstallRequest) (bootstrap.BundleAdmissionStatus, installerPlanResponse, bootstrap.PreflightReport, error) {
	var bundle bootstrap.BundleAdmissionStatus
	var planResponse installerPlanResponse
	var preflight bootstrap.PreflightReport
	if err := installerRequestJSON(connection, http.MethodGet, "/api/v1/bundle/status", nil, &bundle); err != nil {
		return bundle, planResponse, preflight, err
	}
	if !bundle.Verified || strings.TrimSpace(bundle.BundleDigest) == "" || strings.TrimSpace(bundle.LockDigest) == "" || strings.TrimSpace(bundle.SourceReleaseDigest) == "" {
		return bundle, planResponse, preflight, errors.New("installer bundle admission is not verified, locked and bound to a source release")
	}
	body := bootstrap.StartRequest{Installation: request}
	if err := installerRequestJSON(connection, http.MethodPost, "/api/v1/plan", body, &planResponse); err != nil {
		return bundle, planResponse, preflight, err
	}
	if !planResponse.Plan.Executable {
		return bundle, planResponse, preflight, fmt.Errorf("installation plan is not executable: %s", strings.Join(planResponse.Plan.Blockers, "; "))
	}
	if planResponse.BundleDigest != bundle.BundleDigest {
		return bundle, planResponse, preflight, errors.New("plan bundle digest does not match admitted bundle")
	}
	if err := installerRequestJSON(connection, http.MethodPost, "/api/v1/preflight", body, &preflight); err != nil {
		return bundle, planResponse, preflight, err
	}
	if err := preflight.Verify(); err != nil {
		return bundle, planResponse, preflight, fmt.Errorf("verify installer preflight: %w", err)
	}
	if !preflight.Passed() {
		return bundle, planResponse, preflight, errors.New("installer preflight is blocked")
	}
	if preflight.RequestDigest != planResponse.Plan.SpecDigest || preflight.BundleDigest != bundle.BundleDigest {
		return bundle, planResponse, preflight, errors.New("preflight is not bound to the prepared plan and bundle")
	}
	return bundle, planResponse, preflight, nil
}

func startFieldCampaign(connection fieldCampaignConnection, campaign *fieldcampaign.Campaign, now time.Time) error {
	if campaign.State != fieldcampaign.StatePrepared {
		return fmt.Errorf("field campaign must be PREPARED, got %s", campaign.State)
	}
	if campaign.SchemaVersion >= fieldcampaign.RuntimeBindingSchemaVersion {
		if err := verifyInstallerRuntimeBinding(connection, campaign.InstallerBinaryDigest); err != nil {
			return err
		}
	}
	bundle, planResponse, preflight, err := inspectInstallerForCampaign(connection, campaign.Request)
	if err != nil {
		return err
	}
	if planResponse.Plan.SpecDigest != campaign.RequestDigest || bundle.BundleDigest != campaign.BundleDigest || bundle.SourceReleaseDigest != campaign.ReleaseArtifactDigest || planResponse.Plan.ID != campaign.PlanID || preflight.Digest != campaign.PreflightDigest {
		return errors.New("prepared campaign no longer matches current bundle, plan or preflight")
	}
	if !planResponse.ExecutionEnabled {
		return errors.New("installer execution is disabled")
	}
	var accepted map[string]string
	if err = installerRequestJSON(connection, http.MethodPost, "/api/v1/start", bootstrap.StartRequest{Installation: campaign.Request}, &accepted); err != nil {
		return err
	}
	campaign.ExecutionEnabled = true
	campaign.LastError = ""
	return campaign.Transition(fieldcampaign.StateStartRequested, "start", "explicit INSTALL confirmation accepted and installer start requested", now)
}

func watchFieldCampaign(ctx context.Context, connection fieldCampaignConnection, campaign *fieldcampaign.Campaign, interval time.Duration, persist func(fieldcampaign.Campaign) error) error {
	if campaign.State != fieldcampaign.StateStartRequested && campaign.State != fieldcampaign.StateRunning {
		return fmt.Errorf("field campaign must be START_REQUESTED or RUNNING, got %s", campaign.State)
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		terminal, changed, err := observeFieldCampaign(connection, campaign, time.Now().UTC())
		if err != nil {
			return err
		}
		if changed && persist != nil {
			if err = persist(*campaign); err != nil {
				return err
			}
		}
		if terminal {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("field campaign watch stopped before terminal state: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

func observeFieldCampaign(connection fieldCampaignConnection, campaign *fieldcampaign.Campaign, now time.Time) (bool, bool, error) {
	var status installerStatusResponse
	if err := installerRequestJSON(connection, http.MethodGet, "/api/v1/status", nil, &status); err != nil {
		return false, false, err
	}
	campaign.ExecutionEnabled = status.ExecutionEnabled
	if status.Run == nil {
		return false, false, nil
	}
	run := status.Run
	if run.SpecDigest != campaign.RequestDigest || run.BundleDigest != campaign.BundleDigest || run.PreflightDigest != campaign.PreflightDigest {
		return false, false, errors.New("observed installation run does not match prepared campaign digests")
	}
	if campaign.RunID != "" && campaign.RunID != run.ID {
		return false, false, errors.New("installer returned a different run ID for the same campaign")
	}
	previousRunID, previousRunState, previousState, previousError := campaign.RunID, campaign.RunState, campaign.State, campaign.LastError
	campaign.RunID = run.ID
	campaign.RunState = string(run.State)
	simulation := run.Simulation
	campaign.Simulation = &simulation
	campaign.LastError = run.LastError
	next := campaign.State
	detail := "installation state observed: " + string(run.State)
	switch run.State {
	case bootstrap.RunPending:
		next = fieldcampaign.StateStartRequested
	case bootstrap.RunRunning:
		if status.BootstrapActive {
			next = fieldcampaign.StateRunning
		} else {
			next = fieldcampaign.StateInterrupted
			campaign.LastError = "bootstrap execution interrupted; durable run requires explicit resume"
			detail = "installation run is durably RUNNING but no installer worker owns it; explicit resume is required"
		}
	case bootstrap.RunFailed:
		next = fieldcampaign.StateFailed
	case bootstrap.RunSucceeded:
		next = fieldcampaign.StateSucceeded
	default:
		return false, false, fmt.Errorf("unsupported installation run state %q", run.State)
	}
	if next == previousState && previousRunID == campaign.RunID && previousRunState == campaign.RunState && previousError == campaign.LastError {
		return next == fieldcampaign.StateInterrupted || next == fieldcampaign.StateFailed || next == fieldcampaign.StateSucceeded, false, nil
	}
	if next == previousState {
		if err := campaign.Record("observe", detail, now); err != nil {
			return false, false, err
		}
	} else if err := campaign.Transition(next, "observe", detail, now); err != nil {
		return false, false, err
	}
	return next == fieldcampaign.StateInterrupted || next == fieldcampaign.StateFailed || next == fieldcampaign.StateSucceeded, true, nil
}

func resumeFieldCampaign(connection fieldCampaignConnection, campaign *fieldcampaign.Campaign, now time.Time) error {
	if campaign.State != fieldcampaign.StateFailed && campaign.State != fieldcampaign.StateInterrupted {
		return fmt.Errorf("field campaign must be FAILED or INTERRUPTED, got %s", campaign.State)
	}
	if campaign.SchemaVersion >= fieldcampaign.RuntimeBindingSchemaVersion {
		if err := verifyInstallerRuntimeBinding(connection, campaign.InstallerBinaryDigest); err != nil {
			return err
		}
	}
	var status installerStatusResponse
	if err := installerRequestJSON(connection, http.MethodGet, "/api/v1/status", nil, &status); err != nil {
		return err
	}
	if status.Run == nil || status.Run.ID != campaign.RunID {
		return errors.New("installer does not expose the campaign-bound durable run")
	}
	if status.Run.SpecDigest != campaign.RequestDigest || status.Run.BundleDigest != campaign.BundleDigest || status.Run.PreflightDigest != campaign.PreflightDigest {
		return errors.New("durable run digests do not match the campaign")
	}
	failed := status.Run.State == bootstrap.RunFailed
	interrupted := status.Run.State == bootstrap.RunRunning && !status.BootstrapActive
	if !failed && !interrupted {
		return fmt.Errorf("installer durable run is not resumable: state=%s bootstrapActive=%t", status.Run.State, status.BootstrapActive)
	}
	var accepted map[string]string
	if err := installerRequestJSON(connection, http.MethodPost, "/api/v1/resume", map[string]any{}, &accepted); err != nil {
		return err
	}
	campaign.LastError = ""
	detail := "explicit RESUME confirmation accepted and failed installer run resume requested"
	if interrupted {
		detail = "explicit RESUME confirmation accepted for interrupted durable RUNNING installer run"
	}
	return campaign.Transition(fieldcampaign.StateStartRequested, "resume", detail, now)
}

func collectFieldCampaignEvidence(connection fieldCampaignConnection, campaign *fieldcampaign.Campaign, now time.Time) ([]byte, fieldevidence.Verification, error) {
	var empty fieldevidence.Verification
	if campaign.State != fieldcampaign.StateFailed && campaign.State != fieldcampaign.StateSucceeded {
		return nil, empty, fmt.Errorf("field campaign must be terminal before evidence collection, got %s", campaign.State)
	}
	raw, verification, err := downloadFieldEvidenceReport(connection.client, connection.base, connection.token)
	if err != nil {
		return nil, empty, err
	}
	if verification.RunID != campaign.RunID || verification.RunState != campaign.RunState {
		return nil, empty, errors.New("field evidence report does not match campaign run identity and state")
	}
	if verification.SpecDigest != campaign.RequestDigest {
		return nil, empty, errors.New("field evidence report does not match campaign request/spec digest")
	}
	if verification.BundleDigest != campaign.BundleDigest {
		return nil, empty, errors.New("field evidence report does not match campaign appliance bundle digest")
	}
	if verification.PreflightDigest != campaign.PreflightDigest {
		return nil, empty, errors.New("field evidence report does not match campaign preflight digest")
	}
	if verification.ReleaseArtifactDigest != campaign.ReleaseArtifactDigest {
		return nil, empty, errors.New("field evidence report does not match campaign exact release artifact digest")
	}
	if campaign.SchemaVersion >= fieldcampaign.RuntimeBindingSchemaVersion && verification.InstallerBinaryDigest != campaign.InstallerBinaryDigest {
		return nil, empty, errors.New("field evidence report does not match campaign installer binary digest")
	}
	if campaign.Simulation != nil && ((*campaign.Simulation && verification.ExecutionMode != "simulation") || (!*campaign.Simulation && verification.ExecutionMode != "live")) {
		return nil, empty, errors.New("field evidence execution mode does not match campaign observation")
	}
	campaign.EvidenceVerified = true
	campaign.EvidenceReportID = verification.ReportID
	campaign.EvidenceDigest = verification.EvidenceDigest
	if err = campaign.Record("collect-evidence", "field evidence downloaded and independently verified before write", now); err != nil {
		return nil, empty, err
	}
	return raw, verification, nil
}

func installerRequestJSON(connection fieldCampaignConnection, method, path string, body any, target any) error {
	endpoint := strings.TrimRight(connection.base.String(), "/") + path
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, endpoint, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(connection.token))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := connection.client.Do(req)
	if err != nil {
		return fmt.Errorf("installer %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxFieldEvidenceReportBytes+1))
	if err != nil {
		return err
	}
	if len(raw) > maxFieldEvidenceReportBytes {
		return errors.New("installer response exceeds 4 MiB")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("installer returned %s for %s: %s", resp.Status, path, strings.TrimSpace(string(raw)))
	}
	if target == nil {
		return nil
	}
	if err = decodeStrict(raw, target); err != nil {
		return fmt.Errorf("decode installer response for %s: %w", path, err)
	}
	return nil
}
