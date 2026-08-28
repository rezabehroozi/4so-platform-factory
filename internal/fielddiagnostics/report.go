package fielddiagnostics

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"strings"
	"time"

	"platform.4so.io/factory/internal/bootstrap"
	"platform.4so.io/factory/internal/fieldevidence"
)

const (
	APIVersion       = "platform.4so.io/v1alpha1"
	Kind             = "FieldFailureDiagnosticReport"
	SchemaVersion    = 1
	Algorithm        = "sha256"
	Canonicalization = "go-json-struct-v1"
)

var digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

type Metadata struct {
	ID          string    `json:"id"`
	GeneratedAt time.Time `json:"generatedAt"`
	Digest      string    `json:"digest"`
}

type Product struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type FailedStep struct {
	Key     string `json:"key"`
	Title   string `json:"title"`
	Attempt int    `json:"attempt"`
	Error   string `json:"error"`
}

type Analysis struct {
	Status             string      `json:"status"`
	Category           string      `json:"category"`
	OwningLayer        string      `json:"owningLayer"`
	RetryDisposition   string      `json:"retryDisposition"`
	Summary            string      `json:"summary"`
	NextAction         string      `json:"nextAction"`
	FailedStep         *FailedStep `json:"failedStep,omitempty"`
	ManualReviewNeeded bool        `json:"manualReviewNeeded"`
}

type Claims struct {
	DiagnosticOnly       bool `json:"diagnosticOnly"`
	AutomaticRetry       bool `json:"automaticRetry"`
	RuntimeCertified     bool `json:"runtimeCertified"`
	HACertified          bool `json:"haCertified"`
	ProductionReady      bool `json:"productionReady"`
	LiveExecutionDerived bool `json:"liveExecutionDerived"`
}

type Report struct {
	APIVersion    string                  `json:"apiVersion"`
	Kind          string                  `json:"kind"`
	SchemaVersion int                     `json:"schemaVersion"`
	Metadata      Metadata                `json:"metadata"`
	Product       Product                 `json:"product"`
	Snapshots     fieldevidence.Snapshots `json:"snapshots"`
	Analysis      Analysis                `json:"analysis"`
	Claims        Claims                  `json:"claims"`
}

type Verification struct {
	Valid            bool   `json:"valid"`
	ReportID         string `json:"reportId"`
	RunID            string `json:"runId"`
	RunState         string `json:"runState"`
	Category         string `json:"category"`
	OwningLayer      string `json:"owningLayer"`
	RetryDisposition string `json:"retryDisposition"`
	Digest           string `json:"digest"`
}

type digestPayload struct {
	APIVersion    string                  `json:"apiVersion"`
	Kind          string                  `json:"kind"`
	SchemaVersion int                     `json:"schemaVersion"`
	GeneratedAt   time.Time               `json:"generatedAt"`
	Product       Product                 `json:"product"`
	Snapshots     fieldevidence.Snapshots `json:"snapshots"`
	Analysis      Analysis                `json:"analysis"`
	Claims        Claims                  `json:"claims"`
}

func Build(version string, snapshots fieldevidence.Snapshots, now time.Time) (Report, error) {
	var report Report
	if strings.TrimSpace(version) == "" {
		return report, errors.New("installer version is required")
	}
	if err := validateSnapshots(version, snapshots); err != nil {
		return report, err
	}
	analysis := Analyze(snapshots.InstallationRun, snapshots.Preflight)
	claims := Claims{
		DiagnosticOnly:       true,
		AutomaticRetry:       false,
		RuntimeCertified:     false,
		HACertified:          false,
		ProductionReady:      false,
		LiveExecutionDerived: !snapshots.InstallationRun.Simulation,
	}
	report = Report{
		APIVersion: APIVersion, Kind: Kind, SchemaVersion: SchemaVersion,
		Metadata:  Metadata{GeneratedAt: now.UTC()},
		Product:   Product{Name: "4SO Platform Factory", Version: version},
		Snapshots: snapshots, Analysis: analysis, Claims: claims,
	}
	digest, err := report.computeDigest()
	if err != nil {
		return Report{}, err
	}
	report.Metadata.Digest = digest
	report.Metadata.ID = "diagnostic-" + strings.TrimPrefix(digest, "sha256:")[:20]
	return report, nil
}

func Analyze(run bootstrap.Run, preflight bootstrap.PreflightReport) Analysis {
	switch run.State {
	case bootstrap.RunPending, bootstrap.RunRunning:
		return Analysis{
			Status: "IN_PROGRESS", Category: "installation-progress", OwningLayer: "bootstrap-runner",
			RetryDisposition: "NOT_APPLICABLE", Summary: "installation has not reached a terminal state",
			NextAction: "continue observing the same installation run; do not start a second run", ManualReviewNeeded: false,
		}
	case bootstrap.RunSucceeded:
		return Analysis{
			Status: "SUCCEEDED", Category: "no-failure", OwningLayer: "none",
			RetryDisposition: "NOT_APPLICABLE", Summary: "installation completed without a failed step",
			NextAction: "collect and verify Field Execution Evidence", ManualReviewNeeded: false,
		}
	case bootstrap.RunFailed:
		failed := lastFailedStep(run.Steps)
		category, owner := classifyFailure(failed, run.LastError, preflight)
		step := (*FailedStep)(nil)
		if failed != nil {
			step = &FailedStep{Key: failed.Key, Title: failed.Title, Attempt: failed.Attempt, Error: strings.TrimSpace(failed.Error)}
		}
		summary := strings.TrimSpace(run.LastError)
		if summary == "" && step != nil {
			summary = step.Error
		}
		if summary == "" {
			summary = "installation failed without a detailed runner error"
		}
		return Analysis{
			Status: "FAILED", Category: category, OwningLayer: owner,
			RetryDisposition: "FIX_CAUSE_THEN_RESUME_SAME_RUN", Summary: summary,
			NextAction: "fix the owning cause, record the change and use explicit RESUME on the same run; do not create a new run or auto-retry",
			FailedStep: step, ManualReviewNeeded: true,
		}
	default:
		return Analysis{
			Status: "UNKNOWN", Category: "unknown", OwningLayer: "operator-review",
			RetryDisposition: "BLOCKED", Summary: "unsupported installation state",
			NextAction: "inspect the installer state before any mutation", ManualReviewNeeded: true,
		}
	}
}

func lastFailedStep(steps []bootstrap.Step) *bootstrap.Step {
	for i := len(steps) - 1; i >= 0; i-- {
		if steps[i].State == bootstrap.StepFailed {
			copy := steps[i]
			return &copy
		}
	}
	return nil
}

func classifyFailure(step *bootstrap.Step, lastError string, preflight bootstrap.PreflightReport) (string, string) {
	key := ""
	detail := strings.ToLower(strings.TrimSpace(lastError))
	if step != nil {
		key = strings.ToLower(strings.TrimSpace(step.Key))
		detail += " " + strings.ToLower(step.Error)
	}
	if key == "preflight" || strings.Contains(detail, "preflight") {
		return "host-preflight", "bootstrap-preflight"
	}
	if strings.Contains(detail, "bundle") || strings.Contains(detail, "digest") || strings.Contains(detail, "air-gap index") {
		return "bundle-admission", "appliance-bundle"
	}
	switch key {
	case "prepare-host", "stage-bundle", "configure-rke2", "install-rke2":
		return "host-bootstrap", "bootstrap-runner"
	case "verify-ha-quorum", "verify-ha-services":
		return "high-availability", "bootstrap-ha"
	case "deploy-postgresql-operator", "deploy-foundation", "deploy-internal-git", "deploy-oci-registry", "deploy-identity", "verify-embedded-services":
		return "embedded-service", "embedded-services"
	case "seed-offline-registry":
		return "air-gap-runtime", "offline-registry"
	case "configure-secure-exposure":
		return "network-tls", "secure-exposure"
	case "bootstrap-repository", "deploy-gitops-controller", "publish-signed-revision", "verify-gitops-handover":
		return "gitops-handover", "gitops-runtime"
	case "deploy-fleet-hub", "verify-fleet-hub":
		return "fleet-runtime", "fleet-hub"
	case "configure-off-node-backup":
		return "disaster-recovery", "off-node-backup"
	case "verify-runtime":
		return "runtime-verification", "runtime-probe"
	}
	for _, check := range preflight.Checks {
		if check.State == bootstrap.CheckBlocked {
			return "host-preflight", "bootstrap-preflight"
		}
	}
	return "unclassified-runtime", "operator-review"
}

func Verify(raw []byte) (Verification, error) {
	var result Verification
	var report Report
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&report); err != nil {
		return result, fmt.Errorf("decode diagnostic report: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return result, errors.New("diagnostic report contains multiple JSON values")
		}
		return result, err
	}
	if report.APIVersion != APIVersion || report.Kind != Kind || report.SchemaVersion != SchemaVersion {
		return result, errors.New("unsupported diagnostic report contract")
	}
	if report.Product.Name != "4SO Platform Factory" || strings.TrimSpace(report.Product.Version) == "" {
		return result, errors.New("diagnostic report product identity is invalid")
	}
	if report.Metadata.GeneratedAt.IsZero() || !digestPattern.MatchString(report.Metadata.Digest) {
		return result, errors.New("diagnostic report metadata is incomplete")
	}
	if err := validateSnapshots(report.Product.Version, report.Snapshots); err != nil {
		return result, err
	}
	expectedAnalysis := Analyze(report.Snapshots.InstallationRun, report.Snapshots.Preflight)
	if !reflect.DeepEqual(report.Analysis, expectedAnalysis) {
		return result, errors.New("diagnostic analysis does not match installation snapshots")
	}
	expectedClaims := Claims{DiagnosticOnly: true, AutomaticRetry: false, RuntimeCertified: false, HACertified: false, ProductionReady: false, LiveExecutionDerived: !report.Snapshots.InstallationRun.Simulation}
	if report.Claims != expectedClaims {
		return result, errors.New("diagnostic claims are invalid")
	}
	digest, err := report.computeDigest()
	if err != nil {
		return result, err
	}
	expectedID := "diagnostic-" + strings.TrimPrefix(digest, "sha256:")[:20]
	if digest != report.Metadata.Digest || report.Metadata.ID != expectedID {
		return result, errors.New("diagnostic report digest or ID mismatch")
	}
	return Verification{Valid: true, ReportID: report.Metadata.ID, RunID: report.Snapshots.InstallationRun.ID, RunState: string(report.Snapshots.InstallationRun.State), Category: report.Analysis.Category, OwningLayer: report.Analysis.OwningLayer, RetryDisposition: report.Analysis.RetryDisposition, Digest: digest}, nil
}

func validateSnapshots(version string, snapshots fieldevidence.Snapshots) error {
	if err := snapshots.Preflight.Verify(); err != nil {
		return fmt.Errorf("preflight snapshot: %w", err)
	}
	if !snapshots.BundleAdmission.Verified || strings.TrimSpace(snapshots.BundleAdmission.BundleDigest) == "" {
		return errors.New("bundle admission snapshot is not verified")
	}
	run := snapshots.InstallationRun
	if strings.TrimSpace(run.ID) == "" {
		return errors.New("installation run is required")
	}
	if run.Version != version || snapshots.Preflight.Version != version || snapshots.BundleAdmission.Version != version {
		return errors.New("installer, bundle, preflight and run versions do not match")
	}
	if run.BundleDigest != snapshots.BundleAdmission.BundleDigest || run.PreflightDigest != snapshots.Preflight.Digest || run.SpecDigest != snapshots.Preflight.RequestDigest {
		return errors.New("installation run is not bound to bundle and preflight snapshots")
	}
	return nil
}

func (r Report) computeDigest() (string, error) {
	payload := digestPayload{APIVersion: r.APIVersion, Kind: r.Kind, SchemaVersion: r.SchemaVersion, GeneratedAt: r.Metadata.GeneratedAt.UTC(), Product: r.Product, Snapshots: r.Snapshots, Analysis: r.Analysis, Claims: r.Claims}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
