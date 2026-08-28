package fielddiagnostics

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"platform.4so.io/factory/internal/bootstrap"
	"platform.4so.io/factory/internal/fieldevidence"
)

func fixture(t *testing.T, state bootstrap.RunState, stepKey string) fieldevidence.Snapshots {
	t.Helper()
	digest := func(ch string) string { return "sha256:" + strings.Repeat(ch, 64) }
	preflight := bootstrap.PreflightReport{APIVersion: bootstrap.PreflightAPIVersion, Kind: bootstrap.PreflightKind, SchemaVersion: bootstrap.PreflightSchema, Version: "0.0.25", ProfileID: "evaluation-single-node", Connectivity: "connected", RequestDigest: digest("1"), BundleDigest: digest("2"), Simulation: true, GeneratedAt: time.Date(2026, 8, 6, 20, 0, 0, 0, time.UTC), Checks: []bootstrap.PreflightCheck{{Key: "bundle", Title: "Bundle", State: bootstrap.CheckPassed, Detail: "valid"}}}
	if err := preflight.Seal(); err != nil {
		t.Fatal(err)
	}
	steps := []bootstrap.Step{{Key: stepKey, Title: "Execute step", State: bootstrap.StepFailed, Attempt: 1, Error: "temporary execution failure"}}
	if state != bootstrap.RunFailed {
		steps[0].State = bootstrap.StepSucceeded
		steps[0].Error = ""
	}
	return fieldevidence.Snapshots{
		BundleAdmission: bootstrap.BundleAdmissionStatus{Verified: true, Version: "0.0.25", BundleDigest: digest("2"), LockDigest: digest("3"), LockRequired: true},
		Preflight:       preflight,
		InstallationRun: bootstrap.Run{ID: "bootstrap-1", Version: "0.0.25", State: state, SpecDigest: digest("1"), BundleDigest: digest("2"), PreflightDigest: preflight.Digest, Steps: steps, LastError: "temporary execution failure", Simulation: true},
		GitOpsStatus:    bootstrap.GitOpsHandoverStatus{State: "NOT_STARTED"}, HAStatus: map[string]any{"verified": false}, AirgapStatus: map[string]any{"verified": true},
	}
}

func TestBuildVerifyAndClassify(t *testing.T) {
	report, err := Build("0.0.25", fixture(t, bootstrap.RunFailed, "install-rke2"), time.Date(2026, 8, 6, 21, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if report.Analysis.Category != "host-bootstrap" || report.Analysis.RetryDisposition != "FIX_CAUSE_THEN_RESUME_SAME_RUN" {
		t.Fatalf("analysis=%+v", report.Analysis)
	}
	raw, _ := json.Marshal(report)
	result, err := Verify(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Valid || result.RunID != "bootstrap-1" || result.OwningLayer != "bootstrap-runner" {
		t.Fatalf("result=%+v", result)
	}
}

func TestVerifyRejectsTamperAndCertificationClaim(t *testing.T) {
	report, _ := Build("0.0.25", fixture(t, bootstrap.RunFailed, "verify-runtime"), time.Date(2026, 8, 6, 21, 0, 0, 0, time.UTC))
	report.Analysis.OwningLayer = "different"
	raw, _ := json.Marshal(report)
	if _, err := Verify(raw); err == nil {
		t.Fatal("tampered analysis accepted")
	}

	report, _ = Build("0.0.25", fixture(t, bootstrap.RunFailed, "verify-runtime"), time.Date(2026, 8, 6, 21, 0, 0, 0, time.UTC))
	report.Claims.RuntimeCertified = true
	raw, _ = json.Marshal(report)
	if _, err := Verify(raw); err == nil {
		t.Fatal("certification claim accepted")
	}
}
