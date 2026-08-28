package fieldevidence

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"platform.4so.io/factory/internal/bootstrap"
)

func fixtureSnapshots(t *testing.T, simulation bool) Snapshots {
	t.Helper()
	digest := func(ch string) string { return "sha256:" + strings.Repeat(ch, 64) }
	preflight := bootstrap.PreflightReport{
		APIVersion: bootstrap.PreflightAPIVersion, Kind: bootstrap.PreflightKind, SchemaVersion: bootstrap.PreflightSchema,
		Version: "0.0.23", ProfileID: "evaluation-single-node", Connectivity: "connected", RequestDigest: digest("1"),
		BundleDigest: digest("2"), Simulation: simulation, GeneratedAt: time.Date(2026, 8, 6, 18, 0, 0, 0, time.UTC),
		Checks: []bootstrap.PreflightCheck{{Key: "bundle-admission", Title: "Verify bundle", State: bootstrap.CheckPassed, Detail: "bundle is valid"}},
	}
	if err := preflight.Seal(); err != nil {
		t.Fatal(err)
	}
	run := bootstrap.Run{ID: "bootstrap-fixture", Version: "0.0.23", State: bootstrap.RunSucceeded, SpecDigest: digest("1"), BundleDigest: digest("2"), PreflightDigest: preflight.Digest, Simulation: simulation}
	return Snapshots{
		BundleAdmission: bootstrap.BundleAdmissionStatus{Verified: true, Version: "0.0.23", RKE2Version: "v1", SourceReleaseDigest: digest("9"), BundleDigest: digest("2"), LockDigest: digest("3"), LockRequired: true},
		Preflight:       preflight, InstallationRun: run, GitOpsStatus: bootstrap.GitOpsHandoverStatus{State: "SUCCEEDED", RevisionDigest: digest("4")},
		HAStatus: map[string]any{"selected": false, "verified": true}, AirgapStatus: map[string]any{"verified": true},
	}
}

func TestBuildAndVerify(t *testing.T) {
	report, err := Build("0.0.23", fixtureSnapshots(t, true), time.Date(2026, 8, 6, 19, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(report)
	result, err := Verify(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Valid || result.ExecutionMode != "simulation" || result.LiveExecutionObserved || !result.InstallationSucceeded {
		t.Fatalf("unexpected result %#v", result)
	}
}

func TestBuildBindsRunningInstallerBinaryDigest(t *testing.T) {
	report, err := Build("0.0.23", fixtureSnapshots(t, false), time.Date(2026, 8, 6, 19, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	expected, err := CurrentExecutableDigest()
	if err != nil {
		t.Fatal(err)
	}
	if report.Evidence.SchemaVersion != EvidenceSchema || report.Evidence.Inputs.InstallerBinaryDigest != expected {
		t.Fatalf("runtime installer binding missing: schema=%d digest=%s expected=%s", report.Evidence.SchemaVersion, report.Evidence.Inputs.InstallerBinaryDigest, expected)
	}
	raw, _ := json.Marshal(report)
	verification, err := Verify(raw)
	if err != nil {
		t.Fatal(err)
	}
	if verification.InstallerBinaryDigest != expected {
		t.Fatalf("verification digest=%s", verification.InstallerBinaryDigest)
	}
}

func TestVerifyRejectsTamperingAndCertificationClaims(t *testing.T) {
	report, err := Build("0.0.23", fixtureSnapshots(t, false), time.Date(2026, 8, 6, 19, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	report.Snapshots.HAStatus["verified"] = false
	raw, _ := json.Marshal(report)
	if _, err = Verify(raw); err == nil {
		t.Fatal("tampered HA snapshot accepted")
	}

	report, _ = Build("0.0.23", fixtureSnapshots(t, false), time.Date(2026, 8, 6, 19, 0, 0, 0, time.UTC))
	report.Claims.RuntimeCertified = true
	raw, _ = json.Marshal(report)
	if _, err = Verify(raw); err == nil {
		t.Fatal("certification claim accepted")
	}
}

func TestExactReleaseBindingIsCoveredByEvidenceDigest(t *testing.T) {
	report, err := Build("0.0.23", fixtureSnapshots(t, false), time.Date(2026, 8, 6, 19, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	original := report.Evidence.Inputs.ReleaseArtifactDigest
	if original == "" {
		t.Fatal("release binding missing")
	}
	report.Evidence.Inputs.ReleaseArtifactDigest = "sha256:" + strings.Repeat("8", 64)
	raw, _ := json.Marshal(report)
	if _, err = Verify(raw); err == nil || !strings.Contains(err.Error(), "exact source release artifact") {
		t.Fatalf("tampered release artifact binding accepted: %v", err)
	}
}
