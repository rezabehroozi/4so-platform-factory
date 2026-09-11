package main

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"platform.4so.io/factory/internal/bootstrap"
	"platform.4so.io/factory/internal/fieldcampaign"
	"platform.4so.io/factory/internal/fielddiagnostics"
	"platform.4so.io/factory/internal/fieldevidence"
	"platform.4so.io/factory/internal/installation"
	"platform.4so.io/factory/internal/releaseartifact"
)

func campaignRequestFixture() installation.InstallRequest {
	return installation.InstallRequest{
		ProfileID: "evaluation-single-node", Connectivity: installation.ConnectivityConnected,
		Infrastructure: installation.InfrastructureSpec{Provider: "existing-hosts", NodeAddresses: []string{"127.0.0.1"}},
		Network:        installation.NetworkSpec{PublicEndpoint: "https://platform.example", TLSMode: "bootstrap-self-signed"},
		Services:       installation.ServicesSpec{Identity: installation.IdentitySpec{AdminEmail: "admin@example.test"}},
	}
}

func TestFieldCampaignPrepareStartWatchCollect(t *testing.T) {
	digest := func(ch string) string { return "sha256:" + strings.Repeat(ch, 64) }
	request := campaignRequestFixture()
	preflight := bootstrap.PreflightReport{
		APIVersion: bootstrap.PreflightAPIVersion, Kind: bootstrap.PreflightKind, SchemaVersion: bootstrap.PreflightSchema,
		Version: "0.0.23", ProfileID: request.ProfileID, Connectivity: string(request.Connectivity), RequestDigest: digest("1"), BundleDigest: digest("2"),
		Simulation: true, GeneratedAt: time.Date(2026, 8, 6, 20, 0, 0, 0, time.UTC),
		Checks: []bootstrap.PreflightCheck{{Key: "all", Title: "All checks", State: bootstrap.CheckPassed, Detail: "passed"}},
	}
	if err := preflight.Seal(); err != nil {
		t.Fatal(err)
	}
	bundle := bootstrap.BundleAdmissionStatus{Verified: true, Version: "0.0.23", SourceReleaseDigest: digest("9"), BundleDigest: digest("2"), LockDigest: digest("3"), LockRequired: true}
	plan := installation.InstallationPlan{ID: "install-plan-1", SpecDigest: digest("1"), Status: "execution-ready", Executable: true}
	run := bootstrap.Run{ID: "bootstrap-live-1", Version: "0.0.23", State: bootstrap.RunSucceeded, Request: request, SpecDigest: digest("1"), BundleDigest: digest("2"), PreflightDigest: preflight.Digest, Simulation: true}
	report, err := fieldevidence.Build("0.0.23", fieldevidence.Snapshots{
		BundleAdmission: bundle, Preflight: preflight, InstallationRun: run,
		GitOpsStatus: bootstrap.GitOpsHandoverStatus{State: "SUCCEEDED", RevisionDigest: digest("4")},
		HAStatus:     map[string]any{"verified": true}, AirgapStatus: map[string]any{"verified": true},
	}, time.Date(2026, 8, 6, 21, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	diagnostic, err := fielddiagnostics.Build("0.0.23", fieldevidence.Snapshots{
		BundleAdmission: bundle, Preflight: preflight, InstallationRun: run,
		GitOpsStatus: bootstrap.GitOpsHandoverStatus{State: "SUCCEEDED", RevisionDigest: digest("4")},
		HAStatus:     map[string]any{"verified": true}, AirgapStatus: map[string]any{"verified": true},
	}, time.Date(2026, 8, 6, 21, 1, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}

	installerDigest, err := fieldevidence.CurrentExecutableDigest()
	if err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	started := false
	statusCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Fatalf("missing auth for %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/access/status":
			_ = json.NewEncoder(w).Encode(map[string]any{"installerBinaryDigest": installerDigest})
		case "/api/v1/bundle/status":
			_ = json.NewEncoder(w).Encode(bundle)
		case "/api/v1/plan":
			_ = json.NewEncoder(w).Encode(installerPlanResponse{Plan: plan, BundleDigest: bundle.BundleDigest, ExecutionEnabled: true})
		case "/api/v1/preflight":
			_ = json.NewEncoder(w).Encode(preflight)
		case "/api/v1/start":
			mu.Lock()
			started = true
			mu.Unlock()
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "accepted"})
		case "/api/v1/status":
			mu.Lock()
			defer mu.Unlock()
			if !started {
				_ = json.NewEncoder(w).Encode(installerStatusResponse{ExecutionEnabled: true})
				return
			}
			statusCalls++
			observed := run
			if statusCalls == 1 {
				observed.State = bootstrap.RunPending
			} else if statusCalls == 2 {
				observed.State = bootstrap.RunRunning
			}
			active := observed.State == bootstrap.RunPending || observed.State == bootstrap.RunRunning
			_ = json.NewEncoder(w).Encode(installerStatusResponse{ExecutionEnabled: true, BootstrapActive: active, Run: &observed})
		case "/api/v1/field-evidence/report":
			_ = json.NewEncoder(w).Encode(report)
		case "/api/v1/diagnostics/report":
			_ = json.NewEncoder(w).Encode(diagnostic)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	base, _ := url.Parse(server.URL)
	connection := fieldCampaignConnection{base: base, client: server.Client(), token: "token"}
	campaign, err := prepareFieldCampaign(connection, request, digest("9"), installerDigest, digest("7"), time.Now().UTC().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if campaign.State != fieldcampaign.StatePrepared || campaign.PlanID != plan.ID {
		t.Fatalf("prepared=%+v", campaign)
	}
	if err = startFieldCampaign(connection, &campaign, campaign.UpdatedAt.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err = watchFieldCampaign(ctx, connection, &campaign, time.Millisecond, nil); err != nil {
		t.Fatal(err)
	}
	if campaign.State != fieldcampaign.StateSucceeded || campaign.RunID != run.ID {
		t.Fatalf("observed=%+v", campaign)
	}
	raw, verification, err := collectFieldCampaignEvidence(connection, &campaign, campaign.UpdatedAt.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 || !verification.Valid || !campaign.EvidenceVerified || campaign.EvidenceDigest != verification.EvidenceDigest {
		t.Fatalf("verification=%+v campaign=%+v", verification, campaign)
	}
	diagnosticRaw, diagnosticVerification, err := downloadFieldDiagnosticReport(connection.client, connection.base, connection.token)
	if err != nil {
		t.Fatal(err)
	}
	if len(diagnosticRaw) == 0 || !diagnosticVerification.Valid || diagnosticVerification.RunID != campaign.RunID {
		t.Fatalf("diagnostic verification=%+v", diagnosticVerification)
	}
}

func TestFieldCampaignInterruptedRunningRunRequiresExplicitResume(t *testing.T) {
	digest := func(ch string) string { return "sha256:" + strings.Repeat(ch, 64) }
	request := campaignRequestFixture()
	now := time.Date(2026, 8, 29, 4, 0, 0, 0, time.UTC)
	installerDigest := digest("8")
	campaign, err := fieldcampaign.New("http://installer.example", request, digest("1"), digest("2"), digest("9"), installerDigest, digest("7"), "plan-interrupt", digest("3"), true, now)
	if err != nil {
		t.Fatal(err)
	}
	if err = campaign.Transition(fieldcampaign.StateStartRequested, "start", "started", now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	campaign.RunID = "bootstrap-interrupted"
	campaign.RunState = string(bootstrap.RunRunning)
	simulation := false
	campaign.Simulation = &simulation
	if err = campaign.Transition(fieldcampaign.StateRunning, "observe", "running", now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	run := bootstrap.Run{ID: campaign.RunID, State: bootstrap.RunRunning, SpecDigest: campaign.RequestDigest, BundleDigest: campaign.BundleDigest, PreflightDigest: campaign.PreflightDigest, Simulation: false}
	resumeCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/access/status":
			_ = json.NewEncoder(w).Encode(map[string]any{"installerBinaryDigest": installerDigest})
		case "/api/v1/status":
			_ = json.NewEncoder(w).Encode(installerStatusResponse{ExecutionEnabled: true, BootstrapActive: false, Run: &run})
		case "/api/v1/resume":
			resumeCalls++
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "accepted"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	base, _ := url.Parse(server.URL)
	campaign.InstallerURL = server.URL
	if err = campaign.Seal(); err != nil {
		t.Fatal(err)
	}
	connection := fieldCampaignConnection{base: base, client: server.Client(), token: "token"}
	terminal, changed, err := observeFieldCampaign(connection, &campaign, now.Add(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if !terminal || !changed || campaign.State != fieldcampaign.StateInterrupted || campaign.RunState != string(bootstrap.RunRunning) || !strings.Contains(campaign.LastError, "interrupted") {
		t.Fatalf("interrupted campaign was not surfaced truthfully: %+v", campaign)
	}
	if err = resumeFieldCampaign(connection, &campaign, now.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	if resumeCalls != 1 || campaign.State != fieldcampaign.StateStartRequested || campaign.LastError != "" {
		t.Fatalf("interrupted campaign did not resume exactly once: calls=%d campaign=%+v", resumeCalls, campaign)
	}
}

func TestFieldCampaignStartRejectsChangedBundle(t *testing.T) {
	digest := func(ch string) string { return "sha256:" + strings.Repeat(ch, 64) }
	request := campaignRequestFixture()
	preflight := bootstrap.PreflightReport{APIVersion: bootstrap.PreflightAPIVersion, Kind: bootstrap.PreflightKind, SchemaVersion: bootstrap.PreflightSchema, Version: "0.0.23", ProfileID: request.ProfileID, Connectivity: string(request.Connectivity), RequestDigest: digest("1"), BundleDigest: digest("9"), Simulation: true, Checks: []bootstrap.PreflightCheck{{Key: "all", Title: "All", State: bootstrap.CheckPassed, Detail: "passed"}}}
	if err := preflight.Seal(); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/access/status":
			_ = json.NewEncoder(w).Encode(map[string]any{"installerBinaryDigest": digest("8")})
		case "/api/v1/bundle/status":
			_ = json.NewEncoder(w).Encode(bootstrap.BundleAdmissionStatus{Verified: true, Version: "0.0.23", SourceReleaseDigest: digest("7"), BundleDigest: digest("9"), LockDigest: digest("8"), LockRequired: true})
		case "/api/v1/plan":
			_ = json.NewEncoder(w).Encode(installerPlanResponse{Plan: installation.InstallationPlan{ID: "install-plan-1", SpecDigest: digest("1"), Executable: true}, BundleDigest: digest("9"), ExecutionEnabled: true})
		case "/api/v1/preflight":
			_ = json.NewEncoder(w).Encode(preflight)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	base, _ := url.Parse(server.URL)
	connection := fieldCampaignConnection{base: base, client: server.Client(), token: "token"}
	campaign, err := fieldcampaign.New(server.URL, request, digest("1"), digest("2"), digest("9"), digest("8"), digest("7"), "install-plan-1", preflight.Digest, true, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err = startFieldCampaign(connection, &campaign, time.Now().UTC()); err == nil || !strings.Contains(err.Error(), "no longer matches") {
		t.Fatalf("unexpected error %v", err)
	}
}

func TestCollectFieldCampaignEvidenceRejectsDifferentBundleWithSameRunAndRelease(t *testing.T) {
	digest := func(ch string) string { return "sha256:" + strings.Repeat(ch, 64) }
	request := campaignRequestFixture()
	campaignPreflight := bootstrap.PreflightReport{
		APIVersion: bootstrap.PreflightAPIVersion, Kind: bootstrap.PreflightKind, SchemaVersion: bootstrap.PreflightSchema,
		Version: "0.0.23", ProfileID: request.ProfileID, Connectivity: string(request.Connectivity), RequestDigest: digest("1"), BundleDigest: digest("2"),
		Simulation: false, GeneratedAt: time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC),
		Checks: []bootstrap.PreflightCheck{{Key: "all", Title: "All", State: bootstrap.CheckPassed, Detail: "passed"}},
	}
	if err := campaignPreflight.Seal(); err != nil {
		t.Fatal(err)
	}
	campaign, err := fieldcampaign.New("http://installer.example", request, digest("1"), digest("2"), digest("9"), digest("8"), digest("7"), "plan-1", campaignPreflight.Digest, true, time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	campaign.RunID = "bootstrap-same-spec"
	campaign.RunState = string(bootstrap.RunSucceeded)
	campaign.State = fieldcampaign.StateSucceeded
	simulation := false
	campaign.Simulation = &simulation
	if err = campaign.Seal(); err != nil {
		t.Fatal(err)
	}

	// A second appliance bundle assembled from the same exact release and install
	// request can retain the same deterministic run ID while having a different
	// bundle/preflight digest. Such evidence must never attach to the old campaign.
	otherPreflight := campaignPreflight
	otherPreflight.BundleDigest = digest("5")
	otherPreflight.Digest = ""
	if err = otherPreflight.Seal(); err != nil {
		t.Fatal(err)
	}
	otherBundle := bootstrap.BundleAdmissionStatus{Verified: true, Version: "0.0.23", SourceReleaseDigest: digest("9"), BundleDigest: digest("5"), LockDigest: digest("6"), LockRequired: true}
	otherRun := bootstrap.Run{ID: campaign.RunID, Version: "0.0.23", State: bootstrap.RunSucceeded, Request: request, SpecDigest: digest("1"), BundleDigest: digest("5"), PreflightDigest: otherPreflight.Digest, Simulation: false}
	report, err := fieldevidence.Build("0.0.23", fieldevidence.Snapshots{
		BundleAdmission: otherBundle, Preflight: otherPreflight, InstallationRun: otherRun,
		GitOpsStatus: bootstrap.GitOpsHandoverStatus{State: "SUCCEEDED", RevisionDigest: digest("4")},
		HAStatus:     map[string]any{"verified": true}, AirgapStatus: map[string]any{"verified": true},
	}, time.Date(2026, 8, 20, 13, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/field-evidence/report" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(report)
	}))
	defer server.Close()
	base, _ := url.Parse(server.URL)
	connection := fieldCampaignConnection{base: base, client: server.Client(), token: "token"}

	if _, _, err = collectFieldCampaignEvidence(connection, &campaign, time.Now().UTC()); err == nil || !strings.Contains(err.Error(), "bundle digest") {
		t.Fatalf("evidence from a different appliance bundle was accepted: %v", err)
	}
	if campaign.EvidenceVerified {
		t.Fatal("rejected evidence mutated campaign verification state")
	}
}

func TestVerifyCampaignReleaseArtifactRequiresAndMatchesExactArchiveForSchemaV2(t *testing.T) {
	makeRelease := func(version string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "release.zip")
		file, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		zw := zip.NewWriter(file)
		versionBody := []byte(version + "\n")
		releaseNameBody := []byte("test\n")
		versionSum := sha256.Sum256(versionBody)
		releaseNameSum := sha256.Sum256(releaseNameBody)
		manifestRaw, err := json.Marshal(map[string]any{
			"schemaVersion": 2,
			"product":       "4SO Platform Factory",
			"version":       version,
			"releaseName":   "test",
			"fileCount":     2,
			"files": []map[string]any{
				{"path": "VERSION", "sha256": hex.EncodeToString(versionSum[:]), "size": len(versionBody), "mode": "0o644"},
				{"path": "RELEASE-NAME", "sha256": hex.EncodeToString(releaseNameSum[:]), "size": len(releaseNameBody), "mode": "0o644"},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		root := "4so-platform-factory-" + version + "-test"
		for name, body := range map[string][]byte{
			root + "/VERSION":                versionBody,
			root + "/RELEASE-NAME":           releaseNameBody,
			root + "/ARTIFACT-MANIFEST.json": manifestRaw,
		} {
			header := &zip.FileHeader{Name: name, Method: zip.Deflate}
			header.SetMode(0o644)
			w, createErr := zw.CreateHeader(header)
			if createErr != nil {
				t.Fatal(createErr)
			}
			if _, writeErr := w.Write(body); writeErr != nil {
				t.Fatal(writeErr)
			}
		}
		if err = zw.Close(); err != nil {
			t.Fatal(err)
		}
		if err = file.Close(); err != nil {
			t.Fatal(err)
		}
		return path
	}

	path := makeRelease("0.0.23")
	campaign := fieldcampaign.Campaign{SchemaVersion: fieldcampaign.ExactSHASchemaVersion}
	if err := verifyCampaignReleaseArtifact(campaign, "", "0.0.23"); err == nil || !strings.Contains(err.Error(), "requires --release-artifact") {
		t.Fatalf("missing exact release artifact was accepted: %v", err)
	}

	// First learn the exact digest through the same releaseartifact inspection
	// contract used by prepare/collect, then prove a different archive is refused.
	release, err := releaseartifact.Inspect(path, "0.0.23")
	if err != nil {
		t.Fatal(err)
	}
	campaign.ReleaseArtifactDigest = release.Digest
	if err = verifyCampaignReleaseArtifact(campaign, path, "0.0.23"); err != nil {
		t.Fatalf("matching exact release artifact rejected: %v", err)
	}
	other := makeRelease("0.0.23")
	// Make the second valid release archive byte-distinct without changing its
	// release identity contract.
	f, err := os.OpenFile(other, os.O_RDWR|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write([]byte("trailing-bytes")); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	if err = verifyCampaignReleaseArtifact(campaign, other, "0.0.23"); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("different exact release artifact was accepted: %v", err)
	}
}

func TestFieldCampaignStartRejectsDifferentRunningInstallerBinary(t *testing.T) {
	digest := func(ch string) string { return "sha256:" + strings.Repeat(ch, 64) }
	request := campaignRequestFixture()
	preflight := bootstrap.PreflightReport{APIVersion: bootstrap.PreflightAPIVersion, Kind: bootstrap.PreflightKind, SchemaVersion: bootstrap.PreflightSchema, Version: "0.0.23", ProfileID: request.ProfileID, Connectivity: string(request.Connectivity), RequestDigest: digest("1"), BundleDigest: digest("2"), Simulation: false, Checks: []bootstrap.PreflightCheck{{Key: "all", Title: "All", State: bootstrap.CheckPassed, Detail: "passed"}}}
	if err := preflight.Seal(); err != nil {
		t.Fatal(err)
	}
	campaign, err := fieldcampaign.New("http://installer.example", request, digest("1"), digest("2"), digest("9"), digest("8"), digest("7"), "plan-1", preflight.Digest, true, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	mutated := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/access/status" {
			_ = json.NewEncoder(w).Encode(map[string]any{"installerBinaryDigest": digest("7")})
			return
		}
		mutated = true
		http.Error(w, "unexpected request", http.StatusInternalServerError)
	}))
	defer server.Close()
	base, _ := url.Parse(server.URL)
	campaign.InstallerURL = server.URL
	if err = campaign.Seal(); err != nil {
		t.Fatal(err)
	}
	connection := fieldCampaignConnection{base: base, client: server.Client(), token: "token"}
	if err = startFieldCampaign(connection, &campaign, time.Now().UTC()); err == nil || !strings.Contains(err.Error(), "binary digest") {
		t.Fatalf("different running installer binary was accepted: %v", err)
	}
	if mutated {
		t.Fatal("installer mutation path was reached before runtime binary identity rejection")
	}
}
