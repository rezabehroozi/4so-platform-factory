package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"platform.4so.io/factory/internal/bootstrap"
	"platform.4so.io/factory/internal/evidence"
	"platform.4so.io/factory/internal/fieldevidence"
	"platform.4so.io/factory/internal/releaseartifact"
)

func closureReportFixture(t *testing.T) []byte {
	t.Helper()
	inputs := evidence.RuntimeClosureInputs{
		CampaignID: "campaign-cli", ProjectID: "project-cli", ClusterID: "cluster-cli",
		ClusterInventoryDigest: "sha256:" + strings.Repeat("1", 64), BaselineDeploymentID: "baseline-cli",
		BaselineDesiredDigest: "sha256:" + strings.Repeat("2", 64), BaselineObservedDigest: "sha256:" + strings.Repeat("2", 64),
		RuntimeVerificationID: "verification-cli", RuntimeReportDigest: "sha256:" + strings.Repeat("3", 64),
		RuntimeDesiredDigest: "sha256:" + strings.Repeat("2", 64), RuntimeObservedDigest: "sha256:" + strings.Repeat("2", 64),
		ReleaseArtifactDigest: "sha256:" + strings.Repeat("4", 64), ProducerBinaryDigest: "sha256:" + strings.Repeat("5", 64),
	}
	digest, err := inputs.Digest()
	if err != nil {
		t.Fatal(err)
	}
	report := map[string]any{
		"apiVersion": evidence.RuntimeClosureAPIVersion, "kind": evidence.RuntimeClosureKind,
		"metadata": map[string]any{"id": inputs.CampaignID, "evidenceDigest": digest, "state": "SUCCEEDED"},
		"product":  map[string]any{"name": "4SO Platform Factory", "version": "0.0.21"},
		"target": map[string]any{
			"cluster":            map[string]any{"id": inputs.ClusterID, "projectId": inputs.ProjectID, "inventoryDigest": inputs.ClusterInventoryDigest},
			"baselineDeployment": map[string]any{"id": inputs.BaselineDeploymentID, "projectId": inputs.ProjectID, "clusterId": inputs.ClusterID, "desiredDigest": inputs.BaselineDesiredDigest, "observedDigest": inputs.BaselineObservedDigest},
		},
		"runtimeVerification": map[string]any{"id": inputs.RuntimeVerificationID, "projectId": inputs.ProjectID, "clusterId": inputs.ClusterID, "reportDigest": inputs.RuntimeReportDigest, "desiredDigest": inputs.RuntimeDesiredDigest, "observedDigest": inputs.RuntimeObservedDigest},
		"result":              map[string]any{"state": "SUCCEEDED", "summary": "complete", "nextAction": "download-runtime-closure-report", "lastError": ""},
		"claims":              map[string]any{"runtimeClosed": true, "runtimeCertified": false, "productionReady": false, "haCertified": false},
		"evidence":            evidence.RuntimeClosureEvidence{SchemaVersion: evidence.RuntimeClosureEvidenceSchema, Algorithm: "sha256", Canonicalization: evidence.RuntimeClosureCanonicalization, BindingAuthority: evidence.RuntimeClosureExactReleaseBindingAuthority, Inputs: inputs, Digest: digest},
	}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestValidateAPIURL(t *testing.T) {
	for _, value := range []string{"https://platform.example", "http://127.0.0.1:8080", "http://localhost:8080"} {
		if _, err := validateAPIURL(value); err != nil {
			t.Fatalf("valid URL %q rejected: %v", value, err)
		}
	}
	for _, value := range []string{"http://platform.example", "https://user:pass@platform.example", "https://platform.example?token=x", "platform.example"} {
		if _, err := validateAPIURL(value); err == nil {
			t.Fatalf("unsafe URL %q accepted", value)
		}
	}
}

func TestClosureHTTPClientRejectsRedirectsBeforeCredentialForwarding(t *testing.T) {
	var leaked string
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer destination.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL+"/report", http.StatusFound)
	}))
	defer origin.Close()

	client, err := closureHTTPClient("")
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodGet, origin.URL+"/report", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer secret-token")
	if _, err = client.Do(req); err == nil || !strings.Contains(err.Error(), "redirects are denied") {
		t.Fatalf("redirect was not denied: %v", err)
	}
	if leaked != "" {
		t.Fatalf("authorization leaked across redirect: %q", leaked)
	}
}

func TestDownloadClosureReportVerifiesBeforeReturn(t *testing.T) {
	raw := closureReportFixture(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/runtime-closure-campaigns/campaign-cli/report" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer token-value" {
			t.Fatalf("authorization header missing")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
	}))
	defer server.Close()
	base, err := validateAPIURL(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	got, result, err := downloadClosureReport(server.Client(), base, "campaign-cli", "token-value")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(raw) || !result.Valid || result.CampaignID != "campaign-cli" {
		t.Fatalf("unexpected result %#v", result)
	}
}

func TestDownloadClosureReportRejectsTampering(t *testing.T) {
	raw := strings.Replace(string(closureReportFixture(t)), "cluster-cli", "cluster-tampered", 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(raw))
	}))
	defer server.Close()
	base, _ := validateAPIURL(server.URL)
	if _, _, err := downloadClosureReport(server.Client(), base, "campaign-cli", ""); err == nil {
		t.Fatal("tampered report was accepted")
	}
}

func TestWriteAtomicPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "report.json")
	if err := writeAtomicPrivate(path, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("unexpected permissions %o", info.Mode().Perm())
	}
}

func fieldEvidenceFixture(t *testing.T) []byte {
	t.Helper()
	digest := func(ch string) string { return "sha256:" + strings.Repeat(ch, 64) }
	preflight := bootstrap.PreflightReport{
		APIVersion: bootstrap.PreflightAPIVersion, Kind: bootstrap.PreflightKind, SchemaVersion: bootstrap.PreflightSchema,
		Version: "0.0.23", ProfileID: "evaluation-single-node", Connectivity: "connected", RequestDigest: digest("1"), BundleDigest: digest("2"),
		Simulation: true, GeneratedAt: time.Date(2026, 8, 6, 18, 0, 0, 0, time.UTC),
		Checks: []bootstrap.PreflightCheck{{Key: "bundle", Title: "Verify bundle", State: bootstrap.CheckPassed, Detail: "valid"}},
	}
	if err := preflight.Seal(); err != nil {
		t.Fatal(err)
	}
	snapshots := fieldevidence.Snapshots{
		BundleAdmission: bootstrap.BundleAdmissionStatus{Verified: true, Version: "0.0.23", SourceReleaseDigest: digest("9"), BundleDigest: digest("2"), LockDigest: digest("3"), LockRequired: true},
		Preflight:       preflight,
		InstallationRun: bootstrap.Run{ID: "bootstrap-field", Version: "0.0.23", State: bootstrap.RunSucceeded, SpecDigest: digest("1"), BundleDigest: digest("2"), PreflightDigest: preflight.Digest, Simulation: true},
		GitOpsStatus:    bootstrap.GitOpsHandoverStatus{State: "SUCCEEDED", RevisionDigest: digest("4")},
		HAStatus:        map[string]any{"verified": true}, AirgapStatus: map[string]any{"verified": true},
	}
	report, err := fieldevidence.Build("0.0.23", snapshots, time.Date(2026, 8, 6, 19, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestDownloadFieldEvidenceVerifiesBeforeReturn(t *testing.T) {
	raw := fieldEvidenceFixture(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/field-evidence/report" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer bootstrap-token" {
			t.Fatal("authorization header missing")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
	}))
	defer server.Close()
	base, _ := validateAPIURL(server.URL)
	got, result, err := downloadFieldEvidenceReport(server.Client(), base, "bootstrap-token")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(raw) || !result.Valid || result.RunID != "bootstrap-field" {
		t.Fatalf("unexpected result %#v", result)
	}
}

func TestDownloadFieldEvidenceRejectsTampering(t *testing.T) {
	raw := strings.Replace(string(fieldEvidenceFixture(t)), "SUCCEEDED", "FAILED", 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(raw)) }))
	defer server.Close()
	base, _ := validateAPIURL(server.URL)
	if _, _, err := downloadFieldEvidenceReport(server.Client(), base, "bootstrap-token"); err == nil {
		t.Fatal("tampered field evidence accepted")
	}
}

func TestClosureHTTPClientDisablesImplicitProxy(t *testing.T) {
	client, err := closureHTTPClient("")
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("unexpected transport %T", client.Transport)
	}
	if transport.Proxy != nil {
		t.Fatal("credential-bearing control-plane client must not trust environment proxies")
	}
}

func TestControlPlaneTransportRejectsUnsafeResolutionBeforeDial(t *testing.T) {
	lookup := func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("169.254.169.254")}, nil
	}
	dialed := false
	dial := func(context.Context, string, string) (net.Conn, error) {
		dialed = true
		return nil, errors.New("unexpected dial")
	}
	client, err := newClosureHTTPClient("", lookup, dial)
	if err != nil {
		t.Fatal(err)
	}
	transport := client.Transport.(*http.Transport)
	if _, err = transport.DialContext(context.Background(), "tcp", "installer.example:443"); err == nil || !strings.Contains(err.Error(), "unsafe address") {
		t.Fatalf("unsafe resolution was not rejected: %v", err)
	}
	if dialed {
		t.Fatal("unsafe address reached dial boundary")
	}
}

func TestControlPlaneTransportPinsValidatedPrivateAddress(t *testing.T) {
	lookupCalls := 0
	lookup := func(context.Context, string, string) ([]netip.Addr, error) {
		lookupCalls++
		return []netip.Addr{netip.MustParseAddr("10.23.45.67")}, nil
	}
	var dialAddress string
	clientSide, peer := net.Pipe()
	defer peer.Close()
	dial := func(_ context.Context, _ string, address string) (net.Conn, error) {
		dialAddress = address
		return clientSide, nil
	}
	client, err := newClosureHTTPClient("", lookup, dial)
	if err != nil {
		t.Fatal(err)
	}
	transport := client.Transport.(*http.Transport)
	conn, err := transport.DialContext(context.Background(), "tcp", "installer.internal:9443")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if lookupCalls != 1 || dialAddress != "10.23.45.67:9443" {
		t.Fatalf("resolution/dial authority mismatch calls=%d address=%q", lookupCalls, dialAddress)
	}
}

func TestNamedAccessTokenRequiresPrivateRegularFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bootstrap.token")
	if err := os.WriteFile(path, []byte("private-bootstrap-token-abcdefghijklmnopqrstuvwxyz\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := namedAccessToken(path, "IGNORED_TOKEN_ENV")
	if err != nil || got != "private-bootstrap-token-abcdefghijklmnopqrstuvwxyz" {
		t.Fatalf("private token read failed got=%q err=%v", got, err)
	}
	if err = os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err = namedAccessToken(path, "IGNORED_TOKEN_ENV"); err == nil || !strings.Contains(err.Error(), "permissions") {
		t.Fatalf("group/other-readable token file accepted: %v", err)
	}
	if err = os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "token-link")
	if err = os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err = namedAccessToken(link, "IGNORED_TOKEN_ENV"); err == nil || !strings.Contains(err.Error(), "non-symlink") {
		t.Fatalf("symlink token file accepted: %v", err)
	}
}

func TestVerifyRuntimeClosureExactReleaseMatchesReleaseAndProducerBinary(t *testing.T) {
	result, err := evidence.VerifyRuntimeClosureReport(closureReportFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	release := releaseartifact.Inspection{
		Digest:  result.ReleaseArtifactDigest,
		Version: result.ProductVersion,
		FileDigests: map[string]string{
			releaseartifact.PlatformAPIBinaryPath: strings.TrimPrefix(result.ProducerBinaryDigest, "sha256:"),
		},
	}
	if err := verifyRuntimeClosureExactRelease(result, release); err != nil {
		t.Fatal(err)
	}
	badRelease := release
	badRelease.Digest = "sha256:" + strings.Repeat("9", 64)
	if err := verifyRuntimeClosureExactRelease(result, badRelease); err == nil || !strings.Contains(err.Error(), "release artifact digest") {
		t.Fatalf("release mismatch was accepted: %v", err)
	}
	badProducer := release
	badProducer.FileDigests = map[string]string{releaseartifact.PlatformAPIBinaryPath: strings.Repeat("8", 64)}
	if err := verifyRuntimeClosureExactRelease(result, badProducer); err == nil || !strings.Contains(err.Error(), "producer binary digest") {
		t.Fatalf("producer mismatch was accepted: %v", err)
	}
}
