package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"platform.4so.io/factory/internal/bootstrap"
	"platform.4so.io/factory/internal/fieldcampaign"
	"platform.4so.io/factory/internal/installation"
)

func TestValidateZeroToHARequest(t *testing.T) {
	req := installation.InstallRequest{ProfileID: "production-standard-ha"}
	req.Infrastructure.NodeAddresses = []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	req.Infrastructure.CredentialRef = "secret://installer/ssh-private-key"
	if err := validateZeroToHARequest(req); err != nil {
		t.Fatal(err)
	}
	req.Infrastructure.NodeAddresses = req.Infrastructure.NodeAddresses[:2]
	if err := validateZeroToHARequest(req); err == nil {
		t.Fatal("expected exact three-node validation")
	}
}

func TestRequirePeerTrust(t *testing.T) {
	entries := []bootstrap.SSHHostTrustEntry{
		{Host: "NODE-2.EXAMPLE.", KeyType: "ssh-ed25519", Fingerprint: "SHA256:a"},
		{Host: "10.0.0.3", KeyType: "ssh-ed25519", Fingerprint: "SHA256:b"},
	}
	if err := requirePeerTrust([]string{"node-2.example", "10.0.0.3"}, entries); err != nil {
		t.Fatal(err)
	}
	if err := requirePeerTrust([]string{"node-4.example"}, entries); err == nil {
		t.Fatal("expected missing peer trust rejection")
	}
}

func TestReadPrivateInputRejectsBroadPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 64)), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateInput(path, 1024, "secret"); err == nil {
		t.Fatal("expected broad permission rejection")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateInput(path, 1024, "secret"); err != nil {
		t.Fatal(err)
	}
}

func TestZeroToHANextAction(t *testing.T) {
	if got := zeroToHANextAction(fieldcampaign.Campaign{State: fieldcampaign.StatePrepared}); !strings.Contains(got, "INSTALL") {
		t.Fatalf("unexpected next action %q", got)
	}
	if got := zeroToHANextAction(fieldcampaign.Campaign{State: fieldcampaign.StateFailed}); !strings.Contains(got, "diagnose") {
		t.Fatalf("unexpected failed next action %q", got)
	}
}

func TestSyncAndPrepareZeroToHAUsesExistingAuthorities(t *testing.T) {
	request := installation.InstallRequest{ProfileID: "production-standard-ha", Connectivity: installation.ConnectivityDisconnected}
	request.Infrastructure.Provider = "existing-hosts"
	request.Infrastructure.NodeAddresses = []string{"10.0.0.11", "10.0.0.12", "10.0.0.13"}
	request.Infrastructure.CredentialRef = "secret://installer/ssh-private-key"
	bundleDigest := "sha256:" + strings.Repeat("a", 64)
	lockDigest := "sha256:" + strings.Repeat("b", 64)
	requestDigest := "sha256:" + strings.Repeat("c", 64)
	preflight := bootstrap.PreflightReport{
		APIVersion: bootstrap.PreflightAPIVersion, Kind: bootstrap.PreflightKind, SchemaVersion: bootstrap.PreflightSchema,
		Version: "0.0.33", ProfileID: request.ProfileID, Connectivity: string(request.Connectivity),
		RequestDigest: requestDigest, BundleDigest: bundleDigest, Simulation: true,
		Checks: []bootstrap.PreflightCheck{{Key: "topology", Title: "topology", State: bootstrap.CheckPassed, Detail: "three nodes"}},
	}
	if err := preflight.Seal(); err != nil {
		t.Fatal(err)
	}
	calls := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatalf("missing auth on %s", r.URL.Path)
		}
		calls[r.URL.Path]++
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/access/status":
			_ = json.NewEncoder(w).Encode(map[string]any{"installerBinaryDigest": "sha256:" + strings.Repeat("8", 64)})
		case "/api/v1/secrets/ssh-private-key":
			_ = json.NewEncoder(w).Encode(map[string]any{"stored": true, "credentialRef": "secret://installer/ssh-private-key"})
		case "/api/v1/secrets/ssh-known-hosts":
			_ = json.NewEncoder(w).Encode(bootstrap.SSHTrustStatus{PrivateKeyStored: true, KnownHostsStored: true, KnownHostsRef: "trust://installer/ssh-known-hosts", Entries: []bootstrap.SSHHostTrustEntry{{Host: "10.0.0.12", KeyType: "ssh-ed25519", Fingerprint: "SHA256:a"}, {Host: "10.0.0.13", KeyType: "ssh-ed25519", Fingerprint: "SHA256:b"}}})
		case "/api/v1/bundle/status":
			_ = json.NewEncoder(w).Encode(bootstrap.BundleAdmissionStatus{Verified: true, Version: "0.0.33", SourceReleaseDigest: "sha256:" + strings.Repeat("9", 64), BundleDigest: bundleDigest, LockDigest: lockDigest, LockRequired: true})
		case "/api/v1/plan":
			_ = json.NewEncoder(w).Encode(installerPlanResponse{Plan: installation.InstallationPlan{ID: "plan-ha", SpecDigest: requestDigest, Executable: true}, BundleDigest: bundleDigest, ExecutionEnabled: true})
		case "/api/v1/preflight":
			_ = json.NewEncoder(w).Encode(preflight)
		case "/api/v1/start":
			t.Fatal("handoff must not start installation")
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	base, _ := url.Parse(server.URL)
	connection := fieldCampaignConnection{base: base, client: server.Client(), token: "test-token"}
	trust, campaign, err := syncAndPrepareZeroToHA(connection, request, "sha256:"+strings.Repeat("9", 64), "sha256:"+strings.Repeat("8", 64), "sha256:"+strings.Repeat("7", 64), []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nunit\n-----END OPENSSH PRIVATE KEY-----\n"), []byte("known-hosts"), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if !trust.PrivateKeyStored || campaign.State != fieldcampaign.StatePrepared || campaign.PlanID != "plan-ha" {
		t.Fatalf("unexpected handoff result trust=%+v campaign=%+v", trust, campaign)
	}
	for _, path := range []string{"/api/v1/secrets/ssh-private-key", "/api/v1/secrets/ssh-known-hosts", "/api/v1/access/status", "/api/v1/bundle/status", "/api/v1/plan", "/api/v1/preflight"} {
		if calls[path] != 1 {
			t.Fatalf("expected one call to %s, got %d", path, calls[path])
		}
	}
}
