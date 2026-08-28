package fieldcampaign

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"platform.4so.io/factory/internal/bootstrap"
	"platform.4so.io/factory/internal/installation"
)

func campaignFixture(t *testing.T) Campaign {
	t.Helper()
	digest := func(ch string) string { return "sha256:" + strings.Repeat(ch, 64) }
	request := installation.InstallRequest{ProfileID: "evaluation-single-node", Connectivity: installation.ConnectivityConnected, Infrastructure: installation.InfrastructureSpec{Provider: "existing-hosts", NodeAddresses: []string{"127.0.0.1"}}, Network: installation.NetworkSpec{PublicEndpoint: "https://platform.example", TLSMode: "bootstrap-self-signed"}}
	c, err := New("https://installer.example", request, digest("1"), digest("2"), digest("9"), digest("8"), "plan-1", digest("3"), true, time.Date(2026, 8, 6, 20, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCampaignLifecycleAndPrivatePersistence(t *testing.T) {
	c := campaignFixture(t)
	now := c.UpdatedAt.Add(time.Minute)
	if err := c.Transition(StateStartRequested, "start", "explicit INSTALL confirmation accepted", now); err != nil {
		t.Fatal(err)
	}
	c.RunID = "bootstrap-1"
	c.RunState = string(bootstrap.RunRunning)
	simulation := true
	c.Simulation = &simulation
	if err := c.Transition(StateRunning, "observe", "installation is running", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	c.RunState = string(bootstrap.RunSucceeded)
	if err := c.Transition(StateSucceeded, "observe", "installation succeeded", now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	c.EvidenceVerified = true
	c.EvidenceReportID = "field-report"
	c.EvidenceDigest = "sha256:" + strings.Repeat("4", 64)
	if err := c.Record("collect-evidence", "independent verification passed", now.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "nested", "campaign.json")
	if err := Save(path, c); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("permissions=%o", info.Mode().Perm())
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.State != StateSucceeded || !loaded.EvidenceVerified || loaded.RunID != "bootstrap-1" {
		t.Fatalf("loaded=%+v", loaded)
	}
}

func TestCampaignRejectsInvalidTransitionAndTamper(t *testing.T) {
	c := campaignFixture(t)
	if err := c.Transition(StateSucceeded, "skip", "invalid", c.UpdatedAt.Add(time.Minute)); err == nil {
		t.Fatal("invalid transition accepted")
	}
	c.BundleDigest = "sha256:" + strings.Repeat("9", 64)
	if err := c.Verify(); err == nil {
		t.Fatal("tampered state accepted")
	}
}

func TestNewCampaignRequiresExactReleaseArtifactDigest(t *testing.T) {
	digest := func(ch string) string { return "sha256:" + strings.Repeat(ch, 64) }
	request := installation.InstallRequest{ProfileID: "evaluation-single-node", Connectivity: installation.ConnectivityConnected, Infrastructure: installation.InfrastructureSpec{Provider: "existing-hosts", NodeAddresses: []string{"127.0.0.1"}}, Network: installation.NetworkSpec{PublicEndpoint: "https://platform.example", TLSMode: "bootstrap-self-signed"}}
	if _, err := New("https://installer.example", request, digest("1"), digest("2"), "", digest("8"), "plan-1", digest("3"), true, time.Now().UTC()); err == nil || !strings.Contains(err.Error(), "releaseArtifactDigest") {
		t.Fatalf("new campaign accepted without exact release binding: %v", err)
	}
}

func TestLegacyCampaignStateRemainsVerifiableForRecovery(t *testing.T) {
	c := campaignFixture(t)
	c.SchemaVersion = LegacySchemaVersion
	c.ReleaseArtifactDigest = ""
	c.InstallerBinaryDigest = ""
	if err := c.Seal(); err != nil {
		t.Fatalf("legacy recovery state became unreadable: %v", err)
	}
	if err := c.Verify(); err != nil {
		t.Fatal(err)
	}
}

func TestSchemaV2CampaignStateRemainsVerifiableForRecovery(t *testing.T) {
	c := campaignFixture(t)
	c.SchemaVersion = ExactSHASchemaVersion
	c.InstallerBinaryDigest = ""
	if err := c.Seal(); err != nil {
		t.Fatalf("schema v2 recovery state became unreadable: %v", err)
	}
	if err := c.Verify(); err != nil {
		t.Fatal(err)
	}
}
