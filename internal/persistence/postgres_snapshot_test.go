package persistence

import (
	"context"
	"database/sql/driver"
	"testing"
	"time"

	"platform.4so.io/factory/internal/controlplane"
)

type snapshotReaderFixture struct{}

func (snapshotReaderFixture) ListNotificationDestinations(context.Context, string) ([]controlplane.NotificationDestination, error) {
	return []controlplane.NotificationDestination{{ResourceMeta: controlplane.ResourceMeta{ID: "nd-1"}, OrganizationID: "org-1"}}, nil
}
func (snapshotReaderFixture) ListNotificationRoutes(context.Context, string, string) ([]controlplane.NotificationRoute, error) {
	return []controlplane.NotificationRoute{{ResourceMeta: controlplane.ResourceMeta{ID: "nr-1"}, OrganizationID: "org-1", ProjectID: "prj-1"}}, nil
}
func (snapshotReaderFixture) ListNotificationEvents(context.Context, string, string, int) ([]controlplane.NotificationEvent, error) {
	return []controlplane.NotificationEvent{{ResourceMeta: controlplane.ResourceMeta{ID: "ne-1"}, OrganizationID: "org-1", ProjectID: "prj-1"}}, nil
}
func (snapshotReaderFixture) ListNotificationDeliveries(context.Context, string, string, controlplane.NotificationDeliveryState, int) ([]controlplane.NotificationDelivery, error) {
	return []controlplane.NotificationDelivery{{ResourceMeta: controlplane.ResourceMeta{ID: "ndl-1"}, EventID: "ne-1"}}, nil
}
func (snapshotReaderFixture) ListNotificationDeliveryAttempts(context.Context, string) ([]controlplane.NotificationDeliveryAttempt, error) {
	return []controlplane.NotificationDeliveryAttempt{{ResourceMeta: controlplane.ResourceMeta{ID: "nda-1"}, DeliveryID: "ndl-1"}}, nil
}
func (snapshotReaderFixture) ListAgentCertificates(context.Context, string) ([]controlplane.AgentCertificate, error) {
	return []controlplane.AgentCertificate{{ResourceMeta: controlplane.ResourceMeta{ID: "cert-1"}, ClusterID: "clu-1"}}, nil
}
func (snapshotReaderFixture) ListRecoveryCheckpoints(context.Context, string, string) ([]controlplane.RecoveryCheckpoint, error) {
	return []controlplane.RecoveryCheckpoint{{ResourceMeta: controlplane.ResourceMeta{ID: "rcp-1"}, ProjectID: "prj-1"}}, nil
}
func (snapshotReaderFixture) ListGitCredentials(context.Context) ([]controlplane.GitCredential, error) {
	return []controlplane.GitCredential{{ResourceMeta: controlplane.ResourceMeta{ID: "gc-1"}}}, nil
}
func (snapshotReaderFixture) ListGitProviders(context.Context) ([]controlplane.GitProvider, error) {
	return []controlplane.GitProvider{{ResourceMeta: controlplane.ResourceMeta{ID: "gp-1"}}}, nil
}
func (snapshotReaderFixture) ListGitPullRequests(context.Context, string, string) ([]controlplane.GitPullRequest, error) {
	return []controlplane.GitPullRequest{{ResourceMeta: controlplane.ResourceMeta{ID: "gpr-1"}}}, nil
}
func (snapshotReaderFixture) ListManagedGitRevisions(context.Context, string, string) ([]controlplane.ManagedGitRevision, error) {
	return []controlplane.ManagedGitRevision{{ResourceMeta: controlplane.ResourceMeta{ID: "mgr-1"}}}, nil
}
func (snapshotReaderFixture) GetEntitlement(context.Context, string) (controlplane.Entitlement, error) {
	return controlplane.Entitlement{ResourceMeta: controlplane.ResourceMeta{ID: "ent-1"}, OrganizationID: "org-1"}, nil
}
func (snapshotReaderFixture) GetOEMProfile(context.Context, string) (controlplane.OEMProfile, error) {
	return controlplane.OEMProfile{ResourceMeta: controlplane.ResourceMeta{ID: "oem-1"}, OrganizationID: "org-1"}, nil
}
func (snapshotReaderFixture) ListTenants(context.Context, string, string) ([]controlplane.TenantEnvironment, error) {
	return []controlplane.TenantEnvironment{{ResourceMeta: controlplane.ResourceMeta{ID: "ten-1"}, ProjectID: "prj-1"}}, nil
}
func (snapshotReaderFixture) ListProviderProfiles(context.Context, string, string) ([]controlplane.ProviderProfile, error) {
	return []controlplane.ProviderProfile{{ResourceMeta: controlplane.ResourceMeta{ID: "pp-1"}, ProjectID: "prj-1"}}, nil
}
func (snapshotReaderFixture) ListProviderClusters(context.Context, string, string) ([]controlplane.ProviderCluster, error) {
	return []controlplane.ProviderCluster{{ResourceMeta: controlplane.ResourceMeta{ID: "pc-1"}, ProjectID: "prj-1"}}, nil
}

func TestPopulateSupplementalSnapshotRestoresPostgresMemoryParityFamilies(t *testing.T) {
	snap := controlplane.Snapshot{}
	imports := []controlplane.ClusterImport{{ResourceMeta: controlplane.ResourceMeta{ID: "imp-1"}, TokenDigest: "sha256:one", AgentTokenDigest: "sha256:two"}}
	if err := populateSupplementalSnapshot(context.Background(), snapshotReaderFixture{}, &snap, []controlplane.Organization{{ResourceMeta: controlplane.ResourceMeta{ID: "org-1"}}}, imports); err != nil {
		t.Fatal(err)
	}
	checks := map[string]int{
		"destinations": len(snap.NotificationDestinations), "routes": len(snap.NotificationRoutes), "events": len(snap.NotificationEvents),
		"deliveries": len(snap.NotificationDeliveries), "attempts": len(snap.NotificationAttempts), "agentCertificates": len(snap.AgentCertificates),
		"recoveryCheckpoints": len(snap.RecoveryCheckpoints), "gitCredentials": len(snap.GitCredentials), "gitProviders": len(snap.GitProviders),
		"gitPullRequests": len(snap.GitPullRequests), "managedGitRevisions": len(snap.ManagedGitRevisions), "entitlements": len(snap.Entitlements),
		"oemProfiles": len(snap.OEMProfiles), "tenants": len(snap.Tenants), "providerProfiles": len(snap.ProviderProfiles),
		"providerClusters": len(snap.ProviderClusters), "clusterImportCredentials": len(snap.ClusterImportCredentials),
	}
	for name, count := range checks {
		if count != 1 {
			t.Fatalf("snapshot family %s count=%d, want 1", name, count)
		}
	}
	if snap.ClusterImportCredentials[0].TokenDigest != "sha256:one" || snap.ClusterImportCredentials[0].AgentTokenDigest != "sha256:two" {
		t.Fatalf("cluster import credential digests lost: %#v", snap.ClusterImportCredentials[0])
	}
}

func TestSnapshotSecurityAuditPreservesCanonicalFullChainOrder(t *testing.T) {
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	first := controlplane.SecurityAuditEvent{ID: "sau-1", Sequence: 1, OccurredAt: now, MethodVersion: controlplane.SecurityAuditMethod, SecurityAuditInput: controlplane.SecurityAuditInput{Category: "AUTHENTICATION", Decision: "ALLOW", ActorID: "a"}}
	first.Digest = controlplane.SecurityAuditEventDigest(first)
	second := controlplane.SecurityAuditEvent{ID: "sau-2", Sequence: 2, OccurredAt: now.Add(time.Second), MethodVersion: controlplane.SecurityAuditMethod, SecurityAuditInput: controlplane.SecurityAuditInput{Category: "AUTHORIZATION", Decision: "ALLOW", ActorID: "a"}, PreviousDigest: first.Digest}
	second.Digest = controlplane.SecurityAuditEventDigest(second)
	cols := []string{"sequence", "id", "occurred_at", "method_version", "category", "decision", "actor_id", "authentication", "request_method", "request_path", "status_code", "reason_code", "request_id", "scope_type", "scope_id", "effective_role", "mapping_digest", "previous_digest", "event_digest"}
	row := func(v controlplane.SecurityAuditEvent) []driver.Value {
		return []driver.Value{v.Sequence, v.ID, v.OccurredAt, v.MethodVersion, v.Category, v.Decision, v.ActorID, v.Authentication, v.Method, v.Path, int64(v.StatusCode), v.ReasonCode, v.RequestID, v.ScopeType, v.ScopeID, v.EffectiveRole, v.MappingDigest, v.PreviousDigest, v.Digest}
	}
	db, script := openScriptDB(t, scriptStep{kind: "query", contains: "FROM security_audit_events ORDER BY sequence ASC", columns: cols, rows: [][]driver.Value{row(first), row(second)}})
	store, _ := NewPostgresStoreWith(db, func() time.Time { return now }, fixedPGID)
	got, err := store.snapshotSecurityAudit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Sequence != 1 || got[1].Sequence != 2 {
		t.Fatalf("canonical chain order lost: %#v", got)
	}
	if err := controlplane.ValidateSecurityAuditChain(got); err != nil {
		t.Fatalf("snapshot chain invalid: %v", err)
	}
	script.done(t)
}

func TestPostgresReadinessCountsUseConstantSizeAggregateQuery(t *testing.T) {
	db, script := openScriptDB(t,
		scriptStep{kind: "query", contains: "SELECT (SELECT COUNT(*) FROM organizations),(SELECT COUNT(*) FROM operations)", columns: []string{"organizations", "operations"}, rows: [][]driver.Value{{int64(7), int64(23)}}},
	)
	store, err := NewPostgresStoreWith(db, fixedPGTime, fixedPGID)
	if err != nil {
		t.Fatal(err)
	}
	organizations, operations, err := store.ReadinessCounts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if organizations != 7 || operations != 23 {
		t.Fatalf("readiness counts organizations=%d operations=%d", organizations, operations)
	}
	script.done(t)
}
