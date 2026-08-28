package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func deterministicStore() *MemoryStore {
	base := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	var clock atomic.Int64
	var seq atomic.Int64
	return NewMemoryStoreWith(func() time.Time { return base.Add(time.Duration(clock.Add(1)) * time.Microsecond) }, func(prefix string) string { return fmt.Sprintf("%s_%06d", prefix, seq.Add(1)) })
}
func bootstrap(t *testing.T, s Store) (Organization, Project) {
	t.Helper()
	ctx := context.Background()
	org, err := s.CreateOrganization(ctx, Organization{Name: "acme", DisplayName: "Acme"}, "tester")
	if err != nil {
		t.Fatal(err)
	}
	prj, err := s.CreateProject(ctx, Project{OrganizationID: org.ID, Name: "platform", DisplayName: "Platform"}, "tester")
	if err != nil {
		t.Fatal(err)
	}
	return org, prj
}

func TestOptimisticRevisionConflict(t *testing.T) {
	s := deterministicStore()
	org, _ := bootstrap(t, s)
	var wg sync.WaitGroup
	wg.Add(2)
	results := make(chan error, 2)
	for _, name := range []string{"Acme A", "Acme B"} {
		go func(display string) {
			defer wg.Done()
			_, err := s.UpdateOrganization(context.Background(), org.ID, org.Revision, display, "", "actor")
			results <- err
		}(name)
	}
	wg.Wait()
	close(results)
	success, conflict := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, ErrConflict) {
			conflict++
		} else {
			t.Fatalf("unexpected error %v", err)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatalf("success=%d conflict=%d", success, conflict)
	}
}

func TestIdempotencyReplayAndConflict(t *testing.T) {
	s := deterministicStore()
	_, prj := bootstrap(t, s)
	req := OperationRequest{ProjectID: prj.ID, Kind: "blueprint.plan", TargetRef: "cluster/demo", DesiredRevision: "sha256:one", Risk: "low"}
	one, replay, err := s.CreateOperation(context.Background(), req, "key-1", "actor", "request-1")
	if err != nil || replay {
		t.Fatalf("first create err=%v replay=%v", err, replay)
	}
	two, replay, err := s.CreateOperation(context.Background(), req, "key-1", "actor", "request-2")
	if err != nil || !replay || one.ID != two.ID {
		t.Fatalf("replay mismatch %#v %#v replay=%v err=%v", one, two, replay, err)
	}
	req.DesiredRevision = "sha256:two"
	_, _, err = s.CreateOperation(context.Background(), req, "key-1", "actor", "request-3")
	if !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("expected idempotency conflict, got %v", err)
	}
}

func TestLeaseFencingRejectsStaleWorker(t *testing.T) {
	s := deterministicStore()
	_, prj := bootstrap(t, s)
	op, _, _ := s.CreateOperation(context.Background(), OperationRequest{ProjectID: prj.ID, Kind: "test", TargetRef: "target", DesiredRevision: "rev", Risk: "high"}, "k", "actor", "r")
	op, _ = s.TransitionOperation(context.Background(), op.ID, op.Revision, OperationPlanning, "", "actor")
	op, _ = s.TransitionOperation(context.Background(), op.ID, op.Revision, OperationQueued, "", "actor")
	at := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	first, err := s.ClaimOperation(context.Background(), op.ID, "worker-a", time.Minute, at)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.ClaimOperation(context.Background(), op.ID, "worker-b", time.Minute, at.Add(30*time.Second)); !errors.Is(err, ErrLeaseHeld) {
		t.Fatalf("expected lease held, got %v", err)
	}
	second, err := s.ClaimOperation(context.Background(), op.ID, "worker-b", time.Minute, at.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if second.FenceToken <= first.FenceToken {
		t.Fatal("fence token did not increase")
	}
	if err = s.ReleaseOperationLease(context.Background(), op.ID, "worker-a", first.FenceToken); !errors.Is(err, ErrStaleFence) {
		t.Fatalf("stale worker accepted: %v", err)
	}
	if _, err = s.AppendOperationStep(context.Background(), OperationStep{OperationID: op.ID, StepKey: "render", State: OperationRunning, FenceToken: first.FenceToken}, "worker-a"); !errors.Is(err, ErrStaleFence) {
		t.Fatalf("stale step accepted: %v", err)
	}
}

func TestOperationStateMachine(t *testing.T) {
	s := deterministicStore()
	_, prj := bootstrap(t, s)
	op, _, _ := s.CreateOperation(context.Background(), OperationRequest{ProjectID: prj.ID, Kind: "test", TargetRef: "target", DesiredRevision: "rev", Risk: "low"}, "k", "actor", "r")
	if _, err := s.TransitionOperation(context.Background(), op.ID, op.Revision, OperationSucceeded, "", "actor"); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("invalid direct success accepted: %v", err)
	}
	op, err := s.TransitionOperation(context.Background(), op.ID, op.Revision, OperationPlanning, "", "actor")
	if err != nil {
		t.Fatal(err)
	}
	op, err = s.TransitionOperation(context.Background(), op.ID, op.Revision, OperationQueued, "", "actor")
	if err != nil {
		t.Fatal(err)
	}
	op, err = s.TransitionOperation(context.Background(), op.ID, op.Revision, OperationRunning, "", "worker")
	if err != nil {
		t.Fatal(err)
	}
	op, err = s.TransitionOperation(context.Background(), op.ID, op.Revision, OperationVerifying, "", "worker")
	if err != nil {
		t.Fatal(err)
	}
	op, err = s.TransitionOperation(context.Background(), op.ID, op.Revision, OperationSucceeded, "", "worker")
	if err != nil || !IsTerminal(op.State) {
		t.Fatalf("terminal transition failed %v %#v", err, op)
	}
}

func TestOutboxClaimReplay(t *testing.T) {
	s := deterministicStore()
	bootstrap(t, s)
	at := time.Date(2026, 8, 5, 12, 0, 1, 0, time.UTC)
	events, err := s.ClaimOutbox(context.Background(), "publisher-a", 10, time.Minute, at)
	if err != nil || len(events) == 0 {
		t.Fatalf("claim err=%v len=%d", err, len(events))
	}
	if other, err := s.ClaimOutbox(context.Background(), "publisher-b", 10, time.Minute, at.Add(30*time.Second)); err != nil || len(other) != 0 {
		t.Fatalf("leased events were double claimed err=%v len=%d", err, len(other))
	}
	if err := s.MarkOutboxPublished(context.Background(), events[0].ID, "publisher-b", at.Add(40*time.Second)); !errors.Is(err, ErrStaleFence) {
		t.Fatalf("wrong publisher accepted: %v", err)
	}
	if err := s.MarkOutboxPublished(context.Background(), events[0].ID, "publisher-a", at.Add(40*time.Second)); err != nil {
		t.Fatal(err)
	}
}

func TestFileStoreRestartPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "control-plane.json")
	s, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	org, prj := bootstrap(t, s)
	op, _, err := s.CreateOperation(context.Background(), OperationRequest{ProjectID: prj.ID, Kind: "plan", TargetRef: "cluster/demo", DesiredRevision: "sha256:abc", Risk: "medium"}, "stable-key", "actor", "req")
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reopened.GetOperation(context.Background(), op.ID)
	if err != nil || got.RequestDigest != op.RequestDigest {
		t.Fatalf("operation did not survive restart err=%v got=%#v", err, got)
	}
	gotOrg, err := reopened.GetOrganization(context.Background(), org.ID)
	if err != nil || gotOrg.Name != "acme" {
		t.Fatalf("organization did not survive restart err=%v got=%#v", err, gotOrg)
	}
	again, replay, err := reopened.CreateOperation(context.Background(), OperationRequest{ProjectID: prj.ID, Kind: "plan", TargetRef: "cluster/demo", DesiredRevision: "sha256:abc", Risk: "medium"}, "stable-key", "actor", "req2")
	if err != nil || !replay || again.ID != op.ID {
		t.Fatalf("idempotency did not survive restart err=%v replay=%v", err, replay)
	}
}

func TestAuditAndEvidenceAreAppendOnlyByAPI(t *testing.T) {
	s := deterministicStore()
	_, prj := bootstrap(t, s)
	op, _, _ := s.CreateOperation(context.Background(), OperationRequest{ProjectID: prj.ID, Kind: "plan", TargetRef: "target", DesiredRevision: "rev", Risk: "low"}, "k", "actor", "r")
	e, err := s.AppendEvidence(context.Background(), EvidenceMetadata{OperationID: op.ID, Kind: "plan", Digest: "sha256:abc", MediaType: "application/json", Location: "object://evidence/abc", Size: 20}, "worker")
	if err != nil || !e.Sealed {
		t.Fatalf("evidence failed %v %#v", err, e)
	}
	again, err := s.AppendEvidence(context.Background(), EvidenceMetadata{OperationID: op.ID, Kind: "other", Digest: "sha256:abc", MediaType: "text/plain", Location: "object://other", Size: 1}, "worker")
	if err != nil || again.ID != e.ID {
		t.Fatalf("evidence idempotency failed %v %#v", err, again)
	}
	audit, err := s.ListAudit(context.Background(), 100)
	if err != nil || len(audit) < 4 {
		t.Fatalf("audit missing err=%v len=%d", err, len(audit))
	}
}

func TestFileStoreRejectsTamperedSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control-plane.json")
	s, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = bootstrap(t, s)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.Replace(raw, []byte(`"displayName": "Acme"`), []byte(`"displayName": "Evil"`), 1)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFileStore(path); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("tampered state accepted: %v", err)
	}
}

func TestFileStoreOrganizationMembershipPersistsAndRevokes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "control-plane.json")
	s, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	org, err := s.CreateOrganization(context.Background(), Organization{Name: "membership-org", DisplayName: "Membership Org"}, "bootstrap-admin")
	if err != nil {
		t.Fatal(err)
	}
	membership, err := s.UpsertOrganizationMembership(context.Background(), OrganizationMembership{OrganizationID: org.ID, Subject: "user-a", Role: OrganizationOperator}, 0, "bootstrap-admin")
	if err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reopened.GetOrganizationMembership(context.Background(), org.ID, "user-a")
	if err != nil || got.ID != membership.ID || got.Role != OrganizationOperator || got.State != OrganizationMembershipActive {
		t.Fatalf("membership did not survive restart err=%v got=%#v", err, got)
	}
	got, err = reopened.RevokeOrganizationMembership(context.Background(), org.ID, "user-a", got.Revision, "bootstrap-admin")
	if err != nil {
		t.Fatal(err)
	}
	if got.State != OrganizationMembershipRevoked {
		t.Fatalf("membership not revoked: %#v", got)
	}

	reopenedAgain, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err = reopenedAgain.GetOrganizationMembership(context.Background(), org.ID, "user-a")
	if err != nil || got.State != OrganizationMembershipRevoked || got.RevokedAt == nil {
		t.Fatalf("revocation did not survive restart err=%v got=%#v", err, got)
	}
}

func TestOrganizationMembershipCannotRevokeLastAdmin(t *testing.T) {
	s := deterministicStore()
	org, err := s.CreateOrganization(context.Background(), Organization{Name: "last-admin", DisplayName: "Last Admin"}, "creator")
	if err != nil {
		t.Fatal(err)
	}
	membership, err := s.GetOrganizationMembership(context.Background(), org.ID, "creator")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RevokeOrganizationMembership(context.Background(), org.ID, "creator", membership.Revision, "creator"); !errors.Is(err, ErrValidation) {
		t.Fatalf("last organization admin revocation was not blocked: %v", err)
	}
}

func TestFileStorePersistsClusterCredentialDigestsAcrossRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state", "control-plane.json")
	store, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	_, project := bootstrap(t, store)
	enrollmentDigest := fmt.Sprintf("sha256:%064x", 12001)
	agentDigest := fmt.Sprintf("sha256:%064x", 12002)
	imp, err := store.CreateClusterImport(ctx, ClusterImport{ProjectID: project.ID, Name: "persisted-agent", DisplayName: "Persisted Agent", TokenDigest: enrollmentDigest, ExpiresAt: time.Now().Add(time.Hour)}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	imp, err = store.ApproveClusterImport(ctx, imp.ID, imp.Revision, "approver")
	if err != nil {
		t.Fatal(err)
	}
	_, cluster, err := store.ClaimClusterImport(ctx, imp.ID, enrollmentDigest, agentDigest, "persisted-agent-uid", "0.0.43")
	if err != nil {
		t.Fatal(err)
	}

	pendingDigest := fmt.Sprintf("sha256:%064x", 12003)
	pending, err := store.CreateClusterImport(ctx, ClusterImport{ProjectID: project.ID, Name: "pending-agent", DisplayName: "Pending Agent", TokenDigest: pendingDigest, ExpiresAt: time.Now().Add(time.Hour)}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	pending, err = store.ApproveClusterImport(ctx, pending.ID, pending.Revision, "approver")
	if err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	reopenedImport, err := reopened.GetClusterImport(ctx, imp.ID)
	if err != nil {
		t.Fatal(err)
	}
	if reopenedImport.AgentServiceAccount != imp.AgentServiceAccount || reopenedImport.AgentServiceAccount != FleetAgentServiceAccountName(imp.ID) {
		t.Fatalf("import-scoped agent principal did not survive FileStore restart: before=%q after=%q", imp.AgentServiceAccount, reopenedImport.AgentServiceAccount)
	}
	if _, _, err = upsertMutationReadyInventoryForTest(t, reopened, ctx, cluster.ID, agentDigest, cluster.ExternalUID, ClusterInventory{ObservedAt: time.Now(), Distribution: "rke2", Capabilities: []string{TargetMutationRBACActiveCapability}, KubernetesVersion: "v1.34.0", Digest: fmt.Sprintf("sha256:%064x", 12004)}); err != nil {
		t.Fatalf("claimed agent credential did not survive restart: %v", err)
	}
	newAgentDigest := fmt.Sprintf("sha256:%064x", 12005)
	if _, _, err = reopened.ClaimClusterImport(ctx, pending.ID, pendingDigest, newAgentDigest, "pending-agent-uid", "0.0.43"); err != nil {
		t.Fatalf("pending enrollment credential did not survive restart: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var envelope stateEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.SchemaVersion != 2 || len(envelope.Credentials) != 2 {
		t.Fatalf("state envelope does not use schema-v2 credential persistence: schema=%d credentials=%d", envelope.SchemaVersion, len(envelope.Credentials))
	}
	encodedSnapshot, _ := json.Marshal(envelope.Snapshot.ClusterImports)
	if strings.Contains(string(encodedSnapshot), "tokenDigest") || strings.Contains(string(encodedSnapshot), "agentTokenDigest") {
		t.Fatalf("credential digests leaked into normal ClusterImport JSON: %s", encodedSnapshot)
	}
}

func TestFileStoreV1ClaimedClusterRequiresReenrollment(t *testing.T) {
	ctx := context.Background()
	mem := deterministicStore()
	_, project := bootstrap(t, mem)
	enrollmentDigest := fmt.Sprintf("sha256:%064x", 13001)
	agentDigest := fmt.Sprintf("sha256:%064x", 13002)
	imp, err := mem.CreateClusterImport(ctx, ClusterImport{
		ProjectID:   project.ID,
		Name:        "legacy-v1-agent",
		DisplayName: "Legacy v1 Agent",
		TokenDigest: enrollmentDigest,
		ExpiresAt:   time.Now().Add(time.Hour),
	}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	imp, err = mem.ApproveClusterImport(ctx, imp.ID, imp.Revision, "approver")
	if err != nil {
		t.Fatal(err)
	}
	_, cluster, err := mem.ClaimClusterImport(ctx, imp.ID, enrollmentDigest, agentDigest, "legacy-v1-agent-uid", "0.0.42")
	if err != nil {
		t.Fatal(err)
	}

	snapshot, err := mem.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	checksum, err := snapshotChecksum(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "legacy-v1.json")
	raw, err := json.MarshalIndent(stateEnvelope{SchemaVersion: 1, Checksum: checksum, Snapshot: snapshot}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	clusters, err := reopened.ListManagedClusters(ctx, project.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(clusters) != 1 || clusters[0].ID != cluster.ID {
		t.Fatalf("unexpected reopened clusters: %#v", clusters)
	}
	if clusters[0].ConnectionState != "REENROLLMENT_REQUIRED" {
		t.Fatalf("legacy claimed cluster did not surface re-enrollment requirement: %q", clusters[0].ConnectionState)
	}
	imports, err := reopened.ListClusterImports(ctx, project.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(imports) != 1 || imports[0].AgentTokenDigest != "" || imports[0].TokenDigest != "" {
		t.Fatalf("schema-v1 unexpectedly reconstructed unavailable credentials: %#v", imports)
	}
}
