package controlplane

import (
	"context"
	"reflect"
	"testing"
	"time"
)

func TestCanonicalizeSnapshotNormalizesPreviouslyUnorderedFamilies(t *testing.T) {
	s := Snapshot{
		OIDCGroupMappings: []OIDCGroupMapping{{ResourceMeta: ResourceMeta{ID: "z"}}, {ResourceMeta: ResourceMeta{ID: "a"}}},
		CompensationSteps: []OperationCompensationStep{
			{ResourceMeta: ResourceMeta{ID: "c"}, OperationID: "op-b", ForwardOrder: 1},
			{ResourceMeta: ResourceMeta{ID: "b"}, OperationID: "op-a", ForwardOrder: 2},
			{ResourceMeta: ResourceMeta{ID: "a"}, OperationID: "op-a", ForwardOrder: 1},
		},
		AgentCertificates: []AgentCertificate{{ResourceMeta: ResourceMeta{ID: "z"}}, {ResourceMeta: ResourceMeta{ID: "a"}}},
		GitCredentials:    []GitCredential{{ResourceMeta: ResourceMeta{ID: "z"}}, {ResourceMeta: ResourceMeta{ID: "a"}}},
		GitProviders:      []GitProvider{{ResourceMeta: ResourceMeta{ID: "z"}}, {ResourceMeta: ResourceMeta{ID: "a"}}},
	}
	CanonicalizeSnapshot(&s)
	if got := []string{s.OIDCGroupMappings[0].ID, s.OIDCGroupMappings[1].ID}; !reflect.DeepEqual(got, []string{"a", "z"}) {
		t.Fatalf("oidc mappings not canonical: %v", got)
	}
	if got := []string{s.CompensationSteps[0].ID, s.CompensationSteps[1].ID, s.CompensationSteps[2].ID}; !reflect.DeepEqual(got, []string{"a", "b", "c"}) {
		t.Fatalf("compensation steps not canonical: %v", got)
	}
	if got := []string{s.AgentCertificates[0].ID, s.AgentCertificates[1].ID}; !reflect.DeepEqual(got, []string{"a", "z"}) {
		t.Fatalf("agent certificates not canonical: %v", got)
	}
	if got := []string{s.GitCredentials[0].ID, s.GitCredentials[1].ID}; !reflect.DeepEqual(got, []string{"a", "z"}) {
		t.Fatalf("git credentials not canonical: %v", got)
	}
	if got := []string{s.GitProviders[0].ID, s.GitProviders[1].ID}; !reflect.DeepEqual(got, []string{"a", "z"}) {
		t.Fatalf("git providers not canonical: %v", got)
	}
}

func TestMemorySnapshotCanonicalizesMapBackedFamilies(t *testing.T) {
	m := NewMemoryStore()
	m.compensationSteps["op-b:c"] = OperationCompensationStep{ResourceMeta: ResourceMeta{ID: "c"}, OperationID: "op-b", StepKey: "c", ForwardOrder: 1}
	m.compensationSteps["op-a:b"] = OperationCompensationStep{ResourceMeta: ResourceMeta{ID: "b"}, OperationID: "op-a", StepKey: "b", ForwardOrder: 2}
	m.compensationSteps["op-a:a"] = OperationCompensationStep{ResourceMeta: ResourceMeta{ID: "a"}, OperationID: "op-a", StepKey: "a", ForwardOrder: 1}
	m.agentCertificates["z"] = AgentCertificate{ResourceMeta: ResourceMeta{ID: "z"}}
	m.agentCertificates["a"] = AgentCertificate{ResourceMeta: ResourceMeta{ID: "a"}}
	m.gitCredentials["z"] = GitCredential{ResourceMeta: ResourceMeta{ID: "z"}}
	m.gitCredentials["a"] = GitCredential{ResourceMeta: ResourceMeta{ID: "a"}}
	m.gitProviders["z"] = GitProvider{ResourceMeta: ResourceMeta{ID: "z"}}
	m.gitProviders["a"] = GitProvider{ResourceMeta: ResourceMeta{ID: "a"}}

	s, err := m.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := []string{s.CompensationSteps[0].ID, s.CompensationSteps[1].ID, s.CompensationSteps[2].ID}; !reflect.DeepEqual(got, []string{"a", "b", "c"}) {
		t.Fatalf("memory compensation order=%v", got)
	}
	if got := []string{s.AgentCertificates[0].ID, s.AgentCertificates[1].ID}; !reflect.DeepEqual(got, []string{"a", "z"}) {
		t.Fatalf("memory agent certificate order=%v", got)
	}
	if got := []string{s.GitCredentials[0].ID, s.GitCredentials[1].ID}; !reflect.DeepEqual(got, []string{"a", "z"}) {
		t.Fatalf("memory git credential order=%v", got)
	}
	if got := []string{s.GitProviders[0].ID, s.GitProviders[1].ID}; !reflect.DeepEqual(got, []string{"a", "z"}) {
		t.Fatalf("memory git provider order=%v", got)
	}
}

func TestRestoreRejectsInvalidSecurityAuditWithoutMutatingExistingAuthority(t *testing.T) {
	m := NewMemoryStore()
	original := Organization{ResourceMeta: ResourceMeta{ID: "org-existing", Revision: 1}, Name: "existing", DisplayName: "Existing"}
	m.organizations[original.ID] = original

	invalid := Snapshot{
		Organizations: []Organization{{ResourceMeta: ResourceMeta{ID: "org-replacement", Revision: 1}, Name: "replacement", DisplayName: "Replacement"}},
		SecurityAudit: []SecurityAuditEvent{{ID: "sau-invalid", Sequence: 1, MethodVersion: SecurityAuditMethod, Digest: "sha256:invalid"}},
	}
	if err := m.Restore(invalid); err == nil {
		t.Fatal("expected invalid security audit snapshot to be rejected")
	}
	if _, err := m.GetOrganization(context.Background(), original.ID); err != nil {
		t.Fatalf("existing authority was mutated after failed restore: %v", err)
	}
	if _, err := m.GetOrganization(context.Background(), "org-replacement"); err == nil {
		t.Fatal("replacement authority became visible after failed restore")
	}
}

func TestRestoreRejectsDuplicateActivePhysicalClusterAuthorityWithoutMutatingExistingState(t *testing.T) {
	m := NewMemoryStore()
	original := Organization{ResourceMeta: ResourceMeta{ID: "org-existing", Revision: 1}, Name: "existing", DisplayName: "Existing"}
	m.organizations[original.ID] = original

	invalid := Snapshot{
		ManagedClusters: []ManagedCluster{
			{ResourceMeta: ResourceMeta{ID: "clu-a", Revision: 1}, ExternalUID: "same-kube-system-uid", ConnectionState: "CONNECTED"},
			{ResourceMeta: ResourceMeta{ID: "clu-b", Revision: 1}, ExternalUID: "same-kube-system-uid", ConnectionState: "DISCONNECTED"},
		},
	}
	if err := m.Restore(invalid); err == nil {
		t.Fatal("expected duplicate active physical cluster authority to be rejected")
	}
	if _, err := m.GetOrganization(context.Background(), original.ID); err != nil {
		t.Fatalf("existing authority was mutated after failed restore: %v", err)
	}

	validHistory := Snapshot{
		ManagedClusters: []ManagedCluster{
			{ResourceMeta: ResourceMeta{ID: "clu-old", Revision: 2}, ExternalUID: "same-kube-system-uid", ConnectionState: "REVOKED"},
			{ResourceMeta: ResourceMeta{ID: "clu-new", Revision: 1}, ExternalUID: "same-kube-system-uid", ConnectionState: "CONNECTED"},
		},
	}
	if err := m.Restore(validHistory); err != nil {
		t.Fatalf("revoked history plus one active authority must be restorable: %v", err)
	}
}

func TestRestoreBackfillsMutationRBACHistoryAndRepairsUnsafeLegacySuccessor(t *testing.T) {
	now := time.Date(2026, 8, 27, 19, 30, 0, 0, time.UTC)
	predecessor := ManagedCluster{
		ResourceMeta:            ResourceMeta{ID: "clu-old", Revision: 7},
		ImportID:                "imp-old",
		ExternalUID:             "same-kube-system-uid",
		ConnectionState:         "REVOKED",
		InventoryDigest:         digestTenantTest("old-inventory"),
		Capabilities:            []string{TargetReadOnlyAdmissionCapability},
		MutationRBACBasisDigest: digestTenantTest("old-basis"),
	}
	successor := ManagedCluster{
		ResourceMeta:                ResourceMeta{ID: "clu-new", Revision: 4},
		ImportID:                    "imp-new",
		ExternalUID:                 predecessor.ExternalUID,
		ConnectionState:             "CONNECTED",
		Distribution:                "rke2",
		InventoryDigest:             digestTenantTest("new-inventory"),
		MutationRBACBasisDigest:     digestTenantTest("new-basis"),
		MutationRBACIssuedForDigest: digestTenantTest("new-basis"),
		Capabilities: []string{
			TargetIdentityContinuityCapability,
			TargetEnrollmentPrincipalIsolatedCapability,
			TargetMutationRBACActivationIssuedCapability,
			TargetMutationRBACActiveCapability,
			"controlled-baseline-deployment",
		},
	}
	snap := Snapshot{
		ManagedClusters: []ManagedCluster{predecessor, successor},
		Audit: []AuditEvent{{
			ID: "aud-old-activation", OccurredAt: now.Add(-time.Hour), ActorID: "admin", Action: "cluster.mutation_rbac_activation.authorized", ResourceType: "managedCluster", ResourceID: predecessor.ID, Revision: 5,
		}},
	}
	store := NewMemoryStoreWith(func() time.Time { return now }, nil)
	if err := store.Restore(snap); err != nil {
		t.Fatalf("restore legacy same-UID authority: %v", err)
	}
	restoredOld, err := store.GetManagedCluster(context.Background(), predecessor.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !clusterHasCapability(restoredOld, TargetMutationRBACEverIssuedCapability) || !ClusterMayHaveTargetMutationRBAC(restoredOld) {
		t.Fatalf("restore did not backfill sticky mutation-RBAC history from immutable audit: %+v", restoredOld)
	}
	restoredNew, err := store.GetManagedCluster(context.Background(), successor.ID)
	if err != nil {
		t.Fatal(err)
	}
	if clusterHasCapability(restoredNew, TargetMutationRBACActivationIssuedCapability) || clusterHasCapability(restoredNew, TargetMutationRBACActiveCapability) || restoredNew.MutationRBACIssuedForDigest != "" {
		t.Fatalf("restore retained unsafe successor mutation authority before predecessor fence acknowledgement: %+v", restoredNew)
	}
	if !clusterHasCapability(restoredNew, TargetReadOnlyAdmissionCapability) {
		t.Fatalf("restore did not force unsafe legacy successor read-only: %+v", restoredNew)
	}

	fenceDigest := ClusterTargetRBACRevocationFenceDigest(restoredOld)
	restoredOld, err = store.AcknowledgeManagedClusterTargetRBACRevocation(context.Background(), restoredOld.ID, restoredOld.Revision, fenceDigest, "upgrade-admin")
	if err != nil {
		t.Fatalf("acknowledge repaired predecessor fence: %v", err)
	}
	if !ClusterTargetRBACRevocationAcknowledged(restoredOld) {
		t.Fatalf("repaired predecessor acknowledgement is not bound to restored fence: %+v", restoredOld)
	}
}
