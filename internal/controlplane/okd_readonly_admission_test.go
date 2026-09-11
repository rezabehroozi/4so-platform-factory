package controlplane

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func seedAdmissionCluster(t *testing.T, now *time.Time) (*MemoryStore, context.Context, ManagedCluster, string) {
	t.Helper()
	store := NewMemoryStoreWith(func() time.Time { return *now }, nil)
	ctx := context.Background()
	org, err := store.CreateOrganization(ctx, Organization{Name: "admission-org", DisplayName: "Admission Org"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(ctx, Project{OrganizationID: org.ID, Name: "admission-project", DisplayName: "Admission Project"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	enrollment := digestTenantTest("admission-enrollment")
	agent := digestTenantTest("admission-agent")
	imp, err := store.CreateClusterImport(ctx, ClusterImport{ProjectID: project.ID, Name: "target", DisplayName: "Target", TokenDigest: enrollment, ExpiresAt: now.Add(time.Hour)}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	imp, err = store.ApproveClusterImport(ctx, imp.ID, imp.Revision, "approver")
	if err != nil {
		t.Fatal(err)
	}
	_, cluster, err := store.ClaimClusterImport(ctx, imp.ID, enrollment, agent, "uid-admission", "0.0.204")
	if err != nil {
		t.Fatal(err)
	}
	return store, ctx, cluster, agent
}

func authoritativeOKDInventory(now time.Time) ClusterInventory {
	return ClusterInventory{
		ObservedAt:                  now,
		Distribution:                "okd",
		DistributionEvidenceMethod:  DistributionEvidenceOKDClusterV1,
		DistributionEvidenceUID:     "8d8c7780-0c26-4a21-9229-4c60f131fc11",
		DistributionEvidenceVersion: "4.19.0-okd-scos.0",
		KubernetesVersion:           "v1.32.0",
		APIDiscoveryComplete:        true,
		CRDDiscoveryComplete:        true,
		APIResources: []ClusterAPIResourceObservation{{
			APIVersion: "config.openshift.io/v1", Group: "config.openshift.io", Version: "v1", Kind: "ClusterVersion", Resource: "clusterversions", Verbs: []string{"get", "list"},
		}},
		Capabilities: []string{TargetMutationRBACActiveCapability, "controlled-baseline-deployment", TenantDeleteObservedCapability, ClusterMaintenanceFencedReportCapability},
		Digest:       digestTenantTest("forged-agent-inventory-digest"),
	}
}

func healthyAdmittedOKDInventory(now time.Time) ClusterInventory {
	inv := authoritativeOKDInventory(now)
	inv.Capabilities = append(inv.Capabilities, "volume-snapshot-controller")
	inv.SchemaDiscoveryComplete = true
	inv.SchemaDiscoveryVersion = "OPENAPI_V3"
	inv.SchemaDiscoveryDigest = digestTenantTest("okd-openapi")
	inv.Networking = ClusterNetworking{CNI: "OVNKubernetes"}
	inv.APIResources = append(inv.APIResources,
		ClusterAPIResourceObservation{APIVersion: "operators.coreos.com/v1alpha1", Group: "operators.coreos.com", Version: "v1alpha1", Kind: "ClusterServiceVersion", Resource: "clusterserviceversions", Namespaced: true},
		ClusterAPIResourceObservation{APIVersion: "security.openshift.io/v1", Group: "security.openshift.io", Version: "v1", Kind: "SecurityContextConstraints", Resource: "securitycontextconstraints"},
		ClusterAPIResourceObservation{APIVersion: "project.openshift.io/v1", Group: "project.openshift.io", Version: "v1", Kind: "Project", Resource: "projects"},
	)
	inv.AddOns = []ClusterAddOn{
		{Name: "version", Kind: "cluster-version", Version: "4.19.0-okd-scos.0", Healthy: true, Available: "True", Progressing: "False", Degraded: "False", Upgradeable: "True"},
		{Name: "network", Kind: "cluster-operator", Version: "4.19.0", Healthy: true, Available: "True", Progressing: "False", Degraded: "False", Upgradeable: "True"},
		{Name: "monitoring", Kind: "cluster-operator", Version: "4.19.0", Healthy: true, Available: "True", Progressing: "False", Degraded: "False", Upgradeable: "True"},
		{Name: "operator-lifecycle-manager", Kind: "cluster-operator", Version: "4.19.0", Healthy: true, Available: "True", Progressing: "False", Degraded: "False", Upgradeable: "True"},
		{Name: "machine-config", Kind: "cluster-operator", Version: "4.19.0", Healthy: true, Available: "True", Progressing: "False", Degraded: "False", Upgradeable: "True"},
	}
	return inv
}

func TestHealthyOKDInventoryIsImportAdmittedButStillRequiresServerIssuedMutationRBAC(t *testing.T) {
	now := time.Date(2026, 9, 3, 10, 0, 0, 0, time.UTC)
	store, ctx, cluster, agent := seedAdmissionCluster(t, &now)
	inv := healthyAdmittedOKDInventory(now)
	inv.Capabilities = append(inv.Capabilities, TargetEnrollmentPrincipalIsolatedCapability)
	cluster, stored, err := store.UpsertClusterInventory(ctx, cluster.ID, agent, cluster.ExternalUID, inv)
	if err != nil {
		t.Fatal(err)
	}
	for _, capability := range []string{OKDImportAdmissionCapability, OKDHealthHealthyCapability, "networking.ovn-kubernetes", "monitoring.cluster", "operator-lifecycle.olm", "security.scc", "tenancy.projects"} {
		if !clusterHasCapability(cluster, capability) {
			t.Fatalf("missing server-derived OKD capability %q: %v", capability, cluster.Capabilities)
		}
	}
	if clusterHasCapability(cluster, TargetMutationRBACActiveCapability) || ClusterTaskAdmitted(cluster) {
		t.Fatalf("OKD import bypassed server mutation-RBAC issuance: %v", cluster.Capabilities)
	}
	health := TranslateOKDHealth(stored)
	if health.Status != "HEALTHY" || !health.MutationEligible || health.OperatorCount != 4 {
		t.Fatalf("unexpected OKD health: %+v", health)
	}
	profile := CompileTargetProfile(stored, nil)
	if profile.Status != "CONVERGED" || !profile.Resolution.Admitted {
		t.Fatalf("OKD desired/observed profile did not converge: %+v", profile)
	}

	cluster, _, err = store.AuthorizeClusterMutationRBACActivation(ctx, cluster.ID, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if !clusterHasCapability(cluster, TargetMutationRBACActivationIssuedCapability) || ClusterTaskAdmitted(cluster) {
		t.Fatalf("issuance alone incorrectly admitted mutation: %v", cluster.Capabilities)
	}
	inv.ObservedAt = now.Add(time.Minute)
	inv.Capabilities = append(inv.Capabilities, TargetEnrollmentPrincipalIsolatedCapability, TargetMutationRBACActiveCapability)
	cluster, _, err = store.UpsertClusterInventory(ctx, cluster.ID, agent, cluster.ExternalUID, inv)
	if err != nil {
		t.Fatal(err)
	}
	if !ClusterTaskAdmitted(cluster) {
		t.Fatalf("healthy OKD import did not enter admitted task authority after server issuance + agent proof: %+v", cluster)
	}
}

func TestOKDDegradedOperatorFailsClosedAndProfileReportsBlocker(t *testing.T) {
	now := time.Date(2026, 9, 3, 10, 30, 0, 0, time.UTC)
	inv := healthyAdmittedOKDInventory(now)
	for i := range inv.AddOns {
		if inv.AddOns[i].Name == "network" {
			inv.AddOns[i].Healthy = false
			inv.AddOns[i].Degraded = "True"
			inv.AddOns[i].Reason = "OVNDegraded"
			inv.AddOns[i].Message = "OVN rollout is degraded"
		}
	}
	inv = NormalizeClusterInventoryForAdmission(inv)
	if clusterHasCapability(ManagedCluster{Capabilities: inv.Capabilities}, OKDImportAdmissionCapability) {
		t.Fatalf("degraded OKD was admitted: %v", inv.Capabilities)
	}
	if !clusterHasCapability(ManagedCluster{Capabilities: inv.Capabilities}, TargetReadOnlyAdmissionCapability) {
		t.Fatalf("degraded OKD did not fail closed read-only: %v", inv.Capabilities)
	}
	health := TranslateOKDHealth(inv)
	if health.Status != "DEGRADED" || len(health.Degraded) != 1 || health.Degraded[0] != "network" {
		t.Fatalf("unexpected health translation: %+v", health)
	}
	profile := CompileTargetProfile(inv, nil)
	if profile.Status != "BLOCKED" || len(profile.Blockers) == 0 {
		t.Fatalf("degraded OKD profile was reported converged: %+v", profile)
	}
}

func TestClusterReconnectAuthorityDistinguishesAutomaticReconnectFromRevokedReenrollment(t *testing.T) {
	now := time.Date(2026, 9, 3, 11, 0, 0, 0, time.UTC)
	lastSeen := now.Add(-10 * time.Minute)
	cluster := ManagedCluster{ExternalUID: "uid-a", ConnectionState: "CONNECTED", LastSeenAt: &lastSeen}
	reconnect := ClusterReconnectAuthority(cluster, now)
	if reconnect.Status != "WAITING_FOR_AGENT" || !reconnect.Automatic || !reconnect.SameClusterIdentityRequired {
		t.Fatalf("unexpected automatic reconnect authority: %+v", reconnect)
	}
	cluster.ConnectionState = "REVOKED"
	cluster.Capabilities = []string{TargetMutationRBACEverIssuedCapability}
	reconnect = ClusterReconnectAuthority(cluster, now)
	if reconnect.Status != "REENROLLMENT_REQUIRED" || reconnect.Automatic || !reconnect.TargetRBACFenceRequired {
		t.Fatalf("unexpected revoked re-enrollment authority: %+v", reconnect)
	}
}

func TestOKDInventoryWithoutHealthAndNativeOwnershipRemainsReadOnly(t *testing.T) {
	now := time.Date(2026, 8, 27, 9, 0, 0, 0, time.UTC)
	store, ctx, cluster, agent := seedAdmissionCluster(t, &now)
	inv := authoritativeOKDInventory(now)
	forged := inv.Digest
	cluster, stored, err := store.UpsertClusterInventory(ctx, cluster.ID, agent, cluster.ExternalUID, inv)
	if err != nil {
		t.Fatal(err)
	}
	if cluster.Distribution != "okd" || stored.Distribution != "okd" {
		t.Fatalf("authoritative OKD identity was not persisted: cluster=%+v inventory=%+v", cluster, stored)
	}
	if stored.Digest == forged || stored.Digest != ClusterInventoryDigest(stored) {
		t.Fatalf("agent-controlled inventory digest remained authoritative: forged=%s stored=%s recomputed=%s", forged, stored.Digest, ClusterInventoryDigest(stored))
	}
	if clusterHasCapability(cluster, TargetMutationRBACActiveCapability) || clusterHasCapability(cluster, "controlled-baseline-deployment") || clusterHasCapability(cluster, TenantDeleteObservedCapability) || clusterHasCapability(cluster, ClusterMaintenanceFencedReportCapability) {
		t.Fatalf("preview OKD retained mutation capabilities: %v", cluster.Capabilities)
	}
	if !clusterHasCapability(cluster, TargetReadOnlyAdmissionCapability) {
		t.Fatalf("preview OKD did not receive read-only admission marker: %v", cluster.Capabilities)
	}
	if ClusterTaskAdmitted(cluster) {
		t.Fatal("preview OKD was admitted to mutation task queues")
	}
}

func TestOKDIdentityRejectsIncompleteOrCRDSpoofedAuthority(t *testing.T) {
	inv := authoritativeOKDInventory(time.Now().UTC())
	inv.DistributionEvidenceUID = ""
	if err := ValidateClusterInventoryAPISurface(inv); !errors.Is(err, ErrValidation) {
		t.Fatalf("missing ClusterVersion UID evidence was accepted: %v", err)
	}

	inv = authoritativeOKDInventory(time.Now().UTC())
	inv.CRDs = []ClusterCRDObservation{{Name: "clusterversions.config.openshift.io", Group: "config.openshift.io", Kind: "ClusterVersion", Plural: "clusterversions", Scope: "Cluster", Versions: []ClusterCRDVersionObservation{{Name: "v1", Served: true, Storage: true}}}}
	if err := ValidateClusterInventoryAPISurface(inv); !errors.Is(err, ErrValidation) {
		t.Fatalf("CRD-spoofed ClusterVersion authority was accepted: %v", err)
	}
}

func TestOpenShiftClusterVersionIsDistinctAndReadOnly(t *testing.T) {
	now := time.Date(2026, 8, 27, 9, 30, 0, 0, time.UTC)
	store, ctx, cluster, agent := seedAdmissionCluster(t, &now)
	inv := authoritativeOKDInventory(now)
	inv.Distribution = "openshift"
	inv.DistributionEvidenceMethod = DistributionEvidenceOpenShiftClusterV1
	inv.DistributionEvidenceVersion = "4.19.7"
	cluster, stored, err := store.UpsertClusterInventory(ctx, cluster.ID, agent, cluster.ExternalUID, inv)
	if err != nil {
		t.Fatal(err)
	}
	if cluster.Distribution != "openshift" || stored.Distribution != "openshift" {
		t.Fatalf("OpenShift identity was collapsed into another distribution: cluster=%+v inventory=%+v", cluster, stored)
	}
	if clusterHasCapability(cluster, TargetMutationRBACActiveCapability) || ClusterTaskAdmitted(cluster) {
		t.Fatalf("OpenShift target was mutation-admitted through the OKD path: %+v", cluster)
	}
	if !clusterHasCapability(cluster, TargetReadOnlyAdmissionCapability) {
		t.Fatalf("OpenShift target lost read-only admission: %+v", cluster.Capabilities)
	}
}

func TestNativeClusterVersionContradictsGenericOrRKE2Identity(t *testing.T) {
	for _, distribution := range []string{"kubernetes", "rke2"} {
		inv := authoritativeOKDInventory(time.Now().UTC())
		inv.Distribution = distribution
		inv.DistributionEvidenceMethod = DistributionEvidenceKubeletV1
		inv.DistributionEvidenceUID = ""
		inv.DistributionEvidenceVersion = "v1.32.0"
		if err := ValidateClusterInventoryAPISurface(inv); !errors.Is(err, ErrValidation) {
			t.Fatalf("native ClusterVersion was accepted with %q identity: %v", distribution, err)
		}
	}
}

func TestOKDReleaseVersionCannotBeOCPVersion(t *testing.T) {
	inv := authoritativeOKDInventory(time.Now().UTC())
	inv.DistributionEvidenceVersion = "4.19.7"
	if err := ValidateClusterInventoryAPISurface(inv); !errors.Is(err, ErrValidation) {
		t.Fatalf("non-OKD ClusterVersion release was accepted as OKD: %v", err)
	}
}

func TestAgentCannotSelfAuthorizeMutationRBACBeforeServerIssuance(t *testing.T) {
	now := time.Date(2026, 8, 27, 9, 45, 0, 0, time.UTC)
	store, ctx, cluster, agent := seedAdmissionCluster(t, &now)
	claimed := ClusterInventory{ObservedAt: now, Distribution: "rke2", KubernetesVersion: "v1.33.2", Capabilities: []string{TargetEnrollmentPrincipalIsolatedCapability, TargetMutationRBACActiveCapability, TargetMutationRBACActivationIssuedCapability, "controlled-baseline-deployment"}}
	cluster, stored, err := store.UpsertClusterInventory(ctx, cluster.ID, agent, cluster.ExternalUID, claimed)
	if err != nil {
		t.Fatal(err)
	}
	if clusterHasCapability(cluster, TargetMutationRBACActiveCapability) || clusterHasCapability(cluster, TargetMutationRBACActivationIssuedCapability) || ClusterTaskAdmitted(cluster) {
		t.Fatalf("agent self-authorized mutation before server issuance: cluster=%v inventory=%v", cluster.Capabilities, stored.Capabilities)
	}
	if !clusterHasCapability(cluster, TargetReadOnlyAdmissionCapability) {
		t.Fatalf("pre-issuance inventory was not fail-closed read-only: %v", cluster.Capabilities)
	}

	cluster, _, err = store.AuthorizeClusterMutationRBACActivation(ctx, cluster.ID, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if !clusterHasCapability(cluster, TargetMutationRBACActivationIssuedCapability) || clusterHasCapability(cluster, TargetMutationRBACActiveCapability) || ClusterTaskAdmitted(cluster) {
		t.Fatalf("issuance marker itself incorrectly opened mutation admission: %v", cluster.Capabilities)
	}

	claimed.Capabilities = []string{TargetEnrollmentPrincipalIsolatedCapability, TargetMutationRBACActiveCapability, "controlled-baseline-deployment"}
	cluster, stored, err = store.UpsertClusterInventory(ctx, cluster.ID, agent, cluster.ExternalUID, claimed)
	if err != nil {
		t.Fatal(err)
	}
	if !clusterHasCapability(cluster, TargetMutationRBACActivationIssuedCapability) || !clusterHasCapability(cluster, TargetMutationRBACActiveCapability) || !ClusterTaskAdmitted(cluster) {
		t.Fatalf("server-issued + agent-proven activation was not admitted: cluster=%v inventory=%v", cluster.Capabilities, stored.Capabilities)
	}
	if clusterHasCapability(ManagedCluster{Capabilities: stored.Capabilities}, TargetMutationRBACActivationIssuedCapability) {
		t.Fatalf("server-owned issuance marker leaked into agent inventory snapshot: %v", stored.Capabilities)
	}
}

func TestMutationRBACIssuanceIsInvalidatedBySemanticInventoryDrift(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	store, ctx, cluster, agent := seedAdmissionCluster(t, &now)
	base := ClusterInventory{
		ObservedAt: now, Distribution: "rke2", KubernetesVersion: "v1.33.2+rke2r1",
		Capabilities: []string{TargetMutationRBACActiveCapability, "controlled-baseline-deployment"},
	}
	cluster, _, err := upsertMutationReadyInventoryForTest(t, store, ctx, cluster.ID, agent, cluster.ExternalUID, base)
	if err != nil {
		t.Fatal(err)
	}
	issued := cluster.MutationRBACIssuedForDigest
	if issued == "" || issued != cluster.MutationRBACBasisDigest || !ClusterTaskAdmitted(cluster) {
		t.Fatalf("initial mutation authority was not bound to basis: %+v", cluster)
	}

	drifted := base
	drifted.ObservedAt = now.Add(time.Minute)
	drifted.KubernetesVersion = "v1.33.3+rke2r1"
	drifted.Capabilities = []string{TargetEnrollmentPrincipalIsolatedCapability, TargetMutationRBACActiveCapability, "controlled-baseline-deployment"}
	cluster, stored, err := store.UpsertClusterInventory(ctx, cluster.ID, agent, cluster.ExternalUID, drifted)
	if err != nil {
		t.Fatal(err)
	}
	if cluster.MutationRBACBasisDigest == issued {
		t.Fatalf("semantic drift did not change mutation basis: old=%s new=%s", issued, cluster.MutationRBACBasisDigest)
	}
	if cluster.MutationRBACIssuedForDigest != "" || clusterHasCapability(cluster, TargetMutationRBACActivationIssuedCapability) || clusterHasCapability(cluster, TargetMutationRBACActiveCapability) || ClusterTaskAdmitted(cluster) {
		t.Fatalf("stale mutation issuance survived semantic inventory drift: cluster=%+v inventory=%+v", cluster, stored)
	}
	if !clusterHasCapability(cluster, TargetReadOnlyAdmissionCapability) {
		t.Fatalf("drifted inventory did not fail closed read-only: %v", cluster.Capabilities)
	}

	cluster, _, err = store.AuthorizeClusterMutationRBACActivation(ctx, cluster.ID, "admin-reissue")
	if err != nil {
		t.Fatal(err)
	}
	if cluster.MutationRBACIssuedForDigest == "" || cluster.MutationRBACIssuedForDigest != cluster.MutationRBACBasisDigest || cluster.MutationRBACIssuedForDigest == issued {
		t.Fatalf("mutation authority was not re-issued for the new basis: %+v", cluster)
	}
}

func TestMutationRBACIssuanceSurvivesTelemetryChurn(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 30, 0, 0, time.UTC)
	store, ctx, cluster, agent := seedAdmissionCluster(t, &now)
	base := ClusterInventory{
		ObservedAt: now, Distribution: "rke2", KubernetesVersion: "v1.33.2+rke2r1",
		Nodes:          []ClusterNode{{Name: "node-a", UID: "node-a", Ready: true}},
		AddOns:         []ClusterAddOn{{Name: "cilium", Namespace: "kube-system", Version: "1.18", Healthy: true}},
		StorageClasses: []ClusterStorageClass{{Name: "local", Provisioner: "example.csi", Default: true}},
		Capacity:       ClusterCapacity{CPUAllocatableMilli: 4000, MemoryAllocatableBytes: 8 << 30, PodsAllocatable: 110},
		Certificates:   []ClusterCertificateObservation{{Name: "api", Fingerprint: "sha256:" + strings.Repeat("a", 64), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)}},
		Networking:     ClusterNetworking{CNI: "cilium", IngressControllers: []string{"ingress-a"}, GatewayAPI: true},
		Capabilities:   []string{TargetMutationRBACActiveCapability, "controlled-baseline-deployment", "cert.metrics", "storage-inventory"},
	}
	cluster, _, err := upsertMutationReadyInventoryForTest(t, store, ctx, cluster.ID, agent, cluster.ExternalUID, base)
	if err != nil {
		t.Fatal(err)
	}
	issued := cluster.MutationRBACIssuedForDigest
	if issued == "" || !ClusterTaskAdmitted(cluster) {
		t.Fatalf("initial mutation authority missing: %+v", cluster)
	}

	churn := cloneClusterInventory(base)
	churn.ObservedAt = now.Add(time.Minute)
	churn.Nodes[0].Ready = false
	churn.AddOns[0].Healthy = false
	churn.Capacity.CPUAllocatableMilli = 2500
	churn.Capacity.PodsAllocatable = 90
	churn.Certificates[0].NotAfter = now.Add(48 * time.Hour)
	churn.StorageClasses[0].Default = false
	churn.Networking.IngressControllers = []string{"ingress-b"}
	churn.Networking.GatewayAPI = false
	churn.Capabilities = append(churn.Capabilities, TargetEnrollmentPrincipalIsolatedCapability, "cert.logs", "observability-adapter-auto-discovered")
	cluster, _, err = store.UpsertClusterInventory(ctx, cluster.ID, agent, cluster.ExternalUID, churn)
	if err != nil {
		t.Fatal(err)
	}
	if cluster.MutationRBACBasisDigest != issued || cluster.MutationRBACIssuedForDigest != issued || !clusterHasCapability(cluster, TargetMutationRBACActivationIssuedCapability) || !clusterHasCapability(cluster, TargetMutationRBACActiveCapability) || !ClusterTaskAdmitted(cluster) {
		t.Fatalf("telemetry churn invalidated stable mutation RBAC authority: %+v", cluster)
	}
}

func TestMutationRBACIssuanceSurvivesUnrelatedDiscoveryCatalogChurn(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 45, 0, 0, time.UTC)
	store, ctx, cluster, agent := seedAdmissionCluster(t, &now)
	base := ClusterInventory{
		ObservedAt:              now,
		Distribution:            "rke2",
		KubernetesVersion:       "v1.33.2+rke2r1",
		APIDiscoveryComplete:    true,
		CRDDiscoveryComplete:    true,
		SchemaDiscoveryComplete: true,
		SchemaDiscoveryVersion:  "OPENAPI_V3",
		SchemaDiscoveryDigest:   digestTenantTest("schema-a"),
		APIResources:            []ClusterAPIResourceObservation{{APIVersion: "apps/v1", Group: "apps", Version: "v1", Kind: "Deployment", Resource: "deployments", Namespaced: true, Verbs: []string{"get", "list"}}},
		CRDs:                    []ClusterCRDObservation{{Name: "widgets.example.io", Group: "example.io", Kind: "Widget", Plural: "widgets", Scope: "Namespaced", Versions: []ClusterCRDVersionObservation{{Name: "v1", Served: true, Storage: true}}}},
		Capabilities:            []string{TargetMutationRBACActiveCapability, "controlled-baseline-deployment"},
	}
	cluster, firstInventory, err := upsertMutationReadyInventoryForTest(t, store, ctx, cluster.ID, agent, cluster.ExternalUID, base)
	if err != nil {
		t.Fatal(err)
	}
	issued := cluster.MutationRBACIssuedForDigest
	fullDigest := firstInventory.Digest
	if issued == "" || fullDigest == "" || !ClusterTaskAdmitted(cluster) {
		t.Fatalf("initial mutation authority missing: cluster=%+v inventory=%+v", cluster, firstInventory)
	}

	churn := cloneClusterInventory(base)
	churn.ObservedAt = now.Add(time.Minute)
	churn.APIResources = append(churn.APIResources, ClusterAPIResourceObservation{APIVersion: "monitoring.coreos.com/v1", Group: "monitoring.coreos.com", Version: "v1", Kind: "PrometheusRule", Resource: "prometheusrules", Namespaced: true, Verbs: []string{"get", "list", "watch"}})
	churn.CRDs = append(churn.CRDs, ClusterCRDObservation{Name: "prometheusrules.monitoring.coreos.com", Group: "monitoring.coreos.com", Kind: "PrometheusRule", Plural: "prometheusrules", Scope: "Namespaced", Versions: []ClusterCRDVersionObservation{{Name: "v1", Served: true, Storage: true}}})
	churn.SchemaDiscoveryDigest = digestTenantTest("schema-b")
	churn.Capabilities = append(churn.Capabilities, TargetEnrollmentPrincipalIsolatedCapability)
	cluster, secondInventory, err := store.UpsertClusterInventory(ctx, cluster.ID, agent, cluster.ExternalUID, churn)
	if err != nil {
		t.Fatal(err)
	}
	if secondInventory.Digest == fullDigest {
		t.Fatal("unrelated discovery catalog churn did not change the full task/planning inventory digest")
	}
	if cluster.MutationRBACBasisDigest != issued || cluster.MutationRBACIssuedForDigest != issued || !ClusterTaskAdmitted(cluster) {
		t.Fatalf("unrelated discovery catalog churn invalidated stable mutation RBAC authority: %+v", cluster)
	}
}

func TestMutationRBACEverIssuedHistorySurvivesAuthorityDrift(t *testing.T) {
	now := time.Date(2026, 8, 27, 13, 0, 0, 0, time.UTC)
	store, ctx, cluster, agent := seedAdmissionCluster(t, &now)
	base := ClusterInventory{ObservedAt: now, Distribution: "rke2", KubernetesVersion: "v1.33.2+rke2r1", Capabilities: []string{TargetMutationRBACActiveCapability, "controlled-baseline-deployment"}}
	cluster, _, err := upsertMutationReadyInventoryForTest(t, store, ctx, cluster.ID, agent, cluster.ExternalUID, base)
	if err != nil {
		t.Fatal(err)
	}
	if !ClusterMayHaveTargetMutationRBAC(cluster) || !clusterHasCapability(cluster, TargetMutationRBACEverIssuedCapability) {
		t.Fatalf("server-owned mutation RBAC history was not recorded after issuance: %+v", cluster)
	}

	drifted := cloneClusterInventory(base)
	drifted.ObservedAt = now.Add(time.Minute)
	drifted.KubernetesVersion = "v1.33.3+rke2r1"
	drifted.Capabilities = append(drifted.Capabilities, TargetEnrollmentPrincipalIsolatedCapability)
	cluster, _, err = store.UpsertClusterInventory(ctx, cluster.ID, agent, cluster.ExternalUID, drifted)
	if err != nil {
		t.Fatal(err)
	}
	if clusterHasCapability(cluster, TargetMutationRBACActivationIssuedCapability) || clusterHasCapability(cluster, TargetMutationRBACActiveCapability) || ClusterTaskAdmitted(cluster) {
		t.Fatalf("authority drift retained current mutation authorization: %+v", cluster)
	}
	if !clusterHasCapability(cluster, TargetMutationRBACEverIssuedCapability) || !ClusterMayHaveTargetMutationRBAC(cluster) {
		t.Fatalf("authority drift erased durable target-RBAC revocation history: %+v", cluster)
	}
}

func TestHeartbeatWithoutFreshInventoryBreaksMutationAuthorityEpoch(t *testing.T) {
	now := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	store, ctx, cluster, agent := seedAdmissionCluster(t, &now)
	cluster, _, err := upsertMutationReadyInventoryForTest(t, store, ctx, cluster.ID, agent, cluster.ExternalUID, ClusterInventory{ObservedAt: now, Distribution: "rke2", KubernetesVersion: "v1.33.2", Capabilities: []string{TargetMutationRBACActiveCapability, TargetIdentityContinuityCapability}})
	if err != nil {
		t.Fatal(err)
	}
	if !ClusterTaskClaimAdmittedAt(cluster, now) {
		t.Fatalf("fresh admitted RKE2 inventory was not mutation-authorized: %+v", cluster)
	}
	now = now.Add(time.Minute)
	cluster, err = store.HeartbeatCluster(ctx, cluster.ID, agent, cluster.ExternalUID, "0.0.204")
	if err != nil {
		t.Fatal(err)
	}
	if ClusterTaskClaimAdmittedAt(cluster, now) {
		t.Fatalf("heartbeat refreshed task authority without fresh inventory: %+v", cluster)
	}
}
func TestLegacyActiveCapabilityWithoutDigestBoundIssuanceFailsClosed(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 20, 0, 0, time.UTC)
	legacy := ManagedCluster{
		ConnectionState: "CONNECTED", Distribution: "rke2", InventoryDigest: digestTenantTest("legacy-inventory"),
		InventoryUpdatedAt: &now, LastSeenAt: &now,
		Capabilities: []string{TargetMutationRBACActiveCapability, TargetMutationRBACActivationIssuedCapability},
	}
	if ClusterTaskAdmitted(legacy) || ClusterTaskClaimAdmittedAt(legacy, now) {
		t.Fatal("pre-v49 active capability without digest-bound issuance survived upgrade fail-closed boundary")
	}
}

func TestClusterTaskAdmissionExpiresWhenInventoryAuthorityIsStale(t *testing.T) {
	now := time.Date(2026, 8, 27, 10, 30, 0, 0, time.UTC)
	store, ctx, cluster, agent := seedAdmissionCluster(t, &now)
	cluster, _, err := upsertMutationReadyInventoryForTest(t, store, ctx, cluster.ID, agent, cluster.ExternalUID, ClusterInventory{
		ObservedAt:        now,
		Distribution:      "rke2",
		KubernetesVersion: "v1.33.2",
		Capabilities:      []string{TargetMutationRBACActiveCapability, TargetIdentityContinuityCapability},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !ClusterTaskClaimAdmittedAt(cluster, now) {
		t.Fatalf("fresh inventory authority was not admitted: %+v", cluster)
	}
	now = now.Add(ClusterInventoryAuthorityFreshness + time.Second)
	if ClusterTaskClaimAdmittedAt(cluster, now) {
		t.Fatalf("stale inventory retained mutation authority: lastSeen=%v now=%v", cluster.LastSeenAt, now)
	}
	store.mu.Lock()
	_, err = store.requireFreshClusterTaskAdmissionLocked(cluster.ID, agent)
	store.mu.Unlock()
	if !errors.Is(err, ErrPrerequisite) {
		t.Fatalf("stale inventory was admitted by the task store: %v", err)
	}
}

func TestStoreOwnsClusterIdentityContinuityForInventoryAndHeartbeat(t *testing.T) {
	now := time.Date(2026, 8, 27, 11, 0, 0, 0, time.UTC)
	store, ctx, cluster, agent := seedAdmissionCluster(t, &now)
	inventory := ClusterInventory{ObservedAt: now, Distribution: "rke2", KubernetesVersion: "v1.33.2", Capabilities: []string{TargetMutationRBACActiveCapability, TargetIdentityContinuityCapability}}

	if _, _, err := store.UpsertClusterInventory(ctx, cluster.ID, agent, "different-physical-cluster", inventory); !errors.Is(err, ErrValidation) {
		t.Fatalf("store accepted inventory from a different physical cluster: %v", err)
	}

	cluster, stored, err := store.UpsertClusterInventory(ctx, cluster.ID, agent, "", inventory)
	if err != nil {
		t.Fatal(err)
	}
	if clusterHasCapability(cluster, TargetMutationRBACActiveCapability) || clusterHasCapability(cluster, TargetIdentityContinuityCapability) || !clusterHasCapability(cluster, TargetReadOnlyAdmissionCapability) {
		t.Fatalf("identity-unattested direct store inventory was not normalized read-only: cluster=%v inventory=%v", cluster.Capabilities, stored.Capabilities)
	}
	lastSeen := *cluster.LastSeenAt
	now = now.Add(time.Minute)
	cluster, err = store.HeartbeatCluster(ctx, cluster.ID, agent, "", "legacy-agent")
	if err != nil {
		t.Fatal(err)
	}
	if cluster.LastSeenAt == nil || !cluster.LastSeenAt.Equal(lastSeen) {
		t.Fatalf("identity-unattested direct heartbeat refreshed liveness: before=%v after=%v", lastSeen, cluster.LastSeenAt)
	}
	if _, err = store.HeartbeatCluster(ctx, cluster.ID, agent, "different-physical-cluster", "copied-agent"); !errors.Is(err, ErrValidation) {
		t.Fatalf("store accepted heartbeat from a different physical cluster: %v", err)
	}
}
