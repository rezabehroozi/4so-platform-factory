package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"platform.4so.io/factory/internal/controlplane"
	daprruntime "platform.4so.io/factory/internal/dapr"
	"platform.4so.io/factory/internal/targetmodel"
)

type daprAssessmentResponse struct {
	Authority                     string                            `json:"authority"`
	ProfileAuthority              string                            `json:"profileAuthority"`
	SourcePlan                    targetmodel.DaprRuntimeSourcePlan `json:"sourcePlan"`
	SupplyChainAuthority          string                            `json:"supplyChainAuthority"`
	SupplyChainAdmitted           bool                              `json:"supplyChainAdmitted"`
	ReviewedRuntimeVersion        string                            `json:"reviewedRuntimeVersion"`
	Assessment                    targetmodel.DaprTargetAdmission   `json:"assessment"`
	LatestOperation               *controlplane.Operation           `json:"latestOperation,omitempty"`
	RuntimeInstallImplemented     bool                              `json:"runtimeInstallImplemented"`
	PhysicalCertificationInferred bool                              `json:"physicalCertificationInferred"`
}

func seedDaprAssessmentInventory(t *testing.T, store *controlplane.MemoryStore, cluster controlplane.ManagedCluster, capabilities []string, n int) {
	t.Helper()
	agentDigest := "sha256:" + strings.Repeat("b", 64)
	_, _, err := upsertMutationReadyInventoryForAPITest(t, store, context.Background(), cluster.ID, agentDigest, cluster.ExternalUID, controlplane.ClusterInventory{
		ObservedAt: time.Now().UTC().Add(time.Duration(n) * time.Second),
		Distribution: "rke2", KubernetesVersion: "v1.34.1",
		APIDiscoveryComplete: true, CRDDiscoveryComplete: true, SchemaDiscoveryComplete: true,
		SchemaDiscoveryVersion: "OPENAPI_V3", SchemaDiscoveryDigest: fmt.Sprintf("sha256:%064x", 7000+n),
		Capabilities: append([]string{controlplane.TargetMutationRBACActiveCapability, controlplane.DaprExecutorRBACCapability, controlplane.DaprWorkloadAdmissionRBACCapability}, capabilities...),
		Digest: fmt.Sprintf("sha256:%064x", 8000+n),
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestDaprAssessmentUsesNativeCapabilityAndBlocksUnimplementedInstall(t *testing.T) {
	store := controlplane.NewMemoryStore()
	ctx := context.Background()
	org, _ := store.CreateOrganization(ctx, controlplane.Organization{Name: "dapr-assessment", DisplayName: "Dapr Assessment"}, "owner")
	project, _ := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "apps", DisplayName: "Apps"}, "owner")
	nativeCluster := workspaceAPICluster(t, store, project.ID, "dapr-native", "uid-dapr-native")
	installCluster := workspaceAPICluster(t, store, project.ID, "dapr-install", "uid-dapr-install")

	common := []string{
		targetmodel.DaprSidecarSecurityCapability,
		targetmodel.DaprComponentScopeCapability,
		targetmodel.DaprResourceSizingCapability,
	}
	seedDaprAssessmentInventory(t, store, nativeCluster, append(append([]string{}, common...), targetmodel.DaprApplicationRuntimeCapability), 1)
	seedDaprAssessmentInventory(t, store, installCluster, common, 2)
	srv := scopedServer(t, store)

	body := fmt.Sprintf(`{"projectId":%q,"clusterId":%q,"disconnected":false}`, project.ID, nativeCluster.ID)
	w := applicationPlatformRequest(t, srv, http.MethodPost, "/api/v1/application-platform/dapr/assessment", body, "owner", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("native assessment=%d %s", w.Code, w.Body.String())
	}
	native := decodeApplicationResponse[daprAssessmentResponse](t, w)
	if native.Authority != targetmodel.DaprTargetAdmissionAuthority || native.ProfileAuthority != targetmodel.DaprApplicationRuntimeAuthority ||
		native.SourcePlan.Authority != targetmodel.DaprRuntimeSourcePlanAuthority || native.SourcePlan.UpstreamCommit != targetmodel.DaprUpstreamCommit ||
		native.SupplyChainAuthority != targetmodel.DaprRuntimeSupplyChainAuthority || native.SupplyChainAdmitted ||
		native.ReviewedRuntimeVersion != targetmodel.DaprReviewedRuntimeVersion || !native.Assessment.Eligible ||
		native.Assessment.Mode != "USE_NATIVE" || !native.Assessment.InstallSuppressed || !native.RuntimeInstallImplemented ||
		native.PhysicalCertificationInferred {
		t.Fatalf("native Dapr assessment drift: %#v", native)
	}

	body = fmt.Sprintf(`{"projectId":%q,"clusterId":%q,"disconnected":false}`, project.ID, installCluster.ID)
	w = applicationPlatformRequest(t, srv, http.MethodPost, "/api/v1/application-platform/dapr/assessment", body, "owner", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("install assessment=%d %s", w.Code, w.Body.String())
	}
	pending := decodeApplicationResponse[daprAssessmentResponse](t, w)
	if pending.Assessment.Eligible || pending.Assessment.Mode != "INSTALL_REQUIRED" || pending.Assessment.InstallSuppressed {
		t.Fatalf("unimplemented product-managed Dapr install became eligible: %#v", pending.Assessment)
	}
	want := map[string]bool{"DAPR_EXACT_SOURCE_AUTHORITY_PENDING": true}
	for _, blocker := range pending.Assessment.Blockers {
		delete(want, blocker)
	}
	if len(want) != 0 {
		t.Fatalf("missing product-managed Dapr blockers: %v assessment=%#v", want, pending.Assessment)
	}
}


func TestDaprAssessmentKeepsProductManagedOwnershipAfterCapabilityDiscovery(t *testing.T) {
	store := controlplane.NewMemoryStore()
	ctx := context.Background()
	org, _ := store.CreateOrganization(ctx, controlplane.Organization{Name: "dapr-owned-assessment", DisplayName: "Dapr Owned Assessment"}, "owner")
	project, _ := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "apps", DisplayName: "Apps"}, "owner")
	cluster := workspaceAPICluster(t, store, project.ID, "dapr-owned-assessment", "uid-dapr-owned-assessment")
	seedDaprAssessmentInventory(t, store, cluster, []string{targetmodel.DaprApplicationRuntimeCapability}, 4)

	srv := scopedServer(t, store)
	lock := daprAPITestRuntimeLock(t)
	if err := srv.ConfigureDaprRuntimeLock(lock, "https://zot.internal.example"); err != nil { t.Fatal(err) }
	lockDigest, err := daprruntime.RuntimeLockDigest(lock)
	if err != nil { t.Fatal(err) }
	seedProductManagedDaprObserved(t, store, project.ID, cluster.ID, lockDigest)

	body := fmt.Sprintf(`{"projectId":%q,"clusterId":%q,"disconnected":false}`, project.ID, cluster.ID)
	w := applicationPlatformRequest(t, srv, http.MethodPost, "/api/v1/application-platform/dapr/assessment", body, "owner", nil)
	if w.Code != http.StatusOK { t.Fatalf("product-managed assessment=%d %s", w.Code, w.Body.String()) }
	out := decodeApplicationResponse[daprAssessmentResponse](t, w)
	if out.Assessment.Mode != "PRODUCT_MANAGED" || out.Assessment.InstallSuppressed || !out.Assessment.Eligible ||
		!strings.Contains(w.Body.String(), lockDigest) {
		t.Fatalf("product-managed Dapr collapsed into target-native admission: %#v body=%s", out.Assessment, w.Body.String())
	}
}

type daprWorkloadPlanResponse struct {
	Authority                        string                          `json:"authority"`
	TraitID                          string                          `json:"traitId"`
	TraitDigest                      string                          `json:"traitDigest"`
	Plan                             targetmodel.DaprWorkloadRuntimePlan `json:"plan"`
	ConfigurationProjectionAuthority string                         `json:"configurationProjectionAuthority"`
	ConfigurationProjection          map[string]any                 `json:"configurationProjection"`
	ConfigurationPolicyDigest        string                         `json:"configurationPolicyDigest"`
	ComponentScopeDigest             string                         `json:"componentScopeDigest"`
	RuntimeMutationPerformed         bool                           `json:"runtimeMutationPerformed"`
	PhysicalCertificationInferred    bool                           `json:"physicalCertificationInferred"`
}

func TestDaprWorkloadPlanRequiresPersistedDaprSidecarTrait(t *testing.T) {
	store := controlplane.NewMemoryStore()
	ctx := context.Background()
	org, _ := store.CreateOrganization(ctx, controlplane.Organization{Name: "dapr-plan", DisplayName: "Dapr Plan"}, "owner")
	project, _ := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "apps", DisplayName: "Apps"}, "owner")
	digest := "sha256:" + strings.Repeat("a", 64)
	trait, err := store.CreateCapabilityTrait(ctx, controlplane.CapabilityTrait{
		ProjectID: project.ID, Name: "dapr-runtime", Version: "1.0.0", Kind: "sidecar",
		Capability: controlplane.ApplicationRuntimeDaprCapability, InputSchemaDigest: digest, NativeSuppression: true,
	}, "owner")
	if err != nil { t.Fatal(err) }
	other, err := store.CreateCapabilityTrait(ctx, controlplane.CapabilityTrait{
		ProjectID: project.ID, Name: "other-sidecar", Version: "1.0.0", Kind: "sidecar",
		Capability: "application-runtime.other", InputSchemaDigest: digest, NativeSuppression: true,
	}, "owner")
	if err != nil { t.Fatal(err) }
	srv := scopedServer(t, store)
	body := fmt.Sprintf(`{"projectId":%q,"traitId":%q,"namespace":"payments","appId":"payments-api","appPort":8080,"appProtocol":"http","cpuRequest":"100m","cpuLimit":"500m","memoryRequest":"128Mi","memoryLimit":"256Mi","componentNames":["orders-broker"],"enableInvocation":true,"enablePubSub":true}`, project.ID, trait.ID)
	w := applicationPlatformRequest(t, srv, http.MethodPost, "/api/v1/application-platform/dapr/workload-plan", body, "owner", nil)
	if w.Code != http.StatusOK { t.Fatalf("Dapr workload plan=%d %s", w.Code, w.Body.String()) }
	out := decodeApplicationResponse[daprWorkloadPlanResponse](t, w)
	if out.Authority != targetmodel.DaprWorkloadRuntimePlanAuthority || out.TraitID != trait.ID || out.TraitDigest != trait.Digest ||
		out.Plan.AppID != "payments-api" || out.Plan.ConfigurationName != "4so-dapr-payments-api" ||
		out.ConfigurationProjectionAuthority != daprruntime.WorkloadPolicyProjectionAuthority ||
		out.RuntimeMutationPerformed || out.PhysicalCertificationInferred {
		t.Fatalf("Dapr workload plan response drift: %#v", out)
	}
	policyDigest, err := daprruntime.WorkloadConfigurationPolicyDigest(out.Plan)
	if err != nil { t.Fatal(err) }
	componentScopeDigest, err := daprruntime.WorkloadComponentScopeDigest(out.Plan)
	if err != nil { t.Fatal(err) }
	metadata, _ := out.ConfigurationProjection["metadata"].(map[string]any)
	if out.ConfigurationPolicyDigest != policyDigest || out.ComponentScopeDigest != componentScopeDigest ||
		strings.TrimSpace(fmt.Sprint(out.ConfigurationProjection["kind"])) != "Configuration" ||
		strings.TrimSpace(fmt.Sprint(metadata["name"])) != out.Plan.ConfigurationName {
		t.Fatalf("Dapr workload policy projection response drift: %#v", out)
	}
	if len(out.Plan.ComponentScopes) != 1 || len(out.Plan.ComponentScopes[0].Scopes) != 1 || out.Plan.ComponentScopes[0].Scopes[0] != "payments-api" {
		t.Fatalf("Dapr component scope escaped app identity: %#v", out.Plan.ComponentScopes)
	}

	body = fmt.Sprintf(`{"projectId":%q,"traitId":%q,"namespace":"payments","appId":"payments-api","cpuRequest":"100m","cpuLimit":"500m","memoryRequest":"128Mi","memoryLimit":"256Mi","enableInvocation":true}`, project.ID, other.ID)
	w = applicationPlatformRequest(t, srv, http.MethodPost, "/api/v1/application-platform/dapr/workload-plan", body, "owner", nil)
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "DAPR_TRAIT_REQUIRED") {
		t.Fatalf("non-Dapr sidecar trait rendered a Dapr plan: %d %s", w.Code, w.Body.String())
	}
}
