package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"platform.4so.io/factory/internal/controlplane"
	daprruntime "platform.4so.io/factory/internal/dapr"
	"platform.4so.io/factory/internal/targetmodel"
)

type daprWorkloadAdmissionCreateResponse struct {
	Authority        string                               `json:"authority"`
	Operation        controlplane.Operation               `json:"operation"`
	Request          daprruntime.WorkloadAdmissionRequest `json:"request"`
	IdempotentReplay bool                                 `json:"idempotentReplay"`
}

func TestDaprWorkloadAdmissionCreatesReadOnlyDurableNativeDryRun(t *testing.T) {
	store := controlplane.NewMemoryStore()
	ctx := context.Background()
	org, _ := store.CreateOrganization(ctx, controlplane.Organization{Name: "dapr-admission", DisplayName: "Dapr Admission"}, "owner")
	project, _ := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "apps", DisplayName: "Apps"}, "owner")
	cluster := workspaceAPICluster(t, store, project.ID, "dapr-native-admission", "uid-dapr-native-admission")
	seedDaprAssessmentInventory(t, store, cluster, []string{
		targetmodel.DaprApplicationRuntimeCapability,
		"strict-schema-dry-run",
	}, 90)
	trait, err := store.CreateCapabilityTrait(ctx, controlplane.CapabilityTrait{
		ProjectID: project.ID, Name: "dapr-runtime", Version: "1.0.0", Kind: "sidecar",
		Capability: controlplane.ApplicationRuntimeDaprCapability,
		InputSchemaDigest: daprAPITestDigest("7"), NativeSuppression: true,
	}, "owner")
	if err != nil { t.Fatal(err) }

	srv := scopedServer(t, store)
	lock := daprAPITestRuntimeLock(t)
	executorAuthority, err := daprruntime.ExecutorAuthorityFromRuntimeLock(lock)
	if err != nil { t.Fatal(err) }
	if err = srv.ConfigureDaprExecutorAuthority(executorAuthority, "https://zot.internal.example", executorAuthority.SourceReleaseDigest); err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(`{"projectId":%q,"clusterId":%q,"traitId":%q,"workloadImage":%q,"namespace":"payments","appId":"payments-api","appPort":8080,"appProtocol":"http","cpuRequest":"100m","cpuLimit":"500m","memoryRequest":"128Mi","memoryLimit":"256Mi","componentNames":["orders-broker"],"enableInvocation":true,"enablePubSub":true}`,
		project.ID, cluster.ID, trait.ID, "zot.internal.example/apps/payments@"+daprAPITestDigest("8"))
	headers := map[string]string{"Idempotency-Key": "dapr-native-admission-1", "X-Request-ID": "req-dapr-native-admission-1"}
	w := applicationPlatformRequest(t, srv, http.MethodPost, "/api/v1/application-platform/dapr/workload-admissions", body, "owner", headers)
	if w.Code != http.StatusAccepted {
		t.Fatalf("Dapr workload admission create=%d %s", w.Code, w.Body.String())
	}
	created := decodeApplicationResponse[daprWorkloadAdmissionCreateResponse](t, w)
	if created.Authority != daprruntime.WorkloadAdmissionAuthority ||
		created.Operation.State != controlplane.OperationQueued ||
		created.Operation.Class != controlplane.OperationClassReadOnly ||
		created.Request.RuntimeMode != "USE_NATIVE" ||
		created.Request.RuntimeLockDigest != "" || created.Request.ExpectedSidecarImage != "" ||
		created.Request.ExecutorEvidenceDigest != executorAuthority.EvidenceDigest ||
		created.Request.ExecutorSourceReleaseDigest != executorAuthority.SourceReleaseDigest ||
		created.Request.ExecutorImageReference != executorAuthority.ImageReference ||
		created.IdempotentReplay {
		t.Fatalf("native Dapr workload admission authority drift: %#v", created)
	}
	sealed, err := store.GetOperationRequestPayload(ctx, created.Operation.ID)
	if err != nil { t.Fatal(err) }
	if sealed.MediaType != daprruntime.WorkloadAdmissionPayloadMediaType || sealed.PayloadDigest != created.Operation.DesiredRevision {
		t.Fatalf("Dapr workload admission request was not durably sealed: op=%+v payload=%+v", created.Operation, sealed)
	}

	w = applicationPlatformRequest(t, srv, http.MethodPost, "/api/v1/application-platform/dapr/workload-admissions", body, "owner", headers)
	if w.Code != http.StatusOK {
		t.Fatalf("Dapr workload admission replay=%d %s", w.Code, w.Body.String())
	}
	replay := decodeApplicationResponse[daprWorkloadAdmissionCreateResponse](t, w)
	if !replay.IdempotentReplay || replay.Operation.ID != created.Operation.ID || replay.Operation.State != controlplane.OperationQueued {
		t.Fatalf("Dapr workload admission idempotency drift: %#v", replay)
	}
}

func TestDaprWorkloadAdmissionKeepsProductManagedRuntimeFenceAfterCapabilityDiscovery(t *testing.T) {
	store := controlplane.NewMemoryStore()
	ctx := context.Background()
	org, _ := store.CreateOrganization(ctx, controlplane.Organization{Name: "dapr-product-workload", DisplayName: "Dapr Product Workload"}, "owner")
	project, _ := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "apps", DisplayName: "Apps"}, "owner")
	cluster := workspaceAPICluster(t, store, project.ID, "dapr-product-workload", "uid-dapr-product-workload")
	seedDaprAssessmentInventory(t, store, cluster, []string{
		targetmodel.DaprApplicationRuntimeCapability,
		"strict-schema-dry-run",
	}, 94)
	trait, err := store.CreateCapabilityTrait(ctx, controlplane.CapabilityTrait{
		ProjectID: project.ID, Name: "dapr-runtime", Version: "1.0.0", Kind: "sidecar",
		Capability: controlplane.ApplicationRuntimeDaprCapability,
		InputSchemaDigest: daprAPITestDigest("d"), NativeSuppression: true,
	}, "owner")
	if err != nil { t.Fatal(err) }

	srv := scopedServer(t, store)
	lock := daprAPITestRuntimeLock(t)
	if err = srv.ConfigureDaprRuntimeLock(lock, "https://zot.internal.example"); err != nil { t.Fatal(err) }
	executorAuthority, err := daprruntime.ExecutorAuthorityFromRuntimeLock(lock)
	if err != nil { t.Fatal(err) }
	if err = srv.ConfigureDaprExecutorAuthority(executorAuthority, "https://zot.internal.example", executorAuthority.SourceReleaseDigest); err != nil { t.Fatal(err) }
	lockDigest, err := daprruntime.RuntimeLockDigest(lock)
	if err != nil { t.Fatal(err) }
	seedProductManagedDaprObserved(t, store, project.ID, cluster.ID, lockDigest)

	request, admission, err := srv.buildDaprWorkloadAdmissionRequest(ctx, daprWorkloadAdmissionInput{
		ProjectID: project.ID, ClusterID: cluster.ID, TraitID: trait.ID,
		WorkloadImage: "zot.internal.example/apps/payments@" + daprAPITestDigest("e"),
		Namespace: "payments", AppID: "payments-api",
		CPURequest: "100m", CPULimit: "500m", MemoryRequest: "128Mi", MemoryLimit: "256Mi",
		EnableInvocation: true,
	})
	if err != nil { t.Fatal(err) }
	if admission.Mode != "PRODUCT_MANAGED" || request.RuntimeMode != "PRODUCT_MANAGED" ||
		request.RuntimeLockDigest != lockDigest ||
		request.ExpectedSidecarImage != daprRuntimeImageByRole(lock, "sidecar") {
		t.Fatalf("product-managed Dapr workload lost exact runtime ownership admission=%#v request=%#v", admission, request)
	}
	if err = srv.validateDaprWorkloadAdmissionCurrentAuthority(ctx, request); err != nil {
		t.Fatalf("current product-managed Dapr workload authority rejected: %v", err)
	}
}

func TestDaprStandaloneExecutorAuthorityRejectsForeignRelease(t *testing.T) {
	store := controlplane.NewMemoryStore()
	srv := scopedServer(t, store)
	lock := daprAPITestRuntimeLock(t)
	authority, err := daprruntime.ExecutorAuthorityFromRuntimeLock(lock)
	if err != nil { t.Fatal(err) }
	if err = srv.ConfigureDaprExecutorAuthority(authority, "https://zot.internal.example", daprAPITestDigest("9")); err == nil ||
		!strings.Contains(err.Error(), "SOURCE_RELEASE_MISMATCH") {
		t.Fatalf("foreign exact release accepted for standalone Dapr executor: %v", err)
	}
	if err = srv.ConfigureDaprExecutorAuthority(authority, "https://zot.internal.example", authority.SourceReleaseDigest); err != nil {
		t.Fatalf("matching exact release rejected for standalone Dapr executor: %v", err)
	}
}

func TestDaprWorkloadAdmissionCurrentAuthorityRejectsInventoryDrift(t *testing.T) {
	store := controlplane.NewMemoryStore()
	ctx := context.Background()
	org, _ := store.CreateOrganization(ctx, controlplane.Organization{Name: "dapr-admission-current", DisplayName: "Dapr Admission Current"}, "owner")
	project, _ := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "apps", DisplayName: "Apps"}, "owner")
	cluster := workspaceAPICluster(t, store, project.ID, "dapr-native-current", "uid-dapr-native-current")
	seedDaprAssessmentInventory(t, store, cluster, []string{
		targetmodel.DaprApplicationRuntimeCapability,
		"strict-schema-dry-run",
	}, 92)
	trait, err := store.CreateCapabilityTrait(ctx, controlplane.CapabilityTrait{
		ProjectID: project.ID, Name: "dapr-runtime", Version: "1.0.0", Kind: "sidecar",
		Capability: controlplane.ApplicationRuntimeDaprCapability,
		InputSchemaDigest: daprAPITestDigest("b"), NativeSuppression: true,
	}, "owner")
	if err != nil { t.Fatal(err) }
	srv := scopedServer(t, store)
	lock := daprAPITestRuntimeLock(t)
	executorAuthority, err := daprruntime.ExecutorAuthorityFromRuntimeLock(lock)
	if err != nil { t.Fatal(err) }
	if err = srv.ConfigureDaprExecutorAuthority(executorAuthority, "https://zot.internal.example", executorAuthority.SourceReleaseDigest); err != nil { t.Fatal(err) }

	request, _, err := srv.buildDaprWorkloadAdmissionRequest(ctx, daprWorkloadAdmissionInput{
		ProjectID: project.ID, ClusterID: cluster.ID, TraitID: trait.ID,
		WorkloadImage: "zot.internal.example/apps/payments@" + daprAPITestDigest("c"),
		Namespace: "payments", AppID: "payments-api",
		CPURequest: "100m", CPULimit: "500m", MemoryRequest: "128Mi", MemoryLimit: "256Mi",
		EnableInvocation: true,
	})
	if err != nil { t.Fatal(err) }
	if err = srv.validateDaprWorkloadAdmissionCurrentAuthority(ctx, request); err != nil {
		t.Fatalf("fresh native Dapr workload authority rejected: %v", err)
	}

	seedDaprAssessmentInventory(t, store, cluster, []string{
		targetmodel.DaprApplicationRuntimeCapability,
		"strict-schema-dry-run",
	}, 93)
	if err = srv.validateDaprWorkloadAdmissionCurrentAuthority(ctx, request); err == nil ||
		!strings.Contains(err.Error(), "inventory fence changed") {
		t.Fatalf("stale Dapr workload admission remained current after inventory drift: %v", err)
	}
}

func TestDaprWorkloadAdmissionFailsClosedWithoutStrictTargetDryRunCapability(t *testing.T) {
	store := controlplane.NewMemoryStore()
	ctx := context.Background()
	org, _ := store.CreateOrganization(ctx, controlplane.Organization{Name: "dapr-admission-fence", DisplayName: "Dapr Admission Fence"}, "owner")
	project, _ := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "apps", DisplayName: "Apps"}, "owner")
	cluster := workspaceAPICluster(t, store, project.ID, "dapr-native-no-dryrun", "uid-dapr-native-no-dryrun")
	seedDaprAssessmentInventory(t, store, cluster, []string{targetmodel.DaprApplicationRuntimeCapability}, 91)
	trait, err := store.CreateCapabilityTrait(ctx, controlplane.CapabilityTrait{
		ProjectID: project.ID, Name: "dapr-runtime", Version: "1.0.0", Kind: "sidecar",
		Capability: controlplane.ApplicationRuntimeDaprCapability,
		InputSchemaDigest: daprAPITestDigest("9"), NativeSuppression: true,
	}, "owner")
	if err != nil { t.Fatal(err) }
	srv := scopedServer(t, store)
	lock := daprAPITestRuntimeLock(t)
	executorAuthority, err := daprruntime.ExecutorAuthorityFromRuntimeLock(lock)
	if err != nil { t.Fatal(err) }
	if err = srv.ConfigureDaprExecutorAuthority(executorAuthority, "https://zot.internal.example", executorAuthority.SourceReleaseDigest); err != nil { t.Fatal(err) }

	_, _, err = srv.buildDaprWorkloadAdmissionRequest(ctx, daprWorkloadAdmissionInput{
		ProjectID: project.ID, ClusterID: cluster.ID, TraitID: trait.ID,
		WorkloadImage: "zot.internal.example/apps/payments@" + daprAPITestDigest("a"),
		Namespace: "payments", AppID: "payments-api",
		CPURequest: "100m", CPULimit: "500m", MemoryRequest: "128Mi", MemoryLimit: "256Mi",
		EnableInvocation: true,
	})
	if err == nil || !strings.Contains(err.Error(), "strict schema dry-run") {
		t.Fatalf("Dapr workload admission bypassed target dry-run capability: %v", err)
	}
	ops, listErr := store.ListOperations(ctx, project.ID)
	if listErr != nil { t.Fatal(listErr) }
	if len(ops) != 0 {
		t.Fatalf("failed Dapr workload admission created durable work: %#v", ops)
	}
}
