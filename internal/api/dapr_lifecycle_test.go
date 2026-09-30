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

func daprAPITestDigest(ch string) string {
	return "sha256:" + strings.Repeat(ch, 64)
}

func daprAPITestRuntimeLock(t *testing.T) daprruntime.RuntimeLock {
	t.Helper()
	plan := targetmodel.DaprRuntimeSourcePlanModel()
	chars := []string{"a", "b", "c", "d"}
	images := make([]targetmodel.DaprRuntimeImageLock, 0, len(plan.RequiredImages))
	for i, image := range plan.RequiredImages {
		digest := daprAPITestDigest(chars[i])
		images = append(images, targetmodel.DaprRuntimeImageLock{
			Role: image.Role,
			SourceRepository: image.Repository,
			SourceDigest: digest,
			MirrorReference: "zot.internal.example/dapr/" + image.Role + "@" + digest,
			MirrorDigest: digest,
		})
	}
	lock := daprruntime.RuntimeLock{
		Authority: targetmodel.DaprRuntimeSupplyChainAuthority,
		SourcePlanAuthority: plan.Authority,
		Version: plan.Version,
		UpstreamRepository: plan.UpstreamRepository,
		UpstreamRef: plan.UpstreamRef,
		UpstreamCommit: plan.UpstreamCommit,
		SourceArchiveDigest: daprAPITestDigest("e"),
		HelmChartDigest: daprAPITestDigest("f"),
		HelmPackageDigest: daprAPITestDigest("0"),
		HelmRenderDigest: daprAPITestDigest("1"),
		HelmMirrorReference: "zot.internal.example/dapr-charts/dapr@" + daprAPITestDigest("4"),
		HelmMirrorManifestDigest: daprAPITestDigest("4"),
		AcquisitionReceiptDigest: daprAPITestDigest("2"),
		MirrorEvidenceDigest: daprAPITestDigest("3"),
		ExecutorEvidenceDigest: daprAPITestDigest("5"),
		ExecutorImageReference: "zot.internal.example/4so/dapr-runtime@" + daprAPITestDigest("6"),
		ExecutorImageDigest: daprAPITestDigest("6"),
		RegistryAuthority: "zot",
		RegistryScheme: "https",
		MirrorRegistry: "zot.internal.example",
		ImageLocks: images,
		ZotMirrorVerified: true,
		OfflineReplayReady: true,
		Admitted: true,
	}
	if err := daprruntime.ValidateRuntimeLock(lock); err != nil {
		t.Fatalf("fixture Dapr runtime lock invalid: %v", err)
	}
	return lock
}

type daprLifecycleCreateResponse struct {
	Authority        string                       `json:"authority"`
	Operation        controlplane.Operation       `json:"operation"`
	Request          daprruntime.LifecycleRequest `json:"request"`
	IdempotentReplay bool                         `json:"idempotentReplay"`
}

func TestDaprLifecycleCreateIsApprovalGatedAndIdempotent(t *testing.T) {
	store := controlplane.NewMemoryStore()
	ctx := context.Background()
	org, _ := store.CreateOrganization(ctx, controlplane.Organization{Name: "dapr-life", DisplayName: "Dapr Lifecycle"}, "owner")
	project, _ := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "apps", DisplayName: "Apps"}, "owner")
	cluster := workspaceAPICluster(t, store, project.ID, "dapr-managed", "uid-dapr-managed")
	seedDaprAssessmentInventory(t, store, cluster, nil, 20)

	srv := scopedServer(t, store)
	lock := daprAPITestRuntimeLock(t)
	if err := srv.ConfigureDaprRuntimeLock(lock, "https://zot.internal.example"); err != nil {
		t.Fatal(err)
	}
	lockDigest, err := daprruntime.RuntimeLockDigest(lock)
	if err != nil {
		t.Fatal(err)
	}

	body := fmt.Sprintf(`{"projectId":%q,"clusterId":%q,"action":"INSTALL","disconnected":false}`, project.ID, cluster.ID)
	headers := map[string]string{"Idempotency-Key": "dapr-install-1", "X-Request-ID": "req-dapr-install-1"}
	w := applicationPlatformRequest(t, srv, http.MethodPost, "/api/v1/application-platform/dapr/lifecycle", body, "owner", headers)
	if w.Code != http.StatusAccepted {
		t.Fatalf("Dapr lifecycle create=%d %s", w.Code, w.Body.String())
	}
	first := decodeApplicationResponse[daprLifecycleCreateResponse](t, w)
	if first.Authority != daprruntime.LifecycleAuthority || first.Operation.State != controlplane.OperationAwaitingApproval ||
		first.Operation.Kind != daprLifecycleOperationKind || first.Operation.Class != controlplane.OperationClassMutating ||
		first.Request.RuntimeLockDigest != lockDigest || first.Request.Action != daprruntime.ActionInstall || first.IdempotentReplay {
		t.Fatalf("Dapr lifecycle was not sealed behind independent durable approval: %#v", first)
	}

	w = applicationPlatformRequest(t, srv, http.MethodPost, "/api/v1/application-platform/dapr/lifecycle", body, "owner", headers)
	if w.Code != http.StatusOK {
		t.Fatalf("Dapr lifecycle replay=%d %s", w.Code, w.Body.String())
	}
	replay := decodeApplicationResponse[daprLifecycleCreateResponse](t, w)
	if !replay.IdempotentReplay || replay.Operation.ID != first.Operation.ID ||
		replay.Operation.State != controlplane.OperationAwaitingApproval {
		t.Fatalf("Dapr lifecycle idempotency drift: first=%#v replay=%#v", first.Operation, replay.Operation)
	}
}

func TestDaprLifecycleNeverMutatesTargetNativeRuntime(t *testing.T) {
	store := controlplane.NewMemoryStore()
	ctx := context.Background()
	org, _ := store.CreateOrganization(ctx, controlplane.Organization{Name: "dapr-native-life", DisplayName: "Dapr Native Lifecycle"}, "owner")
	project, _ := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "apps", DisplayName: "Apps"}, "owner")
	cluster := workspaceAPICluster(t, store, project.ID, "dapr-native", "uid-dapr-native-life")
	seedDaprAssessmentInventory(t, store, cluster, []string{targetmodel.DaprApplicationRuntimeCapability}, 21)

	srv := scopedServer(t, store)
	if err := srv.ConfigureDaprRuntimeLock(daprAPITestRuntimeLock(t), "https://zot.internal.example"); err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(`{"projectId":%q,"clusterId":%q,"action":"INSTALL"}`, project.ID, cluster.ID)
	w := applicationPlatformRequest(t, srv, http.MethodPost, "/api/v1/application-platform/dapr/lifecycle", body, "owner",
		map[string]string{"Idempotency-Key": "dapr-native-install"})
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "DAPR_NATIVE_RUNTIME_NOT_PRODUCT_MANAGED") {
		t.Fatalf("target-native Dapr entered product mutation lifecycle: %d %s", w.Code, w.Body.String())
	}
	ops, err := store.ListOperations(ctx, project.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(ops) != 0 {
		t.Fatalf("native Dapr lifecycle created durable mutation despite suppression: %#v", ops)
	}
}
