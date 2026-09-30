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

	w = applicationPlatformRequest(t, srv, http.MethodPost, "/api/v1/application-platform/dapr/lifecycle", body, "owner",
		map[string]string{"Idempotency-Key": "dapr-install-2", "X-Request-ID": "req-dapr-install-2"})
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "DAPR_LIFECYCLE_RECOVERY_OR_OPERATION_PENDING") {
		t.Fatalf("parallel Dapr lifecycle mutation was admitted: %d %s", w.Code, w.Body.String())
	}
	ops, err := store.ListOperations(ctx, project.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(ops) != 1 || ops[0].ID != first.Operation.ID {
		t.Fatalf("parallel Dapr lifecycle request created extra operation: %#v", ops)
	}
}

func TestDaprLifecycleApprovalRevalidatesNativeCapabilityDrift(t *testing.T) {
	store := controlplane.NewMemoryStore()
	ctx := context.Background()
	org, _ := store.CreateOrganization(ctx, controlplane.Organization{Name: "dapr-approval-drift", DisplayName: "Dapr Approval Drift"}, "owner")
	project, _ := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "apps", DisplayName: "Apps"}, "owner")
	if _, err := store.UpsertOrganizationMembership(ctx, controlplane.OrganizationMembership{
		OrganizationID: org.ID, Subject: "approver", Role: controlplane.OrganizationAdmin,
	}, 0, "owner"); err != nil {
		t.Fatal(err)
	}
	cluster := workspaceAPICluster(t, store, project.ID, "dapr-approval-target", "uid-dapr-approval-target")
	seedDaprAssessmentInventory(t, store, cluster, nil, 30)

	srv := scopedServer(t, store)
	if err := srv.ConfigureDaprRuntimeLock(daprAPITestRuntimeLock(t), "https://zot.internal.example"); err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(`{"projectId":%q,"clusterId":%q,"action":"INSTALL"}`, project.ID, cluster.ID)
	w := applicationPlatformRequest(t, srv, http.MethodPost, "/api/v1/application-platform/dapr/lifecycle", body, "owner",
		map[string]string{"Idempotency-Key": "dapr-approval-drift"})
	if w.Code != http.StatusAccepted {
		t.Fatalf("Dapr lifecycle create=%d %s", w.Code, w.Body.String())
	}
	created := decodeApplicationResponse[daprLifecycleCreateResponse](t, w)

	// A current inventory update says Dapr is now native. The previously prepared
	// product-managed install must not pass approval against stale admission.
	seedDaprAssessmentInventory(t, store, cluster, []string{targetmodel.DaprApplicationRuntimeCapability}, 31)
	w = applicationPlatformRequest(t, srv, http.MethodPost,
		"/api/v1/application-platform/dapr/lifecycle/"+created.Operation.ID+"/approve", "", "approver",
		map[string]string{"If-Match": fmt.Sprintf("%d", created.Operation.Revision)})
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "DAPR_NATIVE_RUNTIME_NOT_PRODUCT_MANAGED") {
		t.Fatalf("Dapr approval ignored native-capability drift: %d %s", w.Code, w.Body.String())
	}
	current, err := store.GetOperation(ctx, created.Operation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.State != controlplane.OperationAwaitingApproval {
		t.Fatalf("Dapr operation mutated despite approval-time admission drift: %#v", current)
	}
}

func TestDaprLifecycleStateBlocksUnknownRecoveryAndInFlightMutation(t *testing.T) {
	for _, state := range []controlplane.OperationState{
		controlplane.OperationAwaitingApproval, controlplane.OperationQueued, controlplane.OperationRunning,
		controlplane.OperationRetryWait, controlplane.OperationVerifying, controlplane.OperationNeedsOperator,
		controlplane.OperationRollbackFailed,
	} {
		if !daprLifecycleStateBlocksNewMutation(controlplane.Operation{State: state}) {
			t.Fatalf("Dapr state %s did not fence a new mutation", state)
		}
	}
	if !daprLifecycleStateBlocksNewMutation(controlplane.Operation{State: controlplane.OperationFailed, LastFailureClass: controlplane.OperationFailureUnknown}) {
		t.Fatal("unknown Dapr failure did not fence a new mutation")
	}
	for _, op := range []controlplane.Operation{
		{State: controlplane.OperationSucceeded},
		{State: controlplane.OperationCancelled},
		{State: controlplane.OperationRolledBack},
		{State: controlplane.OperationFailed, LastFailureClass: controlplane.OperationFailurePermanent},
	} {
		if daprLifecycleStateBlocksNewMutation(op) {
			t.Fatalf("terminal/converged Dapr state unexpectedly fenced a new mutation: %#v", op)
		}
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


func TestDaprUnknownOutcomeRecoveryRestoresObservedAuthorityFromSealedPayload(t *testing.T) {
	store := controlplane.NewMemoryStore()
	ctx := context.Background()
	org, _ := store.CreateOrganization(ctx, controlplane.Organization{Name: "dapr-recovery", DisplayName: "Dapr Recovery"}, "owner")
	project, _ := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "apps", DisplayName: "Apps"}, "owner")
	cluster := workspaceAPICluster(t, store, project.ID, "dapr-recovery-target", "uid-dapr-recovery")
	seedDaprAssessmentInventory(t, store, cluster, nil, 60)
	srv := scopedServer(t, store)
	lock := daprAPITestRuntimeLock(t)
	if err := srv.ConfigureDaprRuntimeLock(lock, "https://zot.internal.example"); err != nil { t.Fatal(err) }

	body := fmt.Sprintf(`{"projectId":%q,"clusterId":%q,"action":"INSTALL"}`, project.ID, cluster.ID)
	w := applicationPlatformRequest(t, srv, http.MethodPost, "/api/v1/application-platform/dapr/lifecycle", body, "owner",
		map[string]string{"Idempotency-Key": "dapr-recovery-install"})
	if w.Code != http.StatusAccepted { t.Fatalf("create=%d %s", w.Code, w.Body.String()) }
	created := decodeApplicationResponse[daprLifecycleCreateResponse](t, w)

	op, err := store.ApproveOperationAndQueue(ctx, created.Operation.ID, created.Operation.Revision, "approver")
	if err != nil { t.Fatal(err) }
	claim, err := store.ClaimOperation(ctx, op.ID, "agent:"+cluster.ID, time.Hour, time.Now().UTC())
	if err != nil { t.Fatal(err) }
	op, err = store.GetOperation(ctx, op.ID)
	if err != nil { t.Fatal(err) }
	op, err = store.StartOperationAttempt(ctx, op.ID, op.Revision, "agent:"+cluster.ID, claim.FenceToken, "agent:"+cluster.ID)
	if err != nil { t.Fatal(err) }
	op, err = store.ReportOperationFailure(ctx, op.ID, op.Revision, "agent:"+cluster.ID, claim.FenceToken, controlplane.OperationFailureReport{
		Class: controlplane.OperationFailureUnknown, Code: "DAPR_RECOVERY_REQUIRED", Message: "response lost after dispatch",
	}, "agent:"+cluster.ID)
	if err != nil || op.State != controlplane.OperationFailed || op.LastFailureClass != controlplane.OperationFailureUnknown {
		t.Fatalf("unknown failure fixture drift op=%+v err=%v", op, err)
	}

	task := daprRecoveryTask{OperationID: op.ID, OperationRevision: op.Revision, TaskFenceToken: op.FenceToken, Request: created.Request}
	result := daprRecoveryResult{
		ConfirmedSuccess: true, Installed: true,
		ObservedLockDigest: created.Request.RuntimeLockDigest,
		Version: created.Request.RuntimeVersion,
		UpstreamCommit: created.Request.UpstreamCommit,
		Phase: "Installed",
	}
	_, raw, digest, err := canonicalDaprRecoveryReadback(task, result)
	if err != nil { t.Fatal(err) }
	resolved, evidence, err := store.ResolveUnknownOperationOutcomeWithEvidence(ctx, op.ID, op.Revision,
		controlplane.OperationUnknownOutcomeConfirmedSuccess,
		controlplane.EvidenceMetadata{OperationID: op.ID, Kind: daprRecoveryEvidenceKind, MediaType: "application/json", Digest: digest},
		raw, "agent:"+cluster.ID)
	if err != nil { t.Fatal(err) }
	if resolved.State != controlplane.OperationSucceeded || resolved.RecoveryEvidenceDigest != evidence.Digest || !evidence.HasPayload {
		t.Fatalf("recovered operation/evidence drift op=%+v evidence=%+v", resolved, evidence)
	}
	observed, err := srv.latestDaprObserved(ctx, project.ID, cluster.ID)
	if err != nil { t.Fatal(err) }
	if observed == nil || !observed.Installed || observed.OperationID != op.ID ||
		observed.RuntimeLockDigest != created.Request.RuntimeLockDigest ||
		observed.Version != created.Request.RuntimeVersion || observed.UpstreamCommit != created.Request.UpstreamCommit ||
		observed.Phase != "RecoveredConfirmedSuccess" {
		t.Fatalf("recovered observed authority drift: %#v", observed)
	}
}

func TestCanonicalDaprRecoveryReadbackRejectsRuntimeSubstitution(t *testing.T) {
	task := daprRecoveryTask{
		OperationID: "op_recovery", OperationRevision: 9, TaskFenceToken: 12,
		Request: daprruntime.LifecycleRequest{
			ProjectID: "prj", ClusterID: "clu", Action: daprruntime.ActionUpgrade,
			RuntimeLockDigest: daprAPITestDigest("a"), RuntimeVersion: "v1.18.4",
			UpstreamCommit: targetmodel.DaprUpstreamCommit,
		},
	}
	good := daprRecoveryResult{
		ConfirmedSuccess: true, Installed: true, ObservedLockDigest: task.Request.RuntimeLockDigest,
		Version: task.Request.RuntimeVersion, UpstreamCommit: task.Request.UpstreamCommit, Phase: "Upgraded",
	}
	if _, raw, digest, err := canonicalDaprRecoveryReadback(task, good); err != nil || len(raw) == 0 || !strings.HasPrefix(digest, "sha256:") {
		t.Fatalf("exact recovery readback rejected digest=%q err=%v", digest, err)
	}
	bad := good
	bad.ObservedLockDigest = daprAPITestDigest("b")
	if _, _, _, err := canonicalDaprRecoveryReadback(task, bad); err == nil || !strings.Contains(err.Error(), "RUNTIME_IDENTITY_MISMATCH") {
		t.Fatalf("recovery runtime substitution accepted: %v", err)
	}
}
