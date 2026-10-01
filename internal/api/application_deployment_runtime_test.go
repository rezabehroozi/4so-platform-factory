package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"platform.4so.io/factory/internal/auth"
	"platform.4so.io/factory/internal/controlplane"
)

type applicationDeploymentCreateResponse struct {
	Authority        string                                    `json:"authority"`
	Operation        controlplane.Operation                    `json:"operation"`
	Request          controlplane.ApplicationDeploymentRequest `json:"request"`
	IdempotentReplay bool                                      `json:"idempotentReplay"`
}

func applicationDeploymentPrincipalRequest(t *testing.T, s *Server, method, path, body, subject string, roles []string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	if body != "" { req.Header.Set("Content-Type", "application/json") }
	for key, value := range headers { req.Header.Set(key, value) }
	req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{Subject: subject, Roles: roles, Expires: time.Now().Add(time.Hour).Unix()}))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	return w
}

func applicationDeploymentAgentRequest(t *testing.T, s *Server, method, path, body, token string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+token)
	if body != "" { req.Header.Set("Content-Type", "application/json") }
	for key, value := range headers { req.Header.Set(key, value) }
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	return w
}

func TestApplicationDeploymentDurableAuthorityProducesDeliveryEvidence(t *testing.T) {
	store := controlplane.NewMemoryStore()
	ctx := context.Background()
	digest := func(ch string) string { return "sha256:" + strings.Repeat(ch, 64) }
	org, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "app-deploy", DisplayName: "Application Deploy"}, "bootstrap")
	if err != nil { t.Fatal(err) }
	project, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "payments", DisplayName: "Payments"}, "bootstrap")
	if err != nil { t.Fatal(err) }
	policy, err := store.CreatePlatformPolicySet(ctx, controlplane.PlatformPolicySet{
		ProjectID: project.ID, Name: "production", Version: "1.0.0",
		Maintenance: controlplane.PlatformMaintenancePolicy{RiskClass: "PRODUCTION", RequireApproval: true, MaxUnavailable: 1, RequireRecoveryCheckpoint: true},
		Backup: controlplane.PlatformBackupPolicy{Required: true, Provider: "s3", Schedule: "0 2 * * *", Retention: "30d"},
		Security: controlplane.PlatformSecurityPolicy{PodSecurityLevel: "restricted", DefaultDenyIngress: true, DefaultDenyEgress: true, AllowDNS: true},
	}, "bootstrap")
	if err != nil { t.Fatal(err) }

	cluster, agentToken, _ := seedAPICluster(t, store, project, "app-runtime", 481)
	cluster, inventory, err := upsertMutationReadyInventoryForAPITest(t, store, ctx, cluster.ID, credentialDigest(agentToken), cluster.ExternalUID, controlplane.ClusterInventory{
		ObservedAt: time.Now().UTC(), Distribution: "rke2", KubernetesVersion: "v1.34.2",
		Digest: digest("8"), APIDiscoveryComplete: true,
		Capabilities: []string{controlplane.TargetMutationRBACActiveCapability, controlplane.ApplicationDeploymentRBACCapability},
		Nodes: []controlplane.ClusterNode{{Name: "worker-1", UID: "node-1", Ready: true}},
	})
	if err != nil { t.Fatal(err) }
	if cluster.InventoryDigest != inventory.Digest {
		t.Fatalf("mutation-ready inventory authority drift: cluster=%s inventory=%s", cluster.InventoryDigest, inventory.Digest)
	}

	workspace, err := store.CreateWorkspace(ctx, controlplane.Workspace{ProjectID: project.ID, Name: "payments", DisplayName: "Payments"}, "bootstrap")
	if err != nil { t.Fatal(err) }
	workspaceBinding, err := store.CreateWorkspaceBinding(ctx, controlplane.WorkspaceBinding{WorkspaceID: workspace.ID, ClusterID: cluster.ID, Namespace: "payments"}, "bootstrap")
	if err != nil { t.Fatal(err) }
	workload, err := store.CreateWorkloadType(ctx, controlplane.WorkloadType{ProjectID: project.ID, Name: "service", Version: "1.0.0", InputSchemaDigest: digest("a")}, "bootstrap")
	if err != nil { t.Fatal(err) }
	profile, err := store.CreateWorkspaceProfile(ctx, controlplane.WorkspaceProfile{
		ProjectID: project.ID, Name: "production", Version: "1.0.0",
		AuthorityRefs: []controlplane.ApplicationAuthorityRef{{Kind: "policy-set", ID: policy.ID, Digest: policy.Digest}},
	}, "bootstrap")
	if err != nil { t.Fatal(err) }
	workloadImage := "zot.internal.example/apps/payments@" + digest("b")
	release, err := store.CreateApplicationRelease(ctx, controlplane.ApplicationReleaseCreateRequest{
		ProjectID: project.ID, Name: "payments", Version: "1.0.0", WorkloadTypeID: workload.ID,
		WorkspaceProfileID: profile.ID, WorkloadImageReference: workloadImage, SourceDigest: digest("c"),
	}, "bootstrap")
	if err != nil { t.Fatal(err) }
	binding, err := store.CreateEnvironmentBinding(ctx, controlplane.EnvironmentBindingCreateRequest{
		ReleaseID: release.ID, WorkspaceBindingID: workspaceBinding.ID, Environment: "production",
	}, "bootstrap")
	if err != nil { t.Fatal(err) }

	srv := scopedServer(t, store)
	runtimeBody := `{"replicas":2,"containerPort":8080,"servicePort":80,"cpuRequest":"100m","cpuLimit":"500m","memoryRequest":"128Mi","memoryLimit":"512Mi"}`
	headers := map[string]string{"Idempotency-Key": "application-deploy-1", "X-Request-ID": "req-application-deploy-1"}
	w := applicationDeploymentPrincipalRequest(t, srv, http.MethodPost,
		"/api/v1/application-platform/environment-bindings/"+binding.ID+"/deployments",
		runtimeBody, "requester", []string{"platform-operator"}, headers)
	if w.Code != http.StatusAccepted {
		t.Fatalf("application deploy create=%d %s", w.Code, w.Body.String())
	}
	created := decodeApplicationResponse[applicationDeploymentCreateResponse](t, w)
	if created.Authority != controlplane.ApplicationDeploymentRequestAuthority ||
		created.Operation.Kind != applicationDeploymentOperationKind ||
		created.Operation.State != controlplane.OperationAwaitingApproval ||
		created.Operation.Class != controlplane.OperationClassMutating ||
		created.Operation.DesiredRevision != release.Digest ||
		created.Request.InventoryDigest != inventory.Digest ||
		created.Request.Plan.RenderedDigest == "" || created.IdempotentReplay {
		t.Fatalf("application deployment request authority drift: %#v", created)
	}
	sealed, err := store.GetOperationRequestPayload(ctx, created.Operation.ID)
	if err != nil { t.Fatal(err) }
	if sealed.MediaType != controlplane.ApplicationDeploymentPayloadMediaType {
		t.Fatalf("application deployment payload media type drift: %#v", sealed)
	}

	w = applicationDeploymentPrincipalRequest(t, srv, http.MethodPost,
		"/api/v1/application-platform/deployments/"+created.Operation.ID+"/approve",
		"", "approver", []string{"platform-admin"}, map[string]string{"If-Match": fmt.Sprintf("%q", created.Operation.Revision)})
	if w.Code != http.StatusAccepted {
		t.Fatalf("application deploy approve=%d %s", w.Code, w.Body.String())
	}

	w = applicationDeploymentAgentRequest(t, srv, http.MethodGet,
		"/agent/v1/clusters/"+cluster.ID+"/application-deployment-tasks/next",
		"", agentToken, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("application deployment claim=%d %s", w.Code, w.Body.String())
	}
	var task applicationDeploymentTask
	if err = json.Unmarshal(w.Body.Bytes(), &task); err != nil { t.Fatal(err) }
	if task.OperationID != created.Operation.ID || task.TaskFenceToken <= 0 ||
		task.Request.Plan.ClusterID != cluster.ID || task.Request.Plan.WorkloadImageReference != workloadImage {
		t.Fatalf("application deployment task fence drift: %#v", task)
	}

	plan := task.Request.Plan
	evidence := controlplane.ApplicationDeploymentEvidence{
		Authority: controlplane.ApplicationDeploymentEvidenceAuthority,
		OperationID: task.OperationID, ProjectID: plan.ProjectID, ClusterID: plan.ClusterID, Namespace: plan.Namespace,
		EnvironmentBindingID: plan.EnvironmentBindingID, EnvironmentBindingRevision: plan.EnvironmentBindingRevision,
		ReleaseDigest: plan.ReleaseDigest, InventoryDigest: task.Request.InventoryDigest, RenderedDigest: plan.RenderedDigest,
		Readback: controlplane.ApplicationDeploymentReadback{
			DeploymentName: plan.WorkloadName, DeploymentUID: "uid-payments-deployment",
			Generation: 2, ObservedGeneration: 2, DesiredReplicas: 2, ReadyReplicas: 2,
			WorkloadImage: plan.WorkloadImageReference,
			CPURequest: plan.RuntimeSpec.CPURequest, CPULimit: plan.RuntimeSpec.CPULimit,
			MemoryRequest: plan.RuntimeSpec.MemoryRequest, MemoryLimit: plan.RuntimeSpec.MemoryLimit,
			ServiceObserved: true, ServiceName: plan.WorkloadName, ServiceClusterIP: "10.96.0.42",
			ServicePort: plan.RuntimeSpec.ServicePort, ServiceTargetPort: plan.RuntimeSpec.ContainerPort,
			AuthorityLabelsMatch: true, AuthorityDigestsMatch: true,
		},
		ObservedAt: time.Now().UTC().Format(time.RFC3339Nano),
		RuntimeMutationObserved: true, PhysicalCertificationInferred: false,
	}
	evidenceDigest, err := controlplane.ApplicationDeploymentEvidenceDigest(evidence, task.Request, task.OperationID)
	if err != nil { t.Fatal(err) }
	resultRaw, _ := json.Marshal(applicationDeploymentResult{
		Success: true, TaskFenceToken: task.TaskFenceToken, Evidence: &evidence, EvidenceDigest: evidenceDigest,
	})
	w = applicationDeploymentAgentRequest(t, srv, http.MethodPost,
		"/agent/v1/clusters/"+cluster.ID+"/application-deployment-tasks/"+task.OperationID+"/result",
		string(resultRaw), agentToken, map[string]string{"If-Match": fmt.Sprintf("%q", task.OperationRevision)})
	if w.Code != http.StatusOK {
		t.Fatalf("application deployment result=%d %s", w.Code, w.Body.String())
	}
	var result struct{ Operation controlplane.Operation `json:"operation"` }
	if err = json.Unmarshal(w.Body.Bytes(), &result); err != nil { t.Fatal(err) }
	if result.Operation.State != controlplane.OperationSucceeded {
		t.Fatalf("application deployment did not become terminal success: %#v", result.Operation)
	}

	w = applicationDeploymentPrincipalRequest(t, srv, http.MethodGet,
		"/api/v1/application-platform/deployments/"+task.OperationID,
		"", "requester", []string{"platform-viewer"}, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("application deployment get=%d %s", w.Code, w.Body.String())
	}
	var view struct {
		Operation controlplane.Operation `json:"operation"`
		Ready bool `json:"ready"`
		CurrentAuthority bool `json:"currentAuthority"`
		EvidenceDigest string `json:"evidenceDigest"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &view); err != nil { t.Fatal(err) }
	if !view.Ready || !view.CurrentAuthority || view.Operation.State != controlplane.OperationSucceeded || view.EvidenceDigest != evidenceDigest {
		t.Fatalf("application deployment terminal view drift: %#v", view)
	}

	operations, err := store.ListOperations(ctx, project.ID)
	if err != nil { t.Fatal(err) }
	delivery, err := projectApplicationDeliveryEvidence(project.ID, []controlplane.ApplicationRelease{release}, []controlplane.EnvironmentBinding{binding}, operations)
	if err != nil { t.Fatal(err) }
	if len(delivery) != 1 || delivery[0].EventType != "deployment_succeeded" || delivery[0].Revision != release.Digest {
		t.Fatalf("terminal application deployment did not project into delivery evidence: %#v", delivery)
	}

	unknownHeaders := map[string]string{"Idempotency-Key": "application-deploy-unknown-1", "X-Request-ID": "req-application-deploy-unknown-1"}
	w = applicationDeploymentPrincipalRequest(t, srv, http.MethodPost,
		"/api/v1/application-platform/environment-bindings/"+binding.ID+"/deployments",
		runtimeBody, "requester", []string{"platform-operator"}, unknownHeaders)
	if w.Code != http.StatusAccepted {
		t.Fatalf("application deploy unknown fixture create=%d %s", w.Code, w.Body.String())
	}
	unknownCreated := decodeApplicationResponse[applicationDeploymentCreateResponse](t, w)
	w = applicationDeploymentPrincipalRequest(t, srv, http.MethodPost,
		"/api/v1/application-platform/deployments/"+unknownCreated.Operation.ID+"/approve",
		"", "approver", []string{"platform-admin"}, map[string]string{"If-Match": fmt.Sprintf("%q", unknownCreated.Operation.Revision)})
	if w.Code != http.StatusAccepted {
		t.Fatalf("application deploy unknown fixture approve=%d %s", w.Code, w.Body.String())
	}
	w = applicationDeploymentAgentRequest(t, srv, http.MethodGet,
		"/agent/v1/clusters/"+cluster.ID+"/application-deployment-tasks/next", "", agentToken, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("application deploy unknown fixture claim=%d %s", w.Code, w.Body.String())
	}
	var unknownTask applicationDeploymentTask
	if err = json.Unmarshal(w.Body.Bytes(), &unknownTask); err != nil { t.Fatal(err) }
	unknownRaw, _ := json.Marshal(applicationDeploymentResult{
		RecoveryRequired: true, TaskFenceToken: unknownTask.TaskFenceToken,
		Error: "connection reset after target accepted mutation",
	})
	w = applicationDeploymentAgentRequest(t, srv, http.MethodPost,
		"/agent/v1/clusters/"+cluster.ID+"/application-deployment-tasks/"+unknownTask.OperationID+"/result",
		string(unknownRaw), agentToken, map[string]string{"If-Match": fmt.Sprintf("%q", unknownTask.OperationRevision)})
	if w.Code != http.StatusOK {
		t.Fatalf("application deploy unknown fixture result=%d %s", w.Code, w.Body.String())
	}
	var unknownResult struct{ Operation controlplane.Operation `json:"operation"` }
	if err = json.Unmarshal(w.Body.Bytes(), &unknownResult); err != nil { t.Fatal(err) }
	if unknownResult.Operation.State != controlplane.OperationFailed || unknownResult.Operation.LastFailureClass != controlplane.OperationFailureUnknown {
		t.Fatalf("ambiguous deployment did not become FAILED/UNKNOWN: %#v", unknownResult.Operation)
	}

	w = applicationDeploymentPrincipalRequest(t, srv, http.MethodPost,
		"/api/v1/application-platform/environment-bindings/"+binding.ID+"/deployments",
		runtimeBody, "requester", []string{"platform-operator"},
		map[string]string{"Idempotency-Key": "application-deploy-blocked-while-unknown"})
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "APPLICATION_DEPLOYMENT_RECOVERY_OR_OPERATION_PENDING") {
		t.Fatalf("new deployment was not fenced by FAILED/UNKNOWN predecessor: %d %s", w.Code, w.Body.String())
	}

	w = applicationDeploymentAgentRequest(t, srv, http.MethodGet,
		"/agent/v1/clusters/"+cluster.ID+"/application-deployment-recovery/next", "", agentToken, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("application deployment recovery task=%d %s", w.Code, w.Body.String())
	}
	var recoveryTask applicationDeploymentRecoveryTask
	if err = json.Unmarshal(w.Body.Bytes(), &recoveryTask); err != nil { t.Fatal(err) }
	if recoveryTask.OperationID != unknownTask.OperationID || recoveryTask.TaskFenceToken != unknownTask.TaskFenceToken {
		t.Fatalf("application deployment recovery fence drift: %#v", recoveryTask)
	}
	recoveryPlan := recoveryTask.Request.Plan
	recoveryEvidence := controlplane.ApplicationDeploymentEvidence{
		Authority: controlplane.ApplicationDeploymentEvidenceAuthority,
		OperationID: recoveryTask.OperationID, ProjectID: recoveryPlan.ProjectID, ClusterID: recoveryPlan.ClusterID, Namespace: recoveryPlan.Namespace,
		EnvironmentBindingID: recoveryPlan.EnvironmentBindingID, EnvironmentBindingRevision: recoveryPlan.EnvironmentBindingRevision,
		ReleaseDigest: recoveryPlan.ReleaseDigest, InventoryDigest: recoveryTask.Request.InventoryDigest, RenderedDigest: recoveryPlan.RenderedDigest,
		Readback: controlplane.ApplicationDeploymentReadback{
			DeploymentName: recoveryPlan.WorkloadName, DeploymentUID: "uid-payments-deployment-recovered",
			Generation: 3, ObservedGeneration: 3, DesiredReplicas: recoveryPlan.RuntimeSpec.Replicas, ReadyReplicas: recoveryPlan.RuntimeSpec.Replicas,
			WorkloadImage: recoveryPlan.WorkloadImageReference,
			CPURequest: recoveryPlan.RuntimeSpec.CPURequest, CPULimit: recoveryPlan.RuntimeSpec.CPULimit,
			MemoryRequest: recoveryPlan.RuntimeSpec.MemoryRequest, MemoryLimit: recoveryPlan.RuntimeSpec.MemoryLimit,
			ServiceObserved: true, ServiceName: recoveryPlan.WorkloadName, ServiceClusterIP: "10.96.0.43",
			ServicePort: recoveryPlan.RuntimeSpec.ServicePort, ServiceTargetPort: recoveryPlan.RuntimeSpec.ContainerPort,
			AuthorityLabelsMatch: true, AuthorityDigestsMatch: true,
		},
		ObservedAt: time.Now().UTC().Format(time.RFC3339Nano),
		RuntimeMutationObserved: true, PhysicalCertificationInferred: false,
	}
	recoveryDigest, err := controlplane.ApplicationDeploymentEvidenceDigest(recoveryEvidence, recoveryTask.Request, recoveryTask.OperationID)
	if err != nil { t.Fatal(err) }
	recoveryRaw, _ := json.Marshal(applicationDeploymentRecoveryResult{
		ConfirmedSuccess: true, Evidence: &recoveryEvidence, EvidenceDigest: recoveryDigest,
	})
	w = applicationDeploymentAgentRequest(t, srv, http.MethodPost,
		"/agent/v1/clusters/"+cluster.ID+"/application-deployment-recovery/"+recoveryTask.OperationID+"/result",
		string(recoveryRaw), agentToken, map[string]string{"If-Match": fmt.Sprintf("%q", recoveryTask.OperationRevision)})
	if w.Code != http.StatusOK {
		t.Fatalf("application deployment recovery result=%d %s", w.Code, w.Body.String())
	}
	var recovered struct{ Operation controlplane.Operation `json:"operation"`; EvidenceDigest string `json:"evidenceDigest"` }
	if err = json.Unmarshal(w.Body.Bytes(), &recovered); err != nil { t.Fatal(err) }
	if recovered.Operation.State != controlplane.OperationSucceeded || recovered.Operation.RecoveryEvidenceDigest != recoveryDigest || recovered.EvidenceDigest != recoveryDigest {
		t.Fatalf("application deployment recovery did not seal confirmed success: %#v", recovered)
	}

	w = applicationDeploymentPrincipalRequest(t, srv, http.MethodPost,
		"/api/v1/application-platform/environment-bindings/"+binding.ID+"/deployments",
		runtimeBody, "requester", []string{"platform-operator"},
		map[string]string{"Idempotency-Key": "application-deploy-after-recovery"})
	if w.Code != http.StatusAccepted {
		t.Fatalf("recovered deployment continued to fence a new explicit request: %d %s", w.Code, w.Body.String())
	}
}
