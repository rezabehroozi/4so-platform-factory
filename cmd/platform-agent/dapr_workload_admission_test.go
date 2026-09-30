package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	daprruntime "platform.4so.io/factory/internal/dapr"
	"platform.4so.io/factory/internal/targetmodel"
)

func daprWorkloadAdmissionAgentTask(t *testing.T) agentDaprWorkloadAdmissionTask {
	t.Helper()
	lock := daprAgentTestLock(t)
	lockDigest, err := daprruntime.RuntimeLockDigest(lock)
	if err != nil { t.Fatal(err) }
	plan, err := targetmodel.ResolveDaprWorkloadRuntimePlan(targetmodel.DaprWorkloadPlanInput{
		Namespace: "payments", AppID: "payments-api", AppPort: 8080, AppProtocol: "http",
		CPURequest: "100m", CPULimit: "500m", MemoryRequest: "128Mi", MemoryLimit: "256Mi",
		EnableInvocation: true,
	})
	if err != nil { t.Fatal(err) }
	planDigest, err := daprruntime.WorkloadPlanDigest(plan)
	if err != nil { t.Fatal(err) }
	sidecar := ""
	for _, image := range lock.ImageLocks {
		if image.Role == "sidecar" { sidecar = image.MirrorReference }
	}
	request := daprruntime.WorkloadAdmissionRequest{
		Authority: daprruntime.WorkloadAdmissionAuthority,
		ProjectID: "prj_test", ClusterID: "clu_test", TraitID: "trait_test",
		TraitDigest: daprAgentTestDigest("7"), InventoryDigest: daprAgentTestDigest("8"),
		RuntimeMode: "PRODUCT_MANAGED", RuntimeLockDigest: lockDigest,
		ExpectedSidecarImage: sidecar, ExecutorImageReference: lock.ExecutorImageReference,
		WorkloadImage: "zot.internal.example/apps/payments@" + daprAgentTestDigest("9"),
		Plan: plan, PlanDigest: planDigest,
	}
	request, err = daprruntime.CanonicalWorkloadAdmissionRequest(request)
	if err != nil { t.Fatal(err) }
	return agentDaprWorkloadAdmissionTask{
		OperationID: "op_dapr_admission", OperationRevision: 7, TaskFenceToken: 13,
		LeaseExpiresAt: time.Now().UTC().Add(5 * time.Minute),
		Request: request, RuntimeLock: lock,
	}
}

func TestDaprWorkloadAdmissionJobUsesExactExecutorAndDedicatedPrincipal(t *testing.T) {
	task := daprWorkloadAdmissionAgentTask(t)
	a := &agent{clusterID: task.Request.ClusterID}
	if _, ok, err := a.nextDaprWorkloadAdmissionTaskValidation(task); err != nil || !ok {
		t.Fatalf("valid Dapr workload admission task rejected: ok=%v err=%v", ok, err)
	}
	job, err := daprWorkloadAdmissionJob(task, "4so-platform-agent")
	if err != nil { t.Fatal(err) }
	if err = daprWorkloadAdmissionJobOwnership(job, task, "4so-platform-agent"); err != nil {
		t.Fatalf("exact Dapr workload admission Job rejected: %v", err)
	}
	raw, err := json.Marshal(job)
	if err != nil { t.Fatal(err) }
	rendered := string(raw)
	for _, want := range []string{
		`"serviceAccountName":"4so-dapr-executor"`,
		`"image":"` + task.Request.ExecutorImageReference + `"`,
		`"args":["workload-admission"]`,
		`"name":"FOURSO_DAPR_WORKLOAD_OPERATION_ID","value":"` + task.OperationID + `"`,
		`"allowPrivilegeEscalation":false`,
		`"readOnlyRootFilesystem":true`,
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("Dapr workload admission Job missing boundary %q: %s", want, rendered)
		}
	}
	if strings.Contains(rendered, `"kind":"Deployment"`) || strings.Contains(rendered, "dryRun=All") {
		t.Fatalf("Agent Job embedded direct workload mutation instead of delegating dry-run to exact executor: %s", rendered)
	}
}

func TestDaprWorkloadAdmissionJobOwnershipRejectsImageFenceAndClusterDrift(t *testing.T) {
	task := daprWorkloadAdmissionAgentTask(t)
	job, err := daprWorkloadAdmissionJob(task, "4so-platform-agent")
	if err != nil { t.Fatal(err) }
	spec := job["spec"].(map[string]any)
	template := spec["template"].(map[string]any)
	pod := template["spec"].(map[string]any)
	container := pod["containers"].([]any)[0].(map[string]any)
	container["image"] = "zot.internal.example/4so/dapr-runtime@" + daprAgentTestDigest("0")
	if err = daprWorkloadAdmissionJobOwnership(job, task, "4so-platform-agent"); err == nil || !strings.Contains(err.Error(), "image") {
		t.Fatalf("Dapr workload executor image substitution accepted: %v", err)
	}

	job, err = daprWorkloadAdmissionJob(task, "4so-platform-agent")
	if err != nil { t.Fatal(err) }
	meta := job["metadata"].(map[string]any)
	annotations := meta["annotations"].(map[string]any)
	annotations["platform.4so.io/cluster-id"] = "clu_foreign"
	if err = daprWorkloadAdmissionJobOwnership(job, task, "4so-platform-agent"); err == nil || !strings.Contains(err.Error(), "cluster-id") {
		t.Fatalf("Dapr workload admission foreign cluster ownership accepted: %v", err)
	}
}

func TestDaprWorkloadAdmissionTaskRejectsRuntimeAndExecutorSubstitution(t *testing.T) {
	task := daprWorkloadAdmissionAgentTask(t)
	a := &agent{clusterID: task.Request.ClusterID}
	task.Request.ExecutorImageReference = "zot.internal.example/4so/dapr-runtime@" + daprAgentTestDigest("0")
	if _, ok, err := a.nextDaprWorkloadAdmissionTaskValidation(task); err == nil || ok {
		t.Fatalf("foreign Dapr executor image entered admission task: ok=%v err=%v", ok, err)
	}
	task = daprWorkloadAdmissionAgentTask(t)
	task.Request.RuntimeLockDigest = daprAgentTestDigest("0")
	if _, ok, err := a.nextDaprWorkloadAdmissionTaskValidation(task); err == nil || ok {
		t.Fatalf("foreign Dapr runtime lock entered product-managed admission task: ok=%v err=%v", ok, err)
	}
}
