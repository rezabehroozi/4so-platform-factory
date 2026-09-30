package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	daprruntime "platform.4so.io/factory/internal/dapr"
	"platform.4so.io/factory/internal/targetmodel"
)

func daprAgentTestDigest(ch string) string {
	return "sha256:" + strings.Repeat(ch, 64)
}

func daprAgentTestLock(t *testing.T) daprruntime.RuntimeLock {
	t.Helper()
	plan := targetmodel.DaprRuntimeSourcePlanModel()
	chars := []string{"a", "b", "c", "d"}
	images := make([]targetmodel.DaprRuntimeImageLock, 0, len(plan.RequiredImages))
	for i, image := range plan.RequiredImages {
		digest := daprAgentTestDigest(chars[i])
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
		SourceArchiveDigest: daprAgentTestDigest("e"),
		HelmChartDigest: daprAgentTestDigest("f"),
		HelmPackageDigest: daprAgentTestDigest("0"),
		HelmRenderDigest: daprAgentTestDigest("1"),
		HelmMirrorReference: "zot.internal.example/dapr-charts/dapr@" + daprAgentTestDigest("4"),
		HelmMirrorManifestDigest: daprAgentTestDigest("4"),
		AcquisitionReceiptDigest: daprAgentTestDigest("2"),
		MirrorEvidenceDigest: daprAgentTestDigest("3"),
		ExecutorEvidenceDigest: daprAgentTestDigest("5"),
		ExecutorImageReference: "zot.internal.example/4so/dapr-runtime@" + daprAgentTestDigest("6"),
		ExecutorImageDigest: daprAgentTestDigest("6"),
		RegistryAuthority: "zot",
		RegistryScheme: "https",
		MirrorRegistry: "zot.internal.example",
		ImageLocks: images,
		ZotMirrorVerified: true,
		OfflineReplayReady: true,
		Admitted: true,
	}
	if err := daprruntime.ValidateRuntimeLock(lock); err != nil {
		t.Fatalf("fixture Dapr lock invalid: %v", err)
	}
	return lock
}

func daprAgentTestTask(t *testing.T) daprAgentTask {
	t.Helper()
	lock := daprAgentTestLock(t)
	digest, err := daprruntime.RuntimeLockDigest(lock)
	if err != nil {
		t.Fatal(err)
	}
	return daprAgentTask{
		OperationID: "op_dapr_test",
		OperationRevision: 7,
		TaskFenceToken: 11,
		LeaseExpiresAt: time.Now().UTC().Add(10 * time.Minute),
		Request: daprruntime.LifecycleRequest{
			ProjectID: "prj_test",
			ClusterID: "clu_test",
			Action: daprruntime.ActionInstall,
			RuntimeLockDigest: digest,
			RuntimeVersion: lock.Version,
			UpstreamCommit: lock.UpstreamCommit,
		},
		RuntimeLock: lock,
	}
}

func TestDaprAgentTaskAndJobAreExactLockAndFenceBound(t *testing.T) {
	task := daprAgentTestTask(t)
	if err := validateDaprAgentTask(task, "clu_test"); err != nil {
		t.Fatalf("valid Dapr task rejected: %v", err)
	}
	job, err := daprExecutorJob(task, "4so-platform-agent")
	if err != nil {
		t.Fatal(err)
	}
	if err = daprExecutorJobOwnership(job, task, "4so-platform-agent"); err != nil {
		t.Fatalf("own Dapr executor Job rejected: %v", err)
	}
	raw, err := json.Marshal(job)
	if err != nil {
		t.Fatal(err)
	}
	rendered := string(raw)
	for _, want := range []string{
		`"serviceAccountName":"4so-dapr-executor"`,
		`"image":"` + task.RuntimeLock.ExecutorImageReference + `"`,
		`"name":"FOURSO_DAPR_RUNTIME_LOCK_DIGEST","value":"` + task.Request.RuntimeLockDigest + `"`,
		`"name":"FOURSO_DAPR_OPERATION_ID","value":"` + task.OperationID + `"`,
		`"name":"FOURSO_DAPR_TASK_FENCE_TOKEN","value":"11"`,
		`"allowPrivilegeEscalation":false`,
		`"readOnlyRootFilesystem":true`,
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("Dapr executor Job missing exact runtime/fence boundary %q: %s", want, rendered)
		}
	}
}

func TestDaprExecutorJobOwnershipRejectsImageAndFenceDrift(t *testing.T) {
	task := daprAgentTestTask(t)
	job, err := daprExecutorJob(task, "4so-platform-agent")
	if err != nil {
		t.Fatal(err)
	}
	spec := job["spec"].(map[string]any)
	template := spec["template"].(map[string]any)
	pod := template["spec"].(map[string]any)
	containers := pod["containers"].([]any)
	container := containers[0].(map[string]any)
	container["image"] = "zot.internal.example/4so/dapr-runtime@" + daprAgentTestDigest("9")
	if err = daprExecutorJobOwnership(job, task, "4so-platform-agent"); err == nil || !strings.Contains(err.Error(), "image") {
		t.Fatalf("Dapr executor image substitution accepted: %v", err)
	}

	job, err = daprExecutorJob(task, "4so-platform-agent")
	if err != nil {
		t.Fatal(err)
	}
	meta := job["metadata"].(map[string]any)
	annotations := meta["annotations"].(map[string]any)
	annotations["platform.4so.io/task-fence-token"] = "12"
	if err = daprExecutorJobOwnership(job, task, "4so-platform-agent"); err == nil || !strings.Contains(err.Error(), "task-fence-token") {
		t.Fatalf("Dapr executor fence substitution accepted: %v", err)
	}
}

func TestDaprAgentTaskRejectsSealedRuntimeIdentityDrift(t *testing.T) {
	task := daprAgentTestTask(t)
	task.Request.RuntimeVersion = "v1.18.3"
	if err := validateDaprAgentTask(task, "clu_test"); err == nil || !strings.Contains(err.Error(), "runtime identity") {
		t.Fatalf("Dapr runtime version drift accepted: %v", err)
	}
	task = daprAgentTestTask(t)
	task.Request.UpstreamCommit = strings.Repeat("f", 40)
	if err := validateDaprAgentTask(task, "clu_test"); err == nil || !strings.Contains(err.Error(), "runtime identity") {
		t.Fatalf("Dapr upstream commit drift accepted: %v", err)
	}
}

func TestDaprAgentTaskRejectsExpiredLeaseAndLockDrift(t *testing.T) {
	task := daprAgentTestTask(t)
	task.LeaseExpiresAt = time.Now().UTC().Add(-time.Second)
	if err := validateDaprAgentTask(task, "clu_test"); err == nil {
		t.Fatal("expired Dapr task lease was accepted")
	}
	task = daprAgentTestTask(t)
	task.Request.RuntimeLockDigest = daprAgentTestDigest("8")
	if err := validateDaprAgentTask(task, "clu_test"); err == nil || !strings.Contains(err.Error(), "does not match sealed lifecycle request") {
		t.Fatalf("Dapr lock-digest drift was accepted: %v", err)
	}
}
