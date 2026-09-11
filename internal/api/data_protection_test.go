package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"platform.4so.io/factory/catalog"
	"platform.4so.io/factory/internal/controlplane"
)

func TestDataProtectionAPIBackupRestoreApprovalAndAgentFence(t *testing.T) {
	store := controlplane.NewMemoryStore()
	ctx := context.Background()
	org, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "dp-org", DisplayName: "DP Org"}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "dp-project", DisplayName: "DP Project"}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	cluster, agentToken, _ := seedAPICluster(t, store, project, "dp-target", 71)
	cluster, _, err = upsertMutationReadyInventoryForAPITest(t, store, ctx, cluster.ID, credentialDigest(agentToken), cluster.ExternalUID, controlplane.ClusterInventory{ObservedAt: time.Now(), Distribution: "rke2", KubernetesVersion: "1.33.1", Digest: fmt.Sprintf("sha256:%064x", 7171), Capabilities: []string{controlplane.TargetMutationRBACActiveCapability, controlplane.DataProtectionAgentCapability}, Nodes: []controlplane.ClusterNode{{Name: "worker-1", UID: "dp-node-1", Ready: true}}})
	if err != nil {
		t.Fatal(err)
	}
	components, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	s := New("test", components, slog.New(slog.NewTextHandler(io.Discard, nil)), store)
	h := s.Handler()

	policyBody, _ := json.Marshal(map[string]any{"projectId": project.ID, "clusterId": cluster.ID, "name": "critical", "provider": "velero", "backupStorageLocation": "primary", "credentialRef": "k8s-secret://velero/cloud-credentials", "schedule": "0 */6 * * *", "retention": "168h", "includedNamespaces": []string{"payments"}})
	w := apiRequest(t, h, http.MethodPost, "/api/v1/backup-policies", string(policyBody), map[string]string{"X-Actor-ID": "operator"})
	if w.Code != http.StatusCreated {
		t.Fatalf("policy=%d %s", w.Code, w.Body.String())
	}
	policy := decodeBody[controlplane.BackupPolicy](t, w)

	// Policy lifecycle is an explicit optimistic-concurrency workflow. A disabled
	// policy must immediately stop new backup materialization until re-enabled.
	w = apiRequest(t, h, http.MethodPost, "/api/v1/backup-policies/"+policy.ID+"/disable", "{}", map[string]string{"X-Actor-ID": "operator", "If-Match": fmt.Sprintf("\"%d\"", policy.Revision)})
	if w.Code != http.StatusOK {
		t.Fatalf("disable policy=%d %s", w.Code, w.Body.String())
	}
	policy = decodeBody[controlplane.BackupPolicy](t, w)
	if policy.State != controlplane.BackupPolicyDisabled {
		t.Fatalf("disabled policy state=%s", policy.State)
	}
	disabledBackupBody, _ := json.Marshal(map[string]any{"projectId": project.ID, "clusterId": cluster.ID, "policyId": policy.ID, "idempotencyKey": "backup-disabled"})
	w = apiRequest(t, h, http.MethodPost, "/api/v1/backup-runs", string(disabledBackupBody), map[string]string{"X-Actor-ID": "operator"})
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("disabled policy admitted backup=%d %s", w.Code, w.Body.String())
	}
	w = apiRequest(t, h, http.MethodPost, "/api/v1/backup-policies/"+policy.ID+"/enable", "{}", map[string]string{"X-Actor-ID": "operator", "If-Match": fmt.Sprintf("\"%d\"", policy.Revision)})
	if w.Code != http.StatusOK {
		t.Fatalf("enable policy=%d %s", w.Code, w.Body.String())
	}
	policy = decodeBody[controlplane.BackupPolicy](t, w)
	if policy.State != controlplane.BackupPolicyActive {
		t.Fatalf("enabled policy state=%s", policy.State)
	}

	backupBody, _ := json.Marshal(map[string]any{"projectId": project.ID, "clusterId": cluster.ID, "policyId": policy.ID, "idempotencyKey": "backup-api-1"})
	w = apiRequest(t, h, http.MethodPost, "/api/v1/backup-runs", string(backupBody), map[string]string{"X-Actor-ID": "operator"})
	if w.Code != http.StatusAccepted {
		t.Fatalf("backup create=%d %s", w.Code, w.Body.String())
	}
	backup := decodeBody[controlplane.DataProtectionRun](t, w)

	w = apiRequest(t, h, http.MethodGet, "/agent/v1/clusters/"+cluster.ID+"/data-protection-tasks/next", "", map[string]string{"Authorization": "Bearer " + agentToken})
	if w.Code != http.StatusOK {
		t.Fatalf("task=%d %s", w.Code, w.Body.String())
	}
	task := decodeBody[controlplane.DataProtectionTask](t, w)
	if task.RunID != backup.ID || task.PolicyID != policy.ID || task.BackupStorageLocation != "primary" {
		t.Fatalf("task=%+v", task)
	}
	result := controlplane.DataProtectionTaskResult{TaskFenceToken: task.TaskFenceToken, Success: true, Reference: "velero://" + cluster.ID + "/backup/" + task.VeleroName, Checks: []controlplane.RuntimeCheck{{Key: "data-protection/bsl", Status: "PASS"}, {Key: "data-protection/backup", Status: "PASS"}}}
	runForDigest := controlplane.DataProtectionRun{ResourceMeta: controlplane.ResourceMeta{ID: task.RunID}, Kind: task.Kind, ProjectID: task.ProjectID, ClusterID: task.ClusterID, PolicyID: task.PolicyID, BackupRunID: task.BackupRunID, InventoryDigest: task.InventoryDigest, PolicyDigest: task.PolicyDigest, VeleroName: task.VeleroName, SourceBackupName: task.SourceBackupName, TargetNamespace: task.TargetNamespace}
	result.EvidenceDigest = controlplane.DataProtectionEvidenceDigest(runForDigest, result)
	// Stale/wrong fence must not be accepted.
	bad := result
	bad.TaskFenceToken++
	badBody, _ := json.Marshal(bad)
	w = apiRequest(t, h, http.MethodPost, "/agent/v1/clusters/"+cluster.ID+"/data-protection-tasks/"+task.RunID+"/result", string(badBody), map[string]string{"Authorization": "Bearer " + agentToken, "If-Match": fmt.Sprintf("\"%d\"", task.RunRevision)})
	if w.Code != http.StatusConflict {
		t.Fatalf("wrong fence=%d %s", w.Code, w.Body.String())
	}
	resultBody, _ := json.Marshal(result)
	w = apiRequest(t, h, http.MethodPost, "/agent/v1/clusters/"+cluster.ID+"/data-protection-tasks/"+task.RunID+"/result", string(resultBody), map[string]string{"Authorization": "Bearer " + agentToken, "If-Match": fmt.Sprintf("\"%d\"", task.RunRevision)})
	if w.Code != http.StatusOK {
		t.Fatalf("report=%d %s", w.Code, w.Body.String())
	}
	backup = decodeBody[controlplane.DataProtectionRun](t, w)
	if backup.State != controlplane.DataProtectionSucceeded || backup.RecoveryCheckpointID == "" {
		t.Fatalf("backup=%+v", backup)
	}

	restoreBody, _ := json.Marshal(map[string]any{"projectId": project.ID, "clusterId": cluster.ID, "policyId": policy.ID, "backupRunId": backup.ID, "idempotencyKey": "restore-api-1"})
	w = apiRequest(t, h, http.MethodPost, "/api/v1/restore-runs", string(restoreBody), map[string]string{"X-Actor-ID": "operator"})
	if w.Code != http.StatusAccepted {
		t.Fatalf("restore create=%d %s", w.Code, w.Body.String())
	}
	restore := decodeBody[controlplane.DataProtectionRun](t, w)
	if restore.State != controlplane.DataProtectionAwaitingApproval {
		t.Fatalf("restore state=%s", restore.State)
	}
	w = apiRequest(t, h, http.MethodPost, "/api/v1/restore-runs/"+restore.ID+"/approve", "{}", map[string]string{"X-Actor-ID": "operator", "If-Match": fmt.Sprintf("\"%d\"", restore.Revision)})
	if w.Code != http.StatusConflict {
		t.Fatalf("self approve=%d %s", w.Code, w.Body.String())
	}
	w = apiRequest(t, h, http.MethodPost, "/api/v1/restore-runs/"+restore.ID+"/approve", "{}", map[string]string{"X-Actor-ID": "approver", "If-Match": fmt.Sprintf("\"%d\"", restore.Revision)})
	if w.Code != http.StatusOK {
		t.Fatalf("approve=%d %s", w.Code, w.Body.String())
	}
}
