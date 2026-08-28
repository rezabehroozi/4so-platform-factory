package api

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"platform.4so.io/factory/internal/controlplane"
)

func TestTenantResizeAndProtectedDeleteHTTPWorkflow(t *testing.T) {
	ctx := context.Background()
	store := controlplane.NewMemoryStore()
	org, _ := store.CreateOrganization(ctx, controlplane.Organization{Name: "tenant-runtime", DisplayName: "Tenant Runtime"}, "admin")
	project, _ := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "customers", DisplayName: "Customers"}, "admin")
	_, _ = store.UpsertEntitlement(ctx, controlplane.Entitlement{OrganizationID: org.ID, Edition: "service-provider"}, 0, "admin")
	enrollment := "tenant-resize-enrollment-token-abcdefghijklmnopqrstuvwxyz"
	agent := "tenant-resize-agent-token-abcdefghijklmnopqrstuvwxyz"
	imp, err := store.CreateClusterImport(ctx, controlplane.ClusterImport{ProjectID: project.ID, Name: "shared", DisplayName: "Shared", TokenDigest: credentialDigest(enrollment), ExpiresAt: time.Now().Add(time.Hour)}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	imp, _ = store.ApproveClusterImport(ctx, imp.ID, imp.Revision, "approver")
	_, cluster, err := store.ClaimClusterImport(ctx, imp.ID, credentialDigest(enrollment), credentialDigest(agent), "tenant-runtime-uid", "0.0.66")
	if err != nil {
		t.Fatal(err)
	}
	cluster, _, err = upsertMutationReadyInventoryForAPITest(t, store, ctx, cluster.ID, credentialDigest(agent), cluster.ExternalUID, controlplane.ClusterInventory{ObservedAt: time.Now(), Distribution: "rke2", Capabilities: []string{controlplane.TargetMutationRBACActiveCapability}, KubernetesVersion: "v1.33.3", Digest: digestValue("tenant-runtime-inventory")})
	if err != nil {
		t.Fatal(err)
	}
	seedTenantPolicyInventory(t, store, cluster, agent)

	h := New("0.0.66", nil, nil, store).Handler()
	body := fmt.Sprintf(`{"projectId":%q,"clusterId":%q,"name":"customer-resize","displayName":"Customer Resize","planName":"small"}`, project.ID, cluster.ID)
	w := apiRequest(t, h, http.MethodPost, "/api/v1/tenants", body, map[string]string{"X-Actor-ID": "requester", "Idempotency-Key": "tenant-resize-1"})
	if w.Code != http.StatusCreated {
		t.Fatalf("create=%d %s", w.Code, w.Body.String())
	}
	tenant := decodeBody[struct {
		Tenant controlplane.TenantEnvironment `json:"tenant"`
	}](t, w).Tenant
	w = apiRequest(t, h, http.MethodGet, "/agent/v1/clusters/"+cluster.ID+"/tenant-tasks/next", "", map[string]string{"Authorization": "Bearer " + agent})
	task := decodeBody[controlplane.TenantTask](t, w)
	w = apiRequest(t, h, http.MethodPost, "/agent/v1/clusters/"+cluster.ID+"/tenant-tasks/"+tenant.ID+"/result", tenantResultBody(task), map[string]string{"Authorization": "Bearer " + agent, "If-Match": fmt.Sprintf("\"%d\"", task.TenantRevision)})
	tenant = decodeBody[controlplane.TenantEnvironment](t, w)

	w = apiRequest(t, h, http.MethodPost, "/api/v1/tenants/"+tenant.ID+"/resize", `{"planName":"medium"}`, map[string]string{"X-Actor-ID": "requester", "If-Match": fmt.Sprintf("\"%d\"", tenant.Revision)})
	if w.Code != http.StatusOK {
		t.Fatalf("resize request=%d %s", w.Code, w.Body.String())
	}
	tenant = decodeBody[controlplane.TenantEnvironment](t, w)
	if tenant.State != controlplane.TenantResizeApproval || tenant.PlanName != "small" || tenant.PendingPlanName != "medium" {
		t.Fatalf("resize staged=%#v", tenant)
	}
	w = apiRequest(t, h, http.MethodGet, "/agent/v1/clusters/"+cluster.ID+"/tenant-tasks/next", "", map[string]string{"Authorization": "Bearer " + agent})
	if w.Code != http.StatusNoContent {
		t.Fatalf("unapproved resize claim=%d %s", w.Code, w.Body.String())
	}
	w = apiRequest(t, h, http.MethodPost, "/api/v1/tenants/"+tenant.ID+"/approve", `{}`, map[string]string{"X-Actor-ID": "requester", "X-Actor-Role": "platform-admin", "If-Match": fmt.Sprintf("\"%d\"", tenant.Revision)})
	if w.Code != http.StatusForbidden {
		t.Fatalf("same actor approval=%d %s", w.Code, w.Body.String())
	}
	w = apiRequest(t, h, http.MethodPost, "/api/v1/tenants/"+tenant.ID+"/approve", `{}`, map[string]string{"X-Actor-ID": "approver", "X-Actor-Role": "platform-admin", "If-Match": fmt.Sprintf("\"%d\"", tenant.Revision)})
	if w.Code != http.StatusOK {
		t.Fatalf("resize approval=%d %s", w.Code, w.Body.String())
	}
	tenant = decodeBody[controlplane.TenantEnvironment](t, w)
	w = apiRequest(t, h, http.MethodGet, "/agent/v1/clusters/"+cluster.ID+"/tenant-tasks/next", "", map[string]string{"Authorization": "Bearer " + agent})
	if w.Code != http.StatusOK {
		t.Fatalf("resize task=%d %s", w.Code, w.Body.String())
	}
	task = decodeBody[controlplane.TenantTask](t, w)
	if task.Action != "RESIZE" || task.PlanName != "medium" || task.DesiredDigest == "" {
		t.Fatalf("resize task=%#v", task)
	}
	w = apiRequest(t, h, http.MethodPost, "/agent/v1/clusters/"+cluster.ID+"/tenant-tasks/"+tenant.ID+"/result", tenantResultBody(task), map[string]string{"Authorization": "Bearer " + agent, "If-Match": fmt.Sprintf("\"%d\"", task.TenantRevision)})
	if w.Code != http.StatusOK {
		t.Fatalf("resize result=%d %s", w.Code, w.Body.String())
	}
	tenant = decodeBody[controlplane.TenantEnvironment](t, w)
	if tenant.PlanName != "medium" || tenant.State != controlplane.TenantActive || tenant.PendingPlanName != "" {
		t.Fatalf("resized=%#v", tenant)
	}

	cp, err := store.CreateRecoveryCheckpoint(ctx, controlplane.RecoveryCheckpoint{ProjectID: project.ID, ClusterID: cluster.ID, Provider: "s3", Reference: "tenant-protected-delete-backup", EvidenceDigest: digestValue("tenant-protected-delete-evidence"), CompletedAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(4 * time.Hour)}, "backup-operator")
	if err != nil {
		t.Fatal(err)
	}
	w = apiRequest(t, h, http.MethodPost, "/api/v1/tenants/"+tenant.ID+"/delete", fmt.Sprintf(`{"recoveryCheckpointId":%q}`, cp.ID), map[string]string{"X-Actor-ID": "requester", "If-Match": fmt.Sprintf("\"%d\"", tenant.Revision), "X-Confirm-Delete": "delete-tenant-namespace"})
	if w.Code != http.StatusOK {
		t.Fatalf("delete request=%d %s", w.Code, w.Body.String())
	}
	tenant = decodeBody[controlplane.TenantEnvironment](t, w)
	if tenant.State != controlplane.TenantDeleteApproval || tenant.RecoveryCheckpointID != cp.ID || tenant.DestructiveOperationID == "" {
		t.Fatalf("protected delete staged=%#v", tenant)
	}
	w = apiRequest(t, h, http.MethodGet, "/agent/v1/clusters/"+cluster.ID+"/tenant-tasks/next", "", map[string]string{"Authorization": "Bearer " + agent})
	if w.Code != http.StatusNoContent {
		t.Fatalf("unapproved delete claim=%d %s", w.Code, w.Body.String())
	}
	w = apiRequest(t, h, http.MethodPost, "/api/v1/tenants/"+tenant.ID+"/approve", `{}`, map[string]string{"X-Actor-ID": "approver", "X-Actor-Role": "platform-admin", "If-Match": fmt.Sprintf("\"%d\"", tenant.Revision)})
	if w.Code != http.StatusOK {
		t.Fatalf("delete approve=%d %s", w.Code, w.Body.String())
	}
	tenant = decodeBody[controlplane.TenantEnvironment](t, w)
	if tenant.State != controlplane.TenantDeleteQueued || tenant.ApprovedBy != "approver" {
		t.Fatalf("delete approved=%#v", tenant)
	}
}
