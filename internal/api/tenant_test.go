package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"platform.4so.io/factory/internal/controlplane"
	"testing"
	"time"
)

func seedTenantPolicyInventory(t *testing.T, store *controlplane.MemoryStore, cluster controlplane.ManagedCluster, agent string) {
	t.Helper()
	_, _, err := upsertMutationReadyInventoryForAPITest(t, store, context.Background(), cluster.ID, credentialDigest(agent), cluster.ExternalUID, controlplane.ClusterInventory{ObservedAt: time.Now(), Distribution: "rke2", Capabilities: []string{controlplane.TargetMutationRBACActiveCapability}, KubernetesVersion: "v1.34.0", StorageClasses: []controlplane.ClusterStorageClass{{Name: "replicated", Provisioner: "csi.example", Default: true, AllowVolumeExpansion: true}}, APIResources: []controlplane.ClusterAPIResourceObservation{{APIVersion: "networking.k8s.io/v1", Group: "networking.k8s.io", Version: "v1", Kind: "NetworkPolicy", Resource: "networkpolicies", Namespaced: true, Verbs: []string{"get", "patch"}}, {APIVersion: "velero.io/v1", Group: "velero.io", Version: "v1", Kind: "Schedule", Resource: "schedules", Namespaced: true, Verbs: []string{"get", "patch"}}}, APIDiscoveryComplete: true, Digest: digestValue("tenant-policy-inventory")})
	if err != nil {
		t.Fatal(err)
	}
}

func tenantResultBody(task controlplane.TenantTask) string {
	items := make([]controlplane.TenantEvidenceArtifact, 0, 8)
	for _, r := range task.Resources {
		key := "resource/" + r.Kind + "/" + r.Name
		items = append(items, controlplane.TenantEvidenceArtifact{Key: key, Authority: "KUBERNETES_API_READBACK_V1", Resource: r.Kind + "/" + r.Name, Status: "PASS", Digest: digestValue(key)})
	}
	items = append(items, controlplane.TenantEvidenceArtifact{Key: "security/pod-security-admission-negative", Authority: "KUBERNETES_POD_SECURITY_ADMISSION_V1", Status: "PASS", Digest: digestValue("psa-negative")})
	raw, _ := json.Marshal(items)
	sum := sha256.Sum256(raw)
	evidenceDigest := "sha256:" + hex.EncodeToString(sum[:])
	result, _ := json.Marshal(controlplane.TenantTaskResult{TaskFenceToken: task.TaskFenceToken, Action: task.Action, Success: true, ObservedDigest: task.DesiredDigest, Evidence: items, EvidenceDigest: evidenceDigest})
	return string(result)
}

func TestTenantAndOEMHTTPWorkflow(t *testing.T) {
	ctx := context.Background()
	store := controlplane.NewMemoryStore()
	org, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "provider", DisplayName: "Provider"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "customers", DisplayName: "Customers"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	enrollment := "enrollment-token-tenant-http-abcdefghijklmnopqrstuvwxyz"
	agent := "agent-token-tenant-http-abcdefghijklmnopqrstuvwxyz"
	imp, err := store.CreateClusterImport(ctx, controlplane.ClusterImport{ProjectID: project.ID, Name: "shared", DisplayName: "Shared", TokenDigest: credentialDigest(enrollment), ExpiresAt: time.Now().Add(time.Hour)}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	imp, err = store.ApproveClusterImport(ctx, imp.ID, imp.Revision, "approver")
	if err != nil {
		t.Fatal(err)
	}
	_, cluster, err := store.ClaimClusterImport(ctx, imp.ID, credentialDigest(enrollment), credentialDigest(agent), "uid-tenant-http", "0.0.16")
	if err != nil {
		t.Fatal(err)
	}
	seedTenantPolicyInventory(t, store, cluster, agent)
	s := New("0.0.16", nil, nil, store)
	h := s.Handler()
	w := apiRequest(t, h, http.MethodPut, "/api/v1/organizations/"+org.ID+"/entitlement", `{"edition":"service-provider"}`, map[string]string{"X-Actor-ID": "admin", "X-Actor-Role": "platform-admin", "If-None-Match": "*"})
	if w.Code != http.StatusOK {
		t.Fatalf("entitlement %d: %s", w.Code, w.Body.String())
	}
	w = apiRequest(t, h, http.MethodPut, "/api/v1/organizations/"+org.ID+"/oem-profile", `{"brandName":"Example Cloud","productTitle":"Example Kubernetes","supportUrl":"https://support.example.test","logoObjectRef":"object://branding/logo.svg","accentColor":"#3366AA","customDomain":"platform.example.test","defaultLocale":"fa"}`, map[string]string{"X-Actor-ID": "admin", "X-Actor-Role": "platform-admin", "If-None-Match": "*"})
	if w.Code != http.StatusOK {
		t.Fatalf("oem %d: %s", w.Code, w.Body.String())
	}
	body := fmt.Sprintf(`{"projectId":%q,"clusterId":%q,"name":"customer-a","displayName":"Customer A","planName":"small"}`, project.ID, cluster.ID)
	w = apiRequest(t, h, http.MethodPost, "/api/v1/tenants", body, map[string]string{"X-Actor-ID": "operator", "Idempotency-Key": "tenant-http-1"})
	if w.Code != http.StatusCreated {
		t.Fatalf("tenant %d: %s", w.Code, w.Body.String())
	}
	created := decodeBody[struct {
		Tenant controlplane.TenantEnvironment `json:"tenant"`
	}](t, w).Tenant
	w = apiRequest(t, h, http.MethodGet, "/agent/v1/clusters/"+cluster.ID+"/tenant-tasks/next", "", map[string]string{"Authorization": "Bearer " + agent})
	if w.Code != http.StatusOK {
		t.Fatalf("tenant task %d: %s", w.Code, w.Body.String())
	}
	task := decodeBody[controlplane.TenantTask](t, w)
	if task.Action != "PROVISION" || len(task.Resources) != 7 || task.Namespace != created.Namespace {
		t.Fatalf("task=%#v", task)
	}
	expectedSchedule := controlplane.TenantBackupScheduleName(created.ID)
	foundSchedule := false
	for _, resource := range task.Resources {
		if resource.Kind == "Schedule" {
			foundSchedule = resource.Name == expectedSchedule && resource.Name != "tenant-platform-backup"
		}
	}
	if !foundSchedule {
		t.Fatalf("tenant task does not use tenant-unique backup schedule %q: %#v", expectedSchedule, task.Resources)
	}
	result := tenantResultBody(task)
	w = apiRequest(t, h, http.MethodPost, "/agent/v1/clusters/"+cluster.ID+"/tenant-tasks/"+created.ID+"/result", result, map[string]string{"Authorization": "Bearer " + agent, "If-Match": fmt.Sprintf("\"%d\"", task.TenantRevision)})
	if w.Code != http.StatusOK {
		t.Fatalf("tenant result %d: %s", w.Code, w.Body.String())
	}
	active := decodeBody[controlplane.TenantEnvironment](t, w)
	if active.State != controlplane.TenantActive {
		t.Fatalf("state=%s", active.State)
	}
	w = apiRequest(t, h, http.MethodPost, "/api/v1/tenants/"+active.ID+"/delete", `{}`, map[string]string{"X-Actor-ID": "operator", "If-Match": fmt.Sprintf("\"%d\"", active.Revision)})
	if w.Code != http.StatusPreconditionRequired {
		t.Fatalf("delete without confirmation=%d", w.Code)
	}
}
