package api

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"platform.4so.io/factory/internal/controlplane"
)

func TestMaintenanceProfileMissingIsNotConfiguredState(t *testing.T) {
	ctx := context.Background()
	store := controlplane.NewMemoryStore()
	org, _ := store.CreateOrganization(ctx, controlplane.Organization{Name: "maintenance-profile-state-org", DisplayName: "Maintenance Profile State Org"}, "operator")
	project, _ := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "maintenance-profile-state", DisplayName: "Maintenance Profile State"}, "operator")
	cluster, _, _ := seedAPICluster(t, store, project, "maintenance-profile-state-cluster", 78)
	h := New("0.0.test", nil, nil, store).Handler()
	w := apiRequest(t, h, http.MethodGet, "/api/v1/clusters/"+cluster.ID+"/maintenance-profile", "", nil)
	if w.Code != http.StatusOK { t.Fatalf("status=%d body=%s", w.Code, w.Body.String()) }
	body := decodeBody[struct { Profile *controlplane.ClusterMaintenanceProfile `json:"profile"`; ProfileStatus string `json:"profileStatus"`; Method string `json:"method"` }](t, w)
	if body.Profile != nil || body.ProfileStatus != "NOT_CONFIGURED" || body.Method != controlplane.ClusterMaintenanceAuthorityMethod { t.Fatalf("unexpected body: %+v", body) }
}

func TestMaintenanceRunValidationDoesNotLeaveOrphanOperation(t *testing.T) {
	ctx := context.Background()
	store := controlplane.NewMemoryStore()
	org, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "maintenance-atomicity-org", DisplayName: "Maintenance Atomicity Org"}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "maintenance-atomicity", DisplayName: "Maintenance Atomicity"}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	cluster, rawToken, _ := seedAPICluster(t, store, project, "maintenance-atomicity-cluster", 77)
	cluster, _, err = upsertMutationReadyInventoryForAPITest(t, store, ctx, cluster.ID, credentialDigest(rawToken), cluster.ExternalUID, controlplane.ClusterInventory{
		ObservedAt: time.Now().UTC(), Distribution: "rke2", Capabilities: []string{controlplane.TargetMutationRBACActiveCapability}, KubernetesVersion: "1.31.0", Digest: "sha256:" + fmt.Sprintf("%064x", 977),
		Nodes: []controlplane.ClusterNode{{Name: "worker-1", UID: "uid-worker-1", Ready: true, Roles: []string{"worker"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.UpsertClusterMaintenanceProfile(ctx, controlplane.ClusterMaintenanceProfile{ProjectID: project.ID, ClusterID: cluster.ID, Environment: controlplane.ClusterEnvironmentProduction, DefaultDrainTimeoutSeconds: 300}, 0, "operator")
	if err != nil {
		t.Fatal(err)
	}
	window, err := store.CreateClusterMaintenanceWindow(ctx, controlplane.ClusterMaintenanceWindow{ProjectID: project.ID, ClusterID: cluster.ID, Name: "window", StartsAt: time.Now().UTC().Add(-time.Minute), EndsAt: time.Now().UTC().Add(time.Hour), MaxUnavailable: 1, DrainTimeoutSeconds: 300}, "operator")
	if err != nil {
		t.Fatal(err)
	}

	h := New("0.0.test", nil, nil, store).Handler()
	body := fmt.Sprintf(`{"windowId":%q,"nodeNames":["missing-node"]}`, window.ID)
	w := apiRequest(t, h, http.MethodPost, "/api/v1/clusters/"+cluster.ID+"/maintenance-runs", body, map[string]string{"X-Actor-ID": "operator", "Idempotency-Key": "invalid-maintenance-run"})
	if w.Code < 400 {
		t.Fatalf("expected validation failure, got %d body=%s", w.Code, w.Body.String())
	}
	ops, err := store.ListOperations(ctx, project.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(ops) != 0 {
		t.Fatalf("invalid maintenance request left %d orphan operation(s): %+v", len(ops), ops)
	}

	corrected := fmt.Sprintf(`{"windowId":%q,"nodeNames":["worker-1"]}`, window.ID)
	w = apiRequest(t, h, http.MethodPost, "/api/v1/clusters/"+cluster.ID+"/maintenance-runs", corrected, map[string]string{"X-Actor-ID": "operator", "Idempotency-Key": "invalid-maintenance-run"})
	if w.Code != http.StatusCreated {
		t.Fatalf("corrected retry with same idempotency key status=%d body=%s", w.Code, w.Body.String())
	}
	created := decodeBody[struct {
		Run       controlplane.ClusterMaintenanceRun `json:"run"`
		Operation controlplane.Operation             `json:"operation"`
	}](t, w)
	if created.Run.OperationID == "" || created.Run.OperationID != created.Operation.ID || created.Operation.State != controlplane.OperationAwaitingApproval {
		t.Fatalf("maintenance authority was not created atomically: run=%+v operation=%+v", created.Run, created.Operation)
	}
	ops, err = store.ListOperations(ctx, project.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(ops) != 1 || ops[0].ID != created.Operation.ID {
		t.Fatalf("corrected request created unexpected operations: %+v", ops)
	}
}
