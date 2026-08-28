package api

import (
	"context"
	"fmt"
	"net/http"
	"platform.4so.io/factory/internal/controlplane"
	"strings"
	"testing"
	"time"
)

func TestRecoveryCheckpointAndMaintenanceRoutes(t *testing.T) {
	ctx := context.Background()
	store := controlplane.NewMemoryStore()
	org, _ := store.CreateOrganization(ctx, controlplane.Organization{Name: "safe-org", DisplayName: "Safe Org"}, "operator")
	project, _ := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "prod", DisplayName: "Production"}, "operator")
	cluster, _, _ := seedAPICluster(t, store, project, "safe-edge", 77)
	server := New("0.0.42", nil, nil, store)
	server.ConfigureFleetImport("registry.test/platform-agent@sha256:"+strings.Repeat("a", 64), "registry.test/platform-probe@sha256:"+strings.Repeat("b", 64), "https://platform.example.test", "")
	h := server.Handler()

	now := time.Now().UTC()
	body := fmt.Sprintf(`{"projectId":%q,"clusterId":%q,"provider":"s3","reference":"bucket/backups/77","evidenceDigest":%q,"completedAt":%q,"expiresAt":%q}`, project.ID, cluster.ID, "sha256:"+strings.Repeat("d", 64), now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(4*time.Hour).Format(time.RFC3339))
	w := apiRequest(t, h, http.MethodPost, "/api/v1/recovery-checkpoints", body, map[string]string{"X-Actor-ID": "operator"})
	if w.Code != http.StatusCreated {
		t.Fatalf("checkpoint %d: %s", w.Code, w.Body.String())
	}
	checkpoint := decodeBody[controlplane.RecoveryCheckpoint](t, w)
	if checkpoint.InventoryDigest == "" || checkpoint.State != controlplane.RecoveryCheckpointVerified {
		t.Fatalf("unexpected checkpoint: %#v", checkpoint)
	}

	w = apiRequest(t, h, http.MethodGet, "/api/v1/recovery-checkpoints?projectId="+project.ID, "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list %d: %s", w.Code, w.Body.String())
	}
	listed := decodeBody[[]controlplane.RecoveryCheckpoint](t, w)
	if len(listed) != 1 || listed[0].ID != checkpoint.ID {
		t.Fatalf("unexpected checkpoint list: %#v", listed)
	}

	group, _, err := store.CreateFleetGroup(ctx, controlplane.FleetGroup{ProjectID: project.ID, Name: "safe-fleet", DisplayName: "Safe Fleet", ClusterIDs: []string{cluster.ID}, IdempotencyKey: "safe-fleet", RequestDigest: "sha256:" + strings.Repeat("e", 64)}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	windowStart := now.Add(30 * time.Minute)
	windowEnd := now.Add(90 * time.Minute)
	body = fmt.Sprintf(`{"projectId":%q,"fleetGroupId":%q,"baselineId":"secure-namespace-foundation","targetVersion":"1.1.0","canaryCount":1,"waveSize":1,"haltAfterFailures":1,"maintenanceWindowStart":%q,"maintenanceWindowEnd":%q,"recoveryCheckpointIds":[%q]}`, project.ID, group.ID, windowStart.Format(time.RFC3339), windowEnd.Format(time.RFC3339), checkpoint.ID)
	w = apiRequest(t, h, http.MethodPost, "/api/v1/upgrade-campaigns", body, map[string]string{"X-Actor-ID": "operator", "Idempotency-Key": "safe-upgrade"})
	if w.Code != http.StatusCreated {
		t.Fatalf("campaign %d: %s", w.Code, w.Body.String())
	}
	created := decodeBody[struct {
		Campaign controlplane.UpgradeCampaign `json:"campaign"`
	}](t, w).Campaign
	w = apiRequest(t, h, http.MethodPost, "/api/v1/upgrade-campaigns/"+created.ID+"/approve", `{}`, map[string]string{"X-Actor-ID": "approver", "X-Actor-Role": "platform-admin", "If-Match": fmt.Sprintf("\"%d\"", created.Revision)})
	if w.Code != http.StatusOK {
		t.Fatalf("approve %d: %s", w.Code, w.Body.String())
	}
	approved := decodeBody[controlplane.UpgradeCampaign](t, w)
	w = apiRequest(t, h, http.MethodPost, "/api/v1/upgrade-campaigns/"+approved.ID+"/advance", `{}`, map[string]string{"X-Actor-ID": "operator", "If-Match": fmt.Sprintf("\"%d\"", approved.Revision)})
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "MAINTENANCE_WINDOW_CLOSED") {
		t.Fatalf("expected maintenance conflict, got %d: %s", w.Code, w.Body.String())
	}

	w = apiRequest(t, h, http.MethodPost, "/api/v1/recovery-checkpoints/"+checkpoint.ID+"/revoke", `{}`, map[string]string{"X-Actor-ID": "operator", "If-Match": fmt.Sprintf("\"%d\"", checkpoint.Revision)})
	if w.Code != http.StatusOK {
		t.Fatalf("revoke %d: %s", w.Code, w.Body.String())
	}
	w = apiRequest(t, h, http.MethodPost, "/api/v1/upgrade-campaigns/"+approved.ID+"/revalidate", `{}`, map[string]string{"X-Actor-ID": "operator", "If-Match": fmt.Sprintf("\"%d\"", approved.Revision)})
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "PREREQUISITE_NOT_SATISFIED") {
		t.Fatalf("expected prerequisite failure after revoke, got %d: %s", w.Code, w.Body.String())
	}
}
