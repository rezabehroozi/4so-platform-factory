package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/reliability"
)

func sloRequest(method, target, body, actor string) (*http.Request, *httptest.ResponseRecorder) {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if actor != "" {
		r.Header.Set("X-Actor-ID", actor)
	}
	return r, httptest.NewRecorder()
}

func decodeSLOPolicyResponse(t *testing.T, w *httptest.ResponseRecorder) reliability.SLOPolicy {
	t.Helper()
	var policy reliability.SLOPolicy
	if err := json.Unmarshal(w.Body.Bytes(), &policy); err != nil {
		t.Fatalf("decode SLO response: %v body=%s", err, w.Body.String())
	}
	return policy
}

func TestReliabilitySLOAPIUsesClusterTargetAndImmutableRevisionScope(t *testing.T) {
	store := controlplane.NewMemoryStore()
	ctx := context.Background()
	org, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "slo-api", DisplayName: "SLO"}, "owner")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "platform", DisplayName: "Platform"}, "owner")
	if err != nil {
		t.Fatal(err)
	}
	cluster := workspaceAPICluster(t, store, project.ID, "slo-cluster", "uid-slo-api")
	srv := New("test", nil, nil, store)

	body := fmt.Sprintf(`{"projectId":%q,"clusterId":%q,"name":"api-availability","objectiveBasisPoints":9990,"windowSeconds":120,"observationIntervalSeconds":60}`, project.ID, cluster.ID)
	r, w := sloRequest(http.MethodPost, "/api/v1/reliability/slo-policies", body, "operator-a")
	srv.createReliabilitySLOPolicy(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("create=%d body=%s", w.Code, w.Body.String())
	}
	first := decodeSLOPolicyResponse(t, w)
	if first.ProjectID != project.ID || first.ClusterID != cluster.ID || first.Revision != 1 {
		t.Fatalf("SLO scope=%#v", first)
	}

	mutateScope := fmt.Sprintf(`{"predecessorId":%q,"clusterId":"clu-other","objectiveBasisPoints":9950,"windowSeconds":120,"observationIntervalSeconds":60}`, first.ID)
	r, w = sloRequest(http.MethodPost, "/api/v1/reliability/slo-policies", mutateScope, "operator-a")
	r.Header.Set("If-Match", "1")
	srv.createReliabilitySLOPolicy(w, r)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("scope mutation=%d body=%s", w.Code, w.Body.String())
	}

	revise := fmt.Sprintf(`{"predecessorId":%q,"objectiveBasisPoints":9950,"windowSeconds":120,"observationIntervalSeconds":60}`, first.ID)
	r, w = sloRequest(http.MethodPost, "/api/v1/reliability/slo-policies", revise, "operator-a")
	r.Header.Set("If-Match", `"1"`)
	srv.createReliabilitySLOPolicy(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("revision=%d body=%s", w.Code, w.Body.String())
	}
	second := decodeSLOPolicyResponse(t, w)
	if second.Revision != 2 || second.ClusterID != first.ClusterID || second.Name != first.Name || second.ID == first.ID {
		t.Fatalf("revision identity=%#v", second)
	}

	r, w = sloRequest(http.MethodPost, "/api/v1/reliability/slo-policies", revise, "operator-a")
	r.Header.Set("If-Match", "1")
	srv.createReliabilitySLOPolicy(w, r)
	if w.Code != http.StatusConflict {
		t.Fatalf("stale revision=%d body=%s", w.Code, w.Body.String())
	}

	r, w = sloRequest(http.MethodGet, "/api/v1/reliability/error-budgets?projectId="+project.ID, "", "operator-a")
	srv.reliabilityErrorBudgets(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("budgets=%d body=%s", w.Code, w.Body.String())
	}
	var views []reliabilityErrorBudgetView
	if err := json.Unmarshal(w.Body.Bytes(), &views); err != nil {
		t.Fatal(err)
	}
	if len(views) != 1 || views[0].Policy.Revision != 2 || views[0].Projection.CoverageStatus != reliability.CoverageUnknown {
		t.Fatalf("latest fail-closed budget=%#v", views)
	}
	if views[0].Projection.RemainingBudgetBasisPoints != nil || views[0].Projection.BurnRatioMilli != nil {
		t.Fatalf("incomplete coverage published numeric claims: %#v", views[0])
	}
}

func TestLatestSLOPoliciesKeepsLatestRevisionPerClusterAndName(t *testing.T) {
	rows := []reliability.SLOPolicy{
		{ID: "a1", ClusterID: "clu-a", Name: "api", Revision: 1},
		{ID: "a2", ClusterID: "clu-a", Name: "api", Revision: 2},
		{ID: "b1", ClusterID: "clu-b", Name: "api", Revision: 1},
	}
	latest := latestSLOPolicies(rows)
	if len(latest) != 2 || latest[0].ID != "a2" || latest[1].ID != "b1" {
		t.Fatalf("latest policies=%#v", latest)
	}
}
