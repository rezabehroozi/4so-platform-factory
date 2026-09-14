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

func reliabilityHandlerRequest(method, target, body, actor string) (*http.Request, *httptest.ResponseRecorder) {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if actor != "" { r.Header.Set("X-Actor-ID", actor) }
	return r, httptest.NewRecorder()
}

func decodeIncidentResponse(t *testing.T, w *httptest.ResponseRecorder) reliability.Incident {
	t.Helper()
	var incident reliability.Incident
	if err := json.Unmarshal(w.Body.Bytes(), &incident); err != nil { t.Fatalf("decode incident response: %v body=%s", err, w.Body.String()) }
	return incident
}

func TestReliabilityIncidentLifecycleUsesProjectAuthorityAndRevisionFence(t *testing.T) {
	store := controlplane.NewMemoryStore(); ctx := context.Background()
	org, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "rel-api", DisplayName: "Reliability"}, "owner"); if err != nil { t.Fatal(err) }
	project, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "platform", DisplayName: "Platform"}, "owner"); if err != nil { t.Fatal(err) }
	srv := New("test", nil, nil, store)
	r, w := reliabilityHandlerRequest(http.MethodPost, "/api/v1/reliability/incidents", fmt.Sprintf(`{"projectId":%q,"service":"kubernetes-api","severity":"CRITICAL"}`, project.ID), "operator-a")
	srv.createReliabilityIncident(w, r)
	if w.Code != http.StatusCreated { t.Fatalf("create=%d body=%s", w.Code, w.Body.String()) }
	created := decodeIncidentResponse(t, w)
	if created.OrganizationID != org.ID || created.ProjectID != project.ID || created.State != reliability.IncidentOpen || created.Revision != 1 { t.Fatalf("created incident escaped project authority: %#v", created) }

	r, w = reliabilityHandlerRequest(http.MethodPost, "/api/v1/reliability/incidents/"+created.ID+"/acknowledge", "", "operator-a"); r.SetPathValue("id", created.ID)
	srv.acknowledgeReliabilityIncident(w, r)
	if w.Code != http.StatusBadRequest { t.Fatalf("ack without If-Match=%d body=%s", w.Code, w.Body.String()) }

	r, w = reliabilityHandlerRequest(http.MethodPost, "/api/v1/reliability/incidents/"+created.ID+"/acknowledge", "", "operator-a"); r.SetPathValue("id", created.ID); r.Header.Set("If-Match", `"1"`)
	srv.acknowledgeReliabilityIncident(w, r)
	if w.Code != http.StatusOK { t.Fatalf("ack=%d body=%s", w.Code, w.Body.String()) }
	ack := decodeIncidentResponse(t, w)
	if ack.State != reliability.IncidentAcknowledged || ack.Revision != 2 || ack.AcknowledgedBy != "operator-a" { t.Fatalf("ack=%#v", ack) }

	r, w = reliabilityHandlerRequest(http.MethodPost, "/api/v1/reliability/incidents/"+created.ID+"/resolve", `{"resolutionSummary":"recovered"}`, "operator-b"); r.SetPathValue("id", created.ID); r.Header.Set("If-Match", "1")
	srv.resolveReliabilityIncident(w, r)
	if w.Code != http.StatusConflict { t.Fatalf("stale resolve=%d body=%s", w.Code, w.Body.String()) }

	r, w = reliabilityHandlerRequest(http.MethodPost, "/api/v1/reliability/incidents/"+created.ID+"/resolve", `{}`, "operator-b"); r.SetPathValue("id", created.ID); r.Header.Set("If-Match", "2")
	srv.resolveReliabilityIncident(w, r)
	if w.Code != http.StatusUnprocessableEntity { t.Fatalf("resolve without summary=%d body=%s", w.Code, w.Body.String()) }

	r, w = reliabilityHandlerRequest(http.MethodPost, "/api/v1/reliability/incidents/"+created.ID+"/resolve", `{"resolutionSummary":"recovered"}`, "operator-b"); r.SetPathValue("id", created.ID); r.Header.Set("If-Match", "2")
	srv.resolveReliabilityIncident(w, r)
	if w.Code != http.StatusOK { t.Fatalf("resolve=%d body=%s", w.Code, w.Body.String()) }
	resolved := decodeIncidentResponse(t, w)
	if resolved.State != reliability.IncidentResolved || resolved.Revision != 3 || resolved.ResolvedBy != "operator-b" || resolved.ResolutionSummary != "recovered" { t.Fatalf("resolved=%#v", resolved) }

	r, w = reliabilityHandlerRequest(http.MethodPost, "/api/v1/reliability/incidents/"+created.ID+"/acknowledge", "", "operator-c"); r.SetPathValue("id", created.ID); r.Header.Set("If-Match", "3")
	srv.acknowledgeReliabilityIncident(w, r)
	if w.Code != http.StatusUnprocessableEntity { t.Fatalf("resolved incident reopened=%d body=%s", w.Code, w.Body.String()) }
}

func TestReliabilityIncidentListRequiresExplicitProject(t *testing.T) {
	store := controlplane.NewMemoryStore(); srv := New("test", nil, nil, store)
	r, w := reliabilityHandlerRequest(http.MethodGet, "/api/v1/reliability/incidents", "", "operator-a")
	srv.listReliabilityIncidents(w, r)
	if w.Code != http.StatusUnprocessableEntity { t.Fatalf("missing projectId=%d body=%s", w.Code, w.Body.String()) }
}
