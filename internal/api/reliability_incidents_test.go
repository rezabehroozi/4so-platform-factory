package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/reliability"
)

func reliabilityHandlerRequest(method, target, body, actor string) (*http.Request, *httptest.ResponseRecorder) {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if actor != "" {
		r.Header.Set("X-Actor-ID", actor)
	}
	return r, httptest.NewRecorder()
}

func decodeIncidentResponse(t *testing.T, w *httptest.ResponseRecorder) reliability.Incident {
	t.Helper()
	var incident reliability.Incident
	if err := json.Unmarshal(w.Body.Bytes(), &incident); err != nil {
		t.Fatalf("decode incident response: %v body=%s", err, w.Body.String())
	}
	return incident
}

func TestReliabilityIncidentLifecycleUsesProjectAuthorityAndRevisionFence(t *testing.T) {
	store := controlplane.NewMemoryStore()
	ctx := context.Background()
	org, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "rel-api", DisplayName: "Reliability"}, "owner")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "platform", DisplayName: "Platform"}, "owner")
	if err != nil {
		t.Fatal(err)
	}
	srv := New("test", nil, nil, store)
	r, w := reliabilityHandlerRequest(http.MethodPost, "/api/v1/reliability/incidents", fmt.Sprintf(`{"projectId":%q,"service":"kubernetes-api","severity":"CRITICAL"}`, project.ID), "operator-a")
	srv.createReliabilityIncident(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("create=%d body=%s", w.Code, w.Body.String())
	}
	created := decodeIncidentResponse(t, w)
	if created.OrganizationID != org.ID || created.ProjectID != project.ID || created.State != reliability.IncidentOpen || created.Revision != 1 {
		t.Fatalf("created incident escaped project authority: %#v", created)
	}

	r, w = reliabilityHandlerRequest(http.MethodPost, "/api/v1/reliability/incidents/"+created.ID+"/acknowledge", "", "operator-a")
	r.SetPathValue("id", created.ID)
	srv.acknowledgeReliabilityIncident(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("ack without If-Match=%d body=%s", w.Code, w.Body.String())
	}

	r, w = reliabilityHandlerRequest(http.MethodPost, "/api/v1/reliability/incidents/"+created.ID+"/acknowledge", "", "operator-a")
	r.SetPathValue("id", created.ID)
	r.Header.Set("If-Match", `"1"`)
	srv.acknowledgeReliabilityIncident(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("ack=%d body=%s", w.Code, w.Body.String())
	}
	ack := decodeIncidentResponse(t, w)
	if ack.State != reliability.IncidentAcknowledged || ack.Revision != 2 || ack.AcknowledgedBy != "operator-a" {
		t.Fatalf("ack=%#v", ack)
	}

	r, w = reliabilityHandlerRequest(http.MethodPost, "/api/v1/reliability/incidents/"+created.ID+"/resolve", `{"resolutionSummary":"recovered"}`, "operator-b")
	r.SetPathValue("id", created.ID)
	r.Header.Set("If-Match", "1")
	srv.resolveReliabilityIncident(w, r)
	if w.Code != http.StatusConflict {
		t.Fatalf("stale resolve=%d body=%s", w.Code, w.Body.String())
	}

	r, w = reliabilityHandlerRequest(http.MethodPost, "/api/v1/reliability/incidents/"+created.ID+"/resolve", `{}`, "operator-b")
	r.SetPathValue("id", created.ID)
	r.Header.Set("If-Match", "2")
	srv.resolveReliabilityIncident(w, r)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("resolve without summary=%d body=%s", w.Code, w.Body.String())
	}

	r, w = reliabilityHandlerRequest(http.MethodPost, "/api/v1/reliability/incidents/"+created.ID+"/resolve", `{"resolutionSummary":"recovered"}`, "operator-b")
	r.SetPathValue("id", created.ID)
	r.Header.Set("If-Match", "2")
	srv.resolveReliabilityIncident(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("resolve=%d body=%s", w.Code, w.Body.String())
	}
	resolved := decodeIncidentResponse(t, w)
	if resolved.State != reliability.IncidentResolved || resolved.Revision != 3 || resolved.ResolvedBy != "operator-b" || resolved.ResolutionSummary != "recovered" {
		t.Fatalf("resolved=%#v", resolved)
	}

	r, w = reliabilityHandlerRequest(http.MethodPost, "/api/v1/reliability/incidents/"+created.ID+"/acknowledge", "", "operator-c")
	r.SetPathValue("id", created.ID)
	r.Header.Set("If-Match", "3")
	srv.acknowledgeReliabilityIncident(w, r)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("resolved incident reopened=%d body=%s", w.Code, w.Body.String())
	}
}

func TestReliabilityIncidentListRequiresExplicitProject(t *testing.T) {
	store := controlplane.NewMemoryStore()
	srv := New("test", nil, nil, store)
	r, w := reliabilityHandlerRequest(http.MethodGet, "/api/v1/reliability/incidents", "", "operator-a")
	srv.listReliabilityIncidents(w, r)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("missing projectId=%d body=%s", w.Code, w.Body.String())
	}
}

func TestReliabilityIncidentCreateBindsSameProjectOperation(t *testing.T) {
	store := controlplane.NewMemoryStore()
	ctx := context.Background()
	org, _ := store.CreateOrganization(ctx, controlplane.Organization{Name: "rel-evidence", DisplayName: "Reliability Evidence"}, "owner")
	project, _ := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "platform-evidence", DisplayName: "Platform Evidence"}, "owner")
	op, _, err := store.CreateOperation(ctx, controlplane.OperationRequest{ProjectID: project.ID, Kind: "reliability.remediation", TargetRef: "cluster:test", DesiredRevision: "sha256:" + strings.Repeat("a", 64), Risk: "medium", Class: controlplane.OperationClassMutating}, "rel-evidence-op", "operator-a", "sha256:"+strings.Repeat("b", 64))
	if err != nil {
		t.Fatal(err)
	}
	srv := New("test", nil, nil, store)
	r, w := reliabilityHandlerRequest(http.MethodPost, "/api/v1/reliability/incidents", fmt.Sprintf(`{"projectId":%q,"operationId":%q,"severity":"CRITICAL"}`, project.ID, op.ID), "operator-a")
	srv.createReliabilityIncident(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("create=%d body=%s", w.Code, w.Body.String())
	}
	created := decodeIncidentResponse(t, w)
	if created.OperationID != op.ID {
		t.Fatalf("operation link missing: %#v", created)
	}
}

func TestReliabilityIncidentDetailBoundsAndRedactsEvidence(t *testing.T) {
	store := controlplane.NewMemoryStore()
	ctx := context.Background()
	org, _ := store.CreateOrganization(ctx, controlplane.Organization{Name: "rel-detail", DisplayName: "Reliability Detail"}, "owner")
	project, _ := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "detail", DisplayName: "Detail"}, "owner")
	op, _, err := store.CreateOperation(ctx, controlplane.OperationRequest{ProjectID: project.ID, Kind: "reliability.remediation", TargetRef: "cluster:test", DesiredRevision: "sha256:" + strings.Repeat("a", 64), Risk: "medium", Class: controlplane.OperationClassMutating}, "rel-detail-op", "operator-a", "sha256:"+strings.Repeat("b", 64))
	if err != nil {
		t.Fatal(err)
	}
	incident, err := store.CreateIncident(ctx, reliability.Incident{OrganizationID: org.ID, ProjectID: project.ID, OperationID: op.ID, Severity: "CRITICAL"}, "operator-a")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < reliabilityIncidentEvidenceLimit+5; i++ {
		_, err = store.AppendEvidence(ctx, controlplane.EvidenceMetadata{OperationID: op.ID, Phase: controlplane.OperationStepPhaseForward, StepKey: fmt.Sprintf("step-%02d", i), Attempt: 1, TraceID: fmt.Sprintf("secret-trace-%02d", i), Kind: "diagnostic", Digest: "sha256:" + fmt.Sprintf("%064x", i+1), MediaType: "application/json", Location: fmt.Sprintf("file:///secret/path/%02d", i), Size: int64(i + 1), HasPayload: true, Sealed: true}, "operator-a")
		if err != nil {
			t.Fatalf("append evidence %d: %v", i, err)
		}
	}
	srv := New("test", nil, nil, store)
	r, w := reliabilityHandlerRequest(http.MethodGet, "/api/v1/reliability/incidents/"+incident.ID, "", "operator-a")
	r.SetPathValue("id", incident.ID)
	srv.getReliabilityIncident(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("detail=%d body=%s", w.Code, w.Body.String())
	}
	var detail reliabilityIncidentDetail
	if err = json.Unmarshal(w.Body.Bytes(), &detail); err != nil {
		t.Fatal(err)
	}
	if len(detail.Evidence) != reliabilityIncidentEvidenceLimit || !detail.EvidenceTruncated {
		t.Fatalf("evidence bound len=%d truncated=%v", len(detail.Evidence), detail.EvidenceTruncated)
	}
	body := w.Body.String()
	for _, forbidden := range []string{"secret-trace", "secret/path", "location", "traceId", "rawPayload", "payloadBase64"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("incident detail leaked %q: %s", forbidden, body)
		}
	}
}

func TestReliabilityIncidentEvidenceProjectionRedactsLocationAndTrace(t *testing.T) {
	input := controlplane.EvidenceMetadata{ResourceMeta: controlplane.ResourceMeta{ID: "evd-1"}, OperationID: "op-1", Phase: controlplane.OperationStepPhaseForward, StepKey: "repair", Attempt: 2, TraceID: "secret-trace", Kind: "diagnostic", Digest: "sha256:" + strings.Repeat("c", 64), MediaType: "application/json", Location: "file:///secret/path", Size: 42, HasPayload: true, Sealed: true}
	projected := projectReliabilityIncidentEvidence(input)
	raw, err := json.Marshal(projected)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Contains(text, "secret-trace") || strings.Contains(text, "secret/path") || strings.Contains(text, "location") || strings.Contains(text, "traceId") {
		t.Fatalf("sensitive evidence metadata leaked: %s", text)
	}
	if projected.ID != input.ID || projected.Digest != input.Digest || projected.OperationID != input.OperationID || !projected.Sealed {
		t.Fatalf("projection lost authoritative metadata: %#v", projected)
	}
}

func TestReliabilityIncidentDetailReturnsBoundedRedactedEvidenceMetadata(t *testing.T) {
	store := controlplane.NewMemoryStore()
	ctx := context.Background()
	org, _ := store.CreateOrganization(ctx, controlplane.Organization{Name: "rel-detail", DisplayName: "Reliability Detail"}, "owner")
	project, _ := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "rel-detail-project", DisplayName: "Reliability Detail Project"}, "owner")
	op, _, err := store.CreateOperation(ctx, controlplane.OperationRequest{ProjectID: project.ID, Kind: "reliability.remediation", TargetRef: "cluster:test", DesiredRevision: "sha256:" + strings.Repeat("d", 64), Risk: "medium", Class: controlplane.OperationClassMutating}, "rel-detail-op", "owner", "sha256:"+strings.Repeat("e", 64))
	if err != nil {
		t.Fatal(err)
	}
	op, err = store.TransitionOperation(ctx, op.ID, op.Revision, controlplane.OperationPlanning, "", "owner")
	if err != nil {
		t.Fatal(err)
	}
	op, err = store.TransitionOperation(ctx, op.ID, op.Revision, controlplane.OperationQueued, "", "owner")
	if err != nil {
		t.Fatal(err)
	}
	claim, err := store.ClaimOperation(ctx, op.ID, "worker-a", time.Minute, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := store.AppendOperationEvidencePayload(ctx, controlplane.EvidenceMetadata{OperationID: op.ID, Kind: "diagnostic", MediaType: "application/json", Location: "file:///secret/location"}, []byte(`{"secret":"payload"}`), "worker-a", claim.FenceToken, "owner")
	if err != nil {
		t.Fatal(err)
	}
	incident, err := store.CreateIncident(ctx, reliability.Incident{OrganizationID: org.ID, ProjectID: project.ID, OperationID: op.ID, Severity: "CRITICAL"}, "owner")
	if err != nil {
		t.Fatal(err)
	}
	srv := New("test", nil, nil, store)
	r, w := reliabilityHandlerRequest(http.MethodGet, "/api/v1/reliability/incidents/"+incident.ID, "", "owner")
	r.SetPathValue("id", incident.ID)
	srv.getReliabilityIncident(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("detail=%d body=%s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, sealed.ID) || !strings.Contains(body, sealed.Digest) {
		t.Fatalf("authoritative evidence metadata missing: %s", body)
	}
	for _, forbidden := range []string{"secret/location", `\"secret\":\"payload\"`, `"location"`, `"traceId"`} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("sensitive evidence material leaked %q: %s", forbidden, body)
		}
	}
}
