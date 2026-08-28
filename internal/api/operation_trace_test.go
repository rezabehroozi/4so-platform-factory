package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"platform.4so.io/factory/internal/controlplane"
)

func TestOperationStepTraceEvidencePayloadAndAuditAuthority(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	org, err := s.store.CreateOrganization(ctx, controlplane.Organization{Name: "trace-org", DisplayName: "Trace Org"}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	project, err := s.store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "prod", DisplayName: "Production"}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	op, _, err := s.store.CreateOperation(ctx, controlplane.OperationRequest{ProjectID: project.ID, Kind: "trace.test", TargetRef: "cluster/test", DesiredRevision: "sha256:" + fmt.Sprintf("%064x", 1), Risk: "high", Class: controlplane.OperationClassMutating}, "trace-op", "operator", "req")
	if err != nil {
		t.Fatal(err)
	}
	op, err = s.store.TransitionOperation(ctx, op.ID, op.Revision, controlplane.OperationPlanning, "", "operator")
	if err != nil {
		t.Fatal(err)
	}
	op, err = s.store.TransitionOperation(ctx, op.ID, op.Revision, controlplane.OperationQueued, "", "operator")
	if err != nil {
		t.Fatal(err)
	}
	lease, err := s.store.ClaimOperation(ctx, op.ID, "worker-a", time.Minute, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	op, _ = s.store.GetOperation(ctx, op.ID)
	op, err = s.store.StartOperationAttempt(ctx, op.ID, op.Revision, "worker-a", lease.FenceToken, "worker-a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.store.AppendOperationStep(ctx, controlplane.OperationStep{OperationID: op.ID, StepKey: "apply", State: controlplane.OperationRunning, FenceToken: lease.FenceToken}, "worker-a"); err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"resource":"deployment/api","observed":"ready"}`)
	body := fmt.Sprintf(`{"workerId":"worker-a","fenceToken":%d,"traceKey":"apply-ready-1","level":"INFO","eventType":"resource.ready","message":"deployment became ready","evidenceKind":"resource-readback","mediaType":"application/json","payloadBase64":%q}`, lease.FenceToken, base64.StdEncoding.EncodeToString(payload))
	w := apiRequest(t, s.Handler(), http.MethodPost, "/api/v1/operations/"+op.ID+"/steps/forward/apply/trace", body, map[string]string{"X-Actor-ID": "operator"})
	if w.Code != http.StatusCreated {
		t.Fatalf("trace status=%d body=%s", w.Code, w.Body.String())
	}
	var created struct {
		Method   string                          `json:"method"`
		Trace    controlplane.OperationStepTrace `json:"trace"`
		Evidence controlplane.EvidenceMetadata   `json:"evidence"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Method != controlplane.OperationStepTraceMethod || created.Trace.Attempt != 1 || created.Trace.Sequence != 1 || !created.Evidence.HasPayload || created.Evidence.TraceID != created.Trace.ID {
		t.Fatalf("created=%+v", created)
	}

	// Same traceKey is idempotent only for the same content.
	w = apiRequest(t, s.Handler(), http.MethodPost, "/api/v1/operations/"+op.ID+"/steps/forward/apply/trace", body, map[string]string{"X-Actor-ID": "operator"})
	if w.Code != http.StatusCreated {
		t.Fatalf("replay status=%d body=%s", w.Code, w.Body.String())
	}
	conflict := fmt.Sprintf(`{"workerId":"worker-a","fenceToken":%d,"traceKey":"apply-ready-1","level":"ERROR","eventType":"resource.ready","message":"changed","evidenceKind":"resource-readback","mediaType":"application/json","payloadBase64":%q}`, lease.FenceToken, base64.StdEncoding.EncodeToString(payload))
	w = apiRequest(t, s.Handler(), http.MethodPost, "/api/v1/operations/"+op.ID+"/steps/forward/apply/trace", conflict, map[string]string{"X-Actor-ID": "operator"})
	if w.Code != http.StatusConflict {
		t.Fatalf("idempotency conflict status=%d body=%s", w.Code, w.Body.String())
	}

	w = apiRequest(t, s.Handler(), http.MethodGet, "/api/v1/operations/"+op.ID+"/evidence/"+created.Evidence.ID+"/payload", "", map[string]string{"X-Actor-ID": "operator"})
	if w.Code != http.StatusOK || string(w.Body.Bytes()) != string(payload) || w.Header().Get("X-Evidence-Digest") != created.Evidence.Digest || w.Header().Get("X-Operation-Step-Key") != "apply" {
		t.Fatalf("payload status=%d headers=%v body=%s", w.Code, w.Header(), w.Body.String())
	}

	w = apiRequest(t, s.Handler(), http.MethodGet, "/api/v1/operations/"+op.ID, "", map[string]string{"X-Actor-ID": "operator"})
	if w.Code != http.StatusOK {
		t.Fatalf("get status=%d body=%s", w.Code, w.Body.String())
	}
	var view struct {
		TraceMethod string                            `json:"traceMethod"`
		Traces      []controlplane.OperationStepTrace `json:"traces"`
		Evidence    []controlplane.EvidenceMetadata   `json:"evidence"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if view.TraceMethod != controlplane.OperationStepTraceMethod || len(view.Traces) != 1 || len(view.Evidence) != 1 {
		t.Fatalf("view=%+v", view)
	}

	audits, err := s.store.ListAudit(ctx, 1000)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range audits {
		if a.Action == "operation_step.trace_sealed" && a.ResourceID == created.Trace.ID && a.Metadata["evidenceId"] == created.Evidence.ID {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("trace audit linkage missing")
	}
}
