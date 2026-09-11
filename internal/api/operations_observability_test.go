package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"platform.4so.io/factory/internal/controlplane"
)

func TestOperationsQueueCenterScopesBeforeWindowAndExposesNoWorkerControls(t *testing.T) {
	store := controlplane.NewMemoryStore()
	orgA, projectA, _, opA := seedOrganizationScope(t, store)
	_, projectB, _, opB := seedOrganizationScope(t, store)
	if _, err := store.UpsertOrganizationMembership(context.Background(), controlplane.OrganizationMembership{OrganizationID: orgA.ID, Subject: "queue-user", Role: controlplane.OrganizationOperator}, 0, "bootstrap-admin"); err != nil {
		t.Fatal(err)
	}
	s := scopedServer(t, store)
	w := scopedRequest(t, s, http.MethodGet, "/api/v1/operations/queue-center?limit=100", "", "queue-user", "platform-operator")
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var got operationsQueueCenterView
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Authority != operationsQueueCenterAuthority || got.Backend == "" || len(got.Lanes) != 4 {
		t.Fatalf("unexpected queue-center envelope: %#v", got)
	}
	found := false
	for _, item := range got.Items {
		if item.ProjectID == projectB.ID || item.ID == opB.ID {
			t.Fatalf("cross-project queue item leaked: %#v", item)
		}
		if item.ID == opA.ID && item.ProjectID == projectA.ID {
			found = true
		}
	}
	if !found {
		t.Fatalf("authorized operation %s not present: %#v", opA.ID, got.Items)
	}
	foundAgentLane := false
	for _, lane := range got.Lanes {
		if lane.ID == "agent-tasks" {
			foundAgentLane = true
		}
	}
	if !foundAgentLane {
		t.Fatalf("agent task aggregate lane missing: %#v", got.Lanes)
	}
	if got.Safety["rawWorkerControls"] != false || got.Safety["scopeBeforeLimit"] != true || got.Safety["agentTaskItemsExposed"] != false || got.Safety["agentTaskPayloadsExposed"] != false {
		t.Fatalf("queue-center safety contract drifted: %#v", got.Safety)
	}
	if strings.Contains(w.Body.String(), "claimOperation") || strings.Contains(w.Body.String(), "transitionOperation") {
		t.Fatalf("raw worker control leaked in queue-center response: %s", w.Body.String())
	}
}

func TestProductLogCenterScopesAuditAndReportsBoundedSearchSemantics(t *testing.T) {
	store := controlplane.NewMemoryStore()
	orgA, projectA, _, opA := seedOrganizationScope(t, store)
	_, projectB, _, opB := seedOrganizationScope(t, store)
	if _, err := store.UpsertOrganizationMembership(context.Background(), controlplane.OrganizationMembership{OrganizationID: orgA.ID, Subject: "log-user", Role: controlplane.OrganizationViewer}, 0, "bootstrap-admin"); err != nil {
		t.Fatal(err)
	}
	s := scopedServer(t, store)
	w := scopedRequest(t, s, http.MethodGet, "/api/v1/logs?source=audit&limit=200&q=operation", "", "log-user", "platform-viewer")
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var got struct {
		Authority       string            `json:"authority"`
		Entries         []productLogEntry `json:"entries"`
		SearchSemantics string            `json:"searchSemantics"`
		PayloadPolicy   string            `json:"payloadPolicy"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Authority != productLogCenterAuthority || got.SearchSemantics != "LATEST_AUTHORIZED_PRODUCT_LOG_WINDOWS_V1" || got.PayloadPolicy != "METADATA_AND_REDACTED_MESSAGES_ONLY" {
		t.Fatalf("unexpected log-center envelope: %#v", got)
	}
	body := w.Body.String()
	if strings.Contains(body, projectB.ID) || strings.Contains(body, opB.ID) {
		t.Fatalf("cross-project log data leaked: %s", body)
	}
	// The authorized operation creation is audit-visible even though raw evidence
	// payload bytes are intentionally not part of the Product Log Center.
	if !strings.Contains(body, opA.ID) && !strings.Contains(body, projectA.ID) {
		t.Fatalf("authorized audit context missing: %s", body)
	}
}

func TestProductLogCenterOperationFilterNeverWidensScope(t *testing.T) {
	store := controlplane.NewMemoryStore()
	orgA, _, _, _ := seedOrganizationScope(t, store)
	_, _, _, opB := seedOrganizationScope(t, store)
	if _, err := store.UpsertOrganizationMembership(context.Background(), controlplane.OrganizationMembership{OrganizationID: orgA.ID, Subject: "log-user", Role: controlplane.OrganizationViewer}, 0, "bootstrap-admin"); err != nil {
		t.Fatal(err)
	}
	s := scopedServer(t, store)
	w := scopedRequest(t, s, http.MethodGet, "/api/v1/logs?source=operation&operationId="+opB.ID, "", "log-user", "platform-viewer")
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), opB.ID) {
		t.Fatalf("foreign operation became visible through operationId filter: %s", w.Body.String())
	}
}

func TestProductLogCenterReturnsSealedOperationTraceWithoutPayloadBytes(t *testing.T) {
	store := controlplane.NewMemoryStore()
	org, project, _, op := seedOrganizationScope(t, store)
	if _, err := store.UpsertOrganizationMembership(context.Background(), controlplane.OrganizationMembership{OrganizationID: org.ID, Subject: "trace-reader", Role: controlplane.OrganizationViewer}, 0, "bootstrap-admin"); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	var err error
	op, err = store.TransitionOperation(ctx, op.ID, op.Revision, controlplane.OperationPlanning, "", "bootstrap-admin")
	if err != nil {
		t.Fatal(err)
	}
	op, err = store.TransitionOperation(ctx, op.ID, op.Revision, controlplane.OperationQueued, "", "bootstrap-admin")
	if err != nil {
		t.Fatal(err)
	}
	lease, err := store.ClaimOperation(ctx, op.ID, "trace-worker", time.Minute, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	op, err = store.GetOperation(ctx, op.ID)
	if err != nil {
		t.Fatal(err)
	}
	op, err = store.StartOperationAttempt(ctx, op.ID, op.Revision, "trace-worker", lease.FenceToken, "trace-worker")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.AppendOperationStep(ctx, controlplane.OperationStep{OperationID: op.ID, StepKey: "apply", State: controlplane.OperationRunning, FenceToken: lease.FenceToken}, "trace-worker"); err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"secret":"must-not-appear-in-log-center","resource":"deployment/api"}`)
	trace, evidence, err := store.AppendOperationStepTrace(ctx, controlplane.OperationStepTraceInput{
		OperationID: op.ID, Phase: controlplane.OperationStepPhaseForward, StepKey: "apply", TraceKey: "ready-1",
		Level: controlplane.OperationStepLogInfo, EventType: "resource.ready", Message: "deployment became ready",
		EvidenceKind: "resource-readback", MediaType: "application/json", Payload: payload,
	}, "trace-worker", lease.FenceToken, "trace-worker")
	if err != nil {
		t.Fatal(err)
	}

	s := scopedServer(t, store)
	w := scopedRequest(t, s, http.MethodGet, "/api/v1/logs?source=operation&operationId="+op.ID+"&limit=100", "", "trace-reader", "platform-viewer")
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), trace.ID) || !strings.Contains(w.Body.String(), evidence.Digest) || !strings.Contains(w.Body.String(), project.ID) {
		t.Fatalf("sealed trace metadata missing: %s", w.Body.String())
	}
	if strings.Contains(w.Body.String(), "must-not-appear-in-log-center") {
		t.Fatalf("raw evidence payload leaked through Product Log Center: %s", w.Body.String())
	}
}

func TestOperationsObservabilityPlatformAdminCanUseBoundedGlobalRead(t *testing.T) {
	store := controlplane.NewMemoryStore()
	_, _, _, opA := seedOrganizationScope(t, store)
	_, _, _, opB := seedOrganizationScope(t, store)
	s := scopedServer(t, store)

	queue := scopedRequest(t, s, http.MethodGet, "/api/v1/operations/queue-center?limit=100", "", "global-admin", "platform-admin")
	if queue.Code != http.StatusOK {
		t.Fatalf("queue status=%d body=%s", queue.Code, queue.Body.String())
	}
	if !strings.Contains(queue.Body.String(), opA.ID) || !strings.Contains(queue.Body.String(), opB.ID) {
		t.Fatalf("bounded global queue omitted authorized projects: %s", queue.Body.String())
	}

	logs := scopedRequest(t, s, http.MethodGet, "/api/v1/logs?source=audit&limit=200", "", "global-admin", "platform-admin")
	if logs.Code != http.StatusOK {
		t.Fatalf("logs status=%d body=%s", logs.Code, logs.Body.String())
	}
	if !strings.Contains(logs.Body.String(), opA.ID) || !strings.Contains(logs.Body.String(), opB.ID) {
		t.Fatalf("bounded global logs omitted authorized project audit: %s", logs.Body.String())
	}
}
