package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"platform.4so.io/factory/internal/airuntime"
	"platform.4so.io/factory/internal/controlplane"
)

func aiDiagnosisFixture(t *testing.T) (*Server, *controlplane.MemoryStore, controlplane.Project, controlplane.Operation, *atomic.Int32) {
	t.Helper()
	store := controlplane.NewMemoryStore()
	ctx := context.Background()
	org, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "ai-api-org", DisplayName: "AI API"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "ai-api-project", DisplayName: "AI API Project"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	op, _, err := store.CreateOperation(ctx, controlplane.OperationRequest{ProjectID: project.ID, Kind: "cluster.inspect", TargetRef: "cluster/demo", DesiredRevision: "sha256:" + strings.Repeat("a", 64), Risk: "low", Class: controlplane.OperationClassReadOnly}, "ai-op-key", "operator", "req")
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		input, _ := body["input"].(string)
		if strings.Contains(input, "super-secret") || strings.Contains(input, "secret-token-abcdefghijklmnopqrstuvwxyz") {
			t.Fatalf("secret reached provider: %s", input)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"output_text":"{\"classification\":\"environment\",\"summary\":\"target connectivity is unavailable\",\"owner\":\"network\",\"recommendedChecks\":[\"verify route\"],\"recommendedFix\":\"repair the network path after deterministic verification\",\"confidence\":88}","usage":{"input_tokens":11,"output_tokens":22,"input_tokens_details":{"cached_tokens":3}}}`))
	}))
	t.Cleanup(provider.Close)
	runtime, err := airuntime.New(airuntime.Config{Provider: airuntime.ProviderOpenAIResponses, Endpoint: provider.URL, Model: "test-model", MaxInputBytes: 8192, MaxOutputTokens: 600})
	if err != nil {
		t.Fatal(err)
	}
	s := New("test", nil, nil, store)
	s.ConfigureAIRuntime(runtime)
	return s, store, project, op, &calls
}

func TestAIDiagnosisRedactsPersistsAndReplaysWithoutSecondProviderCall(t *testing.T) {
	s, store, project, op, calls := aiDiagnosisFixture(t)
	body := fmt.Sprintf(`{"projectId":%q,"operationId":%q,"question":"password=super-secret Authorization: Bearer secret-token-abcdefghijklmnopqrstuvwxyz why did this fail?"}`, project.ID, op.ID)
	headers := map[string]string{"X-Actor-ID": "operator", "Idempotency-Key": "ai-diagnose-1"}
	w := apiRequest(t, s.Handler(), http.MethodPost, "/api/v1/ai/diagnose", body, headers)
	if w.Code != http.StatusCreated {
		t.Fatalf("diagnose=%d body=%s", w.Code, w.Body.String())
	}
	var created struct {
		Run              controlplane.AIRun  `json:"run"`
		Diagnosis        airuntime.Diagnosis `json:"diagnosis"`
		AdvisoryOnly     bool                `json:"advisoryOnly"`
		ExecutionAllowed bool                `json:"executionAllowed"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 || !created.AdvisoryOnly || created.ExecutionAllowed || created.Run.RedactionCount < 2 || created.Run.Provider != airuntime.ProviderOpenAIResponses || created.Run.InputTokens != 11 || created.Run.CachedTokens != 3 || created.Diagnosis.Classification != "environment" {
		t.Fatalf("created=%+v calls=%d", created, calls.Load())
	}
	if strings.Contains(string(created.Run.Output), "super-secret") || strings.Contains(string(created.Run.Output), "secret-token") {
		t.Fatal("secret persisted in AI output")
	}
	values, err := store.ListAIRuns(context.Background(), project.ID)
	if err != nil || len(values) != 1 {
		t.Fatalf("runs=%+v err=%v", values, err)
	}

	w = apiRequest(t, s.Handler(), http.MethodPost, "/api/v1/ai/diagnose", body, headers)
	if w.Code != http.StatusOK || calls.Load() != 1 || !strings.Contains(w.Body.String(), `"idempotentReplay":true`) {
		t.Fatalf("replay=%d calls=%d body=%s", w.Code, calls.Load(), w.Body.String())
	}

	changed := fmt.Sprintf(`{"projectId":%q,"operationId":%q,"question":"different question"}`, project.ID, op.ID)
	w = apiRequest(t, s.Handler(), http.MethodPost, "/api/v1/ai/diagnose", changed, headers)
	if w.Code != http.StatusConflict || calls.Load() != 1 {
		t.Fatalf("conflict=%d calls=%d body=%s", w.Code, calls.Load(), w.Body.String())
	}
}

func TestAIDiagnosisFailsClosedWhenRuntimeDisabled(t *testing.T) {
	store := controlplane.NewMemoryStore()
	ctx := context.Background()
	org, _ := store.CreateOrganization(ctx, controlplane.Organization{Name: "ai-disabled-org", DisplayName: "AI Disabled"}, "admin")
	project, _ := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "ai-disabled", DisplayName: "AI Disabled"}, "admin")
	op, _, _ := store.CreateOperation(ctx, controlplane.OperationRequest{ProjectID: project.ID, Kind: "inspect", TargetRef: "x", DesiredRevision: "sha256:" + strings.Repeat("b", 64), Risk: "low", Class: controlplane.OperationClassReadOnly}, "disabled-op", "operator", "req")
	s := New("test", nil, nil, store)
	w := apiRequest(t, s.Handler(), http.MethodPost, "/api/v1/ai/diagnose", fmt.Sprintf(`{"projectId":%q,"operationId":%q,"question":"why?"}`, project.ID, op.ID), map[string]string{"X-Actor-ID": "operator", "Idempotency-Key": "disabled-1"})
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "AI_RUNTIME_DISABLED") {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}
