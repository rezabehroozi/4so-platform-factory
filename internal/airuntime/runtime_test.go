package airuntime

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestResponsesRuntimeRedactsAndEnforcesStructuredEnvelope(t *testing.T) {
	seen := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		seen, _ = body["input"].(string)
		if strings.Contains(seen, "abcdefghijklmno") || strings.Contains(seen, "abcdefghijklmnopqrstuvwxyz") {
			t.Fatalf("secret reached provider: %s", seen)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"output_text":"{\"classification\":\"environment\",\"summary\":\"ssh failed\",\"owner\":\"lab\",\"recommendedChecks\":[],\"recommendedFix\":\"check route\",\"confidence\":90}","usage":{"input_tokens":10,"output_tokens":20,"input_tokens_details":{"cached_tokens":4}}}`))
	}))
	defer server.Close()
	runtime, err := New(Config{Provider: ProviderOpenAIResponses, Endpoint: server.URL, Model: "test", MaxInputBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	result, err := runtime.Generate(context.Background(), Request{Purpose: "lab-diagnosis", PromptID: PromptLabFailureDiagnosis, System: DiagnosisSystem(), Input: map[string]any{"password": "abcdefghijklmno", "log": "Authorization: Bearer abcdefghijklmnopqrstuvwxyz"}, JSONSchema: DiagnosisSchema()})
	if err != nil {
		t.Fatal(err)
	}
	if result.RedactionCount < 2 || result.Usage.CachedTokens != 4 || result.Provider != ProviderOpenAIResponses || len(result.JSON) == 0 {
		t.Fatalf("result=%+v seen=%s", result, seen)
	}
}

func TestRuntimeRejectsOversizedContextAfterRedaction(t *testing.T) {
	runtime, err := New(Config{Provider: ProviderOpenAIResponses, Endpoint: "http://127.0.0.1:1", Model: "test", MaxInputBytes: 2048})
	if err != nil {
		t.Fatal(err)
	}
	_, err = runtime.Generate(context.Background(), Request{Purpose: "x", PromptID: "p", System: "system", Input: map[string]any{"log": strings.Repeat("x", 3000)}})
	if err == nil || !strings.Contains(err.Error(), "byte budget") {
		t.Fatalf("err=%v", err)
	}
}

func TestConfigFromEnvSelectsResponsesAndEnforcesBudgets(t *testing.T) {
	values := map[string]string{
		"PLATFORM_FACTORY_AI_PROVIDER":          ProviderOpenAIResponses,
		"PLATFORM_FACTORY_AI_RESPONSES_URL":     "http://127.0.0.1/responses",
		"PLATFORM_FACTORY_AI_MODEL":             "test-model",
		"PLATFORM_FACTORY_AI_MAX_INPUT_BYTES":   "4096",
		"PLATFORM_FACTORY_AI_MAX_OUTPUT_TOKENS": "500",
		"PLATFORM_FACTORY_AI_TIMEOUT":           "5s",
	}
	config, err := ConfigFromEnv(func(k string) string { return values[k] })
	if err != nil {
		t.Fatal(err)
	}
	if config.Provider != ProviderOpenAIResponses || config.Endpoint != values["PLATFORM_FACTORY_AI_RESPONSES_URL"] || config.MaxInputBytes != 4096 || config.MaxOutputTokens != 500 || config.Timeout != 5*time.Second {
		t.Fatalf("unexpected config: %+v", config)
	}
}

func TestConfigFromEnvRejectsInvalidBudgetBeforeRuntime(t *testing.T) {
	values := map[string]string{"PLATFORM_FACTORY_AI_MAX_INPUT_BYTES": "999999"}
	if _, err := ConfigFromEnv(func(k string) string { return values[k] }); err == nil {
		t.Fatal("expected invalid AI input budget to fail")
	}
}
