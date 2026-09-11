package airuntime

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
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

func TestProviderTransportRejectsNonLoopbackPlainHTTP(t *testing.T) {
	_, err := New(Config{Provider: ProviderOpenAIResponses, Endpoint: "http://192.0.2.10/v1/responses", APIKey: "secret", Model: "test"})
	if err == nil || !strings.Contains(err.Error(), "must use HTTPS") {
		t.Fatalf("expected non-loopback HTTP provider to fail closed, err=%v", err)
	}
	if _, err := New(Config{Provider: ProviderOpenAIResponses, Endpoint: "http://localhost:8080/v1/responses", Model: "test"}); err != nil {
		t.Fatalf("loopback HTTP test endpoint should remain supported: %v", err)
	}
	if _, err := New(Config{Provider: ProviderOpenAIResponses, Endpoint: "http://[::1]:8080/v1/responses", Model: "test"}); err != nil {
		t.Fatalf("IPv6 loopback HTTP test endpoint should remain supported: %v", err)
	}
}

func TestProviderTransportRejectsURLCredentialsAndNonHTTPSSchemes(t *testing.T) {
	for _, endpoint := range []string{
		"https://user:password@example.com/v1/responses",
		"https://example.com/v1/responses#fragment",
		"file:///tmp/provider",
	} {
		if _, err := New(Config{Provider: ProviderOpenAIResponses, Endpoint: endpoint, Model: "test"}); err == nil {
			t.Fatalf("expected provider endpoint %q to fail closed", endpoint)
		}
	}
}

func TestResponsesRuntimeRejectsDuplicateKeysInProviderEnvelope(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"output_text":"{}","output_text":"{}","usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer server.Close()
	runtime, err := New(Config{Provider: ProviderOpenAIResponses, Endpoint: server.URL + "/v1/responses", Model: "test"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = runtime.Generate(context.Background(), Request{Purpose: "x", PromptID: "p", System: "system", Input: map[string]any{"value": "safe"}})
	if err == nil || !strings.Contains(err.Error(), "envelope contains ambiguous JSON") {
		t.Fatalf("expected duplicate provider envelope key rejection, err=%v", err)
	}
}

func TestResponsesRuntimeRejectsDuplicateKeysInStructuredOutput(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"output_text":"{\"classification\":\"environment\",\"classification\":\"product-defect\",\"summary\":\"x\",\"owner\":\"lab\",\"recommendedChecks\":[],\"recommendedFix\":\"y\",\"confidence\":90}","usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer server.Close()
	runtime, err := New(Config{Provider: ProviderOpenAIResponses, Endpoint: server.URL + "/v1/responses", Model: "test"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = runtime.Generate(context.Background(), Request{Purpose: "x", PromptID: "p", System: "system", Input: map[string]any{"value": "safe"}})
	if err == nil || !strings.Contains(err.Error(), "output contains ambiguous JSON") {
		t.Fatalf("expected duplicate structured-output key rejection, err=%v", err)
	}
}

func TestProviderTransportRejectsCrossOriginRedirectBeforeFollow(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://192.0.2.10/steal", http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	runtime, err := New(Config{Provider: ProviderOpenAIResponses, Endpoint: server.URL + "/v1/responses", APIKey: "secret", Model: "test"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = runtime.Generate(context.Background(), Request{Purpose: "x", PromptID: "p", System: "system", Input: map[string]any{"value": "safe"}})
	if err == nil || !strings.Contains(err.Error(), "redirect rejected") {
		t.Fatalf("expected redirect transport authority to reject downgrade/cross-origin redirect, err=%v", err)
	}
}

func TestProviderTransportAllowsSameOriginRedirect(t *testing.T) {
	server := httptest.NewServer(nil)
	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/v1/responses", http.StatusTemporaryRedirect)
	})
	mux.HandleFunc("/v1/responses", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"output_text":"{}","usage":{"input_tokens":1,"output_tokens":1}}`))
	})
	server.Config.Handler = mux
	defer server.Close()
	runtime, err := New(Config{Provider: ProviderOpenAIResponses, Endpoint: server.URL + "/start", Model: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = runtime.Generate(context.Background(), Request{Purpose: "x", PromptID: "p", System: "system", Input: map[string]any{"value": "safe"}}); err != nil {
		t.Fatalf("same-origin redirect should remain supported: %v", err)
	}
}

func TestProviderTransportRejectsUnsafeLiteralHTTPSAddresses(t *testing.T) {
	for _, endpoint := range []string{
		"https://169.254.169.254/v1/responses",
		"https://[fe80::1]/v1/responses",
		"https://0.0.0.0/v1/responses",
		"https://[::]/v1/responses",
		"https://224.0.0.1/v1/responses",
	} {
		if _, err := New(Config{Provider: ProviderOpenAIResponses, Endpoint: endpoint, Model: "test"}); err == nil {
			t.Fatalf("expected unsafe provider endpoint %q to fail closed", endpoint)
		}
	}
	for _, endpoint := range []string{
		"https://10.20.30.40/v1/responses",
		"https://192.168.1.10/v1/responses",
		"https://127.0.0.1/v1/responses",
	} {
		if _, err := New(Config{Provider: ProviderOpenAIResponses, Endpoint: endpoint, Model: "test"}); err != nil {
			t.Fatalf("private/self-hosted HTTPS provider %q should remain supported: %v", endpoint, err)
		}
	}
}

func TestProviderTransportRejectsUnsafeResolutionBeforeDial(t *testing.T) {
	endpoint, err := url.Parse("https://provider.example/v1/responses")
	if err != nil {
		t.Fatal(err)
	}
	lookups := 0
	dials := 0
	client := newProviderHTTPClient(endpoint, time.Second,
		func(context.Context, string, string) ([]netip.Addr, error) {
			lookups++
			return []netip.Addr{netip.MustParseAddr("203.0.113.10"), netip.MustParseAddr("169.254.169.254")}, nil
		},
		func(context.Context, string, string) (net.Conn, error) {
			dials++
			return nil, errors.New("unexpected dial")
		},
	)
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.DialContext == nil {
		t.Fatal("provider transport did not install controlled dialer")
	}
	_, err = transport.DialContext(context.Background(), "tcp", "provider.example:443")
	if err == nil || !strings.Contains(err.Error(), "unsafe address") {
		t.Fatalf("unsafe DNS resolution was not rejected: %v", err)
	}
	if lookups != 1 || dials != 0 {
		t.Fatalf("unsafe resolution must fail before connect: lookups=%d dials=%d", lookups, dials)
	}
}

func TestProviderTransportDialsValidatedAddressAndIgnoresEnvironmentProxy(t *testing.T) {
	endpoint, err := url.Parse("https://provider.example/v1/responses")
	if err != nil {
		t.Fatal(err)
	}
	var dialed string
	client := newProviderHTTPClient(endpoint, time.Second,
		func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("203.0.113.77")}, nil
		},
		func(_ context.Context, _ string, address string) (net.Conn, error) {
			dialed = address
			return nil, errors.New("sentinel dial stop")
		},
	)
	transport := client.Transport.(*http.Transport)
	if transport.Proxy != nil {
		t.Fatal("AI provider transport must not inherit implicit environment proxy authority")
	}
	_, err = transport.DialContext(context.Background(), "tcp", "provider.example:443")
	if err == nil || !strings.Contains(err.Error(), "sentinel dial stop") {
		t.Fatalf("expected sentinel dial error, got %v", err)
	}
	if dialed != "203.0.113.77:443" {
		t.Fatalf("provider connection was not pinned to validated IP: %q", dialed)
	}
}
