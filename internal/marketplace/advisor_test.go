package marketplace

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestControlledAdvisorAcceptsOnlyAllowlistedStrictJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatalf("authorization missing")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"recommendations\":[{\"offerId\":\"secure-namespace-foundation\",\"offerVersion\":\"1.0.0\",\"score\":91,\"reason\":\"Approval-bound security baseline.\"}]}"}}]}`))
	}))
	defer server.Close()
	advisor := NewControlledAdvisor(Config{Endpoint: server.URL, APIKey: "test-token", Model: "qwen-local"})
	out, err := advisor.Recommend(context.Background(), AdvisoryInput{Objective: "Improve cluster security"}, Catalog())
	if err != nil {
		t.Fatal(err)
	}
	if out.Engine != "model" || out.Model != "qwen-local" || len(out.Recommendations) != 1 || out.Recommendations[0].Risk != "medium" {
		t.Fatalf("output=%#v", out)
	}
}

func TestControlledAdvisorRejectsUnknownOffer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"recommendations\":[{\"offerId\":\"shell-access\",\"offerVersion\":\"1.0.0\",\"score\":100,\"reason\":\"bad\"}]}"}}]}`))
	}))
	defer server.Close()
	advisor := NewControlledAdvisor(Config{Endpoint: server.URL, Model: "test"})
	_, err := advisor.Recommend(context.Background(), AdvisoryInput{Objective: "anything"}, Catalog())
	if err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("unknown offer accepted: %v", err)
	}
}

func TestControlledAdvisorRejectsInvalidConfiguredProvider(t *testing.T) {
	advisor := NewControlledAdvisor(Config{Provider: "not-a-provider", Endpoint: "http://127.0.0.1", Model: "x"})
	_, err := advisor.Recommend(context.Background(), AdvisoryInput{Objective: "secure baseline"}, Catalog())
	if err == nil || !strings.Contains(err.Error(), "invalid AI advisor configuration") {
		t.Fatalf("expected invalid configuration error, got %v", err)
	}
}
