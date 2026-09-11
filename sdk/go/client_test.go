package factorysdk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func TestClientExecutesFixedRouteWithoutAutomaticMutationRetry(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/api/v1/projects/project%2Fone" && r.URL.Path != "/api/v1/projects/project/one" {
			t.Fatalf("path=%q", r.URL.Path)
		}
		if r.URL.Query().Get("view") != "summary" || r.Header.Get("Authorization") != "Bearer token-a" {
			t.Fatalf("query=%q auth=%q", r.URL.RawQuery, r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"code":"TEMPORARY"}`))
	}))
	defer srv.Close()

	client, err := NewClient(srv.URL, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	client.BearerToken = "token-a"
	route := Route{Method: http.MethodPost, Path: "/api/v1/projects/{id}", PathParams: []string{"id"}, Mutation: true}
	var out map[string]any
	_, err = client.Do(context.Background(), route, map[string]string{"id": "project/one"}, url.Values{"view": {"summary"}}, map[string]any{"displayName": "Project"}, nil, &out)
	var apiErr *APIError
	if err == nil || !strings.Contains(err.Error(), "503") || calls.Load() != 1 {
		t.Fatalf("err=%v calls=%d", err, calls.Load())
	}
	if !AsAPIError(err, &apiErr) || apiErr.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("apiErr=%#v err=%v", apiErr, err)
	}
}

func TestClientRejectsMissingPathParameterBeforeNetwork(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer srv.Close()
	client, err := NewClient(srv.URL, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Do(context.Background(), Route{Method: http.MethodGet, Path: "/api/v1/projects/{id}", PathParams: []string{"id"}}, nil, nil, nil, nil, nil)
	if err == nil || calls.Load() != 0 {
		t.Fatalf("err=%v calls=%d", err, calls.Load())
	}
}

func TestClientDecodesSuccessfulBoundedJSONResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	}))
	defer srv.Close()
	client, err := NewClient(srv.URL, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	resp, err := client.Do(context.Background(), Route{Method: http.MethodGet, Path: "/api/v1/health"}, nil, nil, nil, nil, &out)
	if err != nil || resp.StatusCode != http.StatusOK || out["ok"] != true {
		t.Fatalf("resp=%v out=%v err=%v", resp, out, err)
	}
}
