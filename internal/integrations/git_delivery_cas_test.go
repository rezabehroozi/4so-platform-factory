package integrations

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func forgejoCASTestClient(t *testing.T, handler http.Handler) (*Client, func()) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Setenv("PF_GIT_CAS_TEST_SECRET", "secret")
	client := New(Config{GitConnectionResolver: func(context.Context) (GitConnection, error) {
		return GitConnection{BaseURL: server.URL, CredentialID: "cred-cas", Username: "admin", SecretRef: "env://PF_GIT_CAS_TEST_SECRET"}, nil
	}})
	return client, server.Close
}

func TestMergePullRequestBindsApprovedHeadCommit(t *testing.T) {
	expectedHead := strings.Repeat("a", 40)
	mainCommit := strings.Repeat("b", 40)
	mergeSeen := false
	client, closeServer := forgejoCASTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/repos/platform/desired-state/pulls/7/merge":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode merge: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if body["Do"] != "merge" || body["head_commit_id"] != expectedHead {
				t.Errorf("merge payload=%v", body)
			}
			mergeSeen = true
			_ = json.NewEncoder(w).Encode(map[string]any{"merged": true})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/repos/platform/desired-state/branches/main":
			_ = json.NewEncoder(w).Encode(map[string]any{"commit": map[string]string{"id": mainCommit}})
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer closeServer()
	result, err := client.MergePullRequest(context.Background(), "platform", "desired-state", 7, expectedHead)
	if err != nil {
		t.Fatal(err)
	}
	if !mergeSeen || result.CommitSHA != mainCommit {
		t.Fatalf("mergeSeen=%v result=%+v", mergeSeen, result)
	}
}

func TestManagedBranchCASUsesForgejoFastForwardOnlyWithoutBranchRefUpdate(t *testing.T) {
	expectedBase := strings.Repeat("1", 40)
	stageCommit := strings.Repeat("2", 40)
	var mu sync.Mutex
	targetCommit := expectedBase
	mergeSeen := false
	client, closeServer := forgejoCASTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/branches/") {
			t.Errorf("unsupported Gitea branch-ref update endpoint must never be used: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		switch {
		case r.Method == http.MethodPatch && r.URL.Path == "/api/v1/repos/platform/desired-state":
			_ = json.NewEncoder(w).Encode(map[string]any{"allow_fast_forward_only_merge": true})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/repos/platform/desired-state/branches/main":
			_ = json.NewEncoder(w).Encode(map[string]any{"commit": map[string]string{"id": targetCommit}})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/repos/platform/desired-state/pulls":
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"number": 9})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/repos/platform/desired-state/pulls/9":
			_ = json.NewEncoder(w).Encode(map[string]any{"number": 9, "state": "open", "merged": false, "base": map[string]string{"ref": "main", "sha": expectedBase}, "head": map[string]string{"ref": "platform-stage", "sha": stageCommit}})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/repos/platform/desired-state/pulls/9/reviews":
			_ = json.NewEncoder(w).Encode([]any{})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/repos/platform/desired-state/pulls/9/merge":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode ff merge: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if body["Do"] != "fast-forward-only" || body["head_commit_id"] != stageCommit {
				t.Errorf("ff merge payload=%v", body)
			}
			mergeSeen = true
			targetCommit = stageCommit
			_ = json.NewEncoder(w).Encode(map[string]any{"merged": true})
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer closeServer()
	if err := client.mergeStagedBranchFastForward(context.Background(), "platform", "desired-state", "main", "platform-stage", expectedBase, stageCommit); err != nil {
		t.Fatal(err)
	}
	if !mergeSeen || targetCommit != stageCommit {
		t.Fatalf("mergeSeen=%v target=%s", mergeSeen, targetCommit)
	}
}

func TestManagedBranchCASRejectsBaseMovementBeforeFastForwardMerge(t *testing.T) {
	expectedBase := strings.Repeat("3", 40)
	movedBase := strings.Repeat("4", 40)
	stageCommit := strings.Repeat("5", 40)
	var mu sync.Mutex
	targetReads := 0
	mergeCalls := 0
	client, closeServer := forgejoCASTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodPatch && r.URL.Path == "/api/v1/repos/platform/desired-state":
			_ = json.NewEncoder(w).Encode(map[string]any{"allow_fast_forward_only_merge": true})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/repos/platform/desired-state/branches/main":
			targetReads++
			commit := expectedBase
			if targetReads > 1 {
				commit = movedBase
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"commit": map[string]string{"id": commit}})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/repos/platform/desired-state/pulls":
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"number": 10})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/repos/platform/desired-state/pulls/10":
			_ = json.NewEncoder(w).Encode(map[string]any{"number": 10, "state": "open", "merged": false, "base": map[string]string{"ref": "main", "sha": expectedBase}, "head": map[string]string{"ref": "platform-stage", "sha": stageCommit}})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/repos/platform/desired-state/pulls/10/reviews":
			_ = json.NewEncoder(w).Encode([]any{})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/repos/platform/desired-state/pulls/10/merge":
			mergeCalls++
			_ = json.NewEncoder(w).Encode(map[string]any{"merged": true})
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer closeServer()
	err := client.mergeStagedBranchFastForward(context.Background(), "platform", "desired-state", "main", "platform-stage", expectedBase, stageCommit)
	if err == nil || !strings.Contains(err.Error(), "target branch changed") || mergeCalls != 0 {
		t.Fatalf("err=%v mergeCalls=%d", err, mergeCalls)
	}
}

func TestManagedBranchCASCapabilityFailureHasNoStagingSideEffect(t *testing.T) {
	expectedBase := strings.Repeat("6", 40)
	requests := []string{}
	client, closeServer := forgejoCASTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		if r.Method == http.MethodPatch && r.URL.Path == "/api/v1/repos/platform/desired-state" {
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = w.Write([]byte(`{"message":"unsupported repository merge capability"}`))
			return
		}
		t.Errorf("capability failure must occur before any other Git mutation: %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)
	}))
	defer closeServer()
	_, _, err := client.commitManagedFilesWithBranchCAS(context.Background(), "platform", "desired-state", "main", expectedBase, "platform-direct-rev", map[string][]byte{".platform/revision.json": []byte("x")}, "test")
	if err == nil || !strings.Contains(err.Error(), "fast-forward-only") {
		t.Fatalf("expected capability failure, got %v", err)
	}
	if len(requests) != 1 || requests[0] != "PATCH /api/v1/repos/platform/desired-state" {
		t.Fatalf("unexpected side effects before capability rejection: %v", requests)
	}
}
