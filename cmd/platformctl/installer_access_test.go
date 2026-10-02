package main

import (
	"errors"
	"io"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"platform.4so.io/factory/internal/installeraccess"
)

type installerRoundTripFunc func(*http.Request) (*http.Response, error)

func (fn installerRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func TestInstallerMutationLostResponseUsesOnePostThenReadback(t *testing.T) {
	base, err := url.Parse("https://installer.example")
	if err != nil { t.Fatal(err) }
	tests := []struct {
		name    string
		path    string
		before  installerBootstrapRuntimeStatus
		after   installerBootstrapRuntimeStatus
		changed func(installerBootstrapRuntimeStatus, installerBootstrapRuntimeStatus) bool
	}{
		{
			name: "resume",
			path: "/api/v1/resume",
			before: installerBootstrapRuntimeStatus{ExecutionEnabled:true, Run:&installerRuntimeRunStatus{ID:"run-1",State:"FAILED",LastError:"interrupted"}},
			after: installerBootstrapRuntimeStatus{ExecutionEnabled:true, BootstrapActive:true, Run:&installerRuntimeRunStatus{ID:"run-1",State:"RUNNING"}},
			changed: installerStatusChangedForResume,
		},
		{
			name: "reset",
			path: "/api/v1/reset/start",
			before: installerBootstrapRuntimeStatus{ExecutionEnabled:true, Run:&installerRuntimeRunStatus{ID:"run-1",State:"SUCCEEDED"}},
			after: installerBootstrapRuntimeStatus{ExecutionEnabled:true, ResetActive:true, Run:&installerRuntimeRunStatus{ID:"run-1",State:"SUCCEEDED"}, ResetRuns:[]installerRuntimeRunStatus{{ID:"reset-1",State:"RUNNING"}}},
			changed: installerResetReadbackChanged,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			posts, gets := 0, 0
			client := &http.Client{Transport: installerRoundTripFunc(func(request *http.Request) (*http.Response, error) {
				switch request.Method {
				case http.MethodPost:
					posts++
					if request.URL.Path != test.path { t.Fatalf("POST path=%s want=%s", request.URL.Path, test.path) }
					// Simulate a remote mutation that committed before the network
					// response was lost. The client must read back and must not POST again.
					return nil, errors.New("simulated response loss after remote commit")
				case http.MethodGet:
					gets++
					if request.URL.Path != "/api/v1/status" { t.Fatalf("GET path=%s", request.URL.Path) }
					raw, marshalErr := json.Marshal(test.after)
					if marshalErr != nil { t.Fatal(marshalErr) }
					return &http.Response{
						StatusCode: http.StatusOK,
						Header: make(http.Header),
						Body: io.NopCloser(strings.NewReader(string(raw))),
						Request: request,
					}, nil
				default:
					t.Fatalf("unexpected method %s", request.Method)
					return nil, errors.New("unexpected method")
				}
			})}
			outcome, callErr := performInstallerMutationWithReadback(
				client, base, "bootstrap-token-abcdefghijklmnopqrstuvwxyz",
				test.path, nil, test.before, test.changed, test.name,
			)
			if callErr != nil { t.Fatal(callErr) }
			if outcome.StatusPending { t.Fatal("lost-response readback was incorrectly left status-pending") }
			if posts != 1 { t.Fatalf("POST count=%d want=1; automatic replay is forbidden", posts) }
			if gets != 1 { t.Fatalf("status readback count=%d want=1", gets) }
			if test.name == "resume" && !outcome.After.BootstrapActive { t.Fatal("resume readback did not prove active durable run") }
			if test.name == "reset" && !outcome.After.ResetActive { t.Fatal("reset readback did not prove active durable reset") }
		})
	}
}

func TestInstallerBootstrapNextActionIsStateSpecificAndNeverSuggestsReplay(t *testing.T) {
	if installerBootstrapActionGuidanceAuthority != "INSTALLER_BOOTSTRAP_ACTION_GUIDANCE_V1" {
		t.Fatalf("action guidance authority=%q", installerBootstrapActionGuidanceAuthority)
	}
	tests := []struct {
		name   string
		status installerBootstrapRuntimeStatus
		code   string
		want   string
	}{
		{"execution disabled", installerBootstrapRuntimeStatus{}, "REDEPLOY_EXECUTION_ENABLED", "execution enabled"},
		{"reset active", installerBootstrapRuntimeStatus{ExecutionEnabled:true, ResetActive:true}, "MONITOR_RESET", "monitor bootstrap-status"},
		{"reset interrupted", installerBootstrapRuntimeStatus{ExecutionEnabled:true, ResetRuns:[]installerRuntimeRunStatus{{ID:"reset-1", State:"FAILED"}}}, "RESUME_RESET", "reset-resume --confirmation RESUME-RESET"},
		{"install active", installerBootstrapRuntimeStatus{ExecutionEnabled:true, BootstrapActive:true, Run:&installerRuntimeRunStatus{ID:"run-1", State:"RUNNING"}}, "MONITOR_INSTALL", "monitor bootstrap-status"},
		{"not started", installerBootstrapRuntimeStatus{ExecutionEnabled:true}, "START_BROWSER_INSTALL", "Browser Installer"},
		{"succeeded", installerBootstrapRuntimeStatus{ExecutionEnabled:true, Run:&installerRuntimeRunStatus{ID:"run-1", State:"SUCCEEDED"}}, "VERIFY_INSTALL", "verify evidence/status"},
		{"failed", installerBootstrapRuntimeStatus{ExecutionEnabled:true, Run:&installerRuntimeRunStatus{ID:"run-1", State:"FAILED"}}, "RESUME_INSTALL", "resume --confirmation RESUME"},
		{"interrupted running", installerBootstrapRuntimeStatus{ExecutionEnabled:true, Run:&installerRuntimeRunStatus{ID:"run-1", State:"RUNNING"}}, "RESUME_INSTALL", "resume --confirmation RESUME"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			code, got := installerBootstrapNextActionGuidance(test.status)
			if code != test.code {
				t.Fatalf("nextActionCode=%q want=%q", code, test.code)
			}
			if installerBootstrapNextAction(test.status) != got {
				t.Fatalf("legacy nextAction wrapper drift: %q", installerBootstrapNextAction(test.status))
			}
			if !strings.Contains(got, test.want) {
				t.Fatalf("nextAction=%q want substring %q", got, test.want)
			}
			if strings.Contains(strings.ToLower(got), "replay the mutation") {
				t.Fatalf("nextAction must not recommend replay: %q", got)
			}
		})
	}
}

func TestInstallerAccessStatusAndRotateClient(t *testing.T) {
	var mu sync.Mutex
	current := "current-bootstrap-token-abcdefghijklmnopqrstuvwxyz"
	transport := installeraccess.TransportStatus{Mode: "https", Listen: "0.0.0.0:9443", TransportProtected: true}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer "+current {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api/v1/access/status":
			_ = json.NewEncoder(w).Encode(installeraccess.AccessStatus{Transport: transport, Token: installeraccess.TokenStatus{Authentication: "bearer-token", Source: installeraccess.TokenSourceExisting, Fingerprint: "sha256:1234567890abcdef", TokenFile: "bootstrap-token", RotatedAt: time.Now().UTC()}})
		case "/api/v1/access/token/rotate":
			var request struct {
				Confirmation string `json:"confirmation"`
				NewToken     string `json:"newToken"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil || request.Confirmation != "ROTATE" || len(request.NewToken) < 32 {
				http.Error(w, `{"error":"invalid"}`, http.StatusUnprocessableEntity)
				return
			}
			current = request.NewToken
			_ = json.NewEncoder(w).Encode(map[string]any{"rotated": true, "token": installeraccess.TokenStatus{Authentication: "bearer-token", Source: installeraccess.TokenSourceExisting, Fingerprint: "sha256:fedcba0987654321", TokenFile: "bootstrap-token", RotatedAt: time.Now().UTC()}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	base, _ := url.Parse(server.URL)
	status, err := fetchInstallerAccessStatus(server.Client(), base, current)
	if err != nil || status.Transport.Mode != "https" {
		t.Fatalf("status=%+v err=%v", status, err)
	}
	candidate := "candidate-bootstrap-token-abcdefghijklmnopqrstuvwxyz"
	status, err = rotateInstallerToken(server.Client(), base, current, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if status.Token.Fingerprint == "" {
		t.Fatalf("unexpected status: %+v", status)
	}
	if _, err = fetchInstallerAccessStatus(server.Client(), base, "current-bootstrap-token-abcdefghijklmnopqrstuvwxyz"); err == nil {
		t.Fatal("old token should no longer authenticate")
	}
	if _, err = fetchInstallerAccessStatus(server.Client(), base, candidate); err != nil {
		t.Fatalf("candidate token should authenticate: %v", err)
	}
}

func TestInstallerAccessResumeReadsDurableStatusBeforeMutation(t *testing.T) {
	t.Setenv("PLATFORM_INSTALLER_TOKEN", "resume-bootstrap-token-abcdefghijklmnopqrstuvwxyz")
	var mu sync.Mutex
	sequence := []string{}
	state := "FAILED"
	active := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer resume-bootstrap-token-abcdefghijklmnopqrstuvwxyz" {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		mu.Lock()
		sequence = append(sequence, r.Method+" "+r.URL.Path)
		mu.Unlock()
		switch r.Method + " " + r.URL.Path {
		case "GET /api/v1/status":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"executionEnabled": true,
				"bootstrapActive": active,
				"resetActive": false,
				"run": map[string]any{"id": "bootstrap-1", "state": state, "lastError": "interrupted"},
				"resetRuns": []any{},
			})
		case "POST /api/v1/resume":
			active = true
			state = "RUNNING"
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "accepted"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	installerAccessResumeCommand([]string{"--installer-url", server.URL, "--confirmation", "RESUME"})

	mu.Lock()
	defer mu.Unlock()
	want := []string{"GET /api/v1/status", "POST /api/v1/resume", "GET /api/v1/status"}
	if strings.Join(sequence, "|") != strings.Join(want, "|") {
		t.Fatalf("resume sequence=%v want=%v", sequence, want)
	}
}

func TestInstallerAccessResetAndResetResumeUseDurableIDs(t *testing.T) {
	t.Setenv("PLATFORM_INSTALLER_TOKEN", "reset-bootstrap-token-abcdefghijklmnopqrstuvwxyz")
	var mu sync.Mutex
	sequence := []string{}
	resetActive := false
	resetRuns := []map[string]any{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer reset-bootstrap-token-abcdefghijklmnopqrstuvwxyz" {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		mu.Lock()
		sequence = append(sequence, r.Method+" "+r.URL.Path)
		mu.Unlock()
		switch r.Method + " " + r.URL.Path {
		case "GET /api/v1/status":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"executionEnabled": true,
				"bootstrapActive": false,
				"resetActive": resetActive,
				"run": map[string]any{"id": "bootstrap-1", "state": "SUCCEEDED"},
				"resetRuns": resetRuns,
			})
		case "POST /api/v1/reset/start":
			if r.Header.Get("X-Confirm-Reset") != "reset:bootstrap-1" {
				t.Fatalf("reset confirmation=%q", r.Header.Get("X-Confirm-Reset"))
			}
			resetActive = true
			resetRuns = []map[string]any{{"id":"reset-1","state":"RUNNING"}}
			w.WriteHeader(http.StatusAccepted)
		case "POST /api/v1/reset/resume":
			if r.Header.Get("X-Confirm-Reset-Resume") != "resume:reset-1" {
				t.Fatalf("reset-resume confirmation=%q", r.Header.Get("X-Confirm-Reset-Resume"))
			}
			resetActive = true
			resetRuns[len(resetRuns)-1]["state"] = "RUNNING"
			w.WriteHeader(http.StatusAccepted)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	installerAccessResetCommand([]string{"--installer-url", server.URL, "--confirmation", "RESET"})
	mu.Lock()
	gotReset := append([]string(nil), sequence...)
	sequence = nil
	mu.Unlock()
	wantReset := []string{"GET /api/v1/status", "POST /api/v1/reset/start", "GET /api/v1/status"}
	if strings.Join(gotReset, "|") != strings.Join(wantReset, "|") {
		t.Fatalf("reset sequence=%v want=%v", gotReset, wantReset)
	}

	resetActive = false
	resetRuns[len(resetRuns)-1]["state"] = "FAILED"
	installerAccessResetResumeCommand([]string{"--installer-url", server.URL, "--confirmation", "RESUME-RESET"})
	mu.Lock()
	gotResume := append([]string(nil), sequence...)
	mu.Unlock()
	wantResume := []string{"GET /api/v1/status", "POST /api/v1/reset/resume", "GET /api/v1/status"}
	if strings.Join(gotResume, "|") != strings.Join(wantResume, "|") {
		t.Fatalf("reset-resume sequence=%v want=%v", gotResume, wantResume)
	}
}

func TestValidateInstallerAccessURL(t *testing.T) {
	if _, err := validateAPIURL("http://installer.example:9080"); err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("non-loopback HTTP should fail: %v", err)
	}
}

func TestStageAndCommitPrivateToken(t *testing.T) {
	output := t.TempDir() + "/bootstrap-token"
	pending, absolute, err := stagePrivateToken(output, []byte("candidate-bootstrap-token-abcdefghijklmnopqrstuvwxyz\n"))
	if err != nil {
		t.Fatal(err)
	}
	if pending == absolute {
		t.Fatal("pending file must differ from final output")
	}
	if err = commitPrivateToken(pending, absolute); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(absolute)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("token mode = %04o", info.Mode().Perm())
	}
}
