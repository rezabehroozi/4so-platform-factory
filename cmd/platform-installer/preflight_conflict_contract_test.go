package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"platform.4so.io/factory/internal/bootstrap"
	"platform.4so.io/factory/internal/installeraccess"
)

func TestPreflightConflictIsHTTP409(t *testing.T) {
	token := "preflight-conflict-" + strings.Repeat("x", 32)
	server := installerServerWithRun(t, bootstrap.RunFailed)
	access, _, err := installeraccess.LoadOrCreate(t.TempDir(), token, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	server.access = access
	mux := http.NewServeMux()
	server.routes(mux)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/preflight", bytes.NewBufferString(`{"installation":{}}`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	mux.ServeHTTP(res, req)
	if res.Code != http.StatusConflict {
		t.Fatalf("interrupted-run preflight conflict returned %d: %s", res.Code, res.Body.String())
	}
	if !strings.Contains(res.Body.String(), `"code":"PREFLIGHT_CONFLICT"`) {
		t.Fatalf("preflight conflict lost stable API error category: %s", res.Body.String())
	}
}

func TestAcceptedBootstrapWorkerFencesPreflightAndSSHInputMutation(t *testing.T) {
	token := "bootstrap-worker-fence-" + strings.Repeat("x", 32)
	access, _, err := installeraccess.LoadOrCreate(t.TempDir(), token, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	server := &installerServer{access: access, bootstrapActive: true}
	mux := http.NewServeMux()
	server.routes(mux)

	cases := []struct {
		path string
		body string
		code string
	}{
		{"/api/v1/preflight", `{"installation":{}}`, "PREFLIGHT_CONFLICT"},
		{"/api/v1/secrets/ssh-private-key", `{"privateKey":"-----BEGIN PRIVATE KEY-----\\nblocked\\n-----END PRIVATE KEY-----"}`, "MUTATION_CONFLICT"},
		{"/api/v1/secrets/ssh-known-hosts", `{"knownHosts":"node.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm"}`, "MUTATION_CONFLICT"},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodPost, tc.path, bytes.NewBufferString(tc.body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		res := httptest.NewRecorder()
		mux.ServeHTTP(res, req)
		if res.Code != http.StatusConflict || !strings.Contains(res.Body.String(), `"code":"`+tc.code+`"`) {
			t.Fatalf("%s escaped accepted-bootstrap fence: status=%d body=%s", tc.path, res.Code, res.Body.String())
		}
	}
}
