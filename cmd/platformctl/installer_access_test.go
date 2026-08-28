package main

import (
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
