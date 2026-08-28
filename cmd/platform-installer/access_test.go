package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"platform.4so.io/factory/internal/fieldevidence"
	"platform.4so.io/factory/internal/installeraccess"
)

func TestInstallerAccessStatusAndRotation(t *testing.T) {
	current := "current-bootstrap-token-abcdefghijklmnopqrstuvwxyz"
	access, _, err := installeraccess.LoadOrCreate(t.TempDir(), current, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	server := &installerServer{
		access:    access,
		transport: installeraccess.TransportStatus{Mode: "http-loopback", Listen: "127.0.0.1:9080", LoopbackOnly: true},
		logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	mux := http.NewServeMux()
	server.routes(mux)

	statusRequest := httptest.NewRequest(http.MethodGet, "/api/v1/access/status", nil)
	statusRequest.Header.Set("Authorization", "Bearer "+current)
	statusResponse := httptest.NewRecorder()
	mux.ServeHTTP(statusResponse, statusRequest)
	if statusResponse.Code != http.StatusOK || !strings.Contains(statusResponse.Body.String(), `"http-loopback"`) {
		t.Fatalf("unexpected access status: %d %s", statusResponse.Code, statusResponse.Body.String())
	}
	expectedDigest, err := fieldevidence.CurrentExecutableDigest()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(statusResponse.Body.String(), `"installerBinaryDigest":"`+expectedDigest+`"`) {
		t.Fatalf("access status is not bound to the running installer binary: %s", statusResponse.Body.String())
	}

	newToken := "rotated-bootstrap-token-abcdefghijklmnopqrstuvwxyz"
	payload, _ := json.Marshal(map[string]string{"confirmation": "ROTATE", "newToken": newToken})
	rotateRequest := httptest.NewRequest(http.MethodPost, "/api/v1/access/token/rotate", bytes.NewReader(payload))
	rotateRequest.Header.Set("Content-Type", "application/json")
	rotateRequest.Header.Set("Authorization", "Bearer "+current)
	rotateResponse := httptest.NewRecorder()
	mux.ServeHTTP(rotateResponse, rotateRequest)
	if rotateResponse.Code != http.StatusOK {
		t.Fatalf("rotation failed: %d %s", rotateResponse.Code, rotateResponse.Body.String())
	}
	if strings.Contains(rotateResponse.Body.String(), newToken) {
		t.Fatal("rotation response must not return the new token")
	}

	oldRequest := httptest.NewRequest(http.MethodGet, "/api/v1/access/status", nil)
	oldRequest.Header.Set("Authorization", "Bearer "+current)
	oldResponse := httptest.NewRecorder()
	mux.ServeHTTP(oldResponse, oldRequest)
	if oldResponse.Code != http.StatusUnauthorized {
		t.Fatalf("old token should be invalidated: %d", oldResponse.Code)
	}
	newRequest := httptest.NewRequest(http.MethodGet, "/api/v1/access/status", nil)
	newRequest.Header.Set("Authorization", "Bearer "+newToken)
	newResponse := httptest.NewRecorder()
	mux.ServeHTTP(newResponse, newRequest)
	if newResponse.Code != http.StatusOK {
		t.Fatalf("new token should authenticate: %d %s", newResponse.Code, newResponse.Body.String())
	}
}

func TestInstallerAccessRotationRejectsWrongConfirmation(t *testing.T) {
	current := "current-bootstrap-token-abcdefghijklmnopqrstuvwxyz"
	access, _, err := installeraccess.LoadOrCreate(t.TempDir(), current, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	server := &installerServer{access: access, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	mux := http.NewServeMux()
	server.routes(mux)
	payload, _ := json.Marshal(map[string]string{"confirmation": "YES", "newToken": "rotated-bootstrap-token-abcdefghijklmnopqrstuvwxyz"})
	request := httptest.NewRequest(http.MethodPost, "/api/v1/access/token/rotate", bytes.NewReader(payload))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+current)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("wrong confirmation should be rejected: %d %s", response.Code, response.Body.String())
	}
}
