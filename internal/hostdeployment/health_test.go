package hostdeployment

import (
	"context"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProbeHealthVersionBoundHTTP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","version":"0.0.30"}`))
	}))
	defer server.Close()
	parsed, _ := url.Parse(server.URL)
	plan := HealthPlan{URL: server.URL + "/healthz", DialAddress: parsed.Host, Path: "/healthz", TimeoutSeconds: 2, IntervalMilliseconds: 100}
	status, err := probeHealth(context.Background(), plan, "0.0.30", time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if !status.Ready || status.Status != "ok" || status.Version != "0.0.30" || status.HTTPStatus != http.StatusOK || status.Attempts != 1 {
		t.Fatalf("unexpected readiness status %#v", status)
	}
	client, err := readinessHTTPClient(plan)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	if _, err = probeHealthOnce(context.Background(), client, plan.URL, "0.0.32"); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("expected version mismatch, got %v", err)
	}
}

func TestProbeHealthTLSWithoutBypass(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","version":"0.0.30"}`))
	}))
	defer server.Close()
	certPath := filepath.Join(t.TempDir(), "installer.crt")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	parsed, _ := url.Parse(server.URL)
	_, port, _ := strings.Cut(parsed.Host, ":")
	plan := HealthPlan{
		URL: "https://example.com:" + port + "/healthz", DialAddress: parsed.Host,
		ServerName: "example.com", CertificateFile: certPath, Path: "/healthz",
		TimeoutSeconds: 2, IntervalMilliseconds: 100,
	}
	status, err := probeHealth(context.Background(), plan, "0.0.30", time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if !status.Ready || status.Version != "0.0.30" {
		t.Fatalf("unexpected TLS readiness %#v", status)
	}
	plan.ServerName = "not-covered.example"
	plan.URL = "https://not-covered.example:" + port + "/healthz"
	if _, err = probeHealth(context.Background(), plan, "0.0.30", time.Now); err == nil {
		t.Fatal("expected TLS hostname verification failure")
	}
}

func TestBuildHealthPlanValidatesPathAndExplicitServerName(t *testing.T) {
	spec := Spec{APIVersion: APIVersion, Kind: Kind}
	spec.Spec.Listen = "0.0.0.0:9080"
	plan, err := buildHealthPlan(spec, "")
	if err != nil {
		t.Fatal(err)
	}
	if plan.URL != "http://127.0.0.1:9080/healthz" || plan.TimeoutSeconds != 30 || plan.IntervalMilliseconds != 500 {
		t.Fatalf("unexpected default health plan %#v", plan)
	}
	spec.Spec.Health.Path = "https://other.example/healthz"
	if _, err = buildHealthPlan(spec, ""); err == nil || !strings.Contains(err.Error(), "absolute path") {
		t.Fatalf("expected health path rejection: %v", err)
	}
}

type readinessRunner struct {
	enabled bool
	active  bool
}

func (r readinessRunner) Run(_ context.Context, _ string, args ...string) ([]byte, error) {
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "is-enabled") && !r.enabled {
		return nil, errors.New("disabled")
	}
	if strings.Contains(joined, "is-active") && !r.active {
		return nil, errors.New("inactive")
	}
	return nil, nil
}

func TestVerifyEnforcesDesiredServiceAndReadiness(t *testing.T) {
	source := t.TempDir()
	binary := filepath.Join(source, "platform-installer")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\necho 0.0.30\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	bundle := buildBundle(t, source, "0.0.30")
	root := t.TempDir()
	specPath := writeSpec(t, source, binary, bundle, "127.0.0.1:9080")
	state, err := Apply(context.Background(), specPath, "DEPLOY", Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	state.Status = "APPLIED"
	state.Plan.Root = "/"
	state.Plan.Service = ServiceIntent{Enable: true, Start: true}
	state.Activated = true
	if err = persistCheckpoint(state.Plan.Paths.State, &state); err != nil {
		t.Fatal(err)
	}
	probe := func(_ context.Context, plan HealthPlan, version string, _ func() time.Time) (HealthStatus, error) {
		return HealthStatus{Ready: true, URL: plan.URL, Status: "ok", Version: version, HTTPStatus: 200, Attempts: 1, CheckedAt: time.Now().UTC()}, nil
	}
	result, err := Verify(context.Background(), state.Plan.Paths.State, Options{Runner: readinessRunner{enabled: true, active: true}, HealthProbe: probe})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Valid || !result.ServiceEnableExpected || !result.ServiceStartExpected || !result.ServiceEnabled || !result.ServiceActive || !result.Readiness.Ready {
		t.Fatalf("unexpected verify result %#v", result)
	}
	if _, err = Verify(context.Background(), state.Plan.Paths.State, Options{Runner: readinessRunner{enabled: false, active: true}, HealthProbe: probe}); err == nil || !strings.Contains(err.Error(), "not enabled") {
		t.Fatalf("expected enablement rejection: %v", err)
	}
	if _, err = Verify(context.Background(), state.Plan.Paths.State, Options{Runner: readinessRunner{enabled: true, active: true}, HealthProbe: func(context.Context, HealthPlan, string, func() time.Time) (HealthStatus, error) {
		return HealthStatus{Ready: false, LastError: "wrong version"}, errors.New("wrong version")
	}}); err == nil || !strings.Contains(err.Error(), "wrong version") {
		t.Fatalf("expected readiness rejection: %v", err)
	}
}
