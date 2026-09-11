package bootmedia

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

type staticResolver struct {
	c            Credentials
	wantEndpoint string
}

func (s staticResolver) ResolveBootMediaCredential(_ context.Context, scope CredentialScope) (Credentials, error) {
	if s.wantEndpoint != "" && scope.Endpoint != s.wantEndpoint {
		return Credentials{}, errors.New("credential scope endpoint mismatch")
	}
	if scope.OrganizationID == "" || scope.ProjectID == "" || scope.MachineID == "" || scope.Reference == "" {
		return Credentials{}, errors.New("credential scope incomplete")
	}
	return s.c, nil
}

func trustedTLSClient(srv *httptest.Server) *http.Client {
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
}

type redfishFixture struct {
	mu          sync.Mutex
	image       string
	inserted    bool
	bootEnabled string
	bootTarget  string
	powerState  string
	resetType   string
	authOK      bool
}

func (f *redfishFixture) handler(w http.ResponseWriter, r *http.Request) {
	u, p, ok := r.BasicAuth()
	if !ok || u != "svc" || p != "secret" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.authOK = true
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.URL.Path == "/redfish/v1/Managers/1/VirtualMedia/CD" && r.Method == http.MethodGet:
		json.NewEncoder(w).Encode(map[string]any{"Image": f.image, "Inserted": f.inserted})
	case r.URL.Path == "/redfish/v1/Managers/1/VirtualMedia/CD/Actions/VirtualMedia.InsertMedia" && r.Method == http.MethodPost:
		var b struct {
			Image string `json:"Image"`
		}
		json.NewDecoder(r.Body).Decode(&b)
		f.image = b.Image
		f.inserted = true
		w.WriteHeader(http.StatusNoContent)
	case r.URL.Path == "/redfish/v1/Systems/1" && r.Method == http.MethodGet:
		json.NewEncoder(w).Encode(map[string]any{"PowerState": f.powerState, "Boot": map[string]any{"BootSourceOverrideEnabled": f.bootEnabled, "BootSourceOverrideTarget": f.bootTarget}})
	case r.URL.Path == "/redfish/v1/Systems/1" && r.Method == http.MethodPatch:
		var b struct {
			Boot struct {
				Enabled string `json:"BootSourceOverrideEnabled"`
				Target  string `json:"BootSourceOverrideTarget"`
			} `json:"Boot"`
		}
		json.NewDecoder(r.Body).Decode(&b)
		f.bootEnabled = b.Boot.Enabled
		f.bootTarget = b.Boot.Target
		w.WriteHeader(http.StatusNoContent)
	case r.URL.Path == "/redfish/v1/Systems/1/Actions/ComputerSystem.Reset" && r.Method == http.MethodPost:
		var b struct {
			ResetType string `json:"ResetType"`
		}
		json.NewDecoder(r.Body).Decode(&b)
		f.resetType = b.ResetType
		f.powerState = "On"
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}

func redfishRequest(endpoint string) Request {
	r := request()
	r.Endpoint = endpoint
	return r
}

func TestRedfishProviderEndToEndAndIdempotentAttach(t *testing.T) {
	fixture := &redfishFixture{powerState: "On"}
	srv := httptest.NewTLSServer(http.HandlerFunc(fixture.handler))
	defer srv.Close()
	p := &RedfishProvider{Client: trustedTLSClient(srv), Resolver: staticResolver{c: Credentials{Username: "svc", Password: "secret"}, wantEndpoint: srv.URL}}
	req := redfishRequest(srv.URL)
	if err := p.Attach(req); err != nil {
		t.Fatal(err)
	}
	if err := p.Attach(req); err != nil {
		t.Fatalf("idempotent attach failed: %v", err)
	}
	if err := p.SetOneTimeBoot(req); err != nil {
		t.Fatal(err)
	}
	if err := p.PowerCycle(req); err != nil {
		t.Fatal(err)
	}
	obs, err := p.Observe(req)
	if err != nil {
		t.Fatal(err)
	}
	if !obs.Attached || !obs.OneTimeBootSet || !obs.Powered || !strings.HasPrefix(obs.BootState, "REDFISH_") {
		t.Fatalf("bad observation: %#v", obs)
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if fixture.resetType != "ForceRestart" || !fixture.authOK {
		t.Fatalf("reset=%q auth=%v", fixture.resetType, fixture.authOK)
	}
}

func TestRedfishProviderRefusesDifferentInsertedMedia(t *testing.T) {
	fixture := &redfishFixture{powerState: "On", inserted: true, image: "https://factory.example.test/other.iso"}
	srv := httptest.NewTLSServer(http.HandlerFunc(fixture.handler))
	defer srv.Close()
	p := &RedfishProvider{Client: trustedTLSClient(srv), Resolver: staticResolver{c: Credentials{Username: "svc", Password: "secret"}, wantEndpoint: srv.URL}}
	if err := p.Attach(redfishRequest(srv.URL)); err == nil {
		t.Fatal("expected different inserted media to fail closed")
	}
}

func TestValidateRequestRejectsNonRedfishResourceURI(t *testing.T) {
	r := request()
	r.SystemResource = "https://evil.example/redfish/v1/Systems/1"
	if ValidateRequest(r) == nil {
		t.Fatal("expected absolute resource URL rejection")
	}
}

func TestRedfishProviderRejectsTLSVerificationBypass(t *testing.T) {
	p := &RedfishProvider{Client: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}, Resolver: staticResolver{c: Credentials{Username: "svc", Password: "secret"}}}
	if err := p.Attach(request()); err == nil || !strings.Contains(err.Error(), "TLS verification") {
		t.Fatalf("TLS bypass not rejected: %v", err)
	}
}

func TestValidateRequestRejectsRedfishPathTraversal(t *testing.T) {
	r := request()
	r.SystemResource = "/redfish/v1/Systems/../Managers/1"
	if ValidateRequest(r) == nil {
		t.Fatal("path traversal accepted")
	}
	r = request()
	r.SystemResource = "/redfish/v1/Systems/%2e%2e/Managers/1"
	if ValidateRequest(r) == nil {
		t.Fatal("encoded path accepted")
	}
}
