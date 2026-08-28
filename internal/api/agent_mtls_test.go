package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"platform.4so.io/factory/catalog"
	"platform.4so.io/factory/internal/agentpki"
	"platform.4so.io/factory/internal/controlplane"
)

func csrForTest(t *testing.T) (string, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "agent-test"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), key
}
func parseCertTest(t *testing.T, pemText string) *x509.Certificate {
	t.Helper()
	b, _ := pem.Decode([]byte(pemText))
	if b == nil {
		t.Fatal("missing cert PEM")
	}
	c, e := x509.ParseCertificate(b.Bytes)
	if e != nil {
		t.Fatal(e)
	}
	return c
}

func TestAgentMTLSIssueRotateAndImmediateRevocation(t *testing.T) {
	ctx := context.Background()
	store := controlplane.NewMemoryStore()
	org, _ := store.CreateOrganization(ctx, controlplane.Organization{Name: "mtls", DisplayName: "mTLS"}, "admin")
	project, _ := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "p", DisplayName: "P"}, "admin")
	enrollment := "enrollment-token-abcdefghijklmnopqrstuvwxyz"
	agentToken := agentCredential(enrollment, "imp-fixed")
	imp, err := store.CreateClusterImport(ctx, controlplane.ClusterImport{ProjectID: project.ID, Name: "c", DisplayName: "C", TokenDigest: credentialDigest(enrollment), ExpiresAt: time.Now().Add(time.Hour)}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	imp, err = store.ApproveClusterImport(ctx, imp.ID, imp.Revision, "approver")
	if err != nil {
		t.Fatal(err)
	}
	// agent token is deterministically derived from actual import id
	agentToken = agentCredential(enrollment, imp.ID)
	_, cluster, err := store.ClaimClusterImport(ctx, imp.ID, credentialDigest(enrollment), credentialDigest(agentToken), "uid-mtls", "0.0.37")
	if err != nil {
		t.Fatal(err)
	}
	ca, key, err := agentpki.GenerateCA("test", time.Now(), 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := agentpki.NewSigner(ca, key, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	s := New("0.0.37", map[string]catalog.Component{}, nil, store)
	s.ConfigureAgentMTLS(signer, true)
	issueCSR, _ := csrForTest(t)
	body, _ := json.Marshal(map[string]string{"csrPem": issueCSR})
	req := httptest.NewRequest(http.MethodPost, "/agent/v1/clusters/"+cluster.ID+"/certificates/issue", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+agentToken)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != 201 {
		t.Fatalf("issue=%d %s", w.Code, w.Body.String())
	}
	var issued struct {
		Certificate    controlplane.AgentCertificate `json:"certificate"`
		CertificatePEM string                        `json:"certificatePem"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &issued); err != nil {
		t.Fatal(err)
	}
	oldCert := parseCertTest(t, issued.CertificatePEM)
	// The bootstrap bearer is one-shot for certificate issuance. Replaying it after
	// a certificate exists must require explicit re-enrollment rather than minting
	// a second independent identity.
	reissue := httptest.NewRequest(http.MethodPost, "/agent/v1/clusters/"+cluster.ID+"/certificates/issue", bytes.NewReader(body))
	reissue.Header.Set("Authorization", "Bearer "+agentToken)
	reissue.Header.Set("Content-Type", "application/json")
	reissueW := httptest.NewRecorder()
	s.Handler().ServeHTTP(reissueW, reissue)
	if reissueW.Code != http.StatusConflict {
		t.Fatalf("bootstrap bearer reissue must be denied: %d %s", reissueW.Code, reissueW.Body.String())
	}
	hb := func(cert *x509.Certificate, bearer string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/agent/v1/clusters/"+cluster.ID+"/heartbeat", bytes.NewBufferString(`{"agentVersion":"0.0.37"}`))
		r.Header.Set("Content-Type", "application/json")
		if bearer != "" {
			r.Header.Set("Authorization", "Bearer "+bearer)
		}
		if cert != nil {
			r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
		}
		wr := httptest.NewRecorder()
		s.Handler().ServeHTTP(wr, r)
		return wr
	}
	if got := hb(nil, agentToken); got.Code != 401 {
		t.Fatalf("bearer should be denied when mtls required: %d %s", got.Code, got.Body.String())
	}
	if got := hb(oldCert, ""); got.Code != 200 {
		t.Fatalf("mtls heartbeat=%d %s", got.Code, got.Body.String())
	}
	rotateCSR, _ := csrForTest(t)
	body, _ = json.Marshal(map[string]string{"csrPem": rotateCSR})
	req = httptest.NewRequest(http.MethodPost, "/agent/v1/clusters/"+cluster.ID+"/certificates/rotate", bytes.NewReader(body))
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{oldCert}}
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("rotate=%d %s", w.Code, w.Body.String())
	}
	var rotated struct {
		Certificate    controlplane.AgentCertificate `json:"certificate"`
		CertificatePEM string                        `json:"certificatePem"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &rotated)
	newCert := parseCertTest(t, rotated.CertificatePEM)
	if got := hb(oldCert, ""); got.Code != 401 {
		t.Fatalf("old cert must be invalid immediately: %d %s", got.Code, got.Body.String())
	}
	if got := hb(newCert, ""); got.Code != 200 {
		t.Fatalf("new cert heartbeat=%d %s", got.Code, got.Body.String())
	}
	_, err = store.RevokeAgentCertificate(ctx, rotated.Certificate.ID, rotated.Certificate.Revision, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if got := hb(newCert, ""); got.Code != 401 {
		t.Fatalf("revoked cert must be invalid immediately: %d %s", got.Code, got.Body.String())
	}
	_ = fmt.Sprintf("%s", issued.Certificate.Fingerprint)
}
