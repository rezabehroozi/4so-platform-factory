package agentpki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"
	"time"
)

func TestIssueAndIdentifyAgentCertificate(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	ca, key, err := GenerateCA("test-agent-ca", now, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewSigner(ca, key, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	agentKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "agent"}}, agentKey)
	issued, err := signer.SignCSR(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), "cls_123", 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(issued.CertificatePEM))
	cert, _ := x509.ParseCertificate(block.Bytes)
	got, err := ClusterIDFromCertificate(cert)
	if err != nil || got != "cls_123" {
		t.Fatalf("cluster id=%q err=%v", got, err)
	}
	if issued.NotAfter.Sub(now) != 30*24*time.Hour {
		t.Fatalf("unexpected expiry: %v", issued.NotAfter)
	}
}
