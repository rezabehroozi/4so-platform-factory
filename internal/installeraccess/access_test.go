package installeraccess

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTokenLifecycleAndRotation(t *testing.T) {
	now := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	manager, loaded, err := LoadOrCreate(t.TempDir(), "", now)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Generated || loaded.Status.Fingerprint == "" {
		t.Fatalf("unexpected load result: %+v", loaded)
	}
	if !manager.VerifyAuthorization("Bearer " + readToken(t, manager.tokenPath)) {
		t.Fatal("generated token should authenticate")
	}
	if manager.VerifyAuthorization("Bearer wrong") || manager.VerifyAuthorization("Basic wrong") {
		t.Fatal("invalid authorization must be rejected")
	}
	newToken, err := GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = manager.Rotate(newToken, "wrong", now.Add(time.Minute)); err == nil {
		t.Fatal("rotation without exact confirmation must fail")
	}
	status, err := manager.Rotate(newToken, "ROTATE", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if !manager.VerifyAuthorization("Bearer " + newToken) {
		t.Fatal("rotated token should authenticate")
	}
	if status.RotatedAt != now.Add(time.Minute) {
		t.Fatalf("unexpected rotation time: %s", status.RotatedAt)
	}
	info, err := os.Stat(manager.tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("token mode = %04o", info.Mode().Perm())
	}
}

func TestExistingTokenFileOverridesStaleEnvironmentSeed(t *testing.T) {
	dir := t.TempDir()
	initial := "initial-bootstrap-token-abcdefghijklmnopqrstuvwxyz"
	manager, _, err := LoadOrCreate(dir, initial, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rotated := "rotated-bootstrap-token-abcdefghijklmnopqrstuvwxyz"
	if _, err = manager.Rotate(rotated, "ROTATE", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	reloaded, result, err := LoadOrCreate(dir, initial, time.Now().Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if result.Status.Source != TokenSourceExisting {
		t.Fatalf("source = %s", result.Status.Source)
	}
	if !reloaded.VerifyAuthorization("Bearer "+rotated) || reloaded.VerifyAuthorization("Bearer "+initial) {
		t.Fatal("existing rotated token must remain authoritative after restart")
	}
}

func TestValidateTransport(t *testing.T) {
	now := time.Now().UTC()
	status, err := ValidateTransport("127.0.0.1:9080", "", "", false, now)
	if err != nil || status.Mode != "http-loopback" {
		t.Fatalf("loopback transport: status=%+v err=%v", status, err)
	}
	if _, err = ValidateTransport("0.0.0.0:9080", "", "", false, now); err == nil {
		t.Fatal("non-loopback HTTP must be rejected")
	}
	status, err = ValidateTransport("0.0.0.0:9080", "", "", true, now)
	if err != nil || !status.InsecureOverride {
		t.Fatalf("explicit insecure override: status=%+v err=%v", status, err)
	}
	cert, key := createCertificate(t, now)
	status, err = ValidateTransport("0.0.0.0:9443", cert, key, false, now)
	if err != nil || status.Mode != "https" || !status.TransportProtected || status.CertificateFingerprint == "" {
		t.Fatalf("TLS transport: status=%+v err=%v", status, err)
	}
	if err = os.Chmod(key, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err = ValidateTransport("0.0.0.0:9443", cert, key, false, now); err == nil {
		t.Fatal("world-readable TLS key must be rejected")
	}
}

func createCertificate(t *testing.T, now time.Time) (string, string) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "installer.test"},
		DNSNames:     []string{"installer.test"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyRaw, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")
	if err = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyRaw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func readToken(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw[:len(raw)-1])
}
