package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"os"
	"testing"
	"time"
)

func TestProductionStoreStartupBudgetCoversPingAndMigration(t *testing.T) {
	if productionStoreStartupTimeout <= postgresPingTimeout+postgresMigrationTimeout {
		t.Fatalf("production store startup budget %s truncates ping+migration budget %s", productionStoreStartupTimeout, postgresPingTimeout+postgresMigrationTimeout)
	}
	ctx, cancel := context.WithTimeout(context.Background(), productionStoreStartupTimeout)
	defer cancel()
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) < postgresMigrationTimeout {
		t.Fatalf("production startup context does not preserve migration budget: deadline=%v", deadline)
	}
}

func TestLoadPublicCAPEMRejectsMalformedBase64(t *testing.T) {
	t.Setenv("PLATFORM_FACTORY_PUBLIC_CA_PEM_B64", "%%%not-base64%%%")
	if _, err := loadPublicCAPEM(); err == nil {
		t.Fatal("expected malformed base64 to fail closed")
	}
}

func TestLoadPublicCAPEMRejectsInvalidPEM(t *testing.T) {
	t.Setenv("PLATFORM_FACTORY_PUBLIC_CA_PEM_B64", base64.StdEncoding.EncodeToString([]byte("not a certificate")))
	if _, err := loadPublicCAPEM(); err == nil {
		t.Fatal("expected invalid certificate PEM to fail closed")
	}
}

func TestLoadPublicCAPEMAcceptsCertificatePEM(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "platform-factory-test-ca"},
		NotBefore:    time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	raw := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	t.Setenv("PLATFORM_FACTORY_PUBLIC_CA_PEM_B64", base64.StdEncoding.EncodeToString(raw))
	got, err := loadPublicCAPEM()
	if err != nil {
		t.Fatal(err)
	}
	if got != string(raw) {
		t.Fatal("decoded public CA changed unexpectedly")
	}
}

func TestLoadPublicCAPEMUnset(t *testing.T) {
	old, ok := os.LookupEnv("PLATFORM_FACTORY_PUBLIC_CA_PEM_B64")
	_ = os.Unsetenv("PLATFORM_FACTORY_PUBLIC_CA_PEM_B64")
	t.Cleanup(func() {
		if ok {
			_ = os.Setenv("PLATFORM_FACTORY_PUBLIC_CA_PEM_B64", old)
		} else {
			_ = os.Unsetenv("PLATFORM_FACTORY_PUBLIC_CA_PEM_B64")
		}
	})
	got, err := loadPublicCAPEM()
	if err != nil || got != "" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestOpenStoreRejectsMissingDurableAuthority(t *testing.T) {
	t.Setenv("PLATFORM_FACTORY_STATE_FILE", "")
	t.Setenv("PLATFORM_FACTORY_POSTGRES_DSN", "")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, closeFn, err := openStore(context.Background(), logger)
	if closeFn != nil {
		closeFn()
	}
	if err == nil || store != nil {
		t.Fatalf("expected missing durable authority to fail closed, store=%T err=%v", store, err)
	}
}

func TestGracefulShutdownBudgetCoversServerWriteTimeout(t *testing.T) {
	if httpShutdownTimeout <= serverWriteTimeout {
		t.Fatalf("HTTP shutdown budget %s must exceed server write timeout %s", httpShutdownTimeout, serverWriteTimeout)
	}
	if securityAuditDrainTimeout <= 0 {
		t.Fatalf("security audit drain budget must be positive: %s", securityAuditDrainTimeout)
	}
}

func TestPostgresPoolConfigDefaultsAndBounds(t *testing.T) {
	cfg, err := postgresPoolConfigFromEnv(func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MaxOpen != 30 || cfg.MaxIdle != 10 {
		t.Fatalf("unexpected defaults: %#v", cfg)
	}
	values := map[string]string{
		"PLATFORM_FACTORY_POSTGRES_MAX_OPEN_CONNS": "20",
		"PLATFORM_FACTORY_POSTGRES_MAX_IDLE_CONNS": "5",
	}
	cfg, err = postgresPoolConfigFromEnv(func(k string) string { return values[k] })
	if err != nil || cfg.MaxOpen != 20 || cfg.MaxIdle != 5 {
		t.Fatalf("unexpected configured pool: %#v err=%v", cfg, err)
	}
	values["PLATFORM_FACTORY_POSTGRES_MAX_IDLE_CONNS"] = "21"
	if _, err = postgresPoolConfigFromEnv(func(k string) string { return values[k] }); err == nil {
		t.Fatal("expected idle connections above max-open to fail closed")
	}
	values["PLATFORM_FACTORY_POSTGRES_MAX_OPEN_CONNS"] = "not-an-int"
	values["PLATFORM_FACTORY_POSTGRES_MAX_IDLE_CONNS"] = "5"
	if _, err = postgresPoolConfigFromEnv(func(k string) string { return values[k] }); err == nil {
		t.Fatal("expected malformed max-open setting to fail closed")
	}
}
