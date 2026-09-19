package bootstrap

import (
	"encoding/base64"
	"strings"
	"testing"

	"platform.4so.io/factory/internal/installation"
)

func TestHAInternalServiceSecretsRemainIndependentFromDatabaseCredentials(t *testing.T) {
	request := installation.InstallRequest{}
	request.Infrastructure.StorageClass = "replicated-rwx"
	request.Network.DNSZone = "example.test"
	request.Network.PublicEndpoint = "https://platform.example.test"
	request.Services.Identity.AdminEmail = "admin@example.test"

	manifest := foundationManifestHA(
		BundleManifest{},
		"database-password",
		"keycloak-db-password",
		"forgejo-db-password",
		"forgejo-admin-password",
		"identity-admin-password",
		"session-secret-value",
		"bootstrap-token-value",
		"catalog-signing-key-value",
		nil, nil, nil, nil, nil,
		request,
	)

	start := strings.Index(manifest, "metadata: {name: platform-internal-services")
	if start < 0 {
		t.Fatal("platform-internal-services secret is missing from HA foundation manifest")
	}
	rest := manifest[start:]
	end := strings.Index(rest, "\n---\n")
	if end < 0 {
		t.Fatal("platform-internal-services secret block is not terminated")
	}
	secretBlock := rest[:end]

	enc := func(value string) string {
		return base64.StdEncoding.EncodeToString([]byte(value))
	}
	for key, value := range map[string]string{
		"forgejo-admin-password": "forgejo-admin-password",
		"identity-admin-password": "identity-admin-password",
		"session-secret":          "session-secret-value",
		"bootstrap-token":         "bootstrap-token-value",
		"catalog-signing-key":     "catalog-signing-key-value",
	} {
		if !strings.Contains(secretBlock, key+": "+enc(value)) {
			t.Fatalf("platform-internal-services does not bind %s to its independent authority:\n%s", key, secretBlock)
		}
	}
	for _, forbidden := range []string{"database-password", "keycloak-db-password", "forgejo-db-password"} {
		if strings.Contains(secretBlock, enc(forbidden)) {
			t.Fatalf("database credential %q leaked into platform-internal-services authority:\n%s", forbidden, secretBlock)
		}
	}

	for _, expected := range []string{
		"name: PLATFORM_FACTORY_INTERNAL_GIT_PASSWORD\n              valueFrom: {secretKeyRef: {name: platform-internal-services, key: forgejo-admin-password}}",
		"name: PLATFORM_FACTORY_SESSION_SECRET\n              valueFrom: {secretKeyRef: {name: platform-internal-services, key: session-secret}}",
		"name: PLATFORM_FACTORY_BOOTSTRAP_TOKEN\n              valueFrom: {secretKeyRef: {name: platform-internal-services, key: bootstrap-token}}",
		"name: PLATFORM_FACTORY_CATALOG_SIGNING_PRIVATE_KEY_B64\n              valueFrom: {secretKeyRef: {name: platform-internal-services, key: catalog-signing-key}}",
	} {
		if !strings.Contains(manifest, expected) {
			t.Fatalf("HA Platform API secret reference contract missing %q", expected)
		}
	}
}
