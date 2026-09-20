package persistence

import (
	"errors"
	"strings"
	"testing"

	"platform.4so.io/factory/internal/controlplane"
)

func providerValidationFixture(provider string) controlplane.ProviderProfile {
	return controlplane.ProviderProfile{
		ProjectID: "prj_test", ManagementClusterID: "clu_management",
		Name: provider + "-prod", DisplayName: strings.ToUpper(provider) + " Production",
		Adapter: "cluster-api-topology-v1beta2", Namespace: "4so-provider-system",
		ClusterClassName: provider + "-prod", WorkerClassName: "workers",
		DefaultKubernetesVersion: "v1.33.2", KubernetesSeries: []string{"v1.33"},
		Architectures: []string{"amd64"}, DistributionProfiles: []string{"kubernetes"},
		InfrastructureProvider: provider,
		CredentialRef: "external-secret://4so-provider-system/" + provider + "-prod",
		MaxWorkerReplicas: 20,
		DesiredDigest: "sha256:" + strings.Repeat("a", 64),
		RequestDigest: "sha256:" + strings.Repeat("b", 64),
		IdempotencyKey: provider + "-profile",
	}
}

func TestPostgresProviderValidationUsesCanonicalCloudAdmission(t *testing.T) {
	for _, provider := range []string{"aws", "azure", "gcp"} {
		t.Run(provider, func(t *testing.T) {
			v := providerValidationFixture(provider)
			if err := normalizeProviderProfile(&v); err != nil {
				t.Fatalf("canonical %s profile rejected: %v", provider, err)
			}
			if v.InfrastructureProvider != provider || v.ProvisioningMode != "cluster-api" {
				t.Fatalf("normalized %s profile drift: %#v", provider, v)
			}

			bad := providerValidationFixture(provider)
			bad.InfrastructureEndpoint = "https://custom.example.test"
			if err := normalizeProviderProfile(&bad); err == nil || !errors.Is(err, controlplane.ErrValidation) {
				t.Fatalf("custom %s endpoint admitted by PostgreSQL path: %v", provider, err)
			}

			bad = providerValidationFixture(provider)
			bad.CredentialRef = "inline-secret"
			if err := normalizeProviderProfile(&bad); err == nil || !errors.Is(err, controlplane.ErrValidation) {
				t.Fatalf("inline %s credential admitted by PostgreSQL path: %v", provider, err)
			}
		})
	}
}
