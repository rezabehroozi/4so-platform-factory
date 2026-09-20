package packagecheck

import (
	"os"
	"strings"
	"testing"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"sigs.k8s.io/yaml"
)

func readCRD(t *testing.T, path string) apiextensionsv1.CustomResourceDefinition {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var crd apiextensionsv1.CustomResourceDefinition
	if err := yaml.Unmarshal(raw, &crd); err != nil {
		t.Fatal(err)
	}
	return crd
}

func onlyVersion(t *testing.T, crd apiextensionsv1.CustomResourceDefinition) apiextensionsv1.CustomResourceDefinitionVersion {
	t.Helper()
	if len(crd.Spec.Versions) != 1 {
		t.Fatalf("%s versions=%d", crd.Name, len(crd.Spec.Versions))
	}
	v := crd.Spec.Versions[0]
	if !v.Served || !v.Storage || v.Schema == nil || v.Schema.OpenAPIV3Schema == nil {
		t.Fatalf("%s has non-installable v1alpha1 schema", crd.Name)
	}
	return v
}

func TestProviderPackageMetadataDoesNotClaimUnsupportedSafeStart(t *testing.T) {
	raw, err := os.ReadFile("crossplane.yaml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, "kind: Provider") || !strings.Contains(text, "name: provider-4so-platform") {
		t.Fatalf("provider package metadata identity missing: %s", text)
	}
	if strings.Contains(text, "safe-start") {
		t.Fatal("package must not claim safe-start until controller implements it")
	}
}

func TestProviderConfigCRDIsNamespacedAndSecretReferenced(t *testing.T) {
	crd := readCRD(t, "crds/platform.4so.io_providerconfigs.yaml")
	if crd.Spec.Group != "platform.4so.io" || crd.Spec.Scope != apiextensionsv1.NamespaceScoped || crd.Spec.Names.Kind != "ProviderConfig" {
		t.Fatalf("unexpected ProviderConfig identity: %#v", crd.Spec)
	}
	v := onlyVersion(t, crd)
	spec := v.Schema.OpenAPIV3Schema.Properties["spec"]
	if !contains(spec.Required, "endpoint") || !contains(spec.Required, "tokenSecretRef") {
		t.Fatalf("ProviderConfig required fields=%v", spec.Required)
	}
	ref := spec.Properties["tokenSecretRef"]
	if !contains(ref.Required, "name") || !contains(ref.Required, "key") {
		t.Fatalf("tokenSecretRef required fields=%v", ref.Required)
	}
}

func TestSAMLBrokerCRDDefaultsToNamespacedProviderConfig(t *testing.T) {
	crd := readCRD(t, "crds/identity.platform.4so.io_samlbrokers.yaml")
	if crd.Spec.Group != "identity.platform.4so.io" || crd.Spec.Scope != apiextensionsv1.NamespaceScoped || crd.Spec.Names.Kind != "SAMLBroker" {
		t.Fatalf("unexpected SAMLBroker identity: %#v", crd.Spec)
	}
	v := onlyVersion(t, crd)
	if v.Subresources == nil || v.Subresources.Status == nil {
		t.Fatal("SAMLBroker status subresource is required")
	}
	spec := v.Schema.OpenAPIV3Schema.Properties["spec"]
	ref := spec.Properties["providerConfigRef"]
	if ref.Default == nil || !strings.Contains(string(ref.Default.Raw), "ProviderConfig") || !strings.Contains(string(ref.Default.Raw), "default") {
		t.Fatalf("providerConfigRef default=%v", ref.Default)
	}
	forProvider := spec.Properties["forProvider"]
	for _, required := range []string{"organizationId", "alias", "displayName", "entityId", "singleSignOnServiceUrl", "signingCertificate", "wantAuthnRequestsSigned", "enabled"} {
		if !contains(forProvider.Required, required) {
			t.Fatalf("forProvider missing required field %s: %v", required, forProvider.Required)
		}
	}
}

func TestRuntimeImageIsDigestPinnedAndNonRoot(t *testing.T) {
	raw, err := os.ReadFile("../cluster/images/provider-4so/Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, "FROM gcr.io/distroless/static@sha256:") {
		t.Fatal("runtime base image is not digest pinned")
	}
	if !strings.Contains(text, "USER 65532") {
		t.Fatal("runtime image must run non-root")
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
