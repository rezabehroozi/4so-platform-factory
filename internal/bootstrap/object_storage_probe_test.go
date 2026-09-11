package bootstrap

import (
	"strings"
	"testing"

	"platform.4so.io/factory/internal/installation"
)

func TestObjectStorageProbeIsCredentialBoundIntegrityCheckedAndSelfCleaning(t *testing.T) {
	run := Run{ID: "bootstrap-1234567890abcdef1234", Request: installation.InstallRequest{
		ProfileID: "production-standard-ha",
		Services: installation.ServicesSpec{ObjectStorage: installation.ServiceSpec{
			Mode: installation.ServiceModeExternal, Provider: "s3-compatible", URL: "https://s3.example.test", Bucket: "platform-backups", Prefix: "factory",
			CredentialRef: "external-secret://platform-system/s3-credentials",
		}},
	}}
	bundle := BundleManifest{}
	bundle.Spec.Workloads.MaintenanceImage = "registry.example/maintenance@sha256:" + strings.Repeat("a", 64)
	name, manifest, err := objectStorageProbeManifest(run, bundle)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(name, "platform-s3-probe-") {
		t.Fatalf("unexpected probe name %q", name)
	}
	for _, required := range []string{
		objectStorageProbeAuthority,
		"secretRef: {name: \"s3-credentials\"}",
		"s3 cp /tmp/source",
		"s3://$S3_BUCKET/$S3_OBJECT_KEY",
		"/tmp/readback",
		"cmp -s /tmp/source /tmp/readback",
		"s3 rm",
		"--sse AES256",
		"installer-probes/" + run.ID,
	} {
		if !strings.Contains(manifest, required) {
			t.Fatalf("probe manifest missing %q:\n%s", required, manifest)
		}
	}
	if strings.Contains(manifest, "AWS_ACCESS_KEY_ID:") || strings.Contains(manifest, "AWS_SECRET_ACCESS_KEY:") {
		t.Fatal("probe manifest must not materialize storage credentials")
	}
}

func TestObjectStorageProbeRejectsNonPlatformSecretReference(t *testing.T) {
	run := Run{ID: "bootstrap-123", Request: installation.InstallRequest{ProfileID: "production-standard-ha", Services: installation.ServicesSpec{ObjectStorage: installation.ServiceSpec{CredentialRef: "external-secret://other/s3"}}}}
	if _, _, err := objectStorageProbeManifest(run, BundleManifest{}); err == nil {
		t.Fatal("non-platform object-storage secret must be rejected")
	}
}
