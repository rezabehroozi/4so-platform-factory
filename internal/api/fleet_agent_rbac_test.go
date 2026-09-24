package api

import (
	"strings"
	"testing"

	"platform.4so.io/factory/internal/controlplane"
)

func TestFleetAgentManifestDoesNotGrantPodLogRead(t *testing.T) {
	manifest := renderClusterImportManifest(
		"https://hub.example.test",
		"imp_test",
		controlplane.FleetAgentServiceAccountName("imp_test"),
		strings.Repeat("t", 48),
		"registry.example.test/platform-agent@sha256:"+strings.Repeat("a", 64),
		"registry.example.test/platform-probe@sha256:"+strings.Repeat("b", 64),
		"",
	)
	if strings.Contains(manifest, `resources: ["pods/log"]`) {
		t.Fatal("fleet agent manifest still grants pods/log read; probe evidence must come from Pod termination status")
	}
	if !strings.Contains(manifest, `resources: ["pods"]`) {
		t.Fatal("fleet agent manifest lost required Pod metadata/status access")
	}
	for _, want := range []string{"runAsNonRoot: true", "type: RuntimeDefault", "allowPrivilegeEscalation: false", "readOnlyRootFilesystem: true", `drop: ["ALL"]`} {
		if !strings.Contains(manifest, want) {
			t.Fatalf("fleet agent manifest lost restricted-runtime security context %q", want)
		}
	}
	if strings.Contains(manifest, "runAsUser:") || strings.Contains(manifest, "fsGroup:") {
		t.Fatal("fleet agent manifest pins UID/GID and would conflict with OKD namespace-assigned identity ranges")
	}
}

func TestFleetAgentEnrollmentPrincipalIsImportScoped(t *testing.T) {
	firstImport := "imp_first_generation"
	secondImport := "imp_second_generation"
	firstPrincipal := controlplane.FleetAgentServiceAccountName(firstImport)
	secondPrincipal := controlplane.FleetAgentServiceAccountName(secondImport)
	if firstPrincipal == secondPrincipal {
		t.Fatalf("distinct enrollment generations share service account principal %q", firstPrincipal)
	}
	if strings.Contains(firstPrincipal, "_") || !strings.HasPrefix(firstPrincipal, "4so-platform-agent-") {
		t.Fatalf("service account principal is not Kubernetes-name-safe: %q", firstPrincipal)
	}

	first := renderClusterImportManifest(
		"https://hub.example.test",
		firstImport,
		firstPrincipal,
		strings.Repeat("a", 48),
		"registry.example.test/platform-agent@sha256:"+strings.Repeat("a", 64),
		"registry.example.test/platform-probe@sha256:"+strings.Repeat("b", 64),
		"",
	)
	second := renderClusterImportManifest(
		"https://hub.example.test",
		secondImport,
		secondPrincipal,
		strings.Repeat("b", 48),
		"registry.example.test/platform-agent@sha256:"+strings.Repeat("a", 64),
		"registry.example.test/platform-probe@sha256:"+strings.Repeat("b", 64),
		"",
	)
	for _, want := range []string{"name: " + firstPrincipal, "serviceAccountName: " + firstPrincipal} {
		if !strings.Contains(first, want) {
			t.Fatalf("first enrollment manifest does not bind workload to generation principal %q", want)
		}
	}
	if strings.Contains(second, "name: "+firstPrincipal+"\n") || strings.Contains(second, "serviceAccountName: "+firstPrincipal+"\n") {
		t.Fatalf("re-enrollment manifest inherited revoked generation principal %q", firstPrincipal)
	}
	if !strings.Contains(second, "serviceAccountName: "+secondPrincipal) {
		t.Fatalf("re-enrollment manifest does not use new generation principal %q", secondPrincipal)
	}

	activation := renderClusterMutationActivationManifest(
		"clu_second",
		secondPrincipal,
		"kube-system-uid",
		"sha256:"+strings.Repeat("c", 64),
	)
	if !strings.Contains(activation, "name: "+secondPrincipal+"\n  namespace: 4so-platform-agent") {
		t.Fatalf("mutation activation is not bound to enrollment generation principal %q", secondPrincipal)
	}
	if strings.Contains(activation, "name: "+firstPrincipal+"\n  namespace: 4so-platform-agent") {
		t.Fatalf("mutation activation retained revoked enrollment principal %q", firstPrincipal)
	}
}

func TestClusterRevocationRBACManifestNeutersEveryAgentBinding(t *testing.T) {
	manifest := renderClusterRevocationRBACManifest("clu_revoked", "uid-revoked", "sha256:"+strings.Repeat("d", 64), true)
	if got := strings.Count(manifest, "subjects: []"); got != 10 {
		t.Fatalf("revocation fence neutralized %d bindings, want 10\n%s", got, manifest)
	}
	for _, want := range []string{
		"name: 4so-platform-agent-credential",
		"name: 4so-platform-agent-readonly",
		"name: 4so-platform-provider-manager",
		"name: 4so-platform-baseline-manager",
		"name: 4so-platform-agent-maintenance-manager",
		"name: 4so-platform-agent-tenant-manager",
		"name: 4so-platform-node-maintenance-job-manager",
		"name: 4so-platform-runtime-job-launcher",
		"name: 4so-platform-runtime-rbac-observer",
		"name: 4so-openchoreo-runtime-manager",
		`clusterId: "clu_revoked"`,
		`externalUid: "uid-revoked"`,
		`revoked: "true"`,
	} {
		if !strings.Contains(manifest, want) {
			t.Fatalf("revocation fence missing %q\n%s", want, manifest)
		}
	}
	if strings.Contains(manifest, "subjects:\n-") {
		t.Fatalf("revocation fence retained an RBAC subject\n%s", manifest)
	}
}

func TestClusterRevocationRBACManifestForReadOnlyTargetOmitsMutationNamespaces(t *testing.T) {
	manifest := renderClusterRevocationRBACManifest("clu_readonly", "uid-readonly", "", false)
	if got := strings.Count(manifest, "subjects: []"); got != 2 {
		t.Fatalf("read-only revocation fence neutralized %d bindings, want 2\n%s", got, manifest)
	}
	for _, forbidden := range []string{"4so-provider-system", "4so-platform-baseline", "4so-platform-agent-maintenance-manager", "4so-platform-agent-tenant-manager"} {
		if strings.Contains(manifest, forbidden) {
			t.Fatalf("read-only revocation fence introduced mutation resource %q\n%s", forbidden, manifest)
		}
	}
	if !strings.Contains(manifest, `issuedFromInventoryDigest: "sha256:`+strings.Repeat("0", 64)+`"`) {
		t.Fatalf("read-only revocation fence did not normalize missing inventory digest\n%s", manifest)
	}
}

func TestMutationActivationIncludesBoundedOpenChoreoExecutorAuthority(t *testing.T) {
	manifest := renderClusterMutationActivationManifest("clu_openchoreo", "4so-platform-agent-test", "uid-openchoreo", "sha256:"+strings.Repeat("a", 64))
	for _, want := range []string{"4so-openchoreo-executor", "4so-platform-runtime-job-launcher", "4so-platform-runtime-rbac-observer", "4so-openchoreo-runtime-manager", `resources: ["subjectaccessreviews"]`, `resources: ["customresourcedefinitions"]`, `apiGroups: ["cert-manager.io"]`, `resources: ["issuers", "certificates"]`} {
		if !strings.Contains(manifest, want) { t.Fatalf("OpenChoreo executor RBAC missing %q", want) }
	}
	if strings.Contains(manifest, "cluster-admin") || strings.Contains(manifest, `resources: ["*"]`) {
		t.Fatalf("OpenChoreo executor RBAC became wildcard/cluster-admin:\n%s", manifest)
	}
}
