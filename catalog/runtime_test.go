package catalog

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEmbeddedResolvedComponentBundleVerifiesAndRenders(t *testing.T) {
	components, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	c, ok := components["secure-namespace-foundation"]
	if !ok {
		t.Fatal("secure-namespace-foundation missing")
	}
	if !c.Spec.Source.Resolved {
		t.Fatal("component must be resolved")
	}
	if got := AdmissionBlockers("RENDER", map[string]Component{c.Metadata.Name: c}); len(got) != 0 {
		t.Fatalf("render blockers=%v", got)
	}
	rendered, err := RenderComponent(c, "tenant-a", "catalog-release-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(rendered.Resources) != 6 || rendered.RenderedDigest == "" {
		t.Fatalf("rendered=%+v", rendered)
	}
	raw, _ := json.Marshal(rendered.Resources)
	text := string(raw)
	if strings.Contains(text, "${") || strings.Contains(text, "example.invalid") {
		t.Fatalf("unresolved render=%s", text)
	}
	if !strings.Contains(text, `"name":"tenant-a"`) || !strings.Contains(text, "catalog-release-1") {
		t.Fatalf("render vars missing=%s", text)
	}
}

func TestFullShippedCatalogStillBlocksRenderWhileResearchSourcesAreUnresolved(t *testing.T) {
	components, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	blockers := AdmissionBlockers("RENDER", components)
	if len(blockers) == 0 {
		t.Fatal("full shipped research catalog must remain blocked above candidate")
	}
}

func TestResolvedExternalSourceCannotPassAdmissionWithoutEmbeddedImmutableBundle(t *testing.T) {
	components, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	base := components["ceph-csi-rbd"]
	base.Spec.Release = "3.17.0"
	base.Spec.Source.Resolved = true
	base.Spec.Source.Type = "helm-chart"
	base.Spec.Source.BundleKey = ""
	base.Spec.Source.SignatureVerification = "sha256-pinned-offline"
	base.Spec.Source.ArtifactDigest = "sha256:" + strings.Repeat("a", 64)
	base.Spec.Source.SourceLockDigest = "sha256:" + strings.Repeat("b", 64)
	base.Spec.Source.ImageInventoryDigest = "sha256:" + strings.Repeat("c", 64)
	base.Spec.Source.LicenseManifestDigest = "sha256:" + strings.Repeat("d", 64)
	base.Spec.Source.SBOM = "sha256:" + strings.Repeat("e", 64)
	base.Spec.Source.Provenance = "sha256:" + strings.Repeat("f", 64)
	blockers := AdmissionBlockers("RENDER", map[string]Component{base.Metadata.Name: base})
	found := false
	for _, b := range blockers {
		if strings.Contains(b, "resolved source bundle verification failed") {
			found = true
		}
	}
	if !found {
		t.Fatalf("resolved external source with fake digests passed admission: %v", blockers)
	}
}

func TestRuntimeAndProductionAdmissionUseCanonicalCertificationStatuses(t *testing.T) {
	components, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	base := components["secure-namespace-foundation"]
	base.Spec.Certification.Status = "target-runtime-certified"
	base.Spec.Certification.EvidenceDigest = "sha256:" + strings.Repeat("a", 64)
	if got := AdmissionBlockers("RUNTIME", map[string]Component{base.Metadata.Name: base}); len(got) != 0 {
		t.Fatalf("target-runtime-certified must satisfy runtime admission: %v", got)
	}
	production := AdmissionBlockers("PRODUCTION", map[string]Component{base.Metadata.Name: base})
	if len(production) != 1 || !strings.Contains(production[0], "upgrade-certified") {
		t.Fatalf("production must require upgrade-certified: %v", production)
	}
	base.Spec.Certification.Status = "upgrade-certified"
	if got := AdmissionBlockers("PRODUCTION", map[string]Component{base.Metadata.Name: base}); len(got) != 0 {
		t.Fatalf("upgrade-certified must satisfy production admission: %v", got)
	}
	base.Spec.Certification.Status = "runtime-verified"
	if got := AdmissionBlockers("RUNTIME", map[string]Component{base.Metadata.Name: base}); len(got) == 0 {
		t.Fatal("legacy runtime-verified status must not satisfy canonical admission")
	}
}
