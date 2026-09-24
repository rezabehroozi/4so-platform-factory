package catalogbundle

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"platform.4so.io/factory/catalog"
)

func fixtureRenderGeneration(namespace, minVersion, maxVersion string) []byte {
	return []byte(`{"tool":"helm-template","toolVersion":"v3.18.6","releaseName":"platform-factory","namespace":"` + namespace + `","includeCRDs":true,"kubernetesVersions":["` + minVersion + `","` + maxVersion + `"],"values":[],"imageResolver":"crane-digest","imageResolverVersion":"v0.20.6"}`)
}

func fixtureInput(t *testing.T) AssembleInput {
	t.Helper()
	base, err := os.ReadFile(filepath.Join("..", "..", "catalog", "components", "cilium.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(base, &doc); err != nil {
		t.Fatal(err)
	}
	spec := doc["spec"].(map[string]any)
	src := spec["source"].(map[string]any)
	src["resolved"] = false
	src["bundleKey"] = ""
	src["artifactDigest"] = ""
	src["renderManifestDigest"] = ""
	src["sourceLockDigest"] = ""
	src["imageInventoryDigest"] = ""
	src["licenseManifestDigest"] = ""
	src["signatureVerification"] = "required"
	src["sbom"] = "required"
	src["provenance"] = "required"
	spec["release"] = "1.20.1"
	spec["versionPolicy"] = "exact-upstream-admitted-pending-source-acquisition"
	base, err = json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	base = append(base, '\n')
	image := "quay.io/cilium/cilium@sha256:" + strings.Repeat("a", 64)
	render := []byte(`[
  {"apiVersion":"apps/v1","kind":"DaemonSet","metadata":{"name":"cilium","namespace":"kube-system"},"spec":{"template":{"spec":{"containers":[{"name":"cilium-agent","image":"` + image + `"}]}}}}
]`)
	artifact := helmChartTGZ(t, "cilium", "1.20.1")
	return AssembleInput{
		BaseComponent:    base,
		Artifact:         artifact,
		RenderManifest:   render,
		ImageInventory:   []byte("{\n  \"images\": [{\"reference\": \"" + image + "\"}]\n}\n"),
		Licenses:         []byte("{\n  \"licenses\": [{\"file\": \"LICENSE\", \"spdxExpression\": \"Apache-2.0\"}]\n}\n"),
		SBOM:             []byte("{\n  \"spdxVersion\": \"SPDX-2.3\", \"SPDXID\": \"SPDXRef-DOCUMENT\", \"name\": \"cilium-1.20.1-test-fixture\", \"packages\": [{\"SPDXID\":\"SPDXRef-Package-cilium\",\"name\":\"cilium\",\"versionInfo\":\"1.20.1\"}]\n}\n"),
		RenderGeneration: fixtureRenderGeneration("kube-system", "1.34.0", "1.35.0"),
		Version:          "1.20.1", SourceType: "helm-chart", SourceURL: "oci://quay.io/cilium/charts/cilium", SourceRevision: "1.20.1", UpstreamArtifact: "cilium-1.20.1.tgz", ExpectedArtifactDigest: sha(artifact), BundleKey: "cilium/1.20.1",
	}
}

func writeRuntimeCertificationRegistrySet(t *testing.T, root string, components []string) {
	t.Helper()
	dir := filepath.Join(root, "catalog")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	stages := []string{"install", "readiness", "dependency", "upgrade", "remove", "failure"}
	rows := make([]any, 0, len(components))
	for _, component := range components {
		lifecycle := make([]any, 0, len(stages))
		for _, stage := range stages {
			status, authority := "source-gated-component-executor", "COMPONENT_RUNTIME_V1"
			if stage == "upgrade" {
				status, authority = "pending-upgrade-matrix", "COMPONENT_RUNTIME_UPGRADE_V1"
			}
			lifecycle = append(lifecycle, map[string]any{
				"name": stage, "status": status, "evidenceContract": "component-" + stage + "-evidence/v1", "authority": authority,
			})
		}
		rows = append(rows, map[string]any{
			"component":     component,
			"release":       "1.20.1",
			"sourceBinding": map[string]any{"status": "blocked-source-lock", "resolved": false, "sourceLockDigest": ""},
			"executor":      map[string]any{"status": "source-gated-component-executor", "profile": "COMPONENT_RUNTIME_V1", "owner": "catalog-component"},
			"lifecycle":     lifecycle,
		})
	}
	doc := map[string]any{
		"apiVersion": "platform.4so.io/v1alpha1",
		"kind":       "ComponentRuntimeCertificationRegistry",
		"metadata":   map[string]any{"name": catalog.ComponentRuntimeCertificationAuthority},
		"spec": map[string]any{
			"policy": map[string]any{
				"sourceBinding":           "exact-component-release-and-source-lock",
				"executorBinding":         "component-owned-no-generic-runtime-certification-claim",
				"requiredLifecycleStages": stages,
				"replacementPolicy":       "resolved-source-replacement-denied-without-explicit-versioned-migration",
				"runtimeSuitabilityBinding": "persistent-independent-of-source-acquisition",
			},
			"runtimeSuitabilityHolds": []any{},
			"components": rows,
		},
	}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "component-runtime-certification.json"), append(raw, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeHelmAdmission(t *testing.T, root, component, chart, version, source, upstreamVersion string, status string) {
	t.Helper()
	if upstreamVersion == "" {
		upstreamVersion = version
	}
	dir := filepath.Join(root, "catalog")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	doc := map[string]any{
		"apiVersion": "platform.4so.io/v1alpha1",
		"kind":       "CatalogUpstreamAdmission",
		"metadata":   map[string]any{"name": "test-upstream-admission"},
		"spec": map[string]any{
			"components": []any{map[string]any{
				"component": component, "chart": chart, "catalogConstraint": version,
				"selectedVersion": version, "upstreamVersion": upstreamVersion,
				"source": source, "status": status, "runtimeStatus": "eligible-after-source-resolution", "rationale": "test fixture",
			}},
			"policy": map[string]any{
				"allowLatestResolution": false, "autoWidenCatalogConstraint": false,
				"runtimeCertification": "separate-runtime-evidence-required",
				"candidateAcquisition": "exact-source-may-be-acquired-before-runtime-clearance",
				"sourceAuthority":      "official-upstream-only",
				"sourceResolution":     "separate-immutable-acquisition-required",
				"versionSelection":     "exact-semver-no-prerelease",
			},
		},
	}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "upstream-admission.json"), append(raw, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	writeRuntimeCertificationRegistrySet(t, root, []string{component})
}

func writeRuntimeUpgradeMatrix(t *testing.T, root, component, release string) {
	t.Helper()
	dir := filepath.Join(root, "catalog")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	doc := map[string]any{
		"apiVersion":    "platform.4so.io/v1alpha1",
		"kind":          "ComponentRuntimeUpgradeMatrix",
		"authority":     "COMPONENT_RUNTIME_UPGRADE_MATRIX_V2",
		"schemaVersion": 1,
		"components": []any{map[string]any{
			"component": component, "targetRelease": release, "targetSourceLockDigest": "",
			"status": "pending-source-pair", "admittedEdges": []any{}, "upgradeExecutor": "COMPONENT_RUNTIME_UPGRADE_V1",
		}},
	}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "component-runtime-upgrade-matrix.json"), append(raw, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestAssembleVerifyOfflineExternalBundle(t *testing.T) {
	raw, v, err := Assemble(fixtureInput(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 || !v.OfflineReady || v.Manifest.Component != "cilium" || v.Manifest.Version != "1.20.1" || v.ResourceCount != 1 {
		t.Fatalf("unexpected verification: %+v", v)
	}
	again, err := Verify(raw)
	if err != nil {
		t.Fatal(err)
	}
	if again.BundleDigest != v.BundleDigest {
		t.Fatalf("bundle digest changed")
	}
	if !again.Component.Spec.Source.Resolved || again.Component.Spec.Source.RenderManifestDigest == "" {
		t.Fatalf("resolved evidence missing")
	}
	if again.Component.Spec.Delivery.Type != "helm" {
		t.Fatalf("external bundle import must preserve delivery ownership, got %q", again.Component.Spec.Delivery.Type)
	}
}

func TestVerifyRejectsTamperedArtifact(t *testing.T) {
	raw, _, err := Assemble(fixtureInput(t))
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range zr.File {
		r, _ := f.Open()
		b := new(bytes.Buffer)
		_, _ = b.ReadFrom(r)
		_ = r.Close()
		w, _ := zw.Create(f.Name)
		if f.Name == "artifact.bin" {
			_, _ = w.Write([]byte("tampered"))
		} else {
			_, _ = w.Write(b.Bytes())
		}
	}
	_ = zw.Close()
	if _, err = Verify(buf.Bytes()); err == nil {
		t.Fatal("tampered artifact accepted")
	}
}

func TestVerifyRejectsZipSlip(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("../artifact.bin")
	_, _ = w.Write([]byte("x"))
	_ = zw.Close()
	if _, err := Verify(buf.Bytes()); err == nil {
		t.Fatal("zip-slip bundle accepted")
	}
}

func TestInstallIsIdempotentAndRefusesResolvedReplacement(t *testing.T) {
	_, v, err := Assemble(fixtureInput(t))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err = os.WriteFile(filepath.Join(root, "VERSION"), []byte("test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeHelmAdmission(t, root, "cilium", "cilium", "1.20.1", "oci://quay.io/cilium/charts/cilium", "1.20.1", "ready-for-acquisition")
	writeRuntimeUpgradeMatrix(t, root, "cilium", "1.20.x")
	if err = os.MkdirAll(filepath.Join(root, "catalog", "components"), 0o755); err != nil {
		t.Fatal(err)
	}
	base := fixtureInput(t).BaseComponent
	if err = os.WriteFile(filepath.Join(root, "catalog", "components", "cilium.json"), base, 0o644); err != nil {
		t.Fatal(err)
	}
	if err = Install(v, root); err != nil {
		t.Fatal(err)
	}
	registryRaw, err := os.ReadFile(filepath.Join(root, "catalog", "component-runtime-certification.json"))
	if err != nil {
		t.Fatal(err)
	}
	var registry catalog.ComponentRuntimeCertificationRegistry
	if err = json.Unmarshal(registryRaw, &registry); err != nil {
		t.Fatal(err)
	}
	var resolvedComponent catalog.Component
	if err = json.Unmarshal(v.Files["component.json"], &resolvedComponent); err != nil {
		t.Fatal(err)
	}
	if err = catalog.ValidateComponentRuntimeCertificationRegistry(registry, map[string]catalog.Component{"cilium": resolvedComponent}); err != nil {
		t.Fatalf("runtime certification registry was not rebound atomically: %v", err)
	}
	upgradeRaw, err := os.ReadFile(filepath.Join(root, "catalog", "component-runtime-upgrade-matrix.json"))
	if err != nil {
		t.Fatal(err)
	}
	var upgrade map[string]any
	if err = json.Unmarshal(upgradeRaw, &upgrade); err != nil {
		t.Fatal(err)
	}
	rows := upgrade["components"].([]any)
	row := rows[0].(map[string]any)
	expectedUpgradeDigest, err := sourceLockAuthorityDigest(v.Files["source-lock.json"])
	if err != nil {
		t.Fatal(err)
	}
	if row["targetRelease"] != "1.20.1" || row["targetSourceLockDigest"] != expectedUpgradeDigest || row["status"] != "pending-source-pair" || len(row["admittedEdges"].([]any)) != 0 {
		t.Fatalf("runtime upgrade matrix was not rebound atomically: %+v", row)
	}
	authorityRaw, err := os.ReadFile(filepath.Join(root, "catalog", "upstream-admission.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(authorityRaw, []byte(`"component": "cilium"`)) {
		t.Fatalf("resolved component remained in upstream admission queue: %s", authorityRaw)
	}
	if err = Install(v, root); err != nil {
		t.Fatalf("idempotent install failed: %v", err)
	}
	if _, err = os.Stat(filepath.Join(root, "catalog", "runtime", "cilium", "1.20.1", "artifact.bin")); err != nil {
		t.Fatal(err)
	}
	changed := v
	changed.Files = map[string][]byte{}
	for k, b := range v.Files {
		changed.Files[k] = append([]byte(nil), b...)
	}
	changed.Files["component.json"] = bytes.Replace(changed.Files["component.json"], []byte("1.20.1"), []byte("1.20.2"), 1)
	if err = Install(changed, root); err == nil {
		t.Fatal("resolved replacement was accepted")
	}
}

func TestInstallRejectsHelmBundleOutsideCanonicalAdmission(t *testing.T) {
	_, v, err := Assemble(fixtureInput(t))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err = os.WriteFile(filepath.Join(root, "VERSION"), []byte("test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(filepath.Join(root, "catalog", "components"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, "catalog", "components", "cilium.json"), fixtureInput(t).BaseComponent, 0o644); err != nil {
		t.Fatal(err)
	}
	writeHelmAdmission(t, root, "cilium", "cilium", "1.20.1", "oci://quay.io/cilium/charts/cilium", "1.20.1", "dependency-review-required")
	if err = Install(v, root); err == nil || !strings.Contains(err.Error(), "upstream admission") {
		t.Fatalf("review-required Helm bundle bypassed canonical admission: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(root, "catalog", "runtime", "cilium", "1.20.1")); !os.IsNotExist(statErr) {
		t.Fatalf("rejected bundle mutated runtime destination: %v", statErr)
	}
}

func TestInstallRejectsUnresolvedComponentContractSubstitution(t *testing.T) {
	in := fixtureInput(t)
	var doc map[string]any
	if err := json.Unmarshal(in.BaseComponent, &doc); err != nil {
		t.Fatal(err)
	}
	spec := doc["spec"].(map[string]any)
	spec["supportTier"] = "malicious-substitution"
	mutated, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	in.BaseComponent = append(mutated, '\n')
	_, v, err := Assemble(in)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err = os.WriteFile(filepath.Join(root, "VERSION"), []byte("test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(filepath.Join(root, "catalog", "components"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, "catalog", "components", "cilium.json"), fixtureInput(t).BaseComponent, 0o644); err != nil {
		t.Fatal(err)
	}
	writeHelmAdmission(t, root, "cilium", "cilium", "1.20.1", "oci://quay.io/cilium/charts/cilium", "1.20.1", "ready-for-acquisition")
	if err = Install(v, root); err == nil || !strings.Contains(err.Error(), "component contract") {
		t.Fatalf("bundle replaced unresolved component contract: %v", err)
	}
}

func fixtureInputNamed(t *testing.T, name string) AssembleInput {
	t.Helper()
	in := fixtureInput(t)
	var doc map[string]any
	if err := json.Unmarshal(in.BaseComponent, &doc); err != nil {
		t.Fatal(err)
	}
	doc["metadata"].(map[string]any)["name"] = name
	base, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	in.BaseComponent = append(base, '\n')
	in.BundleKey = name + "/" + in.Version
	return in
}

func writeHelmAdmissionSet(t *testing.T, root string, components []string) {
	t.Helper()
	dir := filepath.Join(root, "catalog")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	rows := make([]any, 0, len(components))
	for _, component := range components {
		rows = append(rows, map[string]any{
			"component": component, "chart": "cilium", "catalogConstraint": "1.20.1",
			"selectedVersion": "1.20.1", "upstreamVersion": "1.20.1",
			"source": "oci://quay.io/cilium/charts/cilium", "status": "ready-for-acquisition", "runtimeStatus": "eligible-after-source-resolution", "rationale": "concurrency regression fixture",
		})
	}
	doc := map[string]any{
		"apiVersion": "platform.4so.io/v1alpha1",
		"kind":       "CatalogUpstreamAdmission",
		"metadata":   map[string]any{"name": "test-upstream-admission"},
		"spec": map[string]any{
			"components": rows,
			"policy": map[string]any{
				"allowLatestResolution": false, "autoWidenCatalogConstraint": false,
				"runtimeCertification": "separate-runtime-evidence-required",
				"candidateAcquisition": "exact-source-may-be-acquired-before-runtime-clearance",
				"sourceAuthority":      "official-upstream-only",
				"sourceResolution":     "separate-immutable-acquisition-required",
				"versionSelection":     "exact-semver-no-prerelease",
			},
		},
	}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "upstream-admission.json"), append(raw, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	writeRuntimeCertificationRegistrySet(t, root, components)
}

func TestConcurrentInstallsSerializeSharedAdmissionRetirement(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "VERSION"), []byte("test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	componentsDir := filepath.Join(root, "catalog", "components")
	if err := os.MkdirAll(componentsDir, 0o755); err != nil {
		t.Fatal(err)
	}

	const count = 8
	names := make([]string, 0, count)
	bundles := make([]Verified, 0, count)
	for i := 0; i < count; i++ {
		name := fmt.Sprintf("concurrent-%02d", i)
		in := fixtureInputNamed(t, name)
		_, verified, err := Assemble(in)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(componentsDir, name+".json"), in.BaseComponent, 0o644); err != nil {
			t.Fatal(err)
		}
		names = append(names, name)
		bundles = append(bundles, verified)
	}
	writeHelmAdmissionSet(t, root, names)

	start := make(chan struct{})
	errs := make(chan error, count)
	var wg sync.WaitGroup
	for i := range bundles {
		verified := bundles[i]
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- Install(verified, root)
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent install failed: %v", err)
		}
	}

	authority, err := loadCanonicalUpstreamAdmission(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		if _, err = findUpstreamAdmissionEntry(&authority, name); !errors.Is(err, errUpstreamAdmissionComponentMissing) {
			t.Fatalf("resolved component %s survived concurrent admission retirement: %v", name, err)
		}
		componentRaw, readErr := os.ReadFile(filepath.Join(componentsDir, name+".json"))
		if readErr != nil {
			t.Fatal(readErr)
		}
		var component catalog.Component
		if err = decodeStrict(componentRaw, &component); err != nil {
			t.Fatal(err)
		}
		if !component.Spec.Source.Resolved {
			t.Fatalf("component %s did not commit resolved source", name)
		}
		if _, statErr := os.Stat(filepath.Join(root, "catalog", "runtime", name, "1.20.1", "artifact.bin")); statErr != nil {
			t.Fatalf("runtime bundle for %s missing after concurrent install: %v", name, statErr)
		}
	}
}

func TestInstallRejectsGloballyInvalidAdmissionBeforeMutation(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "VERSION"), []byte("test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	componentsDir := filepath.Join(root, "catalog", "components")
	if err := os.MkdirAll(componentsDir, 0o755); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"target", "other"} {
		in := fixtureInputNamed(t, name)
		if err := os.WriteFile(filepath.Join(componentsDir, name+".json"), in.BaseComponent, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeHelmAdmissionSet(t, root, []string{"target", "other"})

	authorityPath := filepath.Join(root, "catalog", "upstream-admission.json")
	raw, err := os.ReadFile(authorityPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err = json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	rows := doc["spec"].(map[string]any)["components"].([]any)
	rows[1].(map[string]any)["status"] = "unrecognized-status"
	mutated, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(authorityPath, append(mutated, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}

	_, verified, err := Assemble(fixtureInputNamed(t, "target"))
	if err != nil {
		t.Fatal(err)
	}
	if err = Install(verified, root); err == nil || !strings.Contains(err.Error(), "admission") {
		t.Fatalf("globally invalid admission authority mutated catalog: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(root, "catalog", "runtime", "target", "1.20.1")); !os.IsNotExist(statErr) {
		t.Fatalf("invalid authority mutated runtime destination: %v", statErr)
	}
	componentRaw, err := os.ReadFile(filepath.Join(componentsDir, "target.json"))
	if err != nil {
		t.Fatal(err)
	}
	var component catalog.Component
	if err = decodeStrict(componentRaw, &component); err != nil {
		t.Fatal(err)
	}
	if component.Spec.Source.Resolved {
		t.Fatal("invalid authority resolved target component before rejection")
	}
}

func TestInstallRejectsSymlinkedTransactionStateBeforeMutation(t *testing.T) {
	_, v, err := Assemble(fixtureInput(t))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err = os.WriteFile(filepath.Join(root, "VERSION"), []byte("test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(filepath.Join(root, "catalog", "components"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, "catalog", "components", "cilium.json"), fixtureInput(t).BaseComponent, 0o644); err != nil {
		t.Fatal(err)
	}
	writeHelmAdmission(t, root, "cilium", "cilium", "1.20.1", "oci://quay.io/cilium/charts/cilium", "1.20.1", "ready-for-acquisition")
	outside := t.TempDir()
	if err = os.Symlink(outside, filepath.Join(root, ".state")); err != nil {
		t.Fatal(err)
	}
	if err = Install(v, root); err == nil || !strings.Contains(err.Error(), "state path") {
		t.Fatalf("symlinked transaction state was accepted: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(root, "catalog", "runtime", "cilium", "1.20.1")); !os.IsNotExist(statErr) {
		t.Fatalf("rejected symlinked lock state mutated runtime destination: %v", statErr)
	}
}

func TestInstallRepairsOnlyMatchingPartialRuntimeBundle(t *testing.T) {
	_, v, err := Assemble(fixtureInput(t))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err = os.WriteFile(filepath.Join(root, "VERSION"), []byte("test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeHelmAdmission(t, root, "cilium", "cilium", "1.20.1", "oci://quay.io/cilium/charts/cilium", "1.20.1", "ready-for-acquisition")
	components := filepath.Join(root, "catalog", "components")
	if err = os.MkdirAll(components, 0o755); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(components, "cilium.json"), fixtureInput(t).BaseComponent, 0o644); err != nil {
		t.Fatal(err)
	}
	runtimeDir := filepath.Join(root, "catalog", "runtime", filepath.FromSlash(v.Manifest.BundleKey))
	if err = os.MkdirAll(runtimeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(runtimeDir, "artifact.bin"), v.Files["artifact.bin"], 0o644); err != nil {
		t.Fatal(err)
	}
	if err = Install(v, root); err != nil {
		t.Fatalf("matching partial bundle must be repaired: %v", err)
	}
	for _, name := range requiredFiles {
		if name == "component.json" {
			continue
		}
		got, readErr := os.ReadFile(filepath.Join(runtimeDir, name))
		if readErr != nil || !bytes.Equal(got, v.Files[name]) {
			t.Fatalf("runtime payload %s was not repaired: err=%v", name, readErr)
		}
	}

	// A conflicting partial directory is never repaired by overwriting evidence.
	if err = os.WriteFile(filepath.Join(runtimeDir, "artifact.bin"), []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err = Install(v, root); err == nil {
		t.Fatal("conflicting partial runtime bundle was overwritten")
	}
}

func TestCleanupStaleDurableTempsRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("do-not-touch"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, ".durable-hostile")); err != nil {
		t.Fatal(err)
	}
	if err := cleanupStaleDurableTemps(dir, "test"); err == nil || !strings.Contains(err.Error(), "not a real regular file") {
		t.Fatalf("symlinked durable temp was silently cleaned: %v", err)
	}
	got, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "do-not-touch" {
		t.Fatal("durable temp cleanup mutated symlink target")
	}
}

func TestInstallRecoversOrphanDurableTempFromRuntimeRepairCrash(t *testing.T) {
	_, v, err := Assemble(fixtureInput(t))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err = os.WriteFile(filepath.Join(root, "VERSION"), []byte("test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeHelmAdmission(t, root, "cilium", "cilium", "1.20.1", "oci://quay.io/cilium/charts/cilium", "1.20.1", "ready-for-acquisition")
	components := filepath.Join(root, "catalog", "components")
	if err = os.MkdirAll(components, 0o755); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(components, "cilium.json"), fixtureInput(t).BaseComponent, 0o644); err != nil {
		t.Fatal(err)
	}

	runtimeDir := filepath.Join(root, "catalog", "runtime", filepath.FromSlash(v.Manifest.BundleKey))
	if err = os.MkdirAll(runtimeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(runtimeDir, "artifact.bin"), v.Files["artifact.bin"], 0o644); err != nil {
		t.Fatal(err)
	}
	orphan := filepath.Join(runtimeDir, ".durable-crash-residue")
	if err = os.WriteFile(orphan, []byte("interrupted durable replacement"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err = Install(v, root); err != nil {
		t.Fatalf("repair retry did not recover product-owned durable temp residue: %v", err)
	}
	if _, statErr := os.Lstat(orphan); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("stale durable temp survived successful repair retry: %v", statErr)
	}
	for _, name := range requiredFiles {
		if name == "component.json" {
			continue
		}
		got, readErr := os.ReadFile(filepath.Join(runtimeDir, name))
		if readErr != nil || !bytes.Equal(got, v.Files[name]) {
			t.Fatalf("runtime payload %s was not recovered exactly: err=%v", name, readErr)
		}
	}
}

func TestInstallCleansCatalogMetadataDurableTempsAfterCrash(t *testing.T) {
	_, v, err := Assemble(fixtureInput(t))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err = os.WriteFile(filepath.Join(root, "VERSION"), []byte("test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	components := filepath.Join(root, "catalog", "components")
	if err = os.MkdirAll(components, 0o755); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(components, "cilium.json"), fixtureInput(t).BaseComponent, 0o644); err != nil {
		t.Fatal(err)
	}
	writeHelmAdmission(t, root, "cilium", "cilium", "1.20.1", "oci://quay.io/cilium/charts/cilium", "1.20.1", "ready-for-acquisition")

	catalogTemp := filepath.Join(root, "catalog", ".durable-admission-crash")
	componentTemp := filepath.Join(components, ".durable-component-crash")
	if err = os.WriteFile(catalogTemp, []byte("stale authority temp"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(componentTemp, []byte("stale component temp"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err = Install(v, root); err != nil {
		t.Fatalf("install did not recover catalog metadata durable temp residue: %v", err)
	}
	for _, path := range []string{catalogTemp, componentTemp} {
		if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("stale product-owned durable temp survived install: %s err=%v", path, statErr)
		}
	}
}

func helmChartTGZ(t *testing.T, name, version string) []byte {
	t.Helper()
	files := map[string]string{
		name + "/Chart.yaml":                "apiVersion: v2\nname: " + name + "\nversion: " + version + "\ntype: application\n",
		name + "/values.yaml":               "{}\n",
		name + "/templates/deployment.yaml": "{{- /* test fixture only; runtime consumes immutable render evidence */ -}}\n",
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.Header.ModTime = time.Unix(0, 0)
	tw := tar.NewWriter(gz)
	for _, path := range []string{name + "/Chart.yaml", name + "/values.yaml", name + "/templates/deployment.yaml"} {
		raw := []byte(files[path])
		h := &tar.Header{Name: path, Mode: 0o644, Size: int64(len(raw)), ModTime: time.Unix(0, 0), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(raw); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func ociHelmInput(t *testing.T) AssembleInput {
	t.Helper()
	base, err := os.ReadFile(filepath.Join("..", "..", "catalog", "components", "alloy.json"))
	if err != nil {
		t.Fatal(err)
	}
	var componentDoc struct {
		Spec struct {
			Release string `json:"release"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(base, &componentDoc); err != nil {
		t.Fatal(err)
	}
	version := componentDoc.Spec.Release
	if version == "" || strings.Contains(version, "x") {
		t.Fatalf("alloy fixture requires the catalog authority to carry an exact admitted version, got %q", version)
	}
	image := "ghcr.io/grafana/alloy@sha256:" + strings.Repeat("a", 64)
	render := []byte(`[{
  "apiVersion":"apps/v1",
  "kind":"DaemonSet",
  "metadata":{"name":"alloy","namespace":"logging"},
  "spec":{"template":{"spec":{"containers":[{"name":"alloy","image":"` + image + `"}]}}}
}]`)
	inventory := []byte("{\n  \"images\": [{\"reference\": \"" + image + "\"}]\n}\n")
	artifact := helmChartTGZ(t, "alloy", version)
	return AssembleInput{
		BaseComponent:    base,
		Artifact:         artifact,
		RenderManifest:   render,
		ImageInventory:   inventory,
		Licenses:         []byte("{\n  \"licenses\": [{\"file\": \"LICENSE\", \"spdxExpression\": \"Apache-2.0\"}]\n}\n"),
		SBOM:             []byte("{\n  \"spdxVersion\": \"SPDX-2.3\", \"SPDXID\": \"SPDXRef-DOCUMENT\", \"name\": \"alloy-" + version + "-test-fixture\", \"packages\": [{\"SPDXID\":\"SPDXRef-Package-alloy\",\"name\":\"alloy\",\"versionInfo\":\"" + version + "\"}]\n}\n"),
		RenderGeneration: fixtureRenderGeneration("logging", "1.34.0", "1.35.0"),
		Version:          version, SourceType: "helm-chart", SourceURL: "oci://example.test/charts/alloy", SourceRevision: version, UpstreamArtifact: "alloy-" + version + ".tgz", ExpectedArtifactDigest: sha(artifact), BundleKey: "alloy/" + version,
	}
}

func TestOCIHelmBundleRequiresRealChartAndPreservesChartIdentity(t *testing.T) {
	in := ociHelmInput(t)
	raw, v, err := Assemble(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 || !v.OfflineReady {
		t.Fatal("helm-chart bundle was not verified offline")
	}
	if got := v.Component.Spec.Delivery.Chart; got != "alloy" {
		t.Fatalf("upstream chart identity was lost: %q", got)
	}
	if got := v.Component.Spec.Source.BundleKey; got != "alloy/"+in.Version {
		t.Fatalf("runtime bundle identity mismatch: %q", got)
	}
}

func TestHelmBundleRequiresExactRenderGenerationEvidence(t *testing.T) {
	in := ociHelmInput(t)
	in.RenderGeneration = nil
	if _, _, err := Assemble(in); err == nil || !strings.Contains(err.Error(), "render generation") {
		t.Fatalf("helm-chart source accepted missing render generation evidence: %v", err)
	}

	in = ociHelmInput(t)
	in.RenderGeneration = fixtureRenderGeneration("wrong-namespace", "1.34.0", "1.35.0")
	if _, _, err := Assemble(in); err == nil || !strings.Contains(err.Error(), "namespace") {
		t.Fatalf("helm-chart source accepted mismatched render namespace: %v", err)
	}

	in = ociHelmInput(t)
	in.RenderGeneration = fixtureRenderGeneration("logging", "1.34.0", "1.36.0")
	if _, _, err := Assemble(in); err == nil || !strings.Contains(err.Error(), "Kubernetes") {
		t.Fatalf("helm-chart source accepted mismatched Kubernetes render window: %v", err)
	}
}

func TestOCIHelmBundleRejectsNonChartBytes(t *testing.T) {
	in := ociHelmInput(t)
	in.Artifact = []byte("not-a-chart")
	in.ExpectedArtifactDigest = sha(in.Artifact)
	if _, _, err := Assemble(in); err == nil {
		t.Fatal("helm-chart source accepted arbitrary artifact bytes")
	}
}

func TestOCIHelmBundleRejectsChartIdentityMismatch(t *testing.T) {
	in := ociHelmInput(t)
	in.Artifact = helmChartTGZ(t, "other-chart", in.Version)
	in.ExpectedArtifactDigest = sha(in.Artifact)
	if _, _, err := Assemble(in); err == nil {
		t.Fatal("helm-chart source accepted wrong chart name")
	}
	in = ociHelmInput(t)
	in.Artifact = helmChartTGZ(t, "alloy", "1.11.2")
	in.ExpectedArtifactDigest = sha(in.Artifact)
	if _, _, err := Assemble(in); err == nil {
		t.Fatal("helm-chart source accepted wrong chart version")
	}
}

func taggedSourceSetZIP(t *testing.T, component, version, releaseURL string) []byte {
	t.Helper()
	payload := []byte("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: platform-system\n")
	idx := map[string]any{
		"apiVersion": "platform.4so.io/v1alpha1",
		"kind":       "UpstreamSourceSet",
		"component":  component,
		"version":    version,
		"upstream": map[string]any{
			"project":            component,
			"releaseUrl":         releaseURL,
			"revision":           "v" + version,
			"releaseCommit":      "0123456789abcdef0123456789abcdef01234567",
			"releaseCommitShort": "0123456",
			"channel":            "release",
		},
		"files": []map[string]any{{"path": "install.yaml", "url": releaseURL + "/install.yaml", "sha256": sha(payload)}},
		"assembly": map[string]any{
			"networkFetchRequired": false,
			"method":               "deterministic-zip-from-official-tag-files",
			"note":                 "test fixture",
		},
	}
	idxRaw, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	idxRaw = append(idxRaw, '\n')
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, item := range []struct {
		name string
		raw  []byte
	}{{"install.yaml", payload}, {"source-index.json", idxRaw}} {
		h := &zip.FileHeader{Name: item.name, Method: zip.Deflate}
		h.SetMode(0o644)
		h.Modified = time.Unix(315532800, 0).UTC()
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(item.raw); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func taggedSourceSetInput(t *testing.T) AssembleInput {
	t.Helper()
	base, err := os.ReadFile(filepath.Join("..", "..", "catalog", "components", "gateway-api.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(base, &doc); err != nil {
		t.Fatal(err)
	}
	spec := doc["spec"].(map[string]any)
	src := spec["source"].(map[string]any)
	for _, k := range []string{"bundleKey", "artifactDigest", "renderManifestDigest", "sourceLockDigest", "imageInventoryDigest", "licenseManifestDigest"} {
		src[k] = ""
	}
	src["resolved"] = false
	src["signatureVerification"] = "required"
	src["sbom"] = "required"
	src["provenance"] = "required"
	base, err = json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	base = append(base, '\n')
	version := "1.5.1"
	url := "https://github.com/kubernetes-sigs/gateway-api/releases/tag/v" + version
	artifact := taggedSourceSetZIP(t, "gateway-api", version, url)
	return AssembleInput{
		BaseComponent: base, Artifact: artifact,
		RenderManifest: []byte("[{\"apiVersion\":\"v1\",\"kind\":\"Namespace\",\"metadata\":{\"name\":\"platform-system\"}}]\n"),
		ImageInventory: []byte("{\"images\":[]}\n"),
		Licenses:       []byte("{\"licenses\":[{\"file\":\"LICENSE\",\"spdxExpression\":\"Apache-2.0\"}]}\n"),
		SBOM:           []byte("{\"spdxVersion\":\"SPDX-2.3\",\"SPDXID\":\"SPDXRef-DOCUMENT\",\"name\":\"gateway-api-test\",\"packages\":[{\"SPDXID\":\"SPDXRef-Package-gateway-api\",\"name\":\"gateway-api\",\"versionInfo\":\"1.5.1\"}]}\n"),
		Version:        version, SourceType: "external-tagged-source-set", SourceURL: url, SourceRevision: "v" + version,
		UpstreamArtifact: "gateway-api-v1.5.1-source-set.zip", ExpectedArtifactDigest: sha(artifact), BundleKey: "gateway-api/1.5.1",
	}
}

func TestTaggedSourceSetRequiresDeclaredUpstreamIdentity(t *testing.T) {
	in := taggedSourceSetInput(t)
	if _, _, err := Assemble(in); err != nil {
		t.Fatalf("valid tagged source-set rejected: %v", err)
	}
	in = taggedSourceSetInput(t)
	in.SourceURL = "https://example.invalid/releases/tag/v1.5.1"
	if _, _, err := Assemble(in); err == nil {
		t.Fatal("tagged source-set accepted mismatched upstream release URL")
	}
	in = taggedSourceSetInput(t)
	in.SourceRevision = "v1.5.0"
	if _, _, err := Assemble(in); err == nil {
		t.Fatal("tagged source-set accepted mismatched upstream revision")
	}
}

func TestBundleRejectsUnsupportedExternalSourceType(t *testing.T) {
	in := ociHelmInput(t)
	in.SourceType = "external-native-manifest"
	if _, _, err := Assemble(in); err == nil {
		t.Fatal("bundle accepted unsupported external source type")
	}
}

func TestBundleRejectsVersionOutsideComponentConstraint(t *testing.T) {
	in := ociHelmInput(t)
	in.Version = "2.0.0"
	in.BundleKey = "alloy/2.0.0"
	in.Artifact = helmChartTGZ(t, "alloy", "2.0.0")
	in.ExpectedArtifactDigest = sha(in.Artifact)
	if _, _, err := Assemble(in); err == nil {
		t.Fatal("bundle accepted a version outside the component release constraint")
	}
}

func TestOCIHelmAcceptsUpstreamVPrefixedChartVersion(t *testing.T) {
	in := ociHelmInput(t)
	in.Artifact = helmChartTGZ(t, "alloy", "v"+in.Version)
	in.ExpectedArtifactDigest = sha(in.Artifact)
	if _, _, err := Assemble(in); err != nil {
		t.Fatalf("v-prefixed upstream chart version should normalize to component release: %v", err)
	}
}

func TestBundleRejectsUnpinnedArtifactBytes(t *testing.T) {
	in := ociHelmInput(t)
	in.ExpectedArtifactDigest = "sha256:" + strings.Repeat("f", 64)
	if _, _, err := Assemble(in); err == nil {
		t.Fatal("bundle accepted bytes that did not match independently pinned digest")
	}
}

func TestBundleRejectsRenderImageInventoryDrift(t *testing.T) {
	in := ociHelmInput(t)
	in.ImageInventory = []byte("{\n  \"images\": []\n}\n")
	if _, _, err := Assemble(in); err == nil {
		t.Fatal("bundle accepted render image missing from inventory")
	}
	in = ociHelmInput(t)
	extra := "ghcr.io/grafana/unused@sha256:" + strings.Repeat("b", 64)
	var inv map[string]any
	if err := json.Unmarshal(in.ImageInventory, &inv); err != nil {
		t.Fatal(err)
	}
	images := inv["images"].([]any)
	inv["images"] = append(images, map[string]any{"reference": extra})
	in.ImageInventory, _ = json.Marshal(inv)
	if _, _, err := Assemble(in); err == nil {
		t.Fatal("bundle accepted unused inventory image")
	}
}

func TestBundleAcceptsRealisticSBOMDependencyVersionsButRequiresChartIdentity(t *testing.T) {
	in := ociHelmInput(t)
	in.SBOM = []byte(`{
  "spdxVersion":"SPDX-2.3",
  "SPDXID":"SPDXRef-DOCUMENT",
  "name":"alloy-realistic-sbom",
  "packages":[
    {"SPDXID":"SPDXRef-Package-alloy","name":"alloy","versionInfo":"` + in.Version + `"},
    {"SPDXID":"SPDXRef-Package-dependency","name":"example-dependency","versionInfo":"2026.08-build7"},
    {"SPDXID":"SPDXRef-Package-image","name":"ghcr.io/grafana/alloy","versionInfo":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
  ]
}`)
	if _, _, err := Assemble(in); err != nil {
		t.Fatalf("realistic SPDX dependency versions were rejected: %v", err)
	}
	in = ociHelmInput(t)
	in.SBOM = []byte(`{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"wrong","packages":[{"SPDXID":"SPDXRef-Package-other","name":"other","versionInfo":"` + in.Version + `"}]}`)
	if _, _, err := Assemble(in); err == nil {
		t.Fatal("SBOM without the imported chart identity was accepted")
	}
}

func TestInstallRecoversDurableAuthorityTransactionJournal(t *testing.T) {
	_, v, err := Assemble(fixtureInput(t))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err = os.WriteFile(filepath.Join(root, "VERSION"), []byte("test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	componentsDir := filepath.Join(root, "catalog", "components")
	if err = os.MkdirAll(componentsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	base := fixtureInput(t).BaseComponent
	componentPath := filepath.Join(componentsDir, "cilium.json")
	if err = os.WriteFile(componentPath, base, 0o644); err != nil {
		t.Fatal(err)
	}
	writeHelmAdmission(t, root, "cilium", "cilium", "1.20.1", "oci://quay.io/cilium/charts/cilium", "1.20.1", "ready-for-acquisition")
	writeRuntimeUpgradeMatrix(t, root, "cilium", "1.20.x")
	oldRegistry, err := os.ReadFile(filepath.Join(root, "catalog", "component-runtime-certification.json"))
	if err != nil {
		t.Fatal(err)
	}
	oldAdmission, err := os.ReadFile(filepath.Join(root, "catalog", "upstream-admission.json"))
	if err != nil {
		t.Fatal(err)
	}
	oldUpgradeMatrix, err := os.ReadFile(filepath.Join(root, "catalog", "component-runtime-upgrade-matrix.json"))
	if err != nil {
		t.Fatal(err)
	}
	txn := catalogAuthorityTransaction{Component: "cilium", OldComponent: base, OldRegistry: oldRegistry, OldUpgradeMatrix: oldUpgradeMatrix, OldAdmission: oldAdmission}
	if err = beginCatalogAuthorityTransaction(root, txn); err != nil {
		t.Fatal(err)
	}
	// Simulate a crash after all three authority files were partially committed.
	if err = atomicWrite(componentPath, v.Files["component.json"], 0o644); err != nil {
		t.Fatal(err)
	}
	var rebound catalog.ComponentRuntimeCertificationRegistry
	if err = json.Unmarshal(oldRegistry, &rebound); err != nil {
		t.Fatal(err)
	}
	var resolved catalog.Component
	if err = json.Unmarshal(v.Files["component.json"], &resolved); err != nil {
		t.Fatal(err)
	}
	if err = catalog.RebindComponentRuntimeCertificationSource(&rebound, resolved); err != nil {
		t.Fatal(err)
	}
	reboundRaw, err := json.MarshalIndent(rebound, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = atomicWrite(filepath.Join(root, "catalog", "component-runtime-certification.json"), append(reboundRaw, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	var oldMatrixDoc map[string]any
	if err = json.Unmarshal(oldUpgradeMatrix, &oldMatrixDoc); err != nil {
		t.Fatal(err)
	}
	matrixRow := oldMatrixDoc["components"].([]any)[0].(map[string]any)
	matrixDigest, digestErr := sourceLockAuthorityDigest(v.Files["source-lock.json"])
	if digestErr != nil {
		t.Fatal(digestErr)
	}
	matrixRow["targetRelease"] = "1.20.1"
	matrixRow["targetSourceLockDigest"] = matrixDigest
	partialMatrixRaw, err := json.MarshalIndent(oldMatrixDoc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = atomicWrite(filepath.Join(root, "catalog", "component-runtime-upgrade-matrix.json"), append(partialMatrixRaw, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	if err = retireCanonicalHelmAdmission(root, "cilium"); err != nil {
		t.Fatal(err)
	}
	if err = Install(v, root); err != nil {
		t.Fatalf("install did not recover durable authority transaction: %v", err)
	}
	if _, statErr := os.Stat(catalogAuthorityTransactionPath(root)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("transaction journal survived successful recovery: %v", statErr)
	}
	finalRegistryRaw, err := os.ReadFile(filepath.Join(root, "catalog", "component-runtime-certification.json"))
	if err != nil {
		t.Fatal(err)
	}
	var finalRegistry catalog.ComponentRuntimeCertificationRegistry
	if err = json.Unmarshal(finalRegistryRaw, &finalRegistry); err != nil {
		t.Fatal(err)
	}
	if err = catalog.ValidateComponentRuntimeCertificationRegistry(finalRegistry, map[string]catalog.Component{"cilium": resolved}); err != nil {
		t.Fatalf("recovered runtime certification authority invalid: %v", err)
	}
	finalUpgradeRaw, err := os.ReadFile(filepath.Join(root, "catalog", "component-runtime-upgrade-matrix.json"))
	if err != nil {
		t.Fatal(err)
	}
	var finalUpgrade map[string]any
	if err = json.Unmarshal(finalUpgradeRaw, &finalUpgrade); err != nil {
		t.Fatal(err)
	}
	finalUpgradeRow := finalUpgrade["components"].([]any)[0].(map[string]any)
	if finalUpgradeRow["targetRelease"] != "1.20.1" || finalUpgradeRow["targetSourceLockDigest"] != matrixDigest {
		t.Fatalf("recovered runtime upgrade matrix authority invalid: %+v", finalUpgradeRow)
	}
	doc, err := loadCanonicalUpstreamAdmission(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = findUpstreamAdmissionEntry(&doc, "cilium"); !errors.Is(err, errUpstreamAdmissionComponentMissing) {
		t.Fatalf("recovered install left stale admission: %v", err)
	}
}

func TestInstallRecoversCrashAfterResolvedComponentCommitBeforeAdmissionRetirement(t *testing.T) {
	_, v, err := Assemble(fixtureInput(t))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err = os.WriteFile(filepath.Join(root, "VERSION"), []byte("test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	componentsDir := filepath.Join(root, "catalog", "components")
	if err = os.MkdirAll(componentsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeHelmAdmission(t, root, "cilium", "cilium", "1.20.1", "oci://quay.io/cilium/charts/cilium", "1.20.1", "ready-for-acquisition")

	// Simulate the exact durable state after runtime + resolved component commit,
	// but before the admission retirement write completed.
	runtimeDir := filepath.Join(root, "catalog", "runtime", filepath.FromSlash(v.Manifest.BundleKey))
	if err = installRuntimeBundle(runtimeDir, v.Files); err != nil {
		t.Fatal(err)
	}
	if err = atomicWrite(filepath.Join(componentsDir, "cilium.json"), v.Files["component.json"], 0o644); err != nil {
		t.Fatal(err)
	}

	if err = Install(v, root); err != nil {
		t.Fatalf("idempotent retry did not repair post-component/pre-retirement crash state: %v", err)
	}
	doc, err := loadCanonicalUpstreamAdmission(root)
	if err != nil {
		t.Fatal(err)
	}
	if err = validateCanonicalUpstreamAdmissionCoverage(root, doc); err != nil {
		t.Fatalf("authority remained invalid after crash recovery: %v", err)
	}
	if _, err = findUpstreamAdmissionEntry(&doc, "cilium"); !errors.Is(err, errUpstreamAdmissionComponentMissing) {
		t.Fatalf("stale admission row survived crash recovery: %v", err)
	}
}

func TestInstallRejectsSymlinkedCanonicalAdmissionBeforeMutation(t *testing.T) {
	_, v, err := Assemble(fixtureInput(t))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err = os.WriteFile(filepath.Join(root, "VERSION"), []byte("test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	componentsDir := filepath.Join(root, "catalog", "components")
	if err = os.MkdirAll(componentsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(componentsDir, "cilium.json"), fixtureInput(t).BaseComponent, 0o644); err != nil {
		t.Fatal(err)
	}

	authorityRoot := t.TempDir()
	writeHelmAdmission(t, authorityRoot, "cilium", "cilium", "1.20.1", "oci://quay.io/cilium/charts/cilium", "1.20.1", "ready-for-acquisition")
	authorityTarget := filepath.Join(authorityRoot, "catalog", "upstream-admission.json")
	authorityPath := filepath.Join(root, "catalog", "upstream-admission.json")
	if err = os.Symlink(authorityTarget, authorityPath); err != nil {
		t.Fatal(err)
	}

	if err = Install(v, root); err == nil || !strings.Contains(err.Error(), "real regular file") {
		t.Fatalf("symlinked canonical authority was accepted: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(root, "catalog", "runtime", "cilium", "1.20.1")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("runtime mutated before symlinked authority rejection: %v", statErr)
	}
	current, readErr := os.ReadFile(filepath.Join(componentsDir, "cilium.json"))
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Equal(current, fixtureInput(t).BaseComponent) {
		t.Fatal("component contract mutated before symlinked authority rejection")
	}
}

func TestInstallRejectsSymlinkedRuntimeParentBeforeMutation(t *testing.T) {
	_, v, err := Assemble(fixtureInput(t))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err = os.WriteFile(filepath.Join(root, "VERSION"), []byte("test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	componentsDir := filepath.Join(root, "catalog", "components")
	if err = os.MkdirAll(componentsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	base := fixtureInput(t).BaseComponent
	if err = os.WriteFile(filepath.Join(componentsDir, "cilium.json"), base, 0o644); err != nil {
		t.Fatal(err)
	}
	writeHelmAdmission(t, root, "cilium", "cilium", "1.20.1", "oci://quay.io/cilium/charts/cilium", "1.20.1", "ready-for-acquisition")

	runtimeRoot := filepath.Join(root, "catalog", "runtime")
	if err = os.MkdirAll(runtimeRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err = os.Symlink(outside, filepath.Join(runtimeRoot, "cilium")); err != nil {
		t.Fatal(err)
	}

	if err = Install(v, root); err == nil || !strings.Contains(err.Error(), "runtime component path is not a real directory") {
		t.Fatalf("symlinked runtime parent was accepted: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(outside, "1.20.1")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("install escaped repository through runtime symlink: %v", statErr)
	}
	current, readErr := os.ReadFile(filepath.Join(componentsDir, "cilium.json"))
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Equal(current, base) {
		t.Fatal("component contract mutated after runtime path rejection")
	}
}

func TestInstallRemovesCrashLeftoverRuntimeStage(t *testing.T) {
	_, v, err := Assemble(fixtureInput(t))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err = os.WriteFile(filepath.Join(root, "VERSION"), []byte("test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	componentsDir := filepath.Join(root, "catalog", "components")
	if err = os.MkdirAll(componentsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(componentsDir, "cilium.json"), fixtureInput(t).BaseComponent, 0o644); err != nil {
		t.Fatal(err)
	}
	writeHelmAdmission(t, root, "cilium", "cilium", "1.20.1", "oci://quay.io/cilium/charts/cilium", "1.20.1", "ready-for-acquisition")

	parent := filepath.Join(root, "catalog", "runtime", "cilium")
	if err = os.MkdirAll(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(parent, ".1.20.1.partial-crashed")
	if err = os.Mkdir(stale, 0o755); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(stale, ".durable-orphan"), []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err = Install(v, root); err != nil {
		t.Fatalf("retry after staging crash failed: %v", err)
	}
	if _, statErr := os.Lstat(stale); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("stale runtime stage survived successful retry: %v", statErr)
	}
	if _, statErr := os.Stat(filepath.Join(parent, "1.20.1", "artifact.bin")); statErr != nil {
		t.Fatalf("runtime bundle missing after crash-stage recovery: %v", statErr)
	}
}

func TestInstallRejectsSymlinkedExternalComponentContractBeforeMutation(t *testing.T) {
	in := taggedSourceSetInput(t)
	_, v, err := Assemble(in)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err = os.WriteFile(filepath.Join(root, "VERSION"), []byte("test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	componentsDir := filepath.Join(root, "catalog", "components")
	if err = os.MkdirAll(componentsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "gateway-api.json")
	if err = os.WriteFile(outside, in.BaseComponent, 0o644); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(outside, filepath.Join(componentsDir, "gateway-api.json")); err != nil {
		t.Fatal(err)
	}

	if err = Install(v, root); err == nil || !strings.Contains(err.Error(), "real regular file") {
		t.Fatalf("symlinked component authority was accepted: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(root, "catalog", "runtime", "gateway-api", "1.5.1")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("runtime mutated before component path rejection: %v", statErr)
	}
	outsideRaw, readErr := os.ReadFile(outside)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Equal(outsideRaw, in.BaseComponent) {
		t.Fatal("external symlink target was mutated")
	}
}

func TestInstallRejectsSymlinkedExistingRuntimeFileBeforeCatalogMutation(t *testing.T) {
	_, v, err := Assemble(fixtureInput(t))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err = os.WriteFile(filepath.Join(root, "VERSION"), []byte("test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	componentsDir := filepath.Join(root, "catalog", "components")
	if err = os.MkdirAll(componentsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	base := fixtureInput(t).BaseComponent
	componentPath := filepath.Join(componentsDir, "cilium.json")
	if err = os.WriteFile(componentPath, base, 0o644); err != nil {
		t.Fatal(err)
	}
	writeHelmAdmission(t, root, "cilium", "cilium", "1.20.1", "oci://quay.io/cilium/charts/cilium", "1.20.1", "ready-for-acquisition")

	runtimeDir := filepath.Join(root, "catalog", "runtime", filepath.FromSlash(v.Manifest.BundleKey))
	if err = os.MkdirAll(runtimeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range requiredFiles {
		if name == "component.json" || name == "artifact.bin" {
			continue
		}
		if err = os.WriteFile(filepath.Join(runtimeDir, name), v.Files[name], 0o644); err != nil {
			t.Fatal(err)
		}
	}
	outside := filepath.Join(t.TempDir(), "artifact.bin")
	if err = os.WriteFile(outside, v.Files["artifact.bin"], 0o644); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(outside, filepath.Join(runtimeDir, "artifact.bin")); err != nil {
		t.Fatal(err)
	}

	if err = Install(v, root); err == nil || !strings.Contains(err.Error(), "runtime bundle file artifact.bin is not a real regular file") {
		t.Fatalf("symlinked existing runtime file was accepted: %v", err)
	}
	current, readErr := os.ReadFile(componentPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Equal(current, base) {
		t.Fatal("component contract mutated before runtime file path rejection")
	}
	doc, loadErr := loadCanonicalUpstreamAdmission(root)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if _, findErr := findUpstreamAdmissionEntry(&doc, "cilium"); findErr != nil {
		t.Fatalf("admission row retired before runtime file path rejection: %v", findErr)
	}
}

func TestCanonicalAdmissionAllowsExactReviewCandidateBesideReadyInstall(t *testing.T) {
	root := t.TempDir()
	componentsDir := filepath.Join(root, "catalog", "components")
	if err := os.MkdirAll(componentsDir, 0o755); err != nil {
		t.Fatal(err)
	}

	base := fixtureInput(t).BaseComponent
	var ready map[string]any
	if err := json.Unmarshal(base, &ready); err != nil {
		t.Fatal(err)
	}
	readySpec := ready["spec"].(map[string]any)
	readySpec["release"] = "1.20.1"
	readySpec["versionPolicy"] = "exact-upstream-admitted-pending-source-acquisition"
	if raw, err := json.MarshalIndent(ready, "", "  "); err != nil {
		t.Fatal(err)
	} else if err = os.WriteFile(filepath.Join(componentsDir, "cilium.json"), append(raw, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}

	var review map[string]any
	if err := json.Unmarshal(base, &review); err != nil {
		t.Fatal(err)
	}
	review["metadata"].(map[string]any)["name"] = "kyverno"
	reviewSpec := review["spec"].(map[string]any)
	reviewSpec["release"] = "3.8.2"
	reviewSpec["versionPolicy"] = "exact-upstream-admitted-pending-source-acquisition"
	reviewSpec["delivery"].(map[string]any)["chart"] = "kyverno"
	writeReview := func() {
		raw, err := json.MarshalIndent(review, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(componentsDir, "kyverno.json"), append(raw, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeReview()

	doc := upstreamAdmissionDocument{
		APIVersion: "platform.4so.io/v1alpha1",
		Kind:       "CatalogUpstreamAdmission",
	}
	doc.Metadata.Name = "review-candidate-regression"
	doc.Spec.Policy.AllowLatestResolution = false
	doc.Spec.Policy.AutoWidenCatalogConstraint = false
	doc.Spec.Policy.RuntimeCertification = "separate-runtime-evidence-required"
	doc.Spec.Policy.CandidateAcquisition = "exact-source-may-be-acquired-before-runtime-clearance"
	doc.Spec.Policy.SourceAuthority = "official-upstream-only"
	doc.Spec.Policy.SourceResolution = "separate-immutable-acquisition-required"
	doc.Spec.Policy.VersionSelection = "exact-semver-no-prerelease"
	readyVersion, reviewVersion := "1.20.1", "3.8.2"
	doc.Spec.Components = []upstreamAdmissionEntry{
		{Component: "cilium", Chart: "cilium", CatalogConstraint: "1.20.x", SelectedVersion: &readyVersion, UpstreamVersion: &readyVersion, Source: "oci://quay.io/cilium/charts/cilium", Status: "ready-for-acquisition", RuntimeStatus: "eligible-after-source-resolution", Rationale: "ready fixture"},
		{Component: "kyverno", Chart: "kyverno", CatalogConstraint: "3.8.x", SelectedVersion: &reviewVersion, UpstreamVersion: &reviewVersion, Source: "https://kyverno.github.io/kyverno/", Status: "ready-for-acquisition", RuntimeStatus: "review-required", Rationale: "review fixture", ReviewEvidence: []upstreamAdmissionReviewEvidence{{Kind: "blocker", URL: "https://example.test/issue", Summary: "review remains open"}}},
	}
	if err := validateCanonicalUpstreamAdmissionCoverage(root, doc); err != nil {
		t.Fatalf("exact review candidate incorrectly blocked unrelated ready install: %v", err)
	}

	reviewSpec["release"] = "3.8.1"
	writeReview()
	if err := validateCanonicalUpstreamAdmissionCoverage(root, doc); err == nil || !strings.Contains(err.Error(), "catalog pin mismatch") {
		t.Fatalf("review candidate release drift was accepted: %v", err)
	}
	reviewSpec["release"] = "3.8.2"
	reviewSpec["versionPolicy"] = "resolve-verify-and-pin-before-execution"
	writeReview()
	if err := validateCanonicalUpstreamAdmissionCoverage(root, doc); err == nil || !strings.Contains(err.Error(), "version policy mismatch") {
		t.Fatalf("runtime-blocked acquisition candidate version-policy drift was accepted: %v", err)
	}
}

func writeUpgradeSourceAdmission(t *testing.T, root, component, target, previous, source, status string) {
	t.Helper()
	evidence := []any{}
	if status == "admitted-for-acquisition" {
		evidence = []any{map[string]any{"kind": "upstream-release-history", "reference": "https://example.test/releases", "summary": "reviewed exact predecessor"}}
	}
	doc := map[string]any{
		"apiVersion": "platform.4so.io/v1alpha1", "kind": "ComponentUpgradeSourceAdmission", "authority": "COMPONENT_UPGRADE_SOURCE_ADMISSION_V1", "schemaVersion": 1,
		"policy":     map[string]any{"explicitHumanOrReleaseReviewRequired": true, "exactPreviousVersionRequired": true, "strictUpgradeDirectionRequired": true, "mutableTagForbidden": true, "admissionDoesNotEqualCertification": true, "reviewEvidenceRequiredForAdmission": true, "firstProductReleaseInstallOnlyAllowed": true, "historicalVersionFabricationForbidden": true},
		"components": []any{map[string]any{"component": component, "targetRelease": target, "status": status, "previousVersion": previous, "source": source, "licenseSPDX": func() string { if status == "admitted-for-acquisition" { return "Apache-2.0" }; return "" }(), "valuesFiles": []string{}, "rationale": "reviewed test edge", "reviewEvidence": evidence}},
	}
	raw, _ := json.MarshalIndent(doc, "", "  ")
	if err := os.WriteFile(filepath.Join(root, "catalog", "component-upgrade-source-admission.json"), append(raw, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestInstallHistoricalAdmitsExactSourcePairWithoutChangingCurrentComponent(t *testing.T) {
	_, currentBundle, err := Assemble(fixtureInput(t))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err = os.WriteFile(filepath.Join(root, "VERSION"), []byte("test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeHelmAdmission(t, root, "cilium", "cilium", "1.20.1", "oci://quay.io/cilium/charts/cilium", "1.20.1", "ready-for-acquisition")
	writeRuntimeUpgradeMatrix(t, root, "cilium", "1.20.x")
	if err = os.MkdirAll(filepath.Join(root, "catalog", "components"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, "catalog", "components", "cilium.json"), fixtureInput(t).BaseComponent, 0o644); err != nil {
		t.Fatal(err)
	}
	if err = Install(currentBundle, root); err != nil {
		t.Fatal(err)
	}
	currentRaw, err := os.ReadFile(filepath.Join(root, "catalog", "components", "cilium.json"))
	if err != nil {
		t.Fatal(err)
	}

	h := fixtureInput(t)
	h.BaseComponent = currentRaw
	h.Historical = true
	h.Version = "1.19.0"
	h.SourceRevision = "1.19.0"
	h.UpstreamArtifact = "cilium-1.19.0.tgz"
	h.BundleKey = "cilium/1.19.0"
	h.Artifact = helmChartTGZ(t, "cilium", "1.19.0")
	h.ExpectedArtifactDigest = sha(h.Artifact)
	h.SBOM = []byte("{\n  \"spdxVersion\": \"SPDX-2.3\", \"SPDXID\": \"SPDXRef-DOCUMENT\", \"name\": \"cilium-1.19.0-test-fixture\", \"packages\": [{\"SPDXID\":\"SPDXRef-Package-cilium\",\"name\":\"cilium\",\"versionInfo\":\"1.19.0\"}]\n}\n")
	_, historical, err := Assemble(h)
	if err != nil {
		t.Fatal(err)
	}
	writeUpgradeSourceAdmission(t, root, "cilium", "1.20.1", "1.19.0", h.SourceURL, "admitted-for-acquisition")
	if err = InstallHistorical(historical, root); err != nil {
		t.Fatal(err)
	}
	afterRaw, err := os.ReadFile(filepath.Join(root, "catalog", "components", "cilium.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(currentRaw, afterRaw) {
		t.Fatal("historical install changed current component authority")
	}
	if _, err = os.Stat(filepath.Join(root, "catalog", "runtime", "cilium", "1.19.0", "source-lock.json")); err != nil {
		t.Fatal(err)
	}
	matrixRaw, err := os.ReadFile(filepath.Join(root, "catalog", "component-runtime-upgrade-matrix.json"))
	if err != nil {
		t.Fatal(err)
	}
	var matrix map[string]any
	if err = json.Unmarshal(matrixRaw, &matrix); err != nil {
		t.Fatal(err)
	}
	row := matrix["components"].([]any)[0].(map[string]any)
	if row["status"] != "admitted-source-pair" || len(row["admittedEdges"].([]any)) != 1 {
		t.Fatalf("historical pair not admitted: %#v", row)
	}
	edge := row["admittedEdges"].([]any)[0].(map[string]any)
	if edge["fromRelease"] != "1.19.0" || edge["toRelease"] != "1.20.1" {
		t.Fatalf("wrong edge: %#v", edge)
	}
}

func TestInstallHistoricalRequiresExplicitAdmission(t *testing.T) {
	_, currentBundle, err := Assemble(fixtureInput(t))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	_ = os.WriteFile(filepath.Join(root, "VERSION"), []byte("test\n"), 0o644)
	writeHelmAdmission(t, root, "cilium", "cilium", "1.20.1", "oci://quay.io/cilium/charts/cilium", "1.20.1", "ready-for-acquisition")
	writeRuntimeUpgradeMatrix(t, root, "cilium", "1.20.x")
	_ = os.MkdirAll(filepath.Join(root, "catalog", "components"), 0o755)
	_ = os.WriteFile(filepath.Join(root, "catalog", "components", "cilium.json"), fixtureInput(t).BaseComponent, 0o644)
	if err = Install(currentBundle, root); err != nil {
		t.Fatal(err)
	}
	currentRaw, _ := os.ReadFile(filepath.Join(root, "catalog", "components", "cilium.json"))
	h := fixtureInput(t)
	h.BaseComponent = currentRaw
	h.Historical = true
	h.Version = "1.19.0"
	h.SourceRevision = "1.19.0"
	h.UpstreamArtifact = "cilium-1.19.0.tgz"
	h.BundleKey = "cilium/1.19.0"
	h.Artifact = helmChartTGZ(t, "cilium", "1.19.0")
	h.ExpectedArtifactDigest = sha(h.Artifact)
	h.SBOM = []byte("{\"spdxVersion\":\"SPDX-2.3\",\"SPDXID\":\"SPDXRef-DOCUMENT\",\"name\":\"h\",\"packages\":[{\"SPDXID\":\"SPDXRef-Package-cilium\",\"name\":\"cilium\",\"versionInfo\":\"1.19.0\"}]}\n")
	_, historical, err := Assemble(h)
	if err != nil {
		t.Fatal(err)
	}
	writeUpgradeSourceAdmission(t, root, "cilium", "1.20.1", "", "", "review-required")
	if err = InstallHistorical(historical, root); err == nil || !strings.Contains(err.Error(), "not admitted") {
		t.Fatalf("expected admission rejection, got %v", err)
	}
}

func TestUpstreamAdmissionStrictDecoderAcceptsCanonicalLicenseSPDX(t *testing.T) {
	raw := []byte(`{"catalogConstraint":"1.11.x","chart":"alloy","component":"alloy","licenseSPDX":"Apache-2.0","rationale":"fixture","selectedVersion":"1.11.0","source":"https://example.test/charts","status":"ready-for-acquisition","runtimeStatus":"eligible-after-source-resolution","upstreamVersion":"1.11.0"}`)
	var entry upstreamAdmissionEntry
	if err := decodeStrict(raw, &entry); err != nil {
		t.Fatalf("canonical licenseSPDX rejected by strict admission decoder: %v", err)
	}
}

func TestReservedEndpointPlaceholderAllowsConfigMapShellExpansion(t *testing.T) {
	resource := map[string]any{"data": map[string]any{"redis_liveness.sh": "redis-cli -a \"${REDIS_PASSWORD}\"\nif [ \"${response:0:7}\" != LOADING ]; then exit 1; fi"}}
	if renderResourceHasReservedEndpointPlaceholder(resource) { t.Fatal("shell expansion inside ConfigMap data was rejected") }
}

func TestReservedEndpointPlaceholderRejectsEndpointExpansion(t *testing.T) {
	for _, resource := range []map[string]any{
		{"spec": map[string]any{"server": "https://${ARGO_HOST}"}},
		{"data": map[string]any{"url": "https://${ARGO_HOST}/api"}},
		{"spec": map[string]any{"endpoint": "https://example.invalid"}},
	} {
		if !renderResourceHasReservedEndpointPlaceholder(resource) { t.Fatalf("reserved endpoint placeholder accepted: %#v", resource) }
	}
}
