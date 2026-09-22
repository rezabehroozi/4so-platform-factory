package virtualcluster

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runtimeDigest(ch string) string {
	return "sha256:" + strings.Repeat(ch, 64)
}

func TestSelectedRuntimeSourceIsExplicitlyUnresolved(t *testing.T) {
	source := SelectedRuntimeSource()
	if source.Authority != RuntimeSourceAuthority || source.Engine != RuntimeEngineVClusterOSS ||
		source.Version != RuntimeSelectedVersion || source.ChartRepository != RuntimeChartRepository ||
		source.ChartName != RuntimeChartName || source.ReleaseURL != RuntimeReleaseURL ||
		source.ValuesPath != RuntimeValuesPath || source.ImageRegistry != RuntimeImageRegistry ||
		source.ImageRepository != RuntimeImageRepository || source.Resolved || !source.OfflineAcquisitionRequired ||
		source.PlatformDependency {
		t.Fatalf("selected runtime source drift: %#v", source)
	}
	if err := ValidateRuntimeExecutionSource(source); err == nil {
		t.Fatal("unresolved selected source became execution eligible")
	}
}

func TestResolveRuntimeSourceRequiresExactChartAndImageDigests(t *testing.T) {
	resolved, err := ResolveRuntimeSource(RuntimeSourceResolution{
		Version: RuntimeSelectedVersion,
		ChartRepository: RuntimeChartRepository,
		ChartName: RuntimeChartName,
		ChartSHA256: runtimeDigest("a"),
		ValuesSHA256: runtimeDigest("d"),
		RenderManifestSHA256: runtimeDigest("e"),
		ImageReferences: []string{"ghcr.io/loft-sh/vcluster-oss@" + runtimeDigest("c"), "registry.k8s.io/pause@" + runtimeDigest("b")},
		ChartArtifactPath: "runtime/virtualcluster/chart/vcluster-0.37.1.tgz",
		ExecutorImageReference: "zot.internal/platform/virtual-cluster-runtime@" + runtimeDigest("f"),
		MirrorReady: true,
		MirrorImageReferences: []string{"zot.internal/mirror/vcluster-oss@" + runtimeDigest("c"), "zot.internal/mirror/pause@" + runtimeDigest("b")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !resolved.Resolved || len(resolved.ImageDigests) != 2 ||
		resolved.ImageDigests[0] != runtimeDigest("b") || resolved.ImageDigests[1] != runtimeDigest("c") {
		t.Fatalf("resolved source drift: %#v", resolved)
	}
	if err := ValidateRuntimeExecutionSource(resolved); err != nil {
		t.Fatalf("resolved source must be execution eligible: %v", err)
	}
}

func TestRuntimeSourceFailsClosedOnVersionIdentityAndDigestDrift(t *testing.T) {
	base := RuntimeSourceResolution{
		Version: RuntimeSelectedVersion,
		ChartRepository: RuntimeChartRepository,
		ChartName: RuntimeChartName,
		ChartSHA256: runtimeDigest("a"),
		ValuesSHA256: runtimeDigest("d"),
		RenderManifestSHA256: runtimeDigest("e"),
		ImageReferences: []string{"ghcr.io/loft-sh/vcluster-oss@" + runtimeDigest("b")},
		ChartArtifactPath: "runtime/virtualcluster/chart/vcluster-0.37.1.tgz",
		ExecutorImageReference: "zot.internal/platform/virtual-cluster-runtime@" + runtimeDigest("f"),
		MirrorReady: true,
		MirrorImageReferences: []string{"zot.internal/mirror/vcluster-oss@" + runtimeDigest("b")},
	}
	cases := []RuntimeSourceResolution{
		func() RuntimeSourceResolution { v := base; v.Version = "0.37.0"; return v }(),
		func() RuntimeSourceResolution { v := base; v.ChartRepository = "https://example.invalid/charts"; return v }(),
		func() RuntimeSourceResolution { v := base; v.ChartName = "vcluster-platform"; return v }(),
		func() RuntimeSourceResolution { v := base; v.ChartSHA256 = "sha256:not-exact"; return v }(),
		func() RuntimeSourceResolution { v := base; v.ImageReferences = []string{"ghcr.io/loft-sh/vcluster-oss:latest"}; return v }(),
	}
	for _, candidate := range cases {
		if _, err := ResolveRuntimeSource(candidate); err == nil {
			t.Fatalf("unsafe runtime source was admitted: %#v", candidate)
		}
	}
}

func TestRuntimeExecutionRejectsPlatformDependencyAndDuplicateInventory(t *testing.T) {
	resolved, err := ResolveRuntimeSource(RuntimeSourceResolution{
		Version: RuntimeSelectedVersion,
		ChartRepository: RuntimeChartRepository,
		ChartName: RuntimeChartName,
		ChartSHA256: runtimeDigest("a"),
		ValuesSHA256: runtimeDigest("d"),
		RenderManifestSHA256: runtimeDigest("e"),
		ImageReferences: []string{"ghcr.io/loft-sh/vcluster-oss@" + runtimeDigest("b")},
		ChartArtifactPath: "runtime/virtualcluster/chart/vcluster-0.37.1.tgz",
		ExecutorImageReference: "zot.internal/platform/virtual-cluster-runtime@" + runtimeDigest("f"),
		MirrorReady: true,
		MirrorImageReferences: []string{"zot.internal/mirror/vcluster-oss@" + runtimeDigest("b")},
	})
	if err != nil {
		t.Fatal(err)
	}
	withPlatform := resolved
	withPlatform.PlatformDependency = true
	if err := ValidateRuntimeExecutionSource(withPlatform); err == nil {
		t.Fatal("vCluster Platform dependency was admitted")
	}
	withDuplicate := resolved
	withDuplicate.ImageReferences = []string{"ghcr.io/loft-sh/vcluster-oss@" + runtimeDigest("b"), "ghcr.io/loft-sh/vcluster-oss@" + runtimeDigest("b")}
	if err := ValidateRuntimeExecutionSource(withDuplicate); err == nil {
		t.Fatal("duplicate image reference inventory was admitted")
	}
	unmirrored := resolved
	unmirrored.MirrorReady = false
	unmirrored.MirrorImageReferences = nil
	if err := ValidateRuntimeExecutionSource(unmirrored); err == nil {
		t.Fatal("source-only acquisition became execution eligible before local mirror proof")
	}
}


func TestRuntimeSourceRejectsProImageOrUnownedValuesDrift(t *testing.T) {
	resolved, err := ResolveRuntimeSource(RuntimeSourceResolution{
		Version: RuntimeSelectedVersion,
		ChartRepository: RuntimeChartRepository,
		ChartName: RuntimeChartName,
		ChartSHA256: runtimeDigest("a"),
		ValuesSHA256: runtimeDigest("d"),
		RenderManifestSHA256: runtimeDigest("e"),
		ImageReferences: []string{"ghcr.io/loft-sh/vcluster-oss@" + runtimeDigest("b")},
		ChartArtifactPath: "runtime/virtualcluster/chart/vcluster-0.37.1.tgz",
		ExecutorImageReference: "zot.internal/platform/virtual-cluster-runtime@" + runtimeDigest("f"),
		MirrorReady: true,
		MirrorImageReferences: []string{"zot.internal/mirror/vcluster-oss@" + runtimeDigest("b")},
	})
	if err != nil {
		t.Fatal(err)
	}
	proImage := resolved
	proImage.ImageRepository = "loft-sh/vcluster-pro"
	if err := ValidateRuntimeExecutionSource(proImage); err == nil {
		t.Fatal("vCluster Pro image authority was admitted")
	}
	unownedValues := resolved
	unownedValues.ValuesPath = "/tmp/values.yaml"
	if err := ValidateRuntimeExecutionSource(unownedValues); err == nil {
		t.Fatal("unowned runtime values path was admitted")
	}
}


func TestRuntimeExecutionRequiresExactExecutorImage(t *testing.T) {
	base := RuntimeSourceResolution{
		Version: RuntimeSelectedVersion,
		ChartRepository: RuntimeChartRepository,
		ChartName: RuntimeChartName,
		ChartSHA256: runtimeDigest("a"),
		ValuesSHA256: runtimeDigest("d"),
		RenderManifestSHA256: runtimeDigest("e"),
		ImageReferences: []string{"ghcr.io/loft-sh/vcluster-oss@" + runtimeDigest("b")},
		ChartArtifactPath: "runtime/virtualcluster/chart/vcluster-0.37.1.tgz",
		MirrorReady: true,
		MirrorImageReferences: []string{"zot.internal/mirror/vcluster-oss@" + runtimeDigest("b")},
	}
	for _, ref := range []string{"", "zot.internal/platform/virtual-cluster-runtime:latest", "zot.internal/platform/other@" + runtimeDigest("f")} {
		candidate := base
		candidate.ExecutorImageReference = ref
		if _, err := ResolveRuntimeSource(candidate); err == nil {
			t.Fatalf("unsafe executor image %q was admitted", ref)
		}
	}
	base.ExecutorImageReference = "zot.internal/platform/virtual-cluster-runtime@" + runtimeDigest("f")
	if _, err := ResolveRuntimeSource(base); err != nil {
		t.Fatalf("exact executor image rejected: %v", err)
	}
}

func TestRuntimeSourceMirrorDigestSetMustMatchAcquiredImages(t *testing.T) {
	_, err := ResolveRuntimeSource(RuntimeSourceResolution{
		Version: RuntimeSelectedVersion,
		ChartRepository: RuntimeChartRepository,
		ChartName: RuntimeChartName,
		ChartSHA256: runtimeDigest("a"),
		ValuesSHA256: runtimeDigest("d"),
		RenderManifestSHA256: runtimeDigest("e"),
		ImageReferences: []string{"ghcr.io/loft-sh/vcluster-oss@" + runtimeDigest("b")},
		ChartArtifactPath: "runtime/virtualcluster/chart/vcluster-0.37.1.tgz",
		ExecutorImageReference: "zot.internal/platform/virtual-cluster-runtime@" + runtimeDigest("f"),
		MirrorReady: true,
		MirrorImageReferences: []string{"zot.internal/mirror/vcluster-oss@" + runtimeDigest("c")},
	})
	if err == nil || !strings.Contains(err.Error(), "digest set") {
		t.Fatalf("mismatched mirror digest inventory was admitted: %v", err)
	}
}


func resolvedRuntimeSourceForTest(t *testing.T) RuntimeSource {
	t.Helper()
	source, err := ResolveRuntimeSource(RuntimeSourceResolution{
		Version: RuntimeSelectedVersion,
		ChartRepository: RuntimeChartRepository,
		ChartName: RuntimeChartName,
		ChartSHA256: runtimeDigest("a"),
		ValuesSHA256: runtimeDigest("d"),
		RenderManifestSHA256: runtimeDigest("e"),
		ImageReferences: []string{"ghcr.io/loft-sh/vcluster-oss@" + runtimeDigest("b")},
		ChartArtifactPath: "runtime/virtualcluster/chart/vcluster-0.37.1.tgz",
		ExecutorImageReference: "zot.internal/platform/virtual-cluster-runtime@" + runtimeDigest("f"),
		MirrorReady: true,
		MirrorImageReferences: []string{"zot.internal/mirror/vcluster-oss@" + runtimeDigest("b")},
	})
	if err != nil {
		t.Fatal(err)
	}
	return source
}

func TestRuntimeSourceDigestAndFileLoadingAreFailClosed(t *testing.T) {
	source := resolvedRuntimeSourceForTest(t)
	first, err := RuntimeSourceDigest(source)
	if err != nil {
		t.Fatal(err)
	}
	second, err := RuntimeSourceDigest(source)
	if err != nil || first != second || !strings.HasPrefix(first, "sha256:") {
		t.Fatalf("digest first=%q second=%q err=%v", first, second, err)
	}
	root := t.TempDir()
	path := filepath.Join(root, "runtime-source.json")
	raw, _ := json.Marshal(source)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, digest, err := LoadRuntimeExecutionSource(path)
	if err != nil || digest != first || loaded.ChartSHA256 != source.ChartSHA256 {
		t.Fatalf("loaded=%#v digest=%q err=%v", loaded, digest, err)
	}
	bad := filepath.Join(root, "bad.json")
	if err := os.WriteFile(bad, append(raw, []byte("{}")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadRuntimeExecutionSource(bad); err == nil {
		t.Fatal("trailing JSON was admitted")
	}
	if err := os.Symlink(path, filepath.Join(root, "link.json")); err == nil {
		if _, _, err := LoadRuntimeExecutionSource(filepath.Join(root, "link.json")); err == nil {
			t.Fatal("symlink runtime source was admitted")
		}
	}
}

func TestRuntimeSourceDigestChangesWithMirrorAuthority(t *testing.T) {
	source := resolvedRuntimeSourceForTest(t)
	first, err := RuntimeSourceDigest(source)
	if err != nil {
		t.Fatal(err)
	}
	source.MirrorImageReferences = []string{"zot.internal/other/vcluster-oss@" + runtimeDigest("b")}
	second, err := RuntimeSourceDigest(source)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("mirror authority drift did not change runtime source digest")
	}
}


func TestRuntimeImageMirrorMapBindsRepositoryToExactDigestEquivalentMirror(t *testing.T) {
	source := resolvedRuntimeSourceForTest(t)
	source.ImageReferences = []string{
		"ghcr.io/loft-sh/vcluster-oss@" + runtimeDigest("a"),
		"registry.k8s.io/pause@" + runtimeDigest("b"),
	}
	source.ImageDigests = []string{runtimeDigest("a"), runtimeDigest("b")}
	source.MirrorImageReferences = []string{
		"zot.internal/vcluster/loft-sh-vcluster-oss@" + runtimeDigest("a"),
		"zot.internal/vcluster/registry-k8s-pause@" + runtimeDigest("b"),
	}
	m, err := RuntimeImageMirrorMap(source)
	if err != nil {
		t.Fatal(err)
	}
	if m["ghcr.io/loft-sh/vcluster-oss"] != "zot.internal/vcluster/loft-sh-vcluster-oss@"+runtimeDigest("a") {
		t.Fatalf("vcluster mirror=%q", m["ghcr.io/loft-sh/vcluster-oss"])
	}
	if m["registry.k8s.io/pause"] != "zot.internal/vcluster/registry-k8s-pause@"+runtimeDigest("b") {
		t.Fatalf("pause mirror=%q", m["registry.k8s.io/pause"])
	}
}

func TestRuntimeImageMirrorMapRejectsRepositoryDigestAmbiguity(t *testing.T) {
	source := resolvedRuntimeSourceForTest(t)
	source.ImageReferences = []string{
		"ghcr.io/loft-sh/vcluster-oss@" + runtimeDigest("a"),
		"ghcr.io/loft-sh/vcluster-oss@" + runtimeDigest("b"),
	}
	source.ImageDigests = []string{runtimeDigest("a"), runtimeDigest("b")}
	source.MirrorImageReferences = []string{
		"zot.internal/vcluster/a@" + runtimeDigest("a"),
		"zot.internal/vcluster/b@" + runtimeDigest("b"),
	}
	if _, err := RuntimeImageMirrorMap(source); err == nil || !strings.Contains(err.Error(), "repository maps to multiple digests") {
		t.Fatalf("ambiguous repository mirror mapping was admitted: %v", err)
	}
}
