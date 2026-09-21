package virtualcluster

import (
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
		ImageDigests: []string{runtimeDigest("c"), runtimeDigest("b")},
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
		ImageDigests: []string{runtimeDigest("b")},
	}
	cases := []RuntimeSourceResolution{
		func() RuntimeSourceResolution { v := base; v.Version = "0.37.0"; return v }(),
		func() RuntimeSourceResolution { v := base; v.ChartRepository = "https://example.invalid/charts"; return v }(),
		func() RuntimeSourceResolution { v := base; v.ChartName = "vcluster-platform"; return v }(),
		func() RuntimeSourceResolution { v := base; v.ChartSHA256 = "sha256:not-exact"; return v }(),
		func() RuntimeSourceResolution { v := base; v.ImageDigests = []string{"latest"}; return v }(),
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
		ImageDigests: []string{runtimeDigest("b")},
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
	withDuplicate.ImageDigests = []string{runtimeDigest("b"), runtimeDigest("b")}
	if err := ValidateRuntimeExecutionSource(withDuplicate); err == nil {
		t.Fatal("duplicate image digest inventory was admitted")
	}
}


func TestRuntimeSourceRejectsProImageOrUnownedValuesDrift(t *testing.T) {
	resolved, err := ResolveRuntimeSource(RuntimeSourceResolution{
		Version: RuntimeSelectedVersion,
		ChartRepository: RuntimeChartRepository,
		ChartName: RuntimeChartName,
		ChartSHA256: runtimeDigest("a"),
		ImageDigests: []string{runtimeDigest("b")},
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
