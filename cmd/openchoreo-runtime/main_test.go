package main

import (
	"bytes"
	"strings"
	"testing"

	"platform.4so.io/factory/internal/openchoreo"
)

func executorFixture() openchoreo.RuntimeSource {
	digestA := "sha256:" + strings.Repeat("a", 64)
	digestB := "sha256:" + strings.Repeat("b", 64)
	return openchoreo.RuntimeSource{
		Authority:           openchoreo.RuntimeSourceAuthority,
		Version:             openchoreo.RuntimeVersion,
		UpstreamRepository:  openchoreo.UpstreamRepository,
		UpstreamCommit:      openchoreo.ReviewedUpstreamCommit,
		SourceArchiveSHA256: "sha256:" + strings.Repeat("c", 64),
		Planes: []openchoreo.PlaneSource{
			{Name: "control-plane", ChartRepository: openchoreo.ChartRepository, ChartName: "openchoreo-control-plane", ChartVersion: openchoreo.RuntimeVersion, ChartSHA256: "sha256:" + strings.Repeat("d", 64), ValuesSHA256: "sha256:" + strings.Repeat("e", 64), RenderManifestSHA256: "sha256:" + strings.Repeat("f", 64)},
			{Name: "data-plane", ChartRepository: openchoreo.ChartRepository, ChartName: "openchoreo-data-plane", ChartVersion: openchoreo.RuntimeVersion, ChartSHA256: "sha256:" + strings.Repeat("1", 64), ValuesSHA256: "sha256:" + strings.Repeat("2", 64), RenderManifestSHA256: "sha256:" + strings.Repeat("3", 64)},
		},
		Images: []openchoreo.ImageMirror{
			{SourceReference: "ghcr.io/openchoreo/api@" + digestA, Digest: digestA, MirrorReference: "zot.internal/openchoreo/api@" + digestA},
			{SourceReference: "ghcr.io/openchoreo/agent@" + digestB, Digest: digestB, MirrorReference: "zot.internal/openchoreo/agent@" + digestB},
		},
		ExecutorImageReference: "zot.internal/4so/openchoreo-runtime@sha256:" + strings.Repeat("4", 64),
		ExecutorImageDigest:    "sha256:" + strings.Repeat("4", 64),
		Resolved:               true,
		MirrorReady:            true,
		ExternalOIDCRequired:   true,
		BuildAuthority:         "buildkit",
		RegistryAuthority:      "zot",
	}
}

func TestPostRenderRewritesOnlyThroughExactMirrorAuthority(t *testing.T) {
	source := executorFixture()
	in := strings.NewReader("apiVersion: v1\nspec:\n  containers:\n    - image: ghcr.io/openchoreo/api:1.3.0\n")
	var out bytes.Buffer
	if err := postRender(in, &out, source); err != nil {
		t.Fatal(err)
	}
	want := source.Images[0].MirrorReference
	if !strings.Contains(out.String(), "image: "+want) || strings.Contains(out.String(), "ghcr.io/openchoreo/api:1.3.0") {
		t.Fatalf("post-render output did not converge to exact mirror: %s", out.String())
	}
}

func TestPostRenderFailsClosedOnUninventoriedImage(t *testing.T) {
	source := executorFixture()
	var out bytes.Buffer
	err := postRender(strings.NewReader("image: docker.io/library/busybox:latest\n"), &out, source)
	if err == nil || !strings.Contains(err.Error(), "no exact zot mirror") {
		t.Fatalf("unowned image was admitted: %v", err)
	}
}

func TestRuntimeMirrorMapRejectsRepositoryDigestAmbiguity(t *testing.T) {
	source := executorFixture()
	digest := "sha256:" + strings.Repeat("9", 64)
	source.Images = append(source.Images, openchoreo.ImageMirror{
		SourceReference: "ghcr.io/openchoreo/api@" + digest,
		Digest:          digest,
		MirrorReference: "zot.internal/openchoreo/api@" + digest,
	})
	if _, err := runtimeMirrorMap(source); err == nil || !strings.Contains(err.Error(), "multiple exact mirrors") {
		t.Fatalf("repository ambiguity was not rejected: %v", err)
	}
}

func TestParseSuppressionsCanonicalizesAndRejectsUnknown(t *testing.T) {
	got, err := parseSuppressions(`["tenancy-native","networking-and-ingress-native"]`)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "networking-and-ingress-native,tenancy-native" {
		t.Fatalf("unexpected canonical suppressions: %#v", got)
	}
	if _, err := parseSuppressions(`["fake-native"]`); err == nil {
		t.Fatal("unknown native suppression admitted")
	}
}
