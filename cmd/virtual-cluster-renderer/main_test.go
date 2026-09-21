package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRewritePinsEveryRenderedImageToExactLocalMirror(t *testing.T) {
	mappings := map[string]string{
		"ghcr.io/loft-sh/vcluster-oss": "zot.internal/vcluster/vcluster-oss@sha256:" + strings.Repeat("a", 64),
		"registry.k8s.io/pause": "zot.internal/vcluster/pause@sha256:" + strings.Repeat("b", 64),
	}
	input := "spec:\n  containers:\n  - image: ghcr.io/loft-sh/vcluster-oss:0.37.1\n  initContainers:\n  - image: \"registry.k8s.io/pause:3.10\"\n"
	var out bytes.Buffer
	if err := rewrite(strings.NewReader(input), &out, mappings); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range mappings {
		if !strings.Contains(text, want) {
			t.Fatalf("rendered output missing exact mirror %q: %s", want, text)
		}
	}
	if strings.Contains(text, "ghcr.io/") || strings.Contains(text, "registry.k8s.io/") {
		t.Fatalf("upstream image survived post-render: %s", text)
	}
}

func TestRewriteRejectsUnknownImageAndUnusedAuthority(t *testing.T) {
	mappings := map[string]string{"ghcr.io/known/image": "zot.internal/known@sha256:" + strings.Repeat("a", 64)}
	var out bytes.Buffer
	if err := rewrite(strings.NewReader("image: quay.io/unknown/image:v1\n"), &out, mappings); err == nil || !strings.Contains(err.Error(), "no exact mirror authority") {
		t.Fatalf("unknown image was admitted: %v", err)
	}
	out.Reset()
	if err := rewrite(strings.NewReader("kind: ConfigMap\n"), &out, mappings); err == nil || !strings.Contains(err.Error(), "absent from render") {
		t.Fatalf("unused authority was admitted: %v", err)
	}
}

func TestLoadMapRejectsMutableOrMalformedMirrorReferences(t *testing.T) {
	for _, raw := range []string{
		`{}`,
		`{"ghcr.io/a":"zot.internal/a:latest"}`,
		`{"ghcr.io/a:tag":"zot.internal/a@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`,
	} {
		if _, err := loadMap(raw); err == nil {
			t.Fatalf("invalid map admitted: %s", raw)
		}
	}
}
