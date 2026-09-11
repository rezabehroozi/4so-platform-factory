package manifestimages

import (
	"strings"
	"testing"
)

func d(ch string) string { return strings.Repeat(ch, 64) }

func TestResolveRuntimeImageScalarsAndArguments(t *testing.T) {
	raw := []byte(`apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
      - name: app
        image: quay.io/example/app:v1
        args:
        - --engine-image
        - "docker.io/example/engine:v2"
        - --helper-image=ghcr.io/example/helper:v3
`)
	mappings := map[string]string{
		"quay.io/example/app:v1":      "quay.io/example/app@sha256:" + d("a"),
		"docker.io/example/engine:v2": "docker.io/example/engine@sha256:" + d("b"),
		"ghcr.io/example/helper:v3":   "ghcr.io/example/helper@sha256:" + d("c"),
	}
	resolved, result, err := Resolve(raw, mappings)
	if err != nil {
		t.Fatal(err)
	}
	if result.Authority != ResolutionAuthority || len(result.Images) != 3 {
		t.Fatalf("unexpected result: %+v", result)
	}
	text := string(resolved)
	for _, exact := range mappings {
		if !strings.Contains(text, exact) {
			t.Fatalf("resolved manifest missing %s", exact)
		}
	}
	if strings.Contains(text, ":v1") || strings.Contains(text, ":v2") || strings.Contains(text, ":v3") {
		t.Fatalf("mutable image tag survived:\n%s", text)
	}
}

func TestResolveRejectsMissingOrRepositoryChangingResolution(t *testing.T) {
	raw := []byte("image: quay.io/example/app:v1\n")
	if _, _, err := Resolve(raw, nil); err == nil {
		t.Fatal("expected missing resolution rejection")
	}
	if _, _, err := Resolve(raw, map[string]string{"quay.io/example/app:v1": "quay.io/other/app@sha256:" + d("a")}); err == nil {
		t.Fatal("expected repository-change rejection")
	}
}

func TestResolveRejectsExtraResolutionAndNoRuntimeImages(t *testing.T) {
	raw := []byte("image: quay.io/example/app@sha256:" + d("a") + "\n")
	if _, _, err := Resolve(raw, map[string]string{"quay.io/example/missing:v1": "quay.io/example/missing@sha256:" + d("b")}); err == nil {
		t.Fatal("expected extra resolution rejection")
	}
	if _, err := Extract([]byte("apiVersion: v1\nkind: ConfigMap\n")); err == nil {
		t.Fatal("expected no-image rejection")
	}
}

func TestExtractIgnoresCRDImageDescriptions(t *testing.T) {
	raw := []byte(`description: Image format is <image>:<tag>
properties:
  image:
    description: some field
    type: string
---
image: quay.io/example/runtime:v1
`)
	refs, err := Extract(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 1 || refs[0] != "quay.io/example/runtime:v1" {
		t.Fatalf("unexpected refs: %#v", refs)
	}
}
