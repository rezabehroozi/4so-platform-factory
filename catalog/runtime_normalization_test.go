package catalog

import (
	"strings"
	"testing"
)

func TestKyverno382CanonicalRuntimeRenderNormalizesOnlyKnownEmptyCRDMetadata(t *testing.T) {
	components, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	c, ok := components["kyverno"]
	if !ok {
		t.Fatal("kyverno component missing")
	}
	if c.Spec.Release != "3.8.2" {
		t.Fatalf("release=%s", c.Spec.Release)
	}
	rendered, err := RenderComponent(c, c.Spec.Namespace, "normalization-test")
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, resource := range rendered.Resources {
		if resource["kind"] != "CustomResourceDefinition" {
			continue
		}
		metadata, _ := resource["metadata"].(map[string]any)
		name, _ := metadata["name"].(string)
		if !strings.HasSuffix(name, ".policies.kyverno.io") {
			continue
		}
		count++
		if _, ok := kyverno382PoliciesCRDs[name]; !ok {
			t.Fatalf("unexpected policies CRD %s", name)
		}
		if _, ok := metadata["labels"]; ok {
			t.Fatalf("%s retains empty labels after normalization", name)
		}
		if _, ok := metadata["annotations"]; ok {
			t.Fatalf("%s retains empty annotations after normalization", name)
		}
	}
	if count != 11 {
		t.Fatalf("normalized policies CRDs=%d want=11", count)
	}
}

func TestKyverno382NormalizationRejectsNonEmptyMetadataDrift(t *testing.T) {
	c := Component{}
	c.Metadata.Name = "kyverno"
	c.Spec.Release = "3.8.2"
	resources := make([]map[string]any, 0, len(kyverno382PoliciesCRDs))
	for name := range kyverno382PoliciesCRDs {
		metadata := map[string]any{"name": name, "labels": map[string]any{}, "annotations": map[string]any{}}
		if name == "deletingpolicies.policies.kyverno.io" {
			metadata["labels"] = map[string]any{"unexpected": "value"}
		}
		resources = append(resources, map[string]any{
			"apiVersion": "apiextensions.k8s.io/v1",
			"kind": "CustomResourceDefinition",
			"metadata": metadata,
		})
	}
	if _, err := normalizeRuntimeResources(c, resources); err == nil || !strings.Contains(err.Error(), "refuses non-empty labels") {
		t.Fatalf("expected fail-closed metadata drift, got %v", err)
	}
}
