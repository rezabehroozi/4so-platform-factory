package bundlebuilder

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApplianceBundleSchemasMatchRuntimeContract(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	load := func(rel string) map[string]any {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatal(err)
		}
		var obj map[string]any
		if err := json.Unmarshal(raw, &obj); err != nil {
			t.Fatal(err)
		}
		return obj
	}
	object := func(v any, name string) map[string]any {
		t.Helper()
		m, ok := v.(map[string]any)
		if !ok {
			t.Fatalf("%s is not an object: %#v", name, v)
		}
		return m
	}
	stringsOf := func(v any, name string) []string {
		t.Helper()
		rows, ok := v.([]any)
		if !ok {
			t.Fatalf("%s is not an array: %#v", name, v)
		}
		out := make([]string, 0, len(rows))
		for _, row := range rows {
			s, ok := row.(string)
			if !ok {
				t.Fatalf("%s contains non-string %#v", name, row)
			}
			out = append(out, s)
		}
		return out
	}
	has := func(rows []string, value string) bool {
		for _, row := range rows {
			if row == value {
				return true
			}
		}
		return false
	}

	build := load("schemas/appliance-bundle-build.schema.json")
	buildProps := object(build["properties"], "build.properties")
	buildMeta := object(buildProps["metadata"], "build.metadata")
	buildMetaReq := stringsOf(buildMeta["required"], "build.metadata.required")
	if !has(buildMetaReq, "sourceReleaseDigest") {
		t.Fatal("build schema must require metadata.sourceReleaseDigest")
	}
	buildMetaProps := object(buildMeta["properties"], "build.metadata.properties")
	digestProp := object(buildMetaProps["sourceReleaseDigest"], "build.metadata.sourceReleaseDigest")
	if digestProp["pattern"] != `^sha256:[a-f0-9]{64}$` {
		t.Fatalf("unexpected sourceReleaseDigest pattern %#v", digestProp["pattern"])
	}
	buildSpec := object(buildProps["spec"], "build.spec")
	buildSpecProps := object(buildSpec["properties"], "build.spec.properties")
	buildWork := object(buildSpecProps["workloads"], "build.workloads")
	buildReq := stringsOf(buildWork["required"], "build.workloads.required")
	if !has(buildReq, "storageManifest") {
		t.Fatal("build schema must require storageManifest")
	}
	if has(buildReq, "ocmManifest") {
		t.Fatal("build schema must not require optional ocmManifest")
	}
	buildWorkProps := object(buildWork["properties"], "build.workloads.properties")
	if _, ok := buildWorkProps["storageManifest"]; !ok {
		t.Fatal("build schema must define storageManifest")
	}
	if _, ok := buildWorkProps["ocmManifest"]; !ok {
		t.Fatal("build schema must retain optional ocmManifest property")
	}

	bundle := load("schemas/appliance-bundle.schema.json")
	bundleProps := object(bundle["properties"], "bundle.properties")
	bundleMeta := object(bundleProps["metadata"], "bundle.metadata")
	bundleMetaProps := object(bundleMeta["properties"], "bundle.metadata.properties")
	bundleDigest := object(bundleMetaProps["sourceReleaseDigest"], "bundle.metadata.sourceReleaseDigest")
	if bundleDigest["$ref"] != "#/$defs/optionalDigest" {
		t.Fatalf("bundle sourceReleaseDigest must match runtime optional legacy contract, got %#v", bundleDigest)
	}
	bundleSpec := object(bundleProps["spec"], "bundle.spec")
	bundleSpecProps := object(bundleSpec["properties"], "bundle.spec.properties")
	bundleWork := object(bundleSpecProps["workloads"], "bundle.workloads")
	bundleReq := stringsOf(bundleWork["required"], "bundle.workloads.required")
	if !has(bundleReq, "storageManifest") {
		t.Fatal("bundle schema must require storageManifest")
	}
	if has(bundleReq, "ocmManifest") {
		t.Fatal("bundle schema must not require optional ocmManifest")
	}
	bundleWorkProps := object(bundleWork["properties"], "bundle.workloads.properties")
	ocm := object(bundleWorkProps["ocmManifest"], "bundle.workloads.ocmManifest")
	if ocm["$ref"] != "#/$defs/optionalArtifact" {
		t.Fatalf("bundle OCM must use optionalArtifact, got %#v", ocm)
	}

	exampleRaw, err := os.ReadFile(filepath.Join(root, "examples/appliance-bundle/build-spec.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	var example BuildSpec
	if err := json.Unmarshal(exampleRaw, &example); err != nil {
		t.Fatal(err)
	}
	if err := validateSpec(example); err != nil {
		t.Fatalf("canonical build example violates runtime contract: %v", err)
	}
	if example.Metadata.Version != "0.0.0" {
		t.Fatalf("example must stay release-neutral, got %q", example.Metadata.Version)
	}
	if example.Spec.Workloads.StorageManifest == "" {
		t.Fatal("example must include required storageManifest")
	}
	if example.Spec.Workloads.OCMManifest != "" {
		t.Fatal("default example must not make optional OCM a product dependency")
	}
	if example.Metadata.SourceReleaseDigest != "sha256:"+strings.Repeat("0", 64) {
		t.Fatal("example must retain exact-release digest placeholder")
	}
}
