package ociarchive

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func testDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func writeTestBlob(t *testing.T, root string, raw []byte) descriptor {
	t.Helper()
	digest := testDigest(raw)
	path := filepath.Join(root, "blobs", "sha256", digest[len("sha256:"):])
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return descriptor{MediaType: "application/vnd.oci.image.config.v1+json", Digest: digest, Size: int64(len(raw))}
}
func TestCollectSourceDescriptorAcceptsStandardManifestAnnotations(t *testing.T) {
	root := t.TempDir()
	config := writeTestBlob(t, root, []byte("{}"))
	raw := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"` + config.Digest + `","size":2},"layers":[],"annotations":{"org.opencontainers.image.version":"17.11"}}`)
	digest := testDigest(raw)
	path := filepath.Join(root, "blobs", "sha256", digest[len("sha256:"):])
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	desc := descriptor{MediaType: "application/vnd.oci.image.manifest.v1+json", Digest: digest, Size: int64(len(raw))}
	blobs := map[string]sourceBlob{}
	if err := collectSourceDescriptor(root, desc, blobs, true); err != nil {
		t.Fatalf("standard OCI manifest annotations were rejected: %v", err)
	}
}
