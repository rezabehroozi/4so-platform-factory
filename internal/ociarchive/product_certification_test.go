package ociarchive

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fixtureFile struct {
	path     string
	raw      []byte
	mode     int64
	typeflag byte
	link     string
}

func fixtureDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func writeBlob(t *testing.T, root string, raw []byte) descriptor {
	t.Helper()
	digest := fixtureDigest(raw)
	path := filepath.Join(root, "blobs", "sha256", strings.TrimPrefix(digest, "sha256:"))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return descriptor{Digest: digest, Size: int64(len(raw))}
}

func buildFixtureLayer(t *testing.T, files []fixtureFile) []byte {
	t.Helper()
	var raw bytes.Buffer
	gz, err := gzip.NewWriterLevel(&raw, gzip.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	gz.Header.ModTime = time.Unix(0, 0)
	tw := tar.NewWriter(gz)
	for _, file := range files {
		typeflag := file.typeflag
		if typeflag == 0 {
			typeflag = tar.TypeReg
		}
		h := &tar.Header{Name: file.path, Mode: file.mode, Size: int64(len(file.raw)), Typeflag: typeflag, Linkname: file.link, ModTime: time.Unix(0, 0), Uid: 0, Gid: 0, Format: tar.FormatUSTAR}
		if typeflag != tar.TypeReg && typeflag != tar.TypeRegA {
			h.Size = 0
		}
		if err = tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Size > 0 {
			if _, err = tw.Write(file.raw); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err = tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err = gz.Close(); err != nil {
		t.Fatal(err)
	}
	return raw.Bytes()
}

func writeProductLayout(t *testing.T, repo, role, releaseDigest, user string, entrypoint []string, files []fixtureFile) (string, string) {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "blobs", "sha256"), 0o755); err != nil {
		t.Fatal(err)
	}
	layerRaw := buildFixtureLayer(t, files)
	layer := writeBlob(t, root, layerRaw)
	layer.MediaType = "application/vnd.oci.image.layer.v1.tar+gzip"
	configRaw, _ := json.Marshal(map[string]any{
		"architecture": "amd64", "os": "linux",
		"config": map[string]any{"User": user, "Entrypoint": entrypoint, "Labels": map[string]string{"platform.4so.io/product-role": role, "platform.4so.io/source-release-digest": releaseDigest}},
	})
	config := writeBlob(t, root, configRaw)
	config.MediaType = "application/vnd.oci.image.config.v1+json"
	manifestRaw, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "config": config, "layers": []descriptor{layer}})
	manifest := writeBlob(t, root, manifestRaw)
	manifest.MediaType = "application/vnd.oci.image.manifest.v1+json"
	manifest.Platform = &descriptorPlatform{OS: "linux", Architecture: "amd64"}
	ref := repo + "@" + manifest.Digest
	indexRaw, _ := json.Marshal(sourceIndex{SchemaVersion: 2, MediaType: "application/vnd.oci.image.index.v1+json", Manifests: []descriptor{manifest}})
	if err := os.WriteFile(filepath.Join(root, "index.json"), indexRaw, 0o644); err != nil {
		t.Fatal(err)
	}
	layoutRaw, _ := json.Marshal(map[string]string{"imageLayoutVersion": "1.0.0"})
	if err := os.WriteFile(filepath.Join(root, "oci-layout"), layoutRaw, 0o644); err != nil {
		t.Fatal(err)
	}
	return root, ref
}

func TestCertifyProductImageExactPayloadAndTrust(t *testing.T) {
	binary, readErr := os.ReadFile("/bin/true")
	if readErr != nil {
		t.Fatal(readErr)
	}
	binaryDigest := fixtureDigest(binary)
	releaseDigest := "sha256:" + strings.Repeat("a", 64)
	root, ref := writeProductLayout(t, "platform.4so.local/management/platform-agent", "platform-agent", releaseDigest, "65532:65532", []string{"/platform-agent"}, []fixtureFile{
		{path: "platform-agent", raw: binary, mode: 0o755},
		{path: "etc/ssl/certs/ca-certificates.crt", raw: []byte("certificate-bundle"), mode: 0o644},
	})
	result, err := CertifyProductImage(SourceImage{Reference: ref, LayoutDir: root}, ProductImageSpec{
		Role: "platform-agent", Repository: "platform.4so.local/management/platform-agent", BinaryPath: "/platform-agent", ExpectedBinaryDigest: binaryDigest,
		ExpectedUser: "65532:65532", ExpectedEntrypoint: []string{"/platform-agent"}, ExpectedReleaseDigest: releaseDigest, RequireCABundle: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Authority != ProductImageCertificationAuthority || !result.ExactPayloadBound || !result.CABundlePresent || result.RuntimeClosurePASS {
		t.Fatalf("unexpected certification %+v", result)
	}
}

func TestCertifyProductImageRejectsWrongPayloadOrMissingTrust(t *testing.T) {
	releaseDigest := "sha256:" + strings.Repeat("b", 64)
	root, ref := writeProductLayout(t, "platform.4so.local/management/platform-agent", "platform-agent", releaseDigest, "65532:65532", []string{"/platform-agent"}, []fixtureFile{{path: "platform-agent", raw: []byte("wrong"), mode: 0o755}})
	_, err := CertifyProductImage(SourceImage{Reference: ref, LayoutDir: root}, ProductImageSpec{
		Role: "platform-agent", Repository: "platform.4so.local/management/platform-agent", BinaryPath: "/platform-agent", ExpectedBinaryDigest: fixtureDigest([]byte("expected")),
		ExpectedUser: "65532:65532", ExpectedEntrypoint: []string{"/platform-agent"}, ExpectedReleaseDigest: releaseDigest, RequireCABundle: true,
	})
	if err == nil || (!strings.Contains(err.Error(), "payload digest") && !strings.Contains(err.Error(), "CA trust")) {
		t.Fatalf("expected payload/trust rejection, got %v", err)
	}
}

func TestCertifyProductImageWhiteoutCannotPreserveReleasePayload(t *testing.T) {
	binary, readErr := os.ReadFile("/bin/true")
	if readErr != nil {
		t.Fatal(readErr)
	}
	releaseDigest := "sha256:" + strings.Repeat("c", 64)
	root, ref := writeProductLayout(t, "platform.4so.local/management/platform-probe", "platform-probe", releaseDigest, "65532:65532", []string{"/platform-probe"}, []fixtureFile{
		{path: "platform-probe", raw: binary, mode: 0o755},
		{path: ".wh.platform-probe", mode: 0o000},
	})
	_, err := CertifyProductImage(SourceImage{Reference: ref, LayoutDir: root}, ProductImageSpec{
		Role: "platform-probe", Repository: "platform.4so.local/management/platform-probe", BinaryPath: "/platform-probe", ExpectedBinaryDigest: fixtureDigest(binary),
		ExpectedUser: "65532:65532", ExpectedEntrypoint: []string{"/platform-probe"}, ExpectedReleaseDigest: releaseDigest,
	})
	if err == nil || !strings.Contains(err.Error(), "does not contain executable regular file") {
		t.Fatalf("expected whiteout rejection, got %v", err)
	}
}
