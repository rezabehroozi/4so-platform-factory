package imagebundle

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func d(b []byte) string { s := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(s[:]) }
func writeBlob(t *testing.T, root string, raw []byte) Descriptor {
	t.Helper()
	dg := d(raw)
	p := filepath.Join(root, "blobs", "sha256", dg[7:])
	if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, raw, 0644); err != nil {
		t.Fatal(err)
	}
	return Descriptor{Digest: dg, Size: int64(len(raw))}
}
func fixture(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	_ = os.WriteFile(filepath.Join(root, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`), 0644)
	config := []byte(`{"architecture":"amd64","os":"linux"}`)
	cd := writeBlob(t, root, config)
	cd.MediaType = "application/vnd.oci.image.config.v1+json"
	layer := []byte("layer")
	ld := writeBlob(t, root, layer)
	ld.MediaType = "application/vnd.oci.image.layer.v1.tar"
	m := ImageManifest{SchemaVersion: 2, MediaType: MediaTypeOCIManifest, Config: cd, Layers: []Descriptor{ld}}
	mraw, _ := json.Marshal(m)
	md := writeBlob(t, root, mraw)
	md.MediaType = MediaTypeOCIManifest
	idx := Index{SchemaVersion: 2, Manifests: []Descriptor{md}}
	iraw, _ := json.Marshal(idx)
	_ = os.WriteFile(filepath.Join(root, "index.json"), iraw, 0644)
	return root, "registry.example/team/app@" + md.Digest
}
func TestAssembleVerify(t *testing.T) {
	root, ref := fixture(t)
	raw, v, err := Assemble(root, ref)
	if err != nil {
		t.Fatal(err)
	}
	if v.Manifest.BlobCount != 2 || v.Manifest.ManifestCount != 1 || v.Manifest.MirrorRepository != "mirror/registry.example/team/app" {
		t.Fatalf("bad manifest %+v", v.Manifest)
	}
	got, err := Verify(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Manifest.RootDigest != v.Manifest.RootDigest || got.BundleDigest == "" {
		t.Fatalf("bad verify %+v", got.Manifest)
	}
}
func TestRejectUnreferenced(t *testing.T) {
	root, ref := fixture(t)
	_ = os.WriteFile(filepath.Join(root, "blobs", "sha256", strings64("a")), []byte("junk"), 0644)
	if _, _, err := Assemble(root, ref); err == nil {
		t.Fatal("expected unreferenced rejection")
	}
}

func strings64(s string) string {
	var b bytes.Buffer
	for i := 0; i < 64; i++ {
		b.WriteString(s)
	}
	return b.String()
}

func TestVerifyRejectsTraversal(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("../evil")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte("bad"))
	if err = zw.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = Verify(buf.Bytes()); err == nil {
		t.Fatal("expected traversal rejection")
	}
}

func TestVerifyRejectsTamperedBlob(t *testing.T) {
	root, ref := fixture(t)
	raw, _, err := Assemble(root, ref)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	for _, f := range zr.File {
		r, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(r)
		_ = r.Close()
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(f.Name, "blobs/sha256/") && !strings.Contains(string(b), "schemaVersion") {
			b = append([]byte(nil), b...)
			if len(b) > 0 {
				b[0] ^= 0xff
			}
			files[f.Name] = b
		} else {
			files[f.Name] = b
		}
	}
	mut, err := deterministicZip(files)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Verify(mut); err == nil {
		t.Fatal("expected tampered digest rejection")
	}
}
