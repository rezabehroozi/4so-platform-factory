package ociarchive_test

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"platform.4so.io/factory/internal/ociarchive"
	"platform.4so.io/factory/internal/testsupport"
)

func TestInspectAcceptsDeterministicFixtureAndRejectsBlobTamper(t *testing.T) {
	root := t.TempDir()
	archive := filepath.Join(root, "workloads.oci.tar")
	refs, err := testsupport.WriteWorkloadOCIArchive(archive, testsupport.WorkloadRepositories("registry.local/", false))
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := ociarchive.Inspect(archive)
	if err != nil {
		t.Fatal(err)
	}
	if len(inventory.Images) != len(refs) {
		t.Fatalf("inventory count=%d refs=%d", len(inventory.Images), len(refs))
	}
	bad := filepath.Join(root, "tampered.oci.tar")
	if err := rewriteTar(archive, bad, func(name string, raw []byte) []byte {
		if strings.HasPrefix(name, "blobs/sha256/") && len(raw) > 0 {
			copyRaw := append([]byte(nil), raw...)
			copyRaw[0] ^= 0xff
			return copyRaw
		}
		return raw
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := ociarchive.Inspect(bad); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("expected blob-digest rejection, got %v", err)
	}
}

func TestInspectRejectsSymlinkArchive(t *testing.T) {
	root := t.TempDir()
	realArchive := filepath.Join(root, "real.oci.tar")
	if _, err := testsupport.WriteWorkloadOCIArchive(realArchive, testsupport.WorkloadRepositories("registry.local/", false)); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link.oci.tar")
	if err := os.Symlink(realArchive, link); err != nil {
		t.Skip("symlink unavailable")
	}
	if _, err := ociarchive.Inspect(link); err == nil || !strings.Contains(err.Error(), "non-symlink") {
		t.Fatalf("expected symlink archive rejection, got %v", err)
	}
}

func TestInspectRejectsMissingImportAddressabilityAnnotations(t *testing.T) {
	root := t.TempDir()
	archive := filepath.Join(root, "workloads.oci.tar")
	if _, err := testsupport.WriteWorkloadOCIArchive(archive, testsupport.WorkloadRepositories("registry.local/", false)); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(root, "unaddressable.oci.tar")
	if err := rewriteTar(archive, bad, func(name string, raw []byte) []byte {
		if name != "index.json" {
			return raw
		}
		var index map[string]any
		if err := json.Unmarshal(raw, &index); err != nil {
			t.Fatal(err)
		}
		manifests, _ := index["manifests"].([]any)
		if len(manifests) == 0 {
			t.Fatal("fixture index has no manifests")
		}
		row, _ := manifests[0].(map[string]any)
		delete(row, "annotations")
		out, err := json.Marshal(index)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := ociarchive.Inspect(bad); err == nil || !strings.Contains(err.Error(), "import-addressable") {
		t.Fatalf("expected import-addressability rejection, got %v", err)
	}
}

func TestInspectRejectsUnreferencedBlob(t *testing.T) {
	root := t.TempDir()
	archive := filepath.Join(root, "workloads.oci.tar")
	if _, err := testsupport.WriteWorkloadOCIArchive(archive, testsupport.WorkloadRepositories("registry.local/", false)); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(root, "unreferenced.oci.tar")
	if err := rewriteTarWithExtra(archive, bad, "blobs/sha256/"+strings.Repeat("0", 64), []byte("extra")); err != nil {
		t.Fatal(err)
	}
	if _, err := ociarchive.Inspect(bad); err == nil {
		t.Fatal("expected unreferenced/invalid blob rejection")
	}
}

func TestInspectRejectsSubstringSpoofedManifestMediaType(t *testing.T) {
	root := t.TempDir()
	archive := filepath.Join(root, "workloads.oci.tar")
	if _, err := testsupport.WriteWorkloadOCIArchive(archive, testsupport.WorkloadRepositories("registry.local/", false)); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(root, "spoofed-media.oci.tar")
	if err := rewriteTar(archive, bad, func(name string, raw []byte) []byte {
		if name != "index.json" {
			return raw
		}
		var index map[string]any
		if err := json.Unmarshal(raw, &index); err != nil {
			t.Fatal(err)
		}
		manifests, _ := index["manifests"].([]any)
		if len(manifests) == 0 {
			t.Fatal("fixture index has no manifests")
		}
		row, _ := manifests[0].(map[string]any)
		row["mediaType"] = "application/x-image.manifest.v1+json-evil"
		out, err := json.Marshal(index)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := ociarchive.Inspect(bad); err == nil || !strings.Contains(err.Error(), "unsupported mediaType") {
		t.Fatalf("expected exact media-type rejection, got %v", err)
	}
}

func TestInspectRejectsManifestDocumentMediaTypeMismatch(t *testing.T) {
	root := t.TempDir()
	archive := filepath.Join(root, "workloads.oci.tar")
	if _, err := testsupport.WriteWorkloadOCIArchive(archive, testsupport.WorkloadRepositories("registry.local/", false)); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(root, "mismatched-body-media.oci.tar")
	if err := rewriteOCIManifestAndIndex(archive, bad, func(manifest map[string]any) {
		manifest["mediaType"] = "application/vnd.docker.distribution.manifest.v2+json"
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := ociarchive.Inspect(bad); err == nil || !strings.Contains(err.Error(), "image manifest") {
		t.Fatalf("expected descriptor/document media-type mismatch rejection, got %v", err)
	}
}

func rewriteOCIManifestAndIndex(src, dst string, mutate func(map[string]any)) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tr := tar.NewReader(in)
	entries := map[string][]byte{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		raw, err := io.ReadAll(tr)
		if err != nil {
			return err
		}
		entries[h.Name] = raw
	}
	var index map[string]any
	if err := json.Unmarshal(entries["index.json"], &index); err != nil {
		return err
	}
	manifests, _ := index["manifests"].([]any)
	if len(manifests) == 0 {
		return fmt.Errorf("fixture index has no manifests")
	}
	row, _ := manifests[0].(map[string]any)
	oldDigest, _ := row["digest"].(string)
	oldHex := strings.TrimPrefix(oldDigest, "sha256:")
	manifestRaw := entries["blobs/sha256/"+oldHex]
	var manifest map[string]any
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		return err
	}
	mutate(manifest)
	newRaw, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	newSum := sha256.Sum256(newRaw)
	newHex := hex.EncodeToString(newSum[:])
	delete(entries, "blobs/sha256/"+oldHex)
	entries["blobs/sha256/"+newHex] = newRaw
	row["digest"] = "sha256:" + newHex
	row["size"] = len(newRaw)
	for key, value := range row["annotations"].(map[string]any) {
		if text, ok := value.(string); ok && strings.HasSuffix(text, "@"+oldDigest) {
			row["annotations"].(map[string]any)[key] = strings.TrimSuffix(text, "@"+oldDigest) + "@sha256:" + newHex
		}
	}
	indexRaw, err := json.Marshal(index)
	if err != nil {
		return err
	}
	entries["index.json"] = indexRaw
	var inventory map[string]any
	if err := json.Unmarshal(entries["4so-image-inventory.json"], &inventory); err != nil {
		return err
	}
	images, _ := inventory["images"].([]any)
	for i, value := range images {
		if text, ok := value.(string); ok && strings.HasSuffix(text, "@"+oldDigest) {
			images[i] = strings.TrimSuffix(text, "@"+oldDigest) + "@sha256:" + newHex
		}
	}
	sort.Slice(images, func(i, j int) bool { return images[i].(string) < images[j].(string) })
	inventoryRaw, err := json.Marshal(inventory)
	if err != nil {
		return err
	}
	entries["4so-image-inventory.json"] = inventoryRaw
	return writeTar(dst, entries)
}

func rewriteTar(src, dst string, mutate func(string, []byte) []byte) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tr := tar.NewReader(in)
	entries := map[string][]byte{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		raw, err := io.ReadAll(tr)
		if err != nil {
			return err
		}
		entries[h.Name] = mutate(h.Name, raw)
	}
	return writeTar(dst, entries)
}

func rewriteTarWithExtra(src, dst, name string, raw []byte) error {
	return copyTar(src, dst, name, raw)
}

func copyTar(src, dst, extraName string, extra []byte) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tr := tar.NewReader(in)
	entries := map[string][]byte{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		raw, err := io.ReadAll(tr)
		if err != nil {
			return err
		}
		entries[h.Name] = raw
	}
	entries[extraName] = extra
	return writeTar(dst, entries)
}

func writeTar(dst string, entries map[string][]byte) error {
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	tw := tar.NewWriter(f)
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		raw := entries[name]
		h := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(raw)), ModTime: time.Unix(0, 0), Uid: 0, Gid: 0, Format: tar.FormatUSTAR}
		if err := tw.WriteHeader(h); err != nil {
			_ = f.Close()
			return err
		}
		if _, err := io.Copy(tw, bytes.NewReader(raw)); err != nil {
			_ = f.Close()
			return err
		}
	}
	if err := tw.Close(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func TestAssembleToFileMergesExactSourcesDeterministically(t *testing.T) {
	root := t.TempDir()
	fixture := filepath.Join(root, "fixture.oci.tar")
	refs, err := testsupport.WriteWorkloadOCIArchive(fixture, []string{"registry.local/a", "registry.local/b", "registry.local/c"})
	if err != nil {
		t.Fatal(err)
	}
	layout := filepath.Join(root, "layout")
	if err = extractTarForAssemblyTest(fixture, layout); err != nil {
		t.Fatal(err)
	}
	sources := []ociarchive.SourceImage{{Reference: refs[2], LayoutDir: layout}, {Reference: refs[0], LayoutDir: layout}, {Reference: refs[1], LayoutDir: layout}}
	out1 := filepath.Join(root, "assembled-1.tar")
	first, err := ociarchive.AssembleToFile(sources, out1)
	if err != nil {
		t.Fatal(err)
	}
	out2 := filepath.Join(root, "assembled-2.tar")
	second, err := ociarchive.AssembleToFile([]ociarchive.SourceImage{sources[1], sources[2], sources[0]}, out2)
	if err != nil {
		t.Fatal(err)
	}
	if first.Authority != ociarchive.AssemblyAuthority || first.ImageCount != 3 || first.ArchiveSHA256 != second.ArchiveSHA256 || first.ArchiveBytes != second.ArchiveBytes {
		t.Fatalf("non-deterministic assembly first=%+v second=%+v", first, second)
	}
	raw1, _ := os.ReadFile(out1)
	raw2, _ := os.ReadFile(out2)
	if !bytes.Equal(raw1, raw2) {
		t.Fatal("assembly bytes differ across source ordering")
	}
	inventory, err := ociarchive.Inspect(out1)
	if err != nil {
		t.Fatal(err)
	}
	if !sort.StringsAreSorted(inventory.Images) || len(inventory.Images) != 3 {
		t.Fatalf("bad inventory %#v", inventory)
	}
}

func TestAssembleToFileRejectsMutableOrUnboundSource(t *testing.T) {
	root := t.TempDir()
	fixture := filepath.Join(root, "fixture.oci.tar")
	refs, err := testsupport.WriteWorkloadOCIArchive(fixture, []string{"registry.local/a"})
	if err != nil {
		t.Fatal(err)
	}
	layout := filepath.Join(root, "layout")
	if err = extractTarForAssemblyTest(fixture, layout); err != nil {
		t.Fatal(err)
	}
	if _, err = ociarchive.AssembleToFile([]ociarchive.SourceImage{{Reference: "registry.local/a:latest", LayoutDir: layout}}, filepath.Join(root, "bad.tar")); err == nil || !strings.Contains(err.Error(), "exact") {
		t.Fatalf("expected mutable-ref rejection, got %v", err)
	}
	wrong := "registry.local/a@sha256:" + strings.Repeat("f", 64)
	if _, err = ociarchive.AssembleToFile([]ociarchive.SourceImage{{Reference: wrong, LayoutDir: layout}}, filepath.Join(root, "wrong.tar")); err == nil || !strings.Contains(err.Error(), "not a root descriptor") {
		t.Fatalf("expected source-root binding rejection, got %v", err)
	}
	link := filepath.Join(root, "layout-link")
	if err = os.Symlink(layout, link); err == nil {
		if _, err = ociarchive.AssembleToFile([]ociarchive.SourceImage{{Reference: refs[0], LayoutDir: link}}, filepath.Join(root, "link.tar")); err == nil || !strings.Contains(err.Error(), "real directory") {
			t.Fatalf("expected symlink layout rejection, got %v", err)
		}
	}
}

func extractTarForAssemblyTest(archive, dest string) error {
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return err
	}
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			continue
		}
		path := filepath.Join(dest, filepath.FromSlash(hdr.Name))
		if err = os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		out, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(out, tr)
		closeErr := out.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
}
