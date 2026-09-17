package ociarchive

import (
	"archive/tar"
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

const AssemblyAuthority = "MANAGEMENT_WORKLOAD_OCI_ASSEMBLY_AUTHORITY_V1"

type SourceImage struct {
	Reference string `json:"reference"`
	LayoutDir string `json:"layoutDir"`
}

type AssemblyResult struct {
	Authority     string    `json:"authority"`
	ArchiveSHA256 string    `json:"archiveSha256"`
	ArchiveBytes  int64     `json:"archiveBytes"`
	ImageCount    int       `json:"imageCount"`
	BlobCount     int       `json:"blobCount"`
	Inventory     Inventory `json:"inventory"`
}

type sourceBlob struct {
	digest string
	size   int64
	root   string
	rel    string
}

type sourceIndex struct {
	SchemaVersion int               `json:"schemaVersion"`
	MediaType     string            `json:"mediaType,omitempty"`
	ArtifactType  string            `json:"artifactType,omitempty"`
	Subject       *descriptor       `json:"subject,omitempty"`
	Manifests     []descriptor      `json:"manifests"`
	Annotations   map[string]string `json:"annotations,omitempty"`
}

func exactImageReference(ref string) bool { return imageRefPattern.MatchString(strings.TrimSpace(ref)) }

func safeOpenLayoutFile(root, rel string) (*os.File, error) {
	if strings.TrimSpace(root) != root || root == "" || strings.TrimSpace(rel) != rel || rel == "" || filepath.IsAbs(rel) {
		return nil, fmt.Errorf("OCI layout path is not canonical")
	}
	parts := strings.Split(filepath.ToSlash(rel), "/")
	for _, p := range parts {
		if p == "" || p == "." || p == ".." {
			return nil, fmt.Errorf("OCI layout path %q is not canonical", rel)
		}
	}
	before, err := os.Lstat(root)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.IsDir() {
		return nil, fmt.Errorf("OCI layout root must be a real directory")
	}
	fd, err := syscall.Open(root, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open OCI layout root safely: %w", err)
	}
	for i, p := range parts {
		last := i == len(parts)-1
		flags := syscall.O_RDONLY | syscall.O_CLOEXEC | syscall.O_NOFOLLOW
		if !last {
			flags |= syscall.O_DIRECTORY
		}
		next, openErr := syscall.Openat(fd, p, flags, 0)
		_ = syscall.Close(fd)
		if openErr != nil {
			return nil, fmt.Errorf("open OCI layout path %q safely: %w", rel, openErr)
		}
		fd = next
	}
	file := os.NewFile(uintptr(fd), filepath.Join(root, rel))
	if file == nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("open OCI layout path %q safely", rel)
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 {
		_ = file.Close()
		return nil, fmt.Errorf("OCI layout path %q must be a non-empty regular file", rel)
	}
	return file, nil
}

func readBoundedLayoutFile(root, rel string, max int64) ([]byte, error) {
	f, err := safeOpenLayoutFile(root, rel)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, _ := f.Stat()
	if info.Size() > max {
		return nil, fmt.Errorf("OCI layout path %q exceeds size limit", rel)
	}
	raw, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || int64(len(raw)) != info.Size() {
		return nil, fmt.Errorf("read OCI layout path %q", rel)
	}
	return raw, nil
}

func parseSourceRoot(source SourceImage) (descriptor, map[string]sourceBlob, error) {
	var empty descriptor
	ref := strings.TrimSpace(source.Reference)
	if !exactImageReference(ref) {
		return empty, nil, fmt.Errorf("source image reference %q must be exact registry/repository@sha256:digest", ref)
	}
	root := strings.TrimSpace(source.LayoutDir)
	layoutRaw, err := readBoundedLayoutFile(root, "oci-layout", maxJSONBytes)
	if err != nil {
		return empty, nil, err
	}
	var layout struct {
		ImageLayoutVersion string `json:"imageLayoutVersion"`
	}
	if err = decodeCanonicalJSON(layoutRaw, &layout); err != nil || layout.ImageLayoutVersion != "1.0.0" {
		return empty, nil, fmt.Errorf("source OCI layout is invalid")
	}
	indexRaw, err := readBoundedLayoutFile(root, "index.json", maxJSONBytes)
	if err != nil {
		return empty, nil, err
	}
	var index sourceIndex
	if err = decodeCanonicalJSON(indexRaw, &index); err != nil || index.SchemaVersion != 2 || len(index.Manifests) == 0 || (index.MediaType != "" && index.MediaType != "application/vnd.oci.image.index.v1+json") || index.ArtifactType != "" || index.Subject != nil {
		return empty, nil, fmt.Errorf("source OCI index is invalid")
	}
	digest := ref[strings.LastIndex(ref, "@")+1:]
	var selected *descriptor
	for i := range index.Manifests {
		if index.Manifests[i].Digest == digest {
			if selected != nil {
				return empty, nil, fmt.Errorf("source OCI index repeats root digest %q", digest)
			}
			copy := index.Manifests[i]
			selected = &copy
		}
	}
	if selected == nil {
		return empty, nil, fmt.Errorf("source digest %q is not a root descriptor in OCI index", digest)
	}
	blobs := map[string]sourceBlob{}
	if err = collectSourceDescriptor(root, *selected, blobs, true); err != nil {
		return empty, nil, err
	}
	return *selected, blobs, nil
}

func collectSourceDescriptor(root string, desc descriptor, blobs map[string]sourceBlob, parseDocument bool) error {
	if !digestPattern.MatchString(desc.Digest) || desc.Size <= 0 {
		return fmt.Errorf("source OCI descriptor is invalid")
	}
	rel := "blobs/sha256/" + strings.TrimPrefix(desc.Digest, "sha256:")
	if existing, ok := blobs[desc.Digest]; ok {
		if existing.size != desc.Size {
			return fmt.Errorf("source OCI duplicate digest %q has conflicting size", desc.Digest)
		}
		return nil
	}
	f, err := safeOpenLayoutFile(root, rel)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil || info.Size() != desc.Size {
		_ = f.Close()
		return fmt.Errorf("source OCI descriptor %q size mismatch", desc.Digest)
	}
	h := sha256.New()
	var raw []byte
	if parseDocument {
		if desc.Size > maxJSONBytes {
			_ = f.Close()
			return fmt.Errorf("source OCI descriptor %q document exceeds verification limit", desc.Digest)
		}
		var b strings.Builder
		if _, err = io.Copy(io.MultiWriter(h, &b), f); err != nil {
			_ = f.Close()
			return err
		}
		raw = []byte(b.String())
	} else {
		if _, err = io.Copy(h, f); err != nil {
			_ = f.Close()
			return err
		}
	}
	_ = f.Close()
	if got := "sha256:" + hex.EncodeToString(h.Sum(nil)); got != desc.Digest {
		return fmt.Errorf("source OCI descriptor %q digest mismatch", desc.Digest)
	}
	blobs[desc.Digest] = sourceBlob{digest: desc.Digest, size: desc.Size, root: root, rel: rel}
	if !parseDocument {
		return nil
	}
	switch desc.MediaType {
	case "application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json":
		var value struct {
			SchemaVersion int               `json:"schemaVersion"`
			MediaType     string            `json:"mediaType,omitempty"`
			ArtifactType  string            `json:"artifactType,omitempty"`
			Subject       *descriptor       `json:"subject,omitempty"`
			Manifests     []descriptor      `json:"manifests"`
			Annotations   map[string]string `json:"annotations,omitempty"`
		}
		if err = decodeCanonicalJSON(raw, &value); err != nil || value.SchemaVersion != 2 || len(value.Manifests) == 0 || value.ArtifactType != "" || value.Subject != nil || (value.MediaType != "" && value.MediaType != desc.MediaType) {
			return fmt.Errorf("source OCI nested index %q is invalid", desc.Digest)
		}
		for _, child := range value.Manifests {
			if err = collectSourceDescriptor(root, child, blobs, true); err != nil {
				return err
			}
		}
	case "application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json":
		var value struct {
			SchemaVersion int               `json:"schemaVersion"`
			MediaType     string            `json:"mediaType,omitempty"`
			ArtifactType  string            `json:"artifactType,omitempty"`
			Subject       *descriptor       `json:"subject,omitempty"`
			Config        descriptor        `json:"config"`
			Layers        []descriptor      `json:"layers"`
			Annotations   map[string]string `json:"annotations,omitempty"`
		}
		if err = decodeCanonicalJSON(raw, &value); err != nil || value.SchemaVersion != 2 || value.ArtifactType != "" || value.Subject != nil || (value.MediaType != "" && value.MediaType != desc.MediaType) {
			return fmt.Errorf("source OCI image manifest %q is invalid", desc.Digest)
		}
		if err = collectSourceDescriptor(root, value.Config, blobs, false); err != nil {
			return err
		}
		for _, layer := range value.Layers {
			if err = collectSourceDescriptor(root, layer, blobs, false); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("source OCI root descriptor %q has unsupported mediaType %q", desc.Digest, desc.MediaType)
	}
	return nil
}

func AssembleToFile(sources []SourceImage, outPath string) (AssemblyResult, error) {
	var empty AssemblyResult
	if len(sources) == 0 || len(sources) > 4096 {
		return empty, fmt.Errorf("management workload OCI assembly requires 1-4096 exact image sources")
	}
	refs := make([]string, 0, len(sources))
	roots := make([]descriptor, 0, len(sources))
	allBlobs := map[string]sourceBlob{}
	seenRefs := map[string]bool{}
	seenRootDigests := map[string]string{}
	for _, source := range sources {
		ref := strings.TrimSpace(source.Reference)
		if seenRefs[ref] {
			return empty, fmt.Errorf("duplicate management workload image reference %q", ref)
		}
		seenRefs[ref] = true
		root, blobs, err := parseSourceRoot(SourceImage{Reference: ref, LayoutDir: source.LayoutDir})
		if err != nil {
			return empty, fmt.Errorf("source %q: %w", ref, err)
		}
		if previous, ok := seenRootDigests[root.Digest]; ok {
			return empty, fmt.Errorf("references %q and %q share manifest digest %q; import addressability would be ambiguous", previous, ref, root.Digest)
		}
		seenRootDigests[root.Digest] = ref
		annotations := map[string]string{}
		for key, value := range root.Annotations {
			annotations[key] = value
		}
		annotations["io.containerd.image.name"] = ref
		annotations["org.opencontainers.image.ref.name"] = ref
		root.Annotations = annotations
		refs = append(refs, ref)
		roots = append(roots, root)
		for digest, blob := range blobs {
			if existing, ok := allBlobs[digest]; ok {
				if existing.size != blob.size {
					return empty, fmt.Errorf("shared OCI blob %q has conflicting size", digest)
				}
				continue
			}
			allBlobs[digest] = blob
		}
	}
	sort.Strings(refs)
	sort.Slice(roots, func(i, j int) bool { return seenRootDigests[roots[i].Digest] < seenRootDigests[roots[j].Digest] })
	inventory := Inventory{Authority: InventoryAuthority, SchemaVersion: InventorySchemaVersion, ImportAddressabilityAuthority: ImportAddressabilityAuthority, Images: refs}
	layoutRaw, _ := json.Marshal(struct {
		ImageLayoutVersion string `json:"imageLayoutVersion"`
	}{"1.0.0"})
	indexRaw, _ := json.Marshal(struct {
		SchemaVersion int          `json:"schemaVersion"`
		MediaType     string       `json:"mediaType"`
		Manifests     []descriptor `json:"manifests"`
	}{2, "application/vnd.oci.image.index.v1+json", roots})
	inventoryRaw, _ := json.Marshal(inventory)

	if strings.TrimSpace(outPath) == "" {
		return empty, fmt.Errorf("output archive path is required")
	}
	if _, err := os.Lstat(outPath); err == nil {
		return empty, fmt.Errorf("refusing to overwrite existing management workload OCI archive %s", outPath)
	} else if !os.IsNotExist(err) {
		return empty, err
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return empty, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(outPath), ".management-workload-oci-*.tmp")
	if err != nil {
		return empty, err
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = tmp.Close(); _ = os.Remove(tmpName) }
	defer cleanup()
	hash := sha256.New()
	counting := &countWriter{Writer: io.MultiWriter(tmp, hash)}
	tw := tar.NewWriter(counting)
	writeBytes := func(name string, raw []byte) error {
		h := &tar.Header{Name: name, Mode: 0o644, Uid: 0, Gid: 0, Size: int64(len(raw)), ModTime: time.Unix(0, 0).UTC(), Format: tar.FormatUSTAR}
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		_, err := tw.Write(raw)
		return err
	}
	if err = writeBytes("4so-image-inventory.json", inventoryRaw); err != nil {
		return empty, err
	}
	blobDigests := make([]string, 0, len(allBlobs))
	for digest := range allBlobs {
		blobDigests = append(blobDigests, digest)
	}
	sort.Strings(blobDigests)
	for _, digest := range blobDigests {
		blob := allBlobs[digest]
		name := "blobs/sha256/" + strings.TrimPrefix(digest, "sha256:")
		hdr := &tar.Header{Name: name, Mode: 0o644, Uid: 0, Gid: 0, Size: blob.size, ModTime: time.Unix(0, 0).UTC(), Format: tar.FormatUSTAR}
		if err = tw.WriteHeader(hdr); err != nil {
			return empty, err
		}
		f, openErr := safeOpenLayoutFile(blob.root, blob.rel)
		if openErr != nil {
			return empty, openErr
		}
		h := sha256.New()
		written, copyErr := io.Copy(io.MultiWriter(tw, h), bufio.NewReaderSize(f, 1<<20))
		_ = f.Close()
		if copyErr != nil || written != blob.size {
			return empty, fmt.Errorf("copy OCI blob %q", digest)
		}
		if got := "sha256:" + hex.EncodeToString(h.Sum(nil)); got != digest {
			return empty, fmt.Errorf("OCI blob %q changed during assembly", digest)
		}
	}
	if err = writeBytes("index.json", indexRaw); err != nil {
		return empty, err
	}
	if err = writeBytes("oci-layout", layoutRaw); err != nil {
		return empty, err
	}
	if err = tw.Close(); err != nil {
		return empty, err
	}
	if err = tmp.Sync(); err != nil {
		return empty, err
	}
	if err = tmp.Close(); err != nil {
		return empty, err
	}
	if err = os.Chmod(tmpName, 0o644); err != nil {
		return empty, err
	}
	if err = os.Rename(tmpName, outPath); err != nil {
		return empty, err
	}
	// The output is independently inspected after atomic publication. If this
	// fails, remove the invalid archive rather than leaving a plausible file.
	verified, inspectErr := Inspect(outPath)
	if inspectErr != nil {
		_ = os.Remove(outPath)
		return empty, fmt.Errorf("assembled management workload OCI archive failed independent inspection: %w", inspectErr)
	}
	if !equalStrings(verified.Images, inventory.Images) {
		_ = os.Remove(outPath)
		return empty, fmt.Errorf("assembled management workload OCI inventory drifted")
	}
	return AssemblyResult{Authority: AssemblyAuthority, ArchiveSHA256: "sha256:" + hex.EncodeToString(hash.Sum(nil)), ArchiveBytes: counting.N, ImageCount: len(refs), BlobCount: len(allBlobs), Inventory: inventory}, nil
}

type countWriter struct {
	io.Writer
	N int64
}

func (w *countWriter) Write(p []byte) (int, error) {
	n, err := w.Writer.Write(p)
	w.N += int64(n)
	return n, err
}
