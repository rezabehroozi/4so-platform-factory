package ociarchive

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	pathpkg "path"
	"regexp"
	"sort"
	"strings"
	"syscall"
)

const (
	InventoryAuthority                  = "MANAGEMENT_WORKLOAD_OCI_ARCHIVE_INVENTORY_V2"
	InventorySchemaVersion              = 2
	ImportAddressabilityAuthority       = "MANAGEMENT_WORKLOAD_OCI_IMPORT_ADDRESSABILITY_V2"
	maxEntries                          = 100000
	maxJSONBytes                        = 16 << 20
	maxTotalBytes                 int64 = 64 << 30
)

var imageRefPattern = regexp.MustCompile(`^[^@\s]+@sha256:([a-f0-9]{64})$`)
var digestPattern = regexp.MustCompile(`^sha256:([a-f0-9]{64})$`)

type Inventory struct {
	Authority                     string   `json:"authority"`
	SchemaVersion                 int      `json:"schemaVersion"`
	ImportAddressabilityAuthority string   `json:"importAddressabilityAuthority"`
	Images                        []string `json:"images"`
}

type descriptorPlatform struct {
	Architecture string   `json:"architecture,omitempty"`
	OS           string   `json:"os,omitempty"`
	OSVersion    string   `json:"os.version,omitempty"`
	OSFeatures   []string `json:"os.features,omitempty"`
	Variant      string   `json:"variant,omitempty"`
}

type descriptor struct {
	MediaType    string              `json:"mediaType"`
	Digest       string              `json:"digest"`
	Size         int64               `json:"size"`
	URLs         []string            `json:"urls,omitempty"`
	Annotations  map[string]string   `json:"annotations,omitempty"`
	Data         string              `json:"data,omitempty"`
	ArtifactType string              `json:"artifactType,omitempty"`
	Platform     *descriptorPlatform `json:"platform,omitempty"`
}

type blobInfo struct {
	size int64
	raw  []byte
}

func Inspect(filePath string) (Inventory, error) {
	var empty Inventory
	before, err := os.Lstat(filePath)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() <= 0 {
		return empty, fmt.Errorf("workload OCI archive must be a non-empty regular non-symlink file")
	}
	fd, err := syscall.Open(filePath, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return empty, fmt.Errorf("open workload OCI archive safely: %w", err)
	}
	file := os.NewFile(uintptr(fd), filePath)
	if file == nil {
		_ = syscall.Close(fd)
		return empty, fmt.Errorf("open workload OCI archive safely")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || !os.SameFile(before, info) {
		return empty, fmt.Errorf("workload OCI archive changed while opening")
	}
	var reader io.Reader = file
	prefix := make([]byte, 2)
	n, readErr := io.ReadFull(file, prefix)
	if readErr != nil && readErr != io.ErrUnexpectedEOF {
		return empty, readErr
	}
	if _, err = file.Seek(0, io.SeekStart); err != nil {
		return empty, err
	}
	if n == 2 && prefix[0] == 0x1f && prefix[1] == 0x8b {
		gz, gzErr := gzip.NewReader(file)
		if gzErr != nil {
			return empty, fmt.Errorf("open workload OCI gzip archive: %w", gzErr)
		}
		defer gz.Close()
		reader = gz
	}
	tr := tar.NewReader(reader)
	seen := map[string]struct{}{}
	blobs := map[string]blobInfo{}
	var layoutRaw, indexRaw, inventoryRaw []byte
	var total int64
	entries := 0
	for {
		hdr, nextErr := tr.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return empty, fmt.Errorf("read workload OCI archive: %w", nextErr)
		}
		entries++
		if entries > maxEntries {
			return empty, fmt.Errorf("workload OCI archive has too many entries")
		}
		name, pathErr := canonicalTarPath(hdr.Name)
		if pathErr != nil {
			return empty, pathErr
		}
		if _, exists := seen[name]; exists {
			return empty, fmt.Errorf("workload OCI archive contains duplicate path %q", name)
		}
		seen[name] = struct{}{}
		if hdr.Typeflag == tar.TypeDir {
			continue
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			return empty, fmt.Errorf("workload OCI archive path %q is not a regular file", name)
		}
		if hdr.Size <= 0 {
			return empty, fmt.Errorf("workload OCI archive path %q is empty", name)
		}
		total += hdr.Size
		if total > maxTotalBytes {
			return empty, fmt.Errorf("workload OCI archive unpacked size exceeds limit")
		}
		collect := name == "oci-layout" || name == "index.json" || name == "4so-image-inventory.json" || (strings.HasPrefix(name, "blobs/sha256/") && hdr.Size <= maxJSONBytes)
		var buf bytes.Buffer
		h := sha256.New()
		writer := io.Writer(h)
		if collect {
			writer = io.MultiWriter(h, &buf)
		}
		written, copyErr := io.Copy(writer, tr)
		if copyErr != nil || written != hdr.Size {
			return empty, fmt.Errorf("read workload OCI archive path %q", name)
		}
		if strings.HasPrefix(name, "blobs/sha256/") {
			hexDigest := strings.TrimPrefix(name, "blobs/sha256/")
			if !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(hexDigest) {
				return empty, fmt.Errorf("workload OCI blob path %q has invalid digest", name)
			}
			if got := hex.EncodeToString(h.Sum(nil)); got != hexDigest {
				return empty, fmt.Errorf("workload OCI blob %q digest mismatch", name)
			}
			blobs["sha256:"+hexDigest] = blobInfo{size: hdr.Size, raw: append([]byte(nil), buf.Bytes()...)}
			continue
		}
		switch name {
		case "oci-layout":
			layoutRaw = append([]byte(nil), buf.Bytes()...)
		case "index.json":
			indexRaw = append([]byte(nil), buf.Bytes()...)
		case "4so-image-inventory.json":
			inventoryRaw = append([]byte(nil), buf.Bytes()...)
		default:
			return empty, fmt.Errorf("workload OCI archive contains unowned path %q", name)
		}
	}
	if len(layoutRaw) == 0 || len(indexRaw) == 0 || len(inventoryRaw) == 0 {
		return empty, fmt.Errorf("workload OCI archive requires oci-layout, index.json and 4so-image-inventory.json")
	}
	var layout struct {
		ImageLayoutVersion string `json:"imageLayoutVersion"`
	}
	if err = decodeCanonicalJSON(layoutRaw, &layout); err != nil || layout.ImageLayoutVersion != "1.0.0" {
		return empty, fmt.Errorf("workload OCI layout is invalid")
	}
	var inventory Inventory
	if err = decodeCanonicalJSON(inventoryRaw, &inventory); err != nil {
		return empty, fmt.Errorf("decode workload OCI inventory: %w", err)
	}
	if inventory.Authority != InventoryAuthority || inventory.SchemaVersion != InventorySchemaVersion || inventory.ImportAddressabilityAuthority != ImportAddressabilityAuthority || len(inventory.Images) == 0 {
		return empty, fmt.Errorf("workload OCI inventory authority is invalid")
	}
	normalized := append([]string(nil), inventory.Images...)
	sort.Strings(normalized)
	for i, ref := range normalized {
		if !imageRefPattern.MatchString(ref) {
			return empty, fmt.Errorf("workload OCI inventory image %q is not digest-pinned", ref)
		}
		if i > 0 && normalized[i-1] == ref {
			return empty, fmt.Errorf("workload OCI inventory contains duplicate image %q", ref)
		}
	}
	if !equalStrings(inventory.Images, normalized) {
		return empty, fmt.Errorf("workload OCI inventory images must be sorted canonically")
	}
	var index struct {
		SchemaVersion int               `json:"schemaVersion"`
		MediaType     string            `json:"mediaType,omitempty"`
		ArtifactType  string            `json:"artifactType,omitempty"`
		Subject       *descriptor       `json:"subject,omitempty"`
		Manifests     []descriptor      `json:"manifests"`
		Annotations   map[string]string `json:"annotations,omitempty"`
	}
	if err = decodeCanonicalJSON(indexRaw, &index); err != nil || index.SchemaVersion != 2 || len(index.Manifests) == 0 || (index.MediaType != "" && index.MediaType != "application/vnd.oci.image.index.v1+json") || index.ArtifactType != "" || index.Subject != nil {
		return empty, fmt.Errorf("workload OCI index is invalid")
	}
	expected := map[string]string{}
	for _, ref := range inventory.Images {
		m := imageRefPattern.FindStringSubmatch(ref)
		digest := "sha256:" + m[1]
		if previous, exists := expected[digest]; exists {
			return empty, fmt.Errorf("workload OCI inventory references %q and %q with the same manifest digest; import addressability would be ambiguous", previous, ref)
		}
		expected[digest] = ref
	}
	top := map[string]struct{}{}
	reachable := map[string]struct{}{}
	for _, desc := range index.Manifests {
		if _, dup := top[desc.Digest]; dup {
			return empty, fmt.Errorf("workload OCI index contains duplicate descriptor %q", desc.Digest)
		}
		top[desc.Digest] = struct{}{}
		ref, ok := expected[desc.Digest]
		if !ok {
			return empty, fmt.Errorf("workload OCI index descriptor %q is not declared by inventory", desc.Digest)
		}
		if desc.Annotations["io.containerd.image.name"] != ref || desc.Annotations["org.opencontainers.image.ref.name"] != ref {
			return empty, fmt.Errorf("workload OCI index descriptor %q is not import-addressable as inventory reference %q", desc.Digest, ref)
		}
		if err = verifyDescriptor(desc, blobs, reachable, true); err != nil {
			return empty, err
		}
	}
	if len(top) != len(expected) {
		return empty, fmt.Errorf("workload OCI inventory/index image set mismatch")
	}
	for digest := range expected {
		if _, ok := top[digest]; !ok {
			return empty, fmt.Errorf("workload OCI inventory image digest %q is missing from index", digest)
		}
	}
	if len(reachable) != len(blobs) {
		for digest := range blobs {
			if _, ok := reachable[digest]; !ok {
				return empty, fmt.Errorf("workload OCI archive contains unreferenced blob %q", digest)
			}
		}
	}
	return inventory, nil
}

func verifyDescriptor(desc descriptor, blobs map[string]blobInfo, reachable map[string]struct{}, parseDocument bool) error {
	if !digestPattern.MatchString(desc.Digest) || desc.Size <= 0 {
		return fmt.Errorf("workload OCI descriptor is invalid")
	}
	blob, ok := blobs[desc.Digest]
	if !ok {
		return fmt.Errorf("workload OCI descriptor blob %q is missing", desc.Digest)
	}
	if blob.size != desc.Size {
		return fmt.Errorf("workload OCI descriptor %q size mismatch", desc.Digest)
	}
	reachable[desc.Digest] = struct{}{}
	if !parseDocument {
		return nil
	}
	if len(blob.raw) == 0 {
		return fmt.Errorf("workload OCI descriptor %q document exceeds verification limit", desc.Digest)
	}
	media := desc.MediaType
	switch media {
	case "application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json":
		var value struct {
			SchemaVersion int               `json:"schemaVersion"`
			MediaType     string            `json:"mediaType,omitempty"`
			ArtifactType  string            `json:"artifactType,omitempty"`
			Subject       *descriptor       `json:"subject,omitempty"`
			Manifests     []descriptor      `json:"manifests"`
			Annotations   map[string]string `json:"annotations,omitempty"`
		}
		if err := decodeCanonicalJSON(blob.raw, &value); err != nil || value.SchemaVersion != 2 || len(value.Manifests) == 0 || value.ArtifactType != "" || value.Subject != nil || (value.MediaType != "" && value.MediaType != media) {
			return fmt.Errorf("workload OCI nested index %q is invalid", desc.Digest)
		}
		for _, child := range value.Manifests {
			if err := verifyDescriptor(child, blobs, reachable, true); err != nil {
				return err
			}
		}
		return nil
	case "application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json":
		var value struct {
			SchemaVersion int               `json:"schemaVersion"`
			MediaType     string            `json:"mediaType,omitempty"`
			ArtifactType  string            `json:"artifactType,omitempty"`
			Config        descriptor        `json:"config"`
			Subject       *descriptor       `json:"subject,omitempty"`
			Layers        []descriptor      `json:"layers"`
			Annotations   map[string]string `json:"annotations,omitempty"`
		}
		if err := decodeCanonicalJSON(blob.raw, &value); err != nil || value.SchemaVersion != 2 || value.ArtifactType != "" || value.Subject != nil || (value.MediaType != "" && value.MediaType != media) {
			return fmt.Errorf("workload OCI image manifest %q is invalid", desc.Digest)
		}
		if err := verifyDescriptor(value.Config, blobs, reachable, false); err != nil {
			return err
		}
		for _, layer := range value.Layers {
			if err := verifyDescriptor(layer, blobs, reachable, false); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("workload OCI top-level descriptor %q has unsupported mediaType %q", desc.Digest, media)
	}
}

func canonicalTarPath(raw string) (string, error) {
	if raw == "" || strings.TrimSpace(raw) != raw || strings.Contains(raw, "\\") || strings.HasPrefix(raw, "/") || strings.HasSuffix(raw, "/") {
		return "", fmt.Errorf("workload OCI archive path %q is not canonical", raw)
	}
	clean := pathpkg.Clean(raw)
	if clean != raw || clean == "." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("workload OCI archive path %q is not canonical", raw)
	}
	return clean, nil
}

func decodeCanonicalJSON(raw []byte, target any) error {
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func rejectDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]struct{}{}
			for decoder.More() {
				k, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := k.(string)
				if !ok {
					return errors.New("invalid JSON key")
				}
				if _, exists := seen[key]; exists {
					return fmt.Errorf("duplicate JSON key %q", key)
				}
				seen[key] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return errors.New("invalid JSON delimiter")
		}
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
