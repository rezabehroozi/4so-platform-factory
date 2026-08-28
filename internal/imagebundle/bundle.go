package imagebundle

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	MaxBundleBytes int64 = 8 << 30
	MaxFileBytes   int64 = 4 << 30
)

const (
	MediaTypeOCIManifest    = "application/vnd.oci.image.manifest.v1+json"
	MediaTypeOCIIndex       = "application/vnd.oci.image.index.v1+json"
	MediaTypeDockerManifest = "application/vnd.docker.distribution.manifest.v2+json"
	MediaTypeDockerList     = "application/vnd.docker.distribution.manifest.list.v2+json"
)

type Descriptor struct {
	MediaType string         `json:"mediaType"`
	Digest    string         `json:"digest"`
	Size      int64          `json:"size"`
	Platform  map[string]any `json:"platform,omitempty"`
}

type Index struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType,omitempty"`
	Manifests     []Descriptor `json:"manifests"`
}

type ImageManifest struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType,omitempty"`
	Config        Descriptor   `json:"config"`
	Layers        []Descriptor `json:"layers"`
}

type BundleManifest struct {
	APIVersion           string `json:"apiVersion"`
	Kind                 string `json:"kind"`
	SourceReference      string `json:"sourceReference"`
	SourceRegistry       string `json:"sourceRegistry"`
	SourceRepository     string `json:"sourceRepository"`
	RootDigest           string `json:"rootDigest"`
	RootMediaType        string `json:"rootMediaType"`
	MirrorRepository     string `json:"mirrorRepository"`
	BlobCount            int    `json:"blobCount"`
	ManifestCount        int    `json:"manifestCount"`
	TotalBytes           int64  `json:"totalBytes"`
	NetworkFetchRequired bool   `json:"networkFetchRequired"`
}

type Object struct {
	Digest    string
	MediaType string
	Raw       []byte
	Manifest  bool
}

type Verified struct {
	Manifest     BundleManifest    `json:"manifest"`
	BundleDigest string            `json:"bundleDigest"`
	Objects      []Object          `json:"-"`
	Files        map[string][]byte `json:"-"`
}

func exactDigest(v string) bool {
	if len(v) != 71 || !strings.HasPrefix(v, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(v, "sha256:"))
	return err == nil
}

func digestBytes(b []byte) string { s := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(s[:]) }

func ParseDigestReference(ref string) (registry, repository, digest string, err error) {
	ref = strings.TrimSpace(ref)
	at := strings.LastIndex(ref, "@")
	if at <= 0 || !exactDigest(ref[at+1:]) {
		return "", "", "", fmt.Errorf("image reference must be exact registry/repository@sha256:digest")
	}
	name := ref[:at]
	digest = ref[at+1:]
	slash := strings.Index(name, "/")
	if slash <= 0 || slash == len(name)-1 {
		return "", "", "", fmt.Errorf("image reference requires registry and repository")
	}
	registry, repository = name[:slash], name[slash+1:]
	if strings.ContainsAny(registry, " \\?#") || strings.Contains(repository, "..") || strings.HasPrefix(repository, "/") || strings.ContainsAny(repository, " \\?#@") {
		return "", "", "", fmt.Errorf("unsafe image reference")
	}
	return registry, repository, digest, nil
}

func MirrorRepository(sourceReference string) (string, error) {
	registry, repo, _, err := ParseDigestReference(sourceReference)
	if err != nil {
		return "", err
	}
	cleanRegistry := strings.ReplaceAll(registry, ":", "_")
	return "mirror/" + cleanRegistry + "/" + repo, nil
}

func blobPath(digest string) (string, error) {
	if !exactDigest(digest) {
		return "", fmt.Errorf("invalid digest %q", digest)
	}
	return "blobs/sha256/" + strings.TrimPrefix(digest, "sha256:"), nil
}

func readLayout(root string) (map[string][]byte, error) {
	root, _ = filepath.Abs(root)
	layoutRaw, err := os.ReadFile(filepath.Join(root, "oci-layout"))
	if err != nil {
		return nil, fmt.Errorf("read oci-layout: %w", err)
	}
	var layout struct {
		ImageLayoutVersion string `json:"imageLayoutVersion"`
	}
	if err = json.Unmarshal(layoutRaw, &layout); err != nil || layout.ImageLayoutVersion != "1.0.0" {
		return nil, fmt.Errorf("oci-layout must be version 1.0.0")
	}
	indexRaw, err := os.ReadFile(filepath.Join(root, "index.json"))
	if err != nil {
		return nil, fmt.Errorf("read index.json: %w", err)
	}
	files := map[string][]byte{"oci-layout": layoutRaw, "index.json": indexRaw}
	err = filepath.Walk(filepath.Join(root, "blobs", "sha256"), func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() {
			return nil
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink %s is forbidden", path)
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if !strings.HasPrefix(rel, "blobs/sha256/") {
			return fmt.Errorf("unexpected OCI path %s", rel)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if int64(len(raw)) > MaxFileBytes {
			return fmt.Errorf("blob exceeds size limit")
		}
		files[rel] = raw
		return nil
	})
	if err != nil {
		return nil, err
	}
	return files, nil
}

func descriptorObject(files map[string][]byte, d Descriptor) (Object, error) {
	p, err := blobPath(d.Digest)
	if err != nil {
		return Object{}, err
	}
	raw, ok := files[p]
	if !ok {
		return Object{}, fmt.Errorf("missing OCI blob %s", d.Digest)
	}
	if int64(len(raw)) != d.Size {
		return Object{}, fmt.Errorf("OCI descriptor size mismatch for %s", d.Digest)
	}
	if digestBytes(raw) != d.Digest {
		return Object{}, fmt.Errorf("OCI descriptor digest mismatch for %s", d.Digest)
	}
	manifest := d.MediaType == MediaTypeOCIManifest || d.MediaType == MediaTypeOCIIndex || d.MediaType == MediaTypeDockerManifest || d.MediaType == MediaTypeDockerList
	return Object{Digest: d.Digest, MediaType: d.MediaType, Raw: raw, Manifest: manifest}, nil
}

func walkDescriptor(files map[string][]byte, d Descriptor, seen map[string]bool, out *[]Object) error {
	if seen[d.Digest] {
		return nil
	}
	obj, err := descriptorObject(files, d)
	if err != nil {
		return err
	}
	seen[d.Digest] = true
	*out = append(*out, obj)
	if !obj.Manifest {
		return nil
	}
	switch d.MediaType {
	case MediaTypeOCIIndex, MediaTypeDockerList:
		var idx Index
		if err = json.Unmarshal(obj.Raw, &idx); err != nil || idx.SchemaVersion != 2 {
			return fmt.Errorf("decode image index %s", d.Digest)
		}
		if len(idx.Manifests) == 0 {
			return fmt.Errorf("image index %s has no manifests", d.Digest)
		}
		for _, child := range idx.Manifests {
			if err = walkDescriptor(files, child, seen, out); err != nil {
				return err
			}
		}
	case MediaTypeOCIManifest, MediaTypeDockerManifest:
		var m ImageManifest
		if err = json.Unmarshal(obj.Raw, &m); err != nil || m.SchemaVersion != 2 {
			return fmt.Errorf("decode image manifest %s", d.Digest)
		}
		if !exactDigest(m.Config.Digest) {
			return fmt.Errorf("manifest %s config digest invalid", d.Digest)
		}
		if err = walkDescriptor(files, m.Config, seen, out); err != nil {
			return err
		}
		for _, layer := range m.Layers {
			if err = walkDescriptor(files, layer, seen, out); err != nil {
				return err
			}
		}
	}
	return nil
}

func verifyFiles(files map[string][]byte, sourceReference string) (Verified, error) {
	registry, repo, digest, err := ParseDigestReference(sourceReference)
	if err != nil {
		return Verified{}, err
	}
	indexRaw, ok := files["index.json"]
	if !ok {
		return Verified{}, errors.New("index.json missing")
	}
	var idx Index
	if err = json.Unmarshal(indexRaw, &idx); err != nil || idx.SchemaVersion != 2 {
		return Verified{}, errors.New("invalid index.json")
	}
	var root *Descriptor
	for i := range idx.Manifests {
		if idx.Manifests[i].Digest == digest {
			root = &idx.Manifests[i]
			break
		}
	}
	if root == nil {
		return Verified{}, fmt.Errorf("source digest %s is not a root descriptor in index.json", digest)
	}
	seen := map[string]bool{}
	objects := []Object{}
	if err = walkDescriptor(files, *root, seen, &objects); err != nil {
		return Verified{}, err
	}
	referenced := map[string]bool{"oci-layout": true, "index.json": true}
	var total int64
	manifests := 0
	for _, obj := range objects {
		p, _ := blobPath(obj.Digest)
		referenced[p] = true
		total += int64(len(obj.Raw))
		if obj.Manifest {
			manifests++
		}
	}
	for name := range files {
		if !referenced[name] {
			return Verified{}, fmt.Errorf("OCI layout contains unreferenced payload %s", name)
		}
	}
	mirrorRepo, _ := MirrorRepository(sourceReference)
	manifest := BundleManifest{APIVersion: "platform.4so.io/v1alpha1", Kind: "OCIImageMirrorBundle", SourceReference: sourceReference, SourceRegistry: registry, SourceRepository: repo, RootDigest: digest, RootMediaType: root.MediaType, MirrorRepository: mirrorRepo, BlobCount: len(objects) - manifests, ManifestCount: manifests, TotalBytes: total, NetworkFetchRequired: false}
	return Verified{Manifest: manifest, Objects: objects, Files: files}, nil
}

func Assemble(layoutDir, sourceReference string) ([]byte, Verified, error) {
	files, err := readLayout(layoutDir)
	if err != nil {
		return nil, Verified{}, err
	}
	verified, err := verifyFiles(files, sourceReference)
	if err != nil {
		return nil, Verified{}, err
	}
	manifestRaw, _ := json.MarshalIndent(verified.Manifest, "", "  ")
	manifestRaw = append(manifestRaw, '\n')
	bundleFiles := map[string][]byte{"bundle-manifest.json": manifestRaw, "oci-layout": files["oci-layout"], "index.json": files["index.json"]}
	for name, raw := range files {
		if strings.HasPrefix(name, "blobs/sha256/") {
			bundleFiles[name] = raw
		}
	}
	raw, err := deterministicZip(bundleFiles)
	if err != nil {
		return nil, Verified{}, err
	}
	verified.BundleDigest = digestBytes(raw)
	return raw, verified, nil
}

func deterministicZip(files map[string][]byte) ([]byte, error) {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	epoch := time.Unix(0, 0).UTC()
	for _, name := range names {
		h := &zip.FileHeader{Name: name, Method: zip.Deflate}
		h.SetModTime(epoch)
		h.SetMode(0o644)
		w, err := zw.CreateHeader(h)
		if err != nil {
			return nil, err
		}
		if _, err = w.Write(files[name]); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func safeBundlePath(name string) bool {
	if name == "bundle-manifest.json" || name == "oci-layout" || name == "index.json" {
		return true
	}
	if !strings.HasPrefix(name, "blobs/sha256/") {
		return false
	}
	hexv := strings.TrimPrefix(name, "blobs/sha256/")
	if len(hexv) != 64 {
		return false
	}
	_, err := hex.DecodeString(hexv)
	return err == nil
}

func Verify(raw []byte) (Verified, error) {
	if int64(len(raw)) > MaxBundleBytes {
		return Verified{}, errors.New("image bundle exceeds size limit")
	}
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return Verified{}, err
	}
	files := map[string][]byte{}
	var total int64
	for _, f := range zr.File {
		if !safeBundlePath(f.Name) || f.FileInfo().IsDir() || f.FileInfo().Mode()&os.ModeSymlink != 0 {
			return Verified{}, fmt.Errorf("unsafe image bundle entry %q", f.Name)
		}
		if _, ok := files[f.Name]; ok {
			return Verified{}, fmt.Errorf("duplicate image bundle entry %q", f.Name)
		}
		if f.UncompressedSize64 > uint64(MaxFileBytes) {
			return Verified{}, fmt.Errorf("entry too large %q", f.Name)
		}
		total += int64(f.UncompressedSize64)
		if total > MaxBundleBytes {
			return Verified{}, errors.New("uncompressed image bundle exceeds size limit")
		}
		rc, err := f.Open()
		if err != nil {
			return Verified{}, err
		}
		b, err := io.ReadAll(io.LimitReader(rc, MaxFileBytes+1))
		_ = rc.Close()
		if err != nil {
			return Verified{}, err
		}
		files[f.Name] = b
	}
	mraw, ok := files["bundle-manifest.json"]
	if !ok {
		return Verified{}, errors.New("bundle-manifest.json missing")
	}
	var manifest BundleManifest
	if err = json.Unmarshal(mraw, &manifest); err != nil {
		return Verified{}, err
	}
	if manifest.APIVersion != "platform.4so.io/v1alpha1" || manifest.Kind != "OCIImageMirrorBundle" || manifest.NetworkFetchRequired {
		return Verified{}, errors.New("image bundle manifest identity/offline contract invalid")
	}
	layoutFiles := map[string][]byte{}
	for n, b := range files {
		if n != "bundle-manifest.json" {
			layoutFiles[n] = b
		}
	}
	verified, err := verifyFiles(layoutFiles, manifest.SourceReference)
	if err != nil {
		return Verified{}, err
	}
	if verified.Manifest != manifest {
		return Verified{}, errors.New("image bundle manifest does not match verified OCI layout")
	}
	verified.BundleDigest = digestBytes(raw)
	verified.Files = files
	return verified, nil
}

func RegistryEndpoint(base, repository, objectType, digest string) (string, error) {
	u, err := url.Parse(strings.TrimRight(base, "/"))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("registry URL must include scheme and host")
	}
	u.Path = "/v2/" + repository + "/" + objectType + "/" + digest
	return u.String(), nil
}
