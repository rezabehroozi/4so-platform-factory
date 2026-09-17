package ociarchive

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"fmt"
	"io"
	pathpkg "path"
	"sort"
	"strings"
)

const ProductImageCertificationAuthority = "MANAGEMENT_WORKLOAD_PRODUCT_IMAGE_CERTIFICATION_V1"

const maxProductLayerEntries = 200000

// ProductImageSpec binds a product-owned OCI image to the exact release payload
// and its minimum runtime identity. It intentionally does not claim that the
// image's external runtime/base dependency closure has been physically tested.
type ProductImageSpec struct {
	Role                  string
	Repository            string
	BinaryPath            string
	ExpectedBinaryDigest  string
	ExpectedUser          string
	ExpectedEntrypoint    []string
	ExpectedReleaseDigest string
	RequireCABundle       bool
	ExpectedLinkage       string
	RequiredNeeded        []string
}

type ProductImageCertification struct {
	Authority          string   `json:"authority"`
	Role               string   `json:"role"`
	Reference          string   `json:"reference"`
	ReleaseDigest      string   `json:"releaseDigest"`
	BinaryPath         string   `json:"binaryPath,omitempty"`
	BinaryDigest       string   `json:"binaryDigest,omitempty"`
	User               string   `json:"user"`
	Entrypoint         []string `json:"entrypoint"`
	CABundlePresent    bool     `json:"caBundlePresent,omitempty"`
	ExactPayloadBound  bool     `json:"exactPayloadBound"`
	RuntimeClosurePASS bool     `json:"runtimeClosurePass"`
	Linkage            string   `json:"linkage,omitempty"`
	ELFInterpreter     string   `json:"elfInterpreter,omitempty"`
	NeededLibraries    []string `json:"neededLibraries,omitempty"`
}

type productConfig struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
	Created      string `json:"created,omitempty"`
	RootFS       struct {
		Type    string   `json:"type"`
		DiffIDs []string `json:"diff_ids"`
	} `json:"rootfs,omitempty"`
	History []struct {
		Created    string `json:"created,omitempty"`
		CreatedBy  string `json:"created_by,omitempty"`
		Author     string `json:"author,omitempty"`
		Comment    string `json:"comment,omitempty"`
		EmptyLayer bool   `json:"empty_layer,omitempty"`
	} `json:"history,omitempty"`
	Config struct {
		User         string              `json:"User"`
		Entrypoint   []string            `json:"Entrypoint"`
		Cmd          []string            `json:"Cmd,omitempty"`
		Env          []string            `json:"Env,omitempty"`
		WorkingDir   string              `json:"WorkingDir,omitempty"`
		StopSignal   string              `json:"StopSignal,omitempty"`
		ExposedPorts map[string]struct{} `json:"ExposedPorts,omitempty"`
		Volumes      map[string]struct{} `json:"Volumes,omitempty"`
		Labels       map[string]string   `json:"Labels"`
	} `json:"config"`
}

type productManifest struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType,omitempty"`
	Config        descriptor   `json:"config"`
	Layers        []descriptor `json:"layers"`
}

type layerTarget struct {
	path       string
	present    bool
	regular    bool
	executable bool
	digest     string
	capture    bool
	raw        []byte
}

func sourceBlobBytes(blob sourceBlob, max int64) ([]byte, error) {
	if blob.size <= 0 || blob.size > max {
		return nil, fmt.Errorf("OCI blob %s exceeds verification limit", blob.digest)
	}
	f, err := safeOpenLayoutFile(blob.root, blob.rel)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || int64(len(raw)) != blob.size {
		return nil, fmt.Errorf("read OCI blob %s", blob.digest)
	}
	return raw, nil
}

func canonicalLayerPath(name string) (string, error) {
	if name == "" || strings.ContainsRune(name, '\x00') || strings.Contains(name, "\\") || strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("OCI layer contains non-canonical path %q", name)
	}
	for strings.HasPrefix(name, "./") {
		name = strings.TrimPrefix(name, "./")
	}
	clean := pathpkg.Clean(name)
	if clean == "." || clean == "" || clean != name || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("OCI layer contains non-canonical path %q", name)
	}
	return clean, nil
}

func targetRemovedByWhiteout(target, whiteout string) bool {
	dir, base := pathpkg.Split(whiteout)
	dir = strings.TrimSuffix(dir, "/")
	if base == ".wh..wh..opq" {
		return dir == "" || target == dir || strings.HasPrefix(target, dir+"/")
	}
	if !strings.HasPrefix(base, ".wh.") {
		return false
	}
	removed := strings.TrimPrefix(base, ".wh.")
	if dir != "" {
		removed = dir + "/" + removed
	}
	return target == removed || strings.HasPrefix(target, removed+"/")
}

func scanLayerTargets(blob sourceBlob, mediaType string, targets map[string]*layerTarget) error {
	f, err := safeOpenLayoutFile(blob.root, blob.rel)
	if err != nil {
		return err
	}
	defer f.Close()
	var reader io.Reader = f
	var gz *gzip.Reader
	switch mediaType {
	case "application/vnd.oci.image.layer.v1.tar", "application/vnd.oci.image.layer.nondistributable.v1.tar":
	case "application/vnd.oci.image.layer.v1.tar+gzip", "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip", "application/vnd.docker.image.rootfs.diff.tar.gzip":
		gz, err = gzip.NewReader(f)
		if err != nil {
			return fmt.Errorf("open product image gzip layer %s: %w", blob.digest, err)
		}
		defer gz.Close()
		reader = gz
	default:
		return fmt.Errorf("product image layer %s uses unsupported mediaType %q", blob.digest, mediaType)
	}
	tr := tar.NewReader(reader)
	entries := 0
	for {
		hdr, nextErr := tr.Next()
		if nextErr == io.EOF {
			break
		}
		if nextErr != nil {
			return fmt.Errorf("read product image layer %s: %w", blob.digest, nextErr)
		}
		entries++
		if entries > maxProductLayerEntries {
			return fmt.Errorf("product image layer %s exceeds entry limit", blob.digest)
		}
		if hdr.Typeflag == tar.TypeDir && (hdr.Name == "." || hdr.Name == "./") {
			continue
		}
		if hdr.Typeflag == tar.TypeDir && (hdr.Name == "." || hdr.Name == "./") {
			continue
		}
		name, pathErr := canonicalLayerPath(hdr.Name)
		if pathErr != nil {
			return pathErr
		}
		if strings.Contains(pathpkg.Base(name), ".wh.") {
			for _, target := range targets {
				if targetRemovedByWhiteout(target.path, name) {
					target.present = false
					target.regular = false
					target.executable = false
					target.digest = ""
					target.raw = nil
				}
			}
			continue
		}
		target, ok := targets[name]
		if !ok {
			continue
		}
		target.present = true
		target.regular = hdr.Typeflag == tar.TypeReg || hdr.Typeflag == tar.TypeRegA
		target.executable = hdr.FileInfo().Mode().Perm()&0o111 != 0
		target.digest = ""
		target.raw = nil
		if !target.regular {
			continue
		}
		if hdr.Size <= 0 || hdr.Size > maxTotalBytes {
			return fmt.Errorf("product image target %s has invalid size", name)
		}
		h := sha256.New()
		var buffer bytes.Buffer
		writers := []io.Writer{h}
		if target.capture {
			if hdr.Size > 128<<20 {
				return fmt.Errorf("product image target %s exceeds binary inspection limit", name)
			}
			writers = append(writers, &buffer)
		}
		if _, err = io.CopyN(io.MultiWriter(writers...), tr, hdr.Size); err != nil {
			return fmt.Errorf("hash product image target %s: %w", name, err)
		}
		target.digest = "sha256:" + hex.EncodeToString(h.Sum(nil))
		if target.capture {
			target.raw = append(target.raw[:0], buffer.Bytes()...)
		}
	}
	return nil
}

func inspectELF(raw []byte) (string, string, []string, error) {
	file, err := elf.NewFile(bytes.NewReader(raw))
	if err != nil {
		return "", "", nil, fmt.Errorf("product payload is not a valid ELF executable: %w", err)
	}
	defer file.Close()
	needed, err := file.ImportedLibraries()
	if err != nil {
		return "", "", nil, fmt.Errorf("inspect product ELF imports: %w", err)
	}
	sort.Strings(needed)
	interpreter := ""
	for _, program := range file.Progs {
		if program.Type != elf.PT_INTERP {
			continue
		}
		rawInterpreter, readErr := io.ReadAll(program.Open())
		if readErr != nil {
			return "", "", nil, fmt.Errorf("read product ELF interpreter: %w", readErr)
		}
		interpreter = strings.TrimRight(string(rawInterpreter), "\x00")
		break
	}
	linkage := "static"
	if interpreter != "" || len(needed) != 0 {
		linkage = "dynamic"
	}
	return linkage, interpreter, needed, nil
}

func containsAllStrings(actual, required []string) bool {
	set := make(map[string]bool, len(actual))
	for _, value := range actual {
		set[value] = true
	}
	for _, value := range required {
		if !set[value] {
			return false
		}
	}
	return true
}

func CertifyProductImage(source SourceImage, spec ProductImageSpec) (ProductImageCertification, error) {
	var empty ProductImageCertification
	ref := strings.TrimSpace(source.Reference)
	at := strings.LastIndex(ref, "@sha256:")
	if at <= 0 || ref[:at] != strings.TrimSpace(spec.Repository) {
		return empty, fmt.Errorf("product image role %q reference must use repository %q with an exact digest", spec.Role, spec.Repository)
	}
	if strings.TrimSpace(spec.Role) == "" || strings.TrimSpace(spec.ExpectedReleaseDigest) == "" || !digestPattern.MatchString(spec.ExpectedReleaseDigest) {
		return empty, fmt.Errorf("product image certification release identity is invalid")
	}
	root, blobs, err := parseSourceRoot(source)
	if err != nil {
		return empty, err
	}
	if root.MediaType != "application/vnd.oci.image.manifest.v1+json" && root.MediaType != "application/vnd.docker.distribution.manifest.v2+json" {
		return empty, fmt.Errorf("product image role %q must resolve directly to a single linux/amd64 image manifest, got %q", spec.Role, root.MediaType)
	}
	manifestBlob, ok := blobs[root.Digest]
	if !ok {
		return empty, fmt.Errorf("product image root manifest blob is missing")
	}
	manifestRaw, err := sourceBlobBytes(manifestBlob, maxJSONBytes)
	if err != nil {
		return empty, err
	}
	var manifest productManifest
	if err = decodeCanonicalJSON(manifestRaw, &manifest); err != nil || manifest.SchemaVersion != 2 || len(manifest.Layers) == 0 {
		return empty, fmt.Errorf("product image manifest is invalid")
	}
	configBlob, ok := blobs[manifest.Config.Digest]
	if !ok {
		return empty, fmt.Errorf("product image config blob is missing")
	}
	configRaw, err := sourceBlobBytes(configBlob, maxJSONBytes)
	if err != nil {
		return empty, err
	}
	var config productConfig
	if err = decodeCanonicalJSON(configRaw, &config); err != nil {
		return empty, fmt.Errorf("product image config is invalid")
	}
	if config.OS != "linux" || config.Architecture != "amd64" {
		return empty, fmt.Errorf("product image role %q must be linux/amd64, got %s/%s", spec.Role, config.OS, config.Architecture)
	}
	if config.Config.User != spec.ExpectedUser {
		return empty, fmt.Errorf("product image role %q user %q does not match required %q", spec.Role, config.Config.User, spec.ExpectedUser)
	}
	if !equalStrings(config.Config.Entrypoint, spec.ExpectedEntrypoint) {
		return empty, fmt.Errorf("product image role %q entrypoint %v does not match required %v", spec.Role, config.Config.Entrypoint, spec.ExpectedEntrypoint)
	}
	labels := config.Config.Labels
	if labels == nil || labels["platform.4so.io/product-role"] != spec.Role || labels["platform.4so.io/source-release-digest"] != spec.ExpectedReleaseDigest {
		return empty, fmt.Errorf("product image role %q is not labeled with the exact release identity", spec.Role)
	}
	targets := map[string]*layerTarget{}
	binaryPath := strings.TrimPrefix(strings.TrimSpace(spec.BinaryPath), "/")
	if binaryPath != "" {
		if binaryPath != pathpkg.Clean(binaryPath) || strings.HasPrefix(binaryPath, "../") {
			return empty, fmt.Errorf("product image binary path is invalid")
		}
		targets[binaryPath] = &layerTarget{path: binaryPath, capture: true}
	}
	caPath := "etc/ssl/certs/ca-certificates.crt"
	if spec.RequireCABundle {
		targets[caPath] = &layerTarget{path: caPath}
	}
	for _, layer := range manifest.Layers {
		blob, exists := blobs[layer.Digest]
		if !exists {
			return empty, fmt.Errorf("product image layer %s is missing", layer.Digest)
		}
		if err = scanLayerTargets(blob, layer.MediaType, targets); err != nil {
			return empty, err
		}
	}
	binaryDigest := ""
	if binaryPath != "" {
		target := targets[binaryPath]
		if !target.present || !target.regular || !target.executable {
			return empty, fmt.Errorf("product image role %q does not contain executable regular file /%s", spec.Role, binaryPath)
		}
		if target.digest != spec.ExpectedBinaryDigest || !digestPattern.MatchString(spec.ExpectedBinaryDigest) {
			return empty, fmt.Errorf("product image role %q payload digest %s does not match exact release binary digest %s", spec.Role, target.digest, spec.ExpectedBinaryDigest)
		}
		binaryDigest = target.digest
	}
	linkage, interpreter, needed := "", "", []string(nil)
	if binaryPath != "" {
		target := targets[binaryPath]
		linkage, interpreter, needed, err = inspectELF(target.raw)
		if err != nil {
			return empty, err
		}
		if spec.ExpectedLinkage != "" && linkage != spec.ExpectedLinkage {
			return empty, fmt.Errorf("product image role %q linkage %s does not match required %s", spec.Role, linkage, spec.ExpectedLinkage)
		}
		if !containsAllStrings(needed, spec.RequiredNeeded) {
			return empty, fmt.Errorf("product image role %q is missing required dynamic dependencies in DT_NEEDED: required=%v actual=%v", spec.Role, spec.RequiredNeeded, needed)
		}
	}
	caPresent := false
	if spec.RequireCABundle {
		ca := targets[caPath]
		if !ca.present || !ca.regular || ca.digest == "" {
			return empty, fmt.Errorf("product image role %q requires a regular CA trust bundle at /%s", spec.Role, caPath)
		}
		caPresent = true
	}
	entrypoint := append([]string(nil), config.Config.Entrypoint...)
	return ProductImageCertification{
		Authority: ProductImageCertificationAuthority, Role: spec.Role, Reference: ref,
		ReleaseDigest: spec.ExpectedReleaseDigest, BinaryPath: spec.BinaryPath, BinaryDigest: binaryDigest,
		User: config.Config.User, Entrypoint: entrypoint, CABundlePresent: caPresent,
		ExactPayloadBound:  binaryPath == "" || binaryDigest == spec.ExpectedBinaryDigest,
		RuntimeClosurePASS: false, Linkage: linkage, ELFInterpreter: interpreter, NeededLibraries: needed,
	}, nil
}
