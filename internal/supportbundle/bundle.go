package supportbundle

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	"platform.4so.io/factory/internal/redaction"
	"time"
)

const (
	SchemaVersion  = "support-bundle.v1"
	maxBundleBytes = 64 * 1024 * 1024
	maxEntryBytes  = 16 * 1024 * 1024
	maxEntries     = 256
)

type Input struct {
	ProductVersion string         `json:"productVersion"`
	Profile        string         `json:"profile"`
	Scope          map[string]any `json:"scope"`
	GeneratedAt    time.Time      `json:"generatedAt"`
	Files          map[string]any `json:"-"`
}

type FileManifest struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type Manifest struct {
	SchemaVersion  string         `json:"schemaVersion"`
	ProductVersion string         `json:"productVersion"`
	Profile        string         `json:"profile"`
	GeneratedAt    time.Time      `json:"generatedAt"`
	Scope          map[string]any `json:"scope"`
	Files          []FileManifest `json:"files"`
	Redactions     int            `json:"redactions"`
}

type Verification struct {
	Valid      bool   `json:"valid"`
	FileCount  int    `json:"fileCount"`
	Redactions int    `json:"redactions"`
	Digest     string `json:"digest"`
}

func Build(input Input) ([]byte, Manifest, error) {
	if strings.TrimSpace(input.ProductVersion) == "" || strings.TrimSpace(input.Profile) == "" {
		return nil, Manifest{}, fmt.Errorf("product version and profile are required")
	}
	if input.GeneratedAt.IsZero() {
		input.GeneratedAt = time.Now().UTC()
	}
	files := map[string][]byte{}
	redactions := 0
	for name, value := range input.Files {
		cleanName := path.Clean(strings.TrimSpace(name))
		if cleanName == "." || strings.HasPrefix(cleanName, "../") || strings.HasPrefix(cleanName, "/") || !strings.HasSuffix(cleanName, ".json") {
			return nil, Manifest{}, fmt.Errorf("invalid support bundle file %q", name)
		}
		redacted, count := redaction.Value(value)
		redactions += count
		raw, err := json.MarshalIndent(redacted, "", "  ")
		if err != nil {
			return nil, Manifest{}, err
		}
		raw = append(raw, '\n')
		if findings := DetectSecrets(raw); len(findings) != 0 {
			return nil, Manifest{}, fmt.Errorf("redaction failed for %s: %s", cleanName, strings.Join(findings, ","))
		}
		files[cleanName] = raw
	}
	manifest := Manifest{SchemaVersion: SchemaVersion, ProductVersion: input.ProductVersion, Profile: input.Profile, GeneratedAt: input.GeneratedAt.UTC(), Scope: input.Scope, Redactions: redactions}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		raw := files[name]
		sum := sha256.Sum256(raw)
		manifest.Files = append(manifest.Files, FileManifest{Path: name, SHA256: "sha256:" + hex.EncodeToString(sum[:]), Size: int64(len(raw))})
	}
	manifestRaw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, Manifest{}, err
	}
	manifestRaw = append(manifestRaw, '\n')
	files["manifest.json"] = manifestRaw
	readme := []byte("4SO Platform Factory support bundle\nAll data is collected from product authorities and redacted before archive creation.\nRaw secrets, private keys and bearer tokens are forbidden.\n")
	files["README.txt"] = readme

	var buffer bytes.Buffer
	zw := zip.NewWriter(&buffer)
	allNames := make([]string, 0, len(files))
	for name := range files {
		allNames = append(allNames, name)
	}
	sort.Strings(allNames)
	for _, name := range allNames {
		header := &zip.FileHeader{Name: name, Method: zip.Deflate}
		header.SetMode(0o600)
		header.Modified = input.GeneratedAt.UTC()
		writer, err := zw.CreateHeader(header)
		if err != nil {
			return nil, Manifest{}, err
		}
		if _, err = writer.Write(files[name]); err != nil {
			return nil, Manifest{}, err
		}
	}
	if err = zw.Close(); err != nil {
		return nil, Manifest{}, err
	}
	if _, err = Verify(buffer.Bytes()); err != nil {
		return nil, Manifest{}, err
	}
	return buffer.Bytes(), manifest, nil
}

func Verify(raw []byte) (Verification, error) {
	if len(raw) == 0 || len(raw) > maxBundleBytes {
		return Verification{}, fmt.Errorf("support bundle size is invalid")
	}
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return Verification{}, err
	}
	if len(zr.File) > maxEntries {
		return Verification{}, fmt.Errorf("support bundle has too many entries")
	}
	entries := map[string][]byte{}
	var totalUncompressed uint64
	for _, file := range zr.File {
		if file.UncompressedSize64 > maxEntryBytes {
			return Verification{}, fmt.Errorf("support bundle entry %q exceeds size limit", file.Name)
		}
		totalUncompressed += file.UncompressedSize64
		if totalUncompressed > maxBundleBytes {
			return Verification{}, fmt.Errorf("support bundle uncompressed size exceeds limit")
		}
		name := path.Clean(file.Name)
		if name != file.Name || strings.HasPrefix(name, "../") || strings.HasPrefix(name, "/") || file.FileInfo().IsDir() || !file.Mode().IsRegular() {
			return Verification{}, fmt.Errorf("unsafe support bundle entry %q", file.Name)
		}
		if _, exists := entries[name]; exists {
			return Verification{}, fmt.Errorf("duplicate support bundle entry %q", name)
		}
		r, err := file.Open()
		if err != nil {
			return Verification{}, err
		}
		content, err := io.ReadAll(io.LimitReader(r, maxEntryBytes+1))
		_ = r.Close()
		if err != nil {
			return Verification{}, err
		}
		if findings := DetectSecrets(content); len(findings) != 0 {
			return Verification{}, fmt.Errorf("secret-like content in %s: %s", name, strings.Join(findings, ","))
		}
		entries[name] = content
	}
	manifestRaw, ok := entries["manifest.json"]
	if !ok {
		return Verification{}, fmt.Errorf("manifest.json is missing")
	}
	var manifest Manifest
	if err = strictJSON(manifestRaw, &manifest); err != nil {
		return Verification{}, fmt.Errorf("invalid manifest: %w", err)
	}
	if manifest.SchemaVersion != SchemaVersion {
		return Verification{}, fmt.Errorf("unsupported schema version %q", manifest.SchemaVersion)
	}
	seen := map[string]bool{}
	for _, file := range manifest.Files {
		if file.Path == "manifest.json" || file.Path == "README.txt" || seen[file.Path] {
			return Verification{}, fmt.Errorf("invalid manifest file path %q", file.Path)
		}
		seen[file.Path] = true
		content, ok := entries[file.Path]
		if !ok {
			return Verification{}, fmt.Errorf("manifest file %q is missing", file.Path)
		}
		if int64(len(content)) != file.Size {
			return Verification{}, fmt.Errorf("size mismatch for %s", file.Path)
		}
		sum := sha256.Sum256(content)
		if file.SHA256 != "sha256:"+hex.EncodeToString(sum[:]) {
			return Verification{}, fmt.Errorf("digest mismatch for %s", file.Path)
		}
	}
	if len(entries) != len(manifest.Files)+2 {
		return Verification{}, fmt.Errorf("unindexed support bundle entry detected")
	}
	sum := sha256.Sum256(raw)
	return Verification{Valid: true, FileCount: len(entries), Redactions: manifest.Redactions, Digest: "sha256:" + hex.EncodeToString(sum[:])}, nil
}

func DetectSecrets(raw []byte) []string { return redaction.Detect(raw) }

func strictJSON(raw []byte, out any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return err
	}
	return nil
}
