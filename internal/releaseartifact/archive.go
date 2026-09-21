package releaseartifact

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	pathpkg "path"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	InstallerBinaryPath     = "bin/linux-amd64/platform-installer"
	PlatformAPIBinaryPath   = "bin/linux-amd64/platform-api"
	PlatformAgentBinaryPath = "bin/linux-amd64/platform-agent"
	PlatformProbeBinaryPath = "bin/linux-amd64/platform-probe"
	VirtualClusterRendererBinaryPath = "bin/linux-amd64/virtual-cluster-renderer"
)

const maxArtifactManifestBytes = 8 << 20

var releaseNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
var manifestDigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var manifestModePattern = regexp.MustCompile(`^0o[0-7]{3}$`)

const zipCreatorUnix = 3

func canonicalArchivePath(raw string) (string, error) {
	if raw == "" || strings.TrimSpace(raw) != raw || strings.Contains(raw, "\\") || strings.ContainsRune(raw, '\x00') || strings.HasPrefix(raw, "/") || strings.HasSuffix(raw, "/") {
		return "", fmt.Errorf("release artifact path %q is not canonical", raw)
	}
	clean := pathpkg.Clean(raw)
	if clean != raw || clean == "." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("release artifact path %q is not canonical", raw)
	}
	for _, part := range strings.Split(raw, "/") {
		if part == "" || part == "." || part == ".." {
			return "", fmt.Errorf("release artifact path %q is not canonical", raw)
		}
	}
	return clean, nil
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
				keyToken, keyErr := decoder.Token()
				if keyErr != nil {
					return keyErr
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("release artifact manifest object key is invalid")
				}
				if _, exists := seen[key]; exists {
					return fmt.Errorf("release artifact manifest contains duplicate JSON key %q", key)
				}
				seen[key] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			closing, closeErr := decoder.Token()
			if closeErr != nil || closing != json.Delim('}') {
				if closeErr != nil {
					return closeErr
				}
				return errors.New("release artifact manifest object is malformed")
			}
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			closing, closeErr := decoder.Token()
			if closeErr != nil || closing != json.Delim(']') {
				if closeErr != nil {
					return closeErr
				}
				return errors.New("release artifact manifest array is malformed")
			}
		default:
			return errors.New("release artifact manifest contains invalid JSON delimiter")
		}
		return nil
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return errors.New("release artifact manifest contains multiple JSON values")
		}
		return err
	}
	return nil
}

type Inspection struct {
	Path        string            `json:"path"`
	Digest      string            `json:"digest"`
	Version     string            `json:"version"`
	Root        string            `json:"root"`
	FileDigests map[string]string `json:"-"`
}

type artifactManifest struct {
	SchemaVersion int    `json:"schemaVersion"`
	Product       string `json:"product"`
	Version       string `json:"version"`
	ReleaseName   string `json:"releaseName"`
	FileCount     int    `json:"fileCount"`
	Files         []struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
		Size   uint64 `json:"size"`
		Mode   string `json:"mode"`
	} `json:"files"`
}

func (i Inspection) FileDigest(path string) (string, error) {
	clean, err := canonicalArchivePath(path)
	if err != nil {
		return "", errors.New("release artifact file path is invalid")
	}
	digest, ok := i.FileDigests[clean]
	if !ok || len(digest) != 64 {
		return "", fmt.Errorf("release artifact manifest does not contain a valid digest for %s", clean)
	}
	if _, err := hex.DecodeString(digest); err != nil || strings.ToLower(digest) != digest {
		return "", fmt.Errorf("release artifact manifest digest for %s is invalid", clean)
	}
	return "sha256:" + digest, nil
}

func snapshotArtifact(source *os.File) (*os.File, int64, string, error) {
	if source == nil {
		return nil, 0, "", errors.New("release artifact source file is required")
	}
	if _, err := source.Seek(0, io.SeekStart); err != nil {
		return nil, 0, "", fmt.Errorf("rewind release artifact: %w", err)
	}
	snapshot, err := os.CreateTemp("", "4so-platform-factory-release-inspect-*")
	if err != nil {
		return nil, 0, "", fmt.Errorf("create private release artifact snapshot: %w", err)
	}
	name := snapshot.Name()
	cleanup := func(cause error) (*os.File, int64, string, error) {
		_ = snapshot.Close()
		_ = os.Remove(name)
		return nil, 0, "", cause
	}
	if err = snapshot.Chmod(0o600); err != nil {
		return cleanup(fmt.Errorf("secure release artifact snapshot: %w", err))
	}
	// Unlink immediately so the verification snapshot cannot be replaced or
	// modified through a pathname while the source artifact remains mutable.
	if err = os.Remove(name); err != nil {
		return cleanup(fmt.Errorf("unlink private release artifact snapshot: %w", err))
	}
	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(snapshot, hash), source)
	if err != nil {
		return cleanup(fmt.Errorf("snapshot release artifact: %w", err))
	}
	if written <= 0 {
		return cleanup(errors.New("release artifact snapshot is empty"))
	}
	if err = snapshot.Sync(); err != nil {
		return cleanup(fmt.Errorf("sync release artifact snapshot: %w", err))
	}
	if _, err = snapshot.Seek(0, io.SeekStart); err != nil {
		return cleanup(fmt.Errorf("rewind release artifact snapshot: %w", err))
	}
	return snapshot, written, "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func Inspect(path, expectedVersion string) (Inspection, error) {
	var result Inspection
	absolute, err := filepath.Abs(strings.TrimSpace(path))
	if err != nil {
		return result, err
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return result, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 {
		return result, errors.New("release artifact must be a non-empty regular non-symlink file")
	}
	file, err := os.Open(absolute)
	if err != nil {
		return result, err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return result, err
	}
	if !openedInfo.Mode().IsRegular() || openedInfo.Size() <= 0 || !os.SameFile(info, openedInfo) {
		return result, errors.New("release artifact changed while opening or is not a regular file")
	}
	snapshot, snapshotSize, digest, err := snapshotArtifact(file)
	if err != nil {
		return result, err
	}
	defer snapshot.Close()
	if snapshotSize != openedInfo.Size() {
		return result, errors.New("release artifact changed size while snapshotting")
	}

	reader, err := zip.NewReader(snapshot, snapshotSize)
	if err != nil {
		return result, fmt.Errorf("open release artifact zip: %w", err)
	}

	var root string
	var version string
	var releaseName string
	var manifestRaw []byte
	seenArchivePaths := map[string]struct{}{}
	actualDigests := map[string]string{}
	actualSizes := map[string]uint64{}
	actualModes := map[string]string{}

	for _, entry := range reader.File {
		if entry.FileInfo().IsDir() {
			return result, fmt.Errorf("release artifact contains non-canonical directory entry %q", entry.Name)
		}
		if entry.CreatorVersion>>8 != zipCreatorUnix {
			return result, fmt.Errorf("release artifact entry %s must use canonical Unix ZIP metadata", entry.Name)
		}
		clean, pathErr := canonicalArchivePath(entry.Name)
		if pathErr != nil {
			return result, pathErr
		}
		parts := strings.Split(clean, "/")
		if len(parts) < 2 || strings.TrimSpace(parts[0]) == "" {
			return result, fmt.Errorf("release artifact entry %q is outside the release root", entry.Name)
		}
		if root == "" {
			root = parts[0]
		} else if parts[0] != root {
			return result, errors.New("release artifact must contain exactly one top-level root")
		}
		relative := strings.TrimPrefix(clean, root+"/")
		if relative == "" || relative == "." {
			return result, fmt.Errorf("release artifact entry %q has an invalid relative path", entry.Name)
		}
		if _, exists := seenArchivePaths[relative]; exists {
			return result, fmt.Errorf("release artifact duplicates archive path %s", relative)
		}
		seenArchivePaths[relative] = struct{}{}
		if entry.FileInfo().Mode()&os.ModeSymlink != 0 || !entry.FileInfo().Mode().IsRegular() {
			return result, fmt.Errorf("release artifact entry %s must be a regular non-symlink file", relative)
		}

		r, openErr := entry.Open()
		if openErr != nil {
			return result, openErr
		}
		switch relative {
		case "ARTIFACT-MANIFEST.json":
			if entry.UncompressedSize64 > maxArtifactManifestBytes {
				_ = r.Close()
				return result, errors.New("release artifact manifest is oversized")
			}
			raw, readErr := io.ReadAll(io.LimitReader(r, maxArtifactManifestBytes+1))
			closeErr := r.Close()
			if readErr != nil {
				return result, readErr
			}
			if closeErr != nil {
				return result, closeErr
			}
			if len(raw) > maxArtifactManifestBytes {
				return result, errors.New("release artifact manifest is oversized")
			}
			manifestRaw = raw
		case "VERSION":
			if entry.UncompressedSize64 > 128 {
				_ = r.Close()
				return result, errors.New("release artifact VERSION entry is oversized")
			}
			raw, readErr := io.ReadAll(io.LimitReader(r, 129))
			closeErr := r.Close()
			if readErr != nil {
				return result, readErr
			}
			if closeErr != nil {
				return result, closeErr
			}
			if len(raw) > 128 || version != "" {
				return result, errors.New("release artifact VERSION entry is duplicated or oversized")
			}
			version = strings.TrimSpace(string(raw))
			if string(raw) != version+"\n" {
				return result, errors.New("release artifact VERSION is not canonical")
			}
			sum := sha256.Sum256(raw)
			actualDigests[relative] = hex.EncodeToString(sum[:])
			actualSizes[relative] = uint64(len(raw))
			actualModes[relative] = fmt.Sprintf("0o%03o", entry.FileInfo().Mode().Perm())
		case "RELEASE-NAME":
			if entry.UncompressedSize64 > 256 {
				_ = r.Close()
				return result, errors.New("release artifact RELEASE-NAME entry is oversized")
			}
			raw, readErr := io.ReadAll(io.LimitReader(r, 257))
			closeErr := r.Close()
			if readErr != nil {
				return result, readErr
			}
			if closeErr != nil {
				return result, closeErr
			}
			if len(raw) > 256 || releaseName != "" {
				return result, errors.New("release artifact RELEASE-NAME entry is duplicated or oversized")
			}
			releaseName = strings.TrimSpace(string(raw))
			if string(raw) != releaseName+"\n" {
				return result, errors.New("release artifact RELEASE-NAME is not canonical")
			}
			sum := sha256.Sum256(raw)
			actualDigests[relative] = hex.EncodeToString(sum[:])
			actualSizes[relative] = uint64(len(raw))
			actualModes[relative] = fmt.Sprintf("0o%03o", entry.FileInfo().Mode().Perm())
		default:
			h := sha256.New()
			written, copyErr := io.Copy(h, r)
			closeErr := r.Close()
			if copyErr != nil {
				return result, copyErr
			}
			if closeErr != nil {
				return result, closeErr
			}
			if written < 0 || uint64(written) != entry.UncompressedSize64 {
				return result, fmt.Errorf("release artifact entry size changed while reading %s", relative)
			}
			actualDigests[relative] = hex.EncodeToString(h.Sum(nil))
			actualSizes[relative] = uint64(written)
			actualModes[relative] = fmt.Sprintf("0o%03o", entry.FileInfo().Mode().Perm())
		}
	}
	if root == "" || version == "" || releaseName == "" || len(manifestRaw) == 0 {
		return result, errors.New("release artifact must contain VERSION, RELEASE-NAME and ARTIFACT-MANIFEST.json under one root")
	}
	if !releaseNamePattern.MatchString(releaseName) {
		return result, errors.New("release artifact RELEASE-NAME is invalid")
	}
	if strings.TrimSpace(expectedVersion) != "" && expectedVersion != "devel" && version != strings.TrimSpace(expectedVersion) {
		return result, fmt.Errorf("release artifact version %s does not match binary version %s", version, strings.TrimSpace(expectedVersion))
	}

	if err := rejectDuplicateJSONKeys(manifestRaw); err != nil {
		return result, fmt.Errorf("decode release artifact manifest: %w", err)
	}
	var manifest artifactManifest
	decoder := json.NewDecoder(bytes.NewReader(manifestRaw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return result, fmt.Errorf("decode release artifact manifest: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return result, errors.New("release artifact manifest contains multiple JSON values")
		}
		return result, fmt.Errorf("decode release artifact manifest trailer: %w", err)
	}
	if manifest.SchemaVersion != 2 {
		return result, fmt.Errorf("release artifact manifest schemaVersion must be 2, got %d", manifest.SchemaVersion)
	}
	if manifest.Product != "4SO Platform Factory" {
		return result, errors.New("release artifact manifest product identity is invalid")
	}
	if manifest.Version != version {
		return result, errors.New("release artifact manifest version does not match VERSION")
	}
	if manifest.ReleaseName != releaseName {
		return result, errors.New("release artifact manifest releaseName does not match RELEASE-NAME")
	}
	expectedRoot := "4so-platform-factory-" + version + "-" + releaseName
	if root != expectedRoot {
		return result, fmt.Errorf("release artifact root %s does not match canonical identity %s", root, expectedRoot)
	}
	if manifest.FileCount != len(manifest.Files) {
		return result, errors.New("release artifact manifest fileCount does not match files")
	}

	verifiedDigests := map[string]string{}
	for _, item := range manifest.Files {
		cleanPath, pathErr := canonicalArchivePath(item.Path)
		sha := item.SHA256
		if pathErr != nil || cleanPath == "ARTIFACT-MANIFEST.json" || !manifestDigestPattern.MatchString(sha) {
			return result, errors.New("release artifact manifest contains an invalid file record")
		}
		if _, err := hex.DecodeString(sha); err != nil {
			return result, errors.New("release artifact manifest contains an invalid sha256")
		}
		if _, exists := verifiedDigests[cleanPath]; exists {
			return result, fmt.Errorf("release artifact manifest duplicates %s", cleanPath)
		}
		actual, exists := actualDigests[cleanPath]
		if !exists {
			return result, fmt.Errorf("release artifact manifest references missing file %s", cleanPath)
		}
		if actual != sha {
			return result, fmt.Errorf("release artifact content digest mismatch for %s", cleanPath)
		}
		if actualSizes[cleanPath] != item.Size {
			return result, fmt.Errorf("release artifact content size mismatch for %s", cleanPath)
		}
		if !manifestModePattern.MatchString(item.Mode) || actualModes[cleanPath] != item.Mode {
			return result, fmt.Errorf("release artifact content mode mismatch for %s", cleanPath)
		}
		verifiedDigests[cleanPath] = actual
	}
	if len(verifiedDigests) != len(actualDigests) {
		for path := range actualDigests {
			if _, ok := verifiedDigests[path]; !ok {
				return result, fmt.Errorf("release artifact contains unmanifested file %s", path)
			}
		}
		return result, errors.New("release artifact manifest does not cover archive contents")
	}
	return Inspection{Path: absolute, Digest: digest, Version: version, Root: root, FileDigests: verifiedDigests}, nil
}
