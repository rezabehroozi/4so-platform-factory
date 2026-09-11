package releaseartifact

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testSHA(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func writeArchiveWithOptions(t *testing.T, version string, files map[string][]byte, manifestDigests map[string]string, manifestModes map[string]string, duplicate string, creatorSystem uint16) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "release.zip")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(file)
	root := "4so-platform-factory-" + version + "-test/"
	versionRaw := []byte(version + "\n")
	releaseNameRaw := []byte("test\n")
	all := map[string][]byte{"VERSION": versionRaw, "RELEASE-NAME": releaseNameRaw}
	for name, body := range files {
		all[name] = body
	}
	rows := make([]map[string]any, 0, len(all))
	for name, body := range all {
		digest := testSHA(body)
		if override, ok := manifestDigests[name]; ok {
			digest = override
		}
		mode := "0o644"
		if creatorSystem != zipCreatorUnix {
			mode = "0o666"
		}
		if override, ok := manifestModes[name]; ok {
			mode = override
		}
		rows = append(rows, map[string]any{"path": name, "sha256": digest, "size": len(body), "mode": mode})
	}
	manifest, err := json.Marshal(map[string]any{
		"schemaVersion": 2,
		"product":       "4SO Platform Factory",
		"version":       version,
		"releaseName":   "test",
		"fileCount":     len(rows),
		"files":         rows,
	})
	if err != nil {
		t.Fatal(err)
	}
	allWithManifest := map[string][]byte{"ARTIFACT-MANIFEST.json": manifest}
	for name, body := range all {
		allWithManifest[name] = body
	}
	for name, body := range allWithManifest {
		header := &zip.FileHeader{Name: root + name, Method: zip.Deflate}
		header.SetMode(0o644)
		header.CreatorVersion = header.CreatorVersion&0xff | creatorSystem<<8
		entry, createErr := writer.CreateHeader(header)
		if createErr != nil {
			t.Fatal(createErr)
		}
		if _, createErr = entry.Write(body); createErr != nil {
			t.Fatal(createErr)
		}
		if duplicate == name {
			dupHeader := &zip.FileHeader{Name: root + name, Method: zip.Deflate}
			dupHeader.SetMode(0o644)
			dupHeader.CreatorVersion = dupHeader.CreatorVersion&0xff | creatorSystem<<8
			entry, createErr = writer.CreateHeader(dupHeader)
			if createErr != nil {
				t.Fatal(createErr)
			}
			if _, createErr = entry.Write(body); createErr != nil {
				t.Fatal(createErr)
			}
		}
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeArchive(t *testing.T, version string, files map[string][]byte, manifestDigests map[string]string, duplicate string) string {
	t.Helper()
	return writeArchiveWithOptions(t, version, files, manifestDigests, nil, duplicate, zipCreatorUnix)
}

func makeArchive(t *testing.T, version string) string {
	t.Helper()
	return writeArchive(t, version, nil, nil, "")
}

func TestInspectBindsExactArchiveAndVersion(t *testing.T) {
	path := makeArchive(t, "0.0.124")
	first, err := Inspect(path, "0.0.124")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(first.Digest, "sha256:") || first.Version != "0.0.124" {
		t.Fatalf("unexpected inspection %#v", first)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = file.Write([]byte("tamper"))
	_ = file.Close()
	second, err := Inspect(path, "0.0.124")
	if err == nil && second.Digest == first.Digest {
		t.Fatal("tampered archive retained exact digest")
	}
}

func TestInspectRejectsWrongVersion(t *testing.T) {
	if _, err := Inspect(makeArchive(t, "0.0.123"), "0.0.124"); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("unexpected error %v", err)
	}
}

func TestInspectExposesVerifiedInstallerBinaryDigest(t *testing.T) {
	body := []byte("installer-binary")
	path := writeArchive(t, "0.0.126", map[string][]byte{InstallerBinaryPath: body}, nil, "")
	inspection, err := Inspect(path, "0.0.126")
	if err != nil {
		t.Fatal(err)
	}
	digest, err := inspection.FileDigest(InstallerBinaryPath)
	if err != nil {
		t.Fatal(err)
	}
	if digest != "sha256:"+testSHA(body) {
		t.Fatalf("digest=%s", digest)
	}
}

func TestInspectRejectsManifestDigestThatDoesNotMatchArchiveBytes(t *testing.T) {
	body := []byte("actual-installer")
	forged := strings.Repeat("a", 64)
	path := writeArchive(t, "0.0.126", map[string][]byte{InstallerBinaryPath: body}, map[string]string{InstallerBinaryPath: forged}, "")
	if _, err := Inspect(path, "0.0.126"); err == nil || !strings.Contains(err.Error(), "content digest mismatch") {
		t.Fatalf("expected forged manifest digest rejection, got %v", err)
	}
}

func TestInspectRejectsDuplicateArchivePath(t *testing.T) {
	path := writeArchive(t, "0.0.126", map[string][]byte{InstallerBinaryPath: []byte("installer")}, nil, InstallerBinaryPath)
	if _, err := Inspect(path, "0.0.126"); err == nil || !strings.Contains(err.Error(), "duplicates archive path") {
		t.Fatalf("expected duplicate path rejection, got %v", err)
	}
}

func TestInspectRejectsWhitespacePaddedManifestDigest(t *testing.T) {
	body := []byte("installer")
	padded := " " + testSHA(body) + " "
	path := writeArchive(t, "0.0.130", map[string][]byte{InstallerBinaryPath: body}, map[string]string{InstallerBinaryPath: padded}, "")
	if _, err := Inspect(path, "0.0.130"); err == nil || !strings.Contains(err.Error(), "invalid file record") {
		t.Fatalf("expected non-canonical sha256 rejection, got %v", err)
	}
}

func TestInspectRejectsWhitespacePaddedManifestMode(t *testing.T) {
	path := writeArchiveWithOptions(t, "0.0.130", nil, nil, map[string]string{"VERSION": " 0o644 "}, "", zipCreatorUnix)
	if _, err := Inspect(path, "0.0.130"); err == nil || !strings.Contains(err.Error(), "mode mismatch") {
		t.Fatalf("expected non-canonical mode rejection, got %v", err)
	}
}

func TestInspectRejectsNonUnixZipCreatorMetadata(t *testing.T) {
	path := writeArchiveWithOptions(t, "0.0.130", nil, nil, nil, "", 0)
	if _, err := Inspect(path, "0.0.130"); err == nil || !strings.Contains(err.Error(), "canonical Unix ZIP metadata") {
		t.Fatalf("expected non-Unix ZIP metadata rejection, got %v", err)
	}
}

func TestArtifactSnapshotRemainsBoundAfterInPlaceSourceMutation(t *testing.T) {
	path := makeArchive(t, "0.0.127")
	source, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, size, digest, err := snapshotArtifact(source)
	_ = source.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	if size <= 0 || !strings.HasPrefix(digest, "sha256:") {
		t.Fatalf("invalid snapshot metadata size=%d digest=%q", size, digest)
	}

	before := make([]byte, size)
	if _, err = snapshot.ReadAt(before, 0); err != nil && err.Error() != "EOF" {
		t.Fatal(err)
	}

	mutated := append([]byte(nil), before...)
	if len(mutated) < 32 {
		t.Fatal("fixture archive unexpectedly small")
	}
	mutated[16] ^= 0xff
	if err = os.WriteFile(path, mutated, 0o600); err != nil {
		t.Fatal(err)
	}

	after := make([]byte, size)
	if _, err = snapshot.ReadAt(after, 0); err != nil && err.Error() != "EOF" {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("private release snapshot changed after in-place mutation of source artifact")
	}
	sum := sha256.Sum256(after)
	if digest != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatal("snapshot digest is not bound to the bytes used for inspection")
	}
}

func TestInspectRejectsMissingReleaseName(t *testing.T) {
	path := filepath.Join(t.TempDir(), "release.zip")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(file)
	version := "0.0.129"
	versionRaw := []byte(version + "\n")
	manifestRaw, err := json.Marshal(map[string]any{
		"schemaVersion": 2, "product": "4SO Platform Factory", "version": version, "releaseName": "test",
		"fileCount": 1, "files": []map[string]any{{"path": "VERSION", "sha256": testSHA(versionRaw), "size": len(versionRaw), "mode": "0o644"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string][]byte{
		"4so-platform-factory-0.0.129-test/VERSION":                versionRaw,
		"4so-platform-factory-0.0.129-test/ARTIFACT-MANIFEST.json": manifestRaw,
	} {
		h := &zip.FileHeader{Name: name, Method: zip.Deflate}
		h.SetMode(0o644)
		w, createErr := zw.CreateHeader(h)
		if createErr != nil {
			t.Fatal(createErr)
		}
		if _, writeErr := w.Write(body); writeErr != nil {
			t.Fatal(writeErr)
		}
	}
	if err = zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = Inspect(path, version); err == nil || !strings.Contains(err.Error(), "RELEASE-NAME") {
		t.Fatalf("expected missing RELEASE-NAME rejection, got %v", err)
	}
}

func TestInspectRejectsManifestReleaseNameMismatch(t *testing.T) {
	path := makeArchive(t, "0.0.129")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := zip.NewReader(strings.NewReader(string(raw)), int64(len(raw)))
	_ = reader
	if err != nil {
		t.Fatal(err)
	}
	// Rebuild the otherwise valid archive with only the self-claimed manifest releaseName changed.
	out := filepath.Join(t.TempDir(), "forged.zip")
	of, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(of)
	for _, entry := range reader.File {
		r, openErr := entry.Open()
		if openErr != nil {
			t.Fatal(openErr)
		}
		body, readErr := io.ReadAll(r)
		_ = r.Close()
		if readErr != nil {
			t.Fatal(readErr)
		}
		if strings.HasSuffix(entry.Name, "/ARTIFACT-MANIFEST.json") {
			var doc map[string]any
			if err = json.Unmarshal(body, &doc); err != nil {
				t.Fatal(err)
			}
			doc["releaseName"] = "forged"
			body, err = json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
		}
		h := &zip.FileHeader{Name: entry.Name, Method: zip.Deflate}
		h.SetMode(entry.Mode())
		w, createErr := zw.CreateHeader(h)
		if createErr != nil {
			t.Fatal(createErr)
		}
		if _, writeErr := w.Write(body); writeErr != nil {
			t.Fatal(writeErr)
		}
	}
	if err = zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err = of.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = Inspect(out, "0.0.129"); err == nil || !strings.Contains(err.Error(), "does not match RELEASE-NAME") {
		t.Fatalf("expected forged releaseName rejection, got %v", err)
	}
}

func TestInspectRejectsNonCanonicalArchivePath(t *testing.T) {
	path := makeArchive(t, "0.0.129")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := zip.NewReader(strings.NewReader(string(raw)), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "noncanonical.zip")
	of, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(of)
	for _, entry := range reader.File {
		r, openErr := entry.Open()
		if openErr != nil {
			t.Fatal(openErr)
		}
		body, readErr := io.ReadAll(r)
		_ = r.Close()
		if readErr != nil {
			t.Fatal(readErr)
		}
		name := entry.Name
		if strings.HasSuffix(name, "/VERSION") {
			name = strings.TrimSuffix(name, "/VERSION") + "/meta/../VERSION"
		}
		h := &zip.FileHeader{Name: name, Method: zip.Deflate}
		h.SetMode(entry.Mode())
		w, createErr := zw.CreateHeader(h)
		if createErr != nil {
			t.Fatal(createErr)
		}
		if _, writeErr := w.Write(body); writeErr != nil {
			t.Fatal(writeErr)
		}
	}
	if err = zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err = of.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = Inspect(out, "0.0.129"); err == nil || !strings.Contains(err.Error(), "not canonical") {
		t.Fatalf("expected non-canonical path rejection, got %v", err)
	}
}

func TestInspectRejectsDuplicateManifestJSONKey(t *testing.T) {
	path := makeArchive(t, "0.0.129")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := zip.NewReader(strings.NewReader(string(raw)), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "duplicate-json-key.zip")
	of, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(of)
	for _, entry := range reader.File {
		r, openErr := entry.Open()
		if openErr != nil {
			t.Fatal(openErr)
		}
		body, readErr := io.ReadAll(r)
		_ = r.Close()
		if readErr != nil {
			t.Fatal(readErr)
		}
		if strings.HasSuffix(entry.Name, "/ARTIFACT-MANIFEST.json") {
			before := `"releaseName":"test"`
			after := `"releaseName":"forged","releaseName":"test"`
			if !strings.Contains(string(body), before) {
				t.Fatalf("fixture manifest encoding changed: %s", body)
			}
			body = []byte(strings.Replace(string(body), before, after, 1))
		}
		h := &zip.FileHeader{Name: entry.Name, Method: zip.Deflate}
		h.SetMode(entry.Mode())
		w, createErr := zw.CreateHeader(h)
		if createErr != nil {
			t.Fatal(createErr)
		}
		if _, writeErr := w.Write(body); writeErr != nil {
			t.Fatal(writeErr)
		}
	}
	if err = zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err = of.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = Inspect(out, "0.0.129"); err == nil || !strings.Contains(err.Error(), "duplicate JSON key") {
		t.Fatalf("expected duplicate JSON key rejection, got %v", err)
	}
}

func TestRequireRunningExecutableBindsActualExecutableBytes(t *testing.T) {
	actual, err := RunningExecutableDigest()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(actual, "sha256:") || len(actual) != len("sha256:")+64 {
		t.Fatalf("unexpected running executable digest %q", actual)
	}
	inspection := Inspection{FileDigests: map[string]string{PlatformctlBinaryPath: strings.TrimPrefix(actual, "sha256:")}}
	bound, err := inspection.RequireRunningExecutable(PlatformctlBinaryPath)
	if err != nil {
		t.Fatal(err)
	}
	if bound != actual {
		t.Fatalf("bound digest %q != actual %q", bound, actual)
	}
	inspection.FileDigests[PlatformctlBinaryPath] = strings.Repeat("0", 64)
	if _, err := inspection.RequireRunningExecutable(PlatformctlBinaryPath); err == nil || !strings.Contains(err.Error(), "does not match exact release") {
		t.Fatalf("expected running executable mismatch, err=%v", err)
	}
}
