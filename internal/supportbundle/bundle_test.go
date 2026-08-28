package supportbundle

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"testing"
	"time"
)

func TestBuildRedactsSecretsAndVerifies(t *testing.T) {
	input := Input{ProductVersion: "0.0.39", Profile: "cluster-diagnostics", GeneratedAt: time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC), Scope: map[string]any{"projectId": "prj-1"}, Files: map[string]any{
		"cluster.json": map[string]any{"token": "pft.tokenid.ABCDEFGHIJKLMNOPQRSTUVWXYZ", "tokenDigest": "sha256:abc", "authorization": "Bearer abcdefghijklmnopqrstuvwxyz", "privateKey": "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----", "fingerprint": "sha256:def"},
	}}
	raw, manifest, err := Build(input)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Redactions < 3 {
		t.Fatalf("expected redactions: %#v", manifest)
	}
	verification, err := Verify(raw)
	if err != nil || !verification.Valid {
		t.Fatalf("verify failed: %#v %v", verification, err)
	}
	if bytes.Contains(raw, []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ")) || bytes.Contains(raw, []byte("BEGIN PRIVATE KEY")) {
		t.Fatal("raw secret leaked into bundle")
	}
}

func TestVerifyRejectsSecretAndUnindexedEntry(t *testing.T) {
	var buffer bytes.Buffer
	zw := zip.NewWriter(&buffer)
	manifest := Manifest{SchemaVersion: SchemaVersion, ProductVersion: "0.0.39", Profile: "fleet", GeneratedAt: time.Now().UTC(), Files: []FileManifest{}}
	manifestRaw, _ := json.Marshal(manifest)
	w, _ := zw.Create("manifest.json")
	_, _ = w.Write(manifestRaw)
	w, _ = zw.Create("README.txt")
	_, _ = w.Write([]byte("ok"))
	w, _ = zw.Create("extra.txt")
	_, _ = io.WriteString(w, "Authorization: Bearer abcdefghijklmnopqrstuvwxyz")
	_ = zw.Close()
	if _, err := Verify(buffer.Bytes()); err == nil {
		t.Fatal("unsafe support bundle accepted")
	}
}

func TestStrictJSONRejectsMultipleValues(t *testing.T) {
	var out Manifest
	if err := strictJSON([]byte(`{"schemaVersion":"support-bundle.v1"} {"schemaVersion":"support-bundle.v1"}`), &out); err == nil {
		t.Fatal("multiple JSON values accepted")
	}
}
