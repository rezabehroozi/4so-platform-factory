package managedinstall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func stagedISO(t *testing.T, root string, payload []byte) Artifact {
	t.Helper()
	sum := sha256.Sum256(payload)
	digest := hex.EncodeToString(sum[:])
	dir := filepath.Join(root, "sha256", digest)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "agent.iso"), payload, 0o644); err != nil {
		t.Fatal(err)
	}
	return Artifact{Name: "agent-iso", Version: "4.19.0", URL: "https://untrusted.example.test/agent.iso", SHA256: "sha256:" + digest}
}

func TestMediaStoreServesOnlySignedDigestVerifiedAgentISO(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	artifact := stagedISO(t, root, []byte("agent-iso-exact-bytes"))
	now := time.Date(2026, 9, 9, 6, 0, 0, 0, time.UTC)
	store := &MediaStore{Root: root, PublicBase: "https://factory.example.test", SigningKey: []byte(strings.Repeat("k", 32)), TTL: time.Hour, Now: func() time.Time { return now }}
	req := testRequest()
	u, err := store.ResolveAgentISOMediaURL(context.Background(), req, artifact, "op-1:ATTACH_MEDIA")
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := url.Parse(u)
	r := httptest.NewRequest(http.MethodGet, parsed.RequestURI(), nil)
	w := httptest.NewRecorder()
	store.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK || w.Body.String() != "agent-iso-exact-bytes" {
		t.Fatalf("status=%d body=%q", w.Code, w.Body.String())
	}
	parsed.RawQuery = strings.Replace(parsed.RawQuery, "sig=", "sig=00", 1)
	w = httptest.NewRecorder()
	store.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, parsed.RequestURI(), nil))
	if w.Code != http.StatusForbidden {
		t.Fatalf("tampered signature status=%d", w.Code)
	}
}

func TestMediaStoreRejectsSwappedContentAfterURLIssuance(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	artifact := stagedISO(t, root, []byte("original"))
	now := time.Date(2026, 9, 9, 6, 0, 0, 0, time.UTC)
	store := &MediaStore{Root: root, PublicBase: "https://factory.example.test", SigningKey: []byte(strings.Repeat("s", 32)), Now: func() time.Time { return now }}
	u, err := store.ResolveAgentISOMediaURL(context.Background(), testRequest(), artifact, "op-2")
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := normalizeDigest(artifact.SHA256)
	if err := os.WriteFile(mediaPath(root, digest), []byte("swapped"), 0o644); err != nil {
		t.Fatal(err)
	}
	parsed, _ := url.Parse(u)
	w := httptest.NewRecorder()
	store.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, parsed.RequestURI(), nil))
	if w.Code != http.StatusConflict {
		body, _ := io.ReadAll(w.Result().Body)
		t.Fatalf("status=%d body=%q", w.Code, string(body))
	}
}
