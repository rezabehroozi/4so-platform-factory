package registryacquire

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"platform.4so.io/factory/internal/ociarchive"
	"strings"
	"testing"
	"time"
)

func tdigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func registryFixture(t *testing.T, mutate func(*fixtureRegistry)) (*httptest.Server, Spec, []byte, []byte) {
	t.Helper()
	config := []byte(`{"architecture":"amd64","os":"linux","config":{"User":"65532:65532"}}`)
	layer := []byte("fixture-layer")
	cfgD, layerD := tdigest(config), tdigest(layer)
	manifestDoc := map[string]any{"schemaVersion": 2, "mediaType": mediaOCIManifest, "config": map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": cfgD, "size": len(config)}, "layers": []any{map[string]any{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": layerD, "size": len(layer)}}}
	manifest, _ := json.Marshal(manifestDoc)
	manifestD := tdigest(manifest)
	armManifest := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":1},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","size":1}]}`)
	armD := tdigest(armManifest)
	indexDoc := map[string]any{"schemaVersion": 2, "mediaType": mediaOCIIndex, "annotations": map[string]string{"org.opencontainers.image.version": "1.2.3"}, "manifests": []any{
		map[string]any{"mediaType": mediaOCIManifest, "digest": manifestD, "size": len(manifest), "annotations": map[string]string{"org.opencontainers.image.ref.name": "v1.2.3-amd64"}, "platform": map[string]string{"os": "linux", "architecture": "amd64"}},
		map[string]any{"mediaType": mediaOCIManifest, "digest": armD, "size": len(armManifest), "platform": map[string]string{"os": "linux", "architecture": "arm64"}},
	}}
	index, _ := json.Marshal(indexDoc)
	fr := &fixtureRegistry{tag: "v1.2.3", repo: "team/app", config: config, layer: layer, manifest: manifest, index: index, manifestDigest: manifestD, indexDigest: tdigest(index), configDigest: cfgD, layerDigest: layerD}
	if mutate != nil {
		mutate(fr)
	}
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fr.serve(server.URL, w, r) }))
	u, _ := url.Parse(server.URL)
	spec := Spec{Role: "fixture", SourceRepository: "registry.example/team/app", RegistryEndpoint: u.Host, RegistryRepo: "team/app", SelectedVersion: "1.2.3", Tag: "v1.2.3", SelectionChannel: "fixture-stable", SelectionEvidenceURL: "https://example.test/releases/1.2.3", ReleaseArtifactDigest: "sha256:" + strings.Repeat("a", 64), PlanDigest: "sha256:" + strings.Repeat("b", 64), OS: "linux", Architecture: "amd64"}
	return server, spec, manifest, index
}

type fixtureRegistry struct {
	tag, repo                                              string
	config, layer, manifest, index                         []byte
	manifestDigest, indexDigest, configDigest, layerDigest string
	wrongBlob                                              bool
	duplicatePlatform                                      bool
	wrongScope                                             bool
}

func (f *fixtureRegistry) serve(base string, w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/token" {
		if r.URL.Query().Get("scope") != "repository:"+f.repo+":pull" {
			http.Error(w, "scope", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"token":"fixture-token","expires_in":300,"issued_at":"2026-08-31T00:00:00Z"}`)
		return
	}
	if r.Header.Get("Authorization") != "Bearer fixture-token" {
		scope := "repository:" + f.repo + ":pull"
		if f.wrongScope {
			scope = "repository:other/repo:pull"
		}
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s/token",service="fixture",scope="%s"`, base, scope))
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	prefix := "/v2/" + f.repo + "/"
	switch {
	case r.Method == http.MethodGet && r.URL.Path == prefix+"manifests/"+f.tag:
		raw := f.index
		if f.duplicatePlatform {
			var doc map[string]any
			_ = json.Unmarshal(raw, &doc)
			rows := doc["manifests"].([]any)
			rows = append(rows, rows[0])
			doc["manifests"] = rows
			raw, _ = json.Marshal(doc)
		}
		w.Header().Set("Content-Type", mediaOCIIndex)
		w.Header().Set("Docker-Content-Digest", tdigest(raw))
		_, _ = w.Write(raw)
	case r.Method == http.MethodGet && r.URL.Path == prefix+"manifests/"+f.manifestDigest:
		w.Header().Set("Content-Type", mediaOCIManifest)
		w.Header().Set("Docker-Content-Digest", f.manifestDigest)
		_, _ = w.Write(f.manifest)
	case r.Method == http.MethodGet && r.URL.Path == prefix+"blobs/"+f.configDigest:
		_, _ = w.Write(f.config)
	case r.Method == http.MethodGet && r.URL.Path == prefix+"blobs/"+f.layerDigest:
		if f.wrongBlob {
			_, _ = w.Write([]byte("tampered-layer"))
		} else {
			_, _ = w.Write(f.layer)
		}
	default:
		http.NotFound(w, r)
	}
}

func TestPublicClientUsesBoundedOperationDeadlineInsteadOfWholeBodyTimeout(t *testing.T) {
	client := NewPublicClient()
	if client.HTTP.Timeout != 0 {
		t.Fatalf("public client whole-response timeout=%s; large OCI blobs must be bounded by operation context instead", client.HTTP.Timeout)
	}
	transport, ok := client.HTTP.Transport.(*http.Transport)
	if !ok || transport.ResponseHeaderTimeout <= 0 || transport.TLSHandshakeTimeout <= 0 {
		t.Fatalf("public transport header/TLS timeouts are not bounded: %#v", client.HTTP.Transport)
	}

	var remaining time.Duration
	probe := NewTestClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		deadline, ok := req.Context().Deadline()
		if !ok {
			return nil, fmt.Errorf("request context has no acquisition deadline")
		}
		remaining = time.Until(deadline)
		return nil, fmt.Errorf("probe stop")
	})})
	spec := Spec{Role: "fixture", SourceRepository: "registry.example/team/app", RegistryEndpoint: "registry.example", RegistryRepo: "team/app", SelectedVersion: "1.2.3", Tag: "v1.2.3", SelectionChannel: "fixture-stable", SelectionEvidenceURL: "https://example.test/releases/1.2.3", ReleaseArtifactDigest: "sha256:" + strings.Repeat("a", 64), PlanDigest: "sha256:" + strings.Repeat("b", 64), OS: "linux", Architecture: "amd64"}
	_, err := probe.Acquire(context.Background(), spec, filepath.Join(t.TempDir(), "layout"), filepath.Join(t.TempDir(), "lock.json"))
	if err == nil || remaining <= 0 || remaining > 30*time.Minute || remaining < 29*time.Minute {
		t.Fatalf("acquisition deadline remaining=%s err=%v", remaining, err)
	}
}
func TestAcquireBearerIndexPlatformAndBlobIntegrity(t *testing.T) {
	srv, spec, manifest, index := registryFixture(t, nil)
	defer srv.Close()
	client := NewTestClient(srv.Client())
	out := filepath.Join(t.TempDir(), "layout")
	lock := filepath.Join(t.TempDir(), "lock.json")
	got, err := client.Acquire(context.Background(), spec, out, lock)
	if err != nil {
		t.Fatal(err)
	}
	if got.Authority != Authority || got.TagRootDigest != tdigest(index) || got.ManifestDigest != tdigest(manifest) || got.ExactReference != "registry.example/team/app@"+tdigest(manifest) {
		t.Fatalf("unexpected result %+v", got)
	}
	if got.SchemaVersion != 2 || got.TagRootBytes != int64(len(index)) {
		t.Fatalf("unexpected V2 tag-root evidence %+v", got)
	}
	for _, p := range []string{"oci-layout", "index.json", filepath.Join("blobs", "sha256", strings.TrimPrefix(got.TagRootDigest, "sha256:")), filepath.Join("blobs", "sha256", strings.TrimPrefix(got.ManifestDigest, "sha256:")), filepath.Join("blobs", "sha256", strings.TrimPrefix(got.Config.Digest, "sha256:")), filepath.Join("blobs", "sha256", strings.TrimPrefix(got.Layers[0].Digest, "sha256:"))} {
		if _, err := os.Stat(filepath.Join(out, p)); err != nil {
			t.Fatalf("missing %s: %v", p, err)
		}
	}
	raw, err := os.ReadFile(lock)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), got.ExactReference) {
		t.Fatal("lock missing exact reference")
	}
	verified, err := VerifyOffline(spec, out, lock)
	if err != nil {
		t.Fatalf("offline verification failed: %v", err)
	}
	if verified.ManifestDigest != got.ManifestDigest || verified.TagRootDigest != got.TagRootDigest {
		t.Fatalf("offline verification drift: %+v", verified)
	}
}

func TestVerifyOfflineRejectsMissingOrTamperedTagRootEvidence(t *testing.T) {
	srv, spec, _, _ := registryFixture(t, nil)
	defer srv.Close()
	layout := filepath.Join(t.TempDir(), "layout")
	lock := filepath.Join(t.TempDir(), "lock.json")
	got, err := NewTestClient(srv.Client()).Acquire(context.Background(), spec, layout, lock)
	if err != nil {
		t.Fatal(err)
	}
	rootPath := filepath.Join(layout, "blobs", "sha256", strings.TrimPrefix(got.TagRootDigest, "sha256:"))
	if err := os.WriteFile(rootPath, []byte("tampered-tag-root"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err = VerifyOffline(spec, layout, lock); err == nil || !strings.Contains(err.Error(), "tag-root") {
		t.Fatalf("expected tag-root evidence rejection, got %v", err)
	}
}

func TestVerifyOfflineRejectsUnownedLayoutFile(t *testing.T) {
	srv, spec, _, _ := registryFixture(t, nil)
	defer srv.Close()
	layout := filepath.Join(t.TempDir(), "layout")
	lock := filepath.Join(t.TempDir(), "lock.json")
	if _, err := NewTestClient(srv.Client()).Acquire(context.Background(), spec, layout, lock); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(layout, "unexpected.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyOffline(spec, layout, lock); err == nil || !strings.Contains(err.Error(), "unowned file") {
		t.Fatalf("expected unowned layout rejection, got %v", err)
	}
}

func TestAcquireRejectsMutableLatestTag(t *testing.T) {
	srv, spec, _, _ := registryFixture(t, nil)
	defer srv.Close()
	spec.Tag = "latest"
	_, err := NewTestClient(srv.Client()).Acquire(context.Background(), spec, filepath.Join(t.TempDir(), "layout"), filepath.Join(t.TempDir(), "lock.json"))
	if err == nil || !strings.Contains(err.Error(), "tag") {
		t.Fatalf("expected tag rejection, got %v", err)
	}
}
func TestAcquireRejectsAmbiguousPlatformIndex(t *testing.T) {
	srv, spec, _, _ := registryFixture(t, func(f *fixtureRegistry) { f.duplicatePlatform = true })
	defer srv.Close()
	_, err := NewTestClient(srv.Client()).Acquire(context.Background(), spec, filepath.Join(t.TempDir(), "layout"), filepath.Join(t.TempDir(), "lock.json"))
	if err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("expected ambiguous platform rejection, got %v", err)
	}
}
func TestAcquireRejectsBlobDigestMismatch(t *testing.T) {
	srv, spec, _, _ := registryFixture(t, func(f *fixtureRegistry) { f.wrongBlob = true })
	defer srv.Close()
	_, err := NewTestClient(srv.Client()).Acquire(context.Background(), spec, filepath.Join(t.TempDir(), "layout"), filepath.Join(t.TempDir(), "lock.json"))
	if err == nil || (!strings.Contains(err.Error(), "size") && !strings.Contains(err.Error(), "digest")) {
		t.Fatalf("expected blob integrity rejection, got %v", err)
	}
}
func TestAcquireRejectsBearerScopeConfusion(t *testing.T) {
	srv, spec, _, _ := registryFixture(t, func(f *fixtureRegistry) { f.wrongScope = true })
	defer srv.Close()
	_, err := NewTestClient(srv.Client()).Acquire(context.Background(), spec, filepath.Join(t.TempDir(), "layout"), filepath.Join(t.TempDir(), "lock.json"))
	if err == nil || !strings.Contains(err.Error(), "scope") {
		t.Fatalf("expected scope rejection, got %v", err)
	}
}

func TestAcquireRejectsResponseDocumentMediaTypeMismatch(t *testing.T) {
	srv, spec, _, _ := registryFixture(t, nil)
	defer srv.Close()
	base := srv.Client()
	orig := base.Transport
	base.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		resp, err := orig.RoundTrip(req)
		if err == nil && strings.Contains(req.URL.Path, "/manifests/v1.2.3") && resp.StatusCode == http.StatusOK {
			resp.Header.Set("Content-Type", mediaDockerList)
		}
		return resp, err
	})
	_, err := NewTestClient(base).Acquire(context.Background(), spec, filepath.Join(t.TempDir(), "layout"), filepath.Join(t.TempDir(), "lock.json"))
	if err == nil || !strings.Contains(err.Error(), "does not match document") {
		t.Fatalf("expected media-type mismatch rejection, got %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestParsePlanExternalV5(t *testing.T) {
	raw := []byte(`{"authority":"MANAGEMENT_WORKLOAD_IMAGE_BUILD_PLAN_V5","schemaVersion":5,"releaseVersion":"0.0.272","targetPlatform":{"os":"linux","architecture":"amd64"},"coreImages":[{"role":"postgresql","ownership":"external","repository":"docker.io/library/postgres","registryEndpoint":"registry-1.docker.io","registryRepository":"library/postgres","version":"17.11","tag":"17.11-bookworm","selectionChannel":"postgresql-17-patch","selectionEvidenceURL":"https://www.postgresql.org/docs/17/release-17-11.html","state":"pending","blocker":"EXACT_DIGEST_AND_RUNTIME_COMPATIBILITY_PENDING"}]}`)
	spec, err := ParsePlanExternal(raw, "postgresql", "0.0.272")
	if err != nil {
		t.Fatal(err)
	}
	if spec.RegistryEndpoint != "registry-1.docker.io" || spec.Tag != "17.11-bookworm" {
		t.Fatalf("bad spec %+v", spec)
	}
}

func TestAcquireRejectsDuplicateManifestJSONKey(t *testing.T) {
	srv, spec, _, _ := registryFixture(t, nil)
	defer srv.Close()
	base := srv.Client()
	orig := base.Transport
	base.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		resp, err := orig.RoundTrip(req)
		if err != nil || resp.StatusCode != http.StatusOK || !strings.Contains(req.URL.Path, "/manifests/") {
			return resp, err
		}
		raw, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil {
			return nil, readErr
		}
		// Duplicate a top-level schemaVersion key while preserving valid JSON.
		tampered := append([]byte(`{"schemaVersion":2,`), raw[1:]...)
		resp.Body = io.NopCloser(bytes.NewReader(tampered))
		resp.ContentLength = int64(len(tampered))
		resp.Header.Set("Docker-Content-Digest", tdigest(tampered))
		return resp, nil
	})
	_, err := NewTestClient(base).Acquire(context.Background(), spec, filepath.Join(t.TempDir(), "layout"), filepath.Join(t.TempDir(), "lock.json"))
	if err == nil || !strings.Contains(err.Error(), "duplicate JSON key") {
		t.Fatalf("expected duplicate JSON key rejection, got %v", err)
	}
}

func TestAcquiredLayoutAssemblesAndInspects(t *testing.T) {
	srv, spec, _, _ := registryFixture(t, nil)
	defer srv.Close()
	layout := filepath.Join(t.TempDir(), "layout")
	lock := filepath.Join(t.TempDir(), "lock.json")
	got, err := NewTestClient(srv.Client()).Acquire(context.Background(), spec, layout, lock)
	if err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(t.TempDir(), "management-workloads.oci.tar")
	assembled, err := ociarchive.AssembleToFile([]ociarchive.SourceImage{{Reference: got.ExactReference, LayoutDir: layout}}, archivePath)
	if err != nil {
		t.Fatalf("assemble acquired OCI layout: %v", err)
	}
	if assembled.ImageCount != 1 || assembled.Inventory.Authority != ociarchive.InventoryAuthority {
		t.Fatalf("unexpected assembly result %+v", assembled)
	}
	inventory, err := ociarchive.Inspect(archivePath)
	if err != nil {
		t.Fatalf("inspect assembled acquired archive: %v", err)
	}
	if len(inventory.Images) != 1 || inventory.Images[0] != got.ExactReference {
		t.Fatalf("unexpected acquired archive inventory %+v", inventory)
	}
}

func TestPublicRedirectPolicyAllowsHTTPSAndStripsCrossOriginAuthorization(t *testing.T) {
	prev, _ := http.NewRequest(http.MethodGet, "https://registry.example/v2/team/app/blobs/sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", nil)
	prev.Header.Set("Authorization", "Bearer secret")
	next, _ := http.NewRequest(http.MethodGet, "https://cdn.example/object?signature=opaque", nil)
	next.Header.Set("Authorization", "Bearer secret")
	if err := checkPublicRedirect(next, []*http.Request{prev}); err != nil {
		t.Fatal(err)
	}
	if got := next.Header.Get("Authorization"); got != "" {
		t.Fatalf("cross-origin redirect retained Authorization header %q", got)
	}
}

func TestPublicRedirectPolicyRejectsHTTPSDowngradeAndTooManyHops(t *testing.T) {
	prev, _ := http.NewRequest(http.MethodGet, "https://registry.example/source", nil)
	downgrade, _ := http.NewRequest(http.MethodGet, "http://cdn.example/object", nil)
	if err := checkPublicRedirect(downgrade, []*http.Request{prev}); err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("expected HTTPS downgrade rejection, got %v", err)
	}
	secure, _ := http.NewRequest(http.MethodGet, "https://cdn.example/object", nil)
	via := make([]*http.Request, 6)
	for i := range via {
		via[i] = prev
	}
	if err := checkPublicRedirect(secure, via); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("expected redirect limit rejection, got %v", err)
	}
}

func TestPublicRedirectPolicyPreservesSameOriginAuthorization(t *testing.T) {
	prev, _ := http.NewRequest(http.MethodGet, "https://registry.example/source", nil)
	next, _ := http.NewRequest(http.MethodGet, "https://registry.example/next", nil)
	next.Header.Set("Authorization", "Bearer secret")
	if err := checkPublicRedirect(next, []*http.Request{prev}); err != nil {
		t.Fatal(err)
	}
	if got := next.Header.Get("Authorization"); got != "Bearer secret" {
		t.Fatalf("same-origin redirect unexpectedly removed Authorization header: %q", got)
	}
}
