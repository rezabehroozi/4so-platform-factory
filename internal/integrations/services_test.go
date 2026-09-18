package integrations

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"platform.4so.io/factory/internal/gitops"
)

func TestForgejoStatusRejectsVersionWithoutAtomicMultiFileAPI(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/version" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"version": "1.19.4"})
	}))
	defer server.Close()
	t.Setenv("FORGEJO_TEST_SECRET", "secret")
	c := New(Config{GitConnectionResolver: func(context.Context) (GitConnection, error) {
		return GitConnection{BaseURL: server.URL, CredentialID: "cred-test", Username: "admin", SecretRef: "env://FORGEJO_TEST_SECRET"}, nil
	}})
	status := c.forgejoStatus(context.Background())
	if status.Healthy || !strings.Contains(status.Error, "atomic multi-file") {
		t.Fatalf("status=%+v", status)
	}
	for _, tc := range []struct {
		version string
		want    bool
	}{
		{"1.19.4", false}, {"1.20.0", true}, {"v1.20.1-0", true}, {"7.0.5+gitea-1.21.0", true}, {"15.0.5", true},
	} {
		if got := forgejoSupportsAtomicMultiFile(tc.version); got != tc.want {
			t.Fatalf("version %s got=%v want=%v", tc.version, got, tc.want)
		}
	}
}

func TestPublishRevisionRejectsIncompatibleForgejoBeforeRepositoryMutation(t *testing.T) {
	mutations := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/version" && r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(map[string]string{"version": "1.19.4"})
			return
		}
		mutations++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	t.Setenv("FORGEJO_PUBLISH_CAPABILITY_SECRET", "secret")
	client := New(Config{GitConnectionResolver: func(context.Context) (GitConnection, error) {
		return GitConnection{BaseURL: server.URL, CredentialID: "cred-test", Username: "admin", SecretRef: "env://FORGEJO_PUBLISH_CAPABILITY_SECRET"}, nil
	}})
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := gitops.Build(gitops.RevisionInput{ProductVersion: "0.0.105", SpecDigest: "sha256:" + repeatTest("a", 64), BundleDigest: "sha256:" + repeatTest("b", 64), PublicEndpoint: "https://platform.example.test", GitEndpoint: "https://git.example.test", Registry: "https://registry.example.test", Identity: "https://auth.example.test"}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{}
	for name, raw := range signed.Files {
		files[name] = string(raw)
	}
	_, err = client.PublishRevision(context.Background(), RevisionRequest{Organization: "platform", Repository: "desired-state", RevisionID: signed.ID, Digest: signed.Digest, Files: files})
	if err == nil || !strings.Contains(err.Error(), "atomic multi-file") || mutations != 0 {
		t.Fatalf("err=%v mutations=%d", err, mutations)
	}
}

func TestValidatePullRequestRevisionIntentRejectsIncompleteBundleAndUnsignedRevisionID(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := gitops.Build(gitops.RevisionInput{ProductVersion: "0.0.118", SpecDigest: "sha256:" + repeatTest("a", 64), BundleDigest: "sha256:" + repeatTest("b", 64), PublicEndpoint: "https://platform.example.test", GitEndpoint: "https://git.example.test", Registry: "https://registry.example.test", Identity: "https://auth.example.test"}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	clone := func() map[string]string {
		files := make(map[string]string, len(signed.Files))
		for name, raw := range signed.Files {
			files[name] = string(raw)
		}
		return files
	}
	missing := clone()
	delete(missing, "clusters/appliance/kustomization.yaml")
	if _, err := ValidatePullRequestRevisionIntent(RevisionRequest{Organization: "platform", Repository: "desired-state", RevisionID: signed.ID, Digest: signed.Digest, Files: missing}); err == nil || !strings.Contains(err.Error(), "canonical") {
		t.Fatalf("incomplete bundle err=%v", err)
	}

	unsignedID := clone()
	var descriptor map[string]any
	if err := json.Unmarshal([]byte(unsignedID[".platform/revision.json"]), &descriptor); err != nil {
		t.Fatal(err)
	}
	metadata := descriptor["metadata"].(map[string]any)
	metadata["id"] = "revision-ffffffffffffffff"
	raw, err := json.Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	unsignedID[".platform/revision.json"] = string(raw)
	if _, err := ValidatePullRequestRevisionIntent(RevisionRequest{Organization: "platform", Repository: "desired-state", RevisionID: "revision-ffffffffffffffff", Digest: signed.Digest, Files: unsignedID}); err == nil || !strings.Contains(err.Error(), "deterministically bound") {
		t.Fatalf("unsigned revision id err=%v", err)
	}
}

func TestStatusAndRepositoryBootstrap(t *testing.T) {
	organization := false
	repository := false
	seeded := false
	atomicPublishes := 0
	files := map[string]string{}
	forgejo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if user, password, ok := r.BasicAuth(); r.URL.Path != "/api/v1/version" && (!ok || user != "admin" || password != "secret") {
			t.Fatalf("missing basic auth path=%s", r.URL.Path)
		}
		switch {
		case r.URL.Path == "/api/v1/version":
			_ = json.NewEncoder(w).Encode(map[string]string{"version": "15.0.5"})
		case r.URL.Path == "/api/v1/orgs/platform" && r.Method == http.MethodGet:
			if !organization {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"username": "platform"})
		case r.URL.Path == "/api/v1/orgs" && r.Method == http.MethodPost:
			organization = true
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{"username": "platform"})
		case r.URL.Path == "/api/v1/repos/platform/desired-state" && r.Method == http.MethodGet:
			if !repository {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"name": "desired-state", "html_url": "https://git.local/platform/desired-state", "clone_url": "https://git.local/platform/desired-state.git", "owner": map[string]string{"login": "platform"}})
		case r.URL.Path == "/api/v1/orgs/platform/repos" && r.Method == http.MethodPost:
			repository = true
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"name": "desired-state", "html_url": "https://git.local/platform/desired-state", "clone_url": "https://git.local/platform/desired-state.git", "owner": map[string]string{"login": "platform"}})
		case r.URL.Path == "/api/v1/repos/platform/desired-state/contents/README.md" && r.Method == http.MethodPost:
			seeded = true
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"content": map[string]string{"path": "README.md"}})
		case r.URL.Path == "/api/v1/repos/platform/desired-state/contents" && r.Method == http.MethodPost:
			atomicPublishes++
			raw, _ := io.ReadAll(r.Body)
			var payload struct {
				Branch string `json:"branch"`
				Files  []struct {
					Operation string `json:"operation"`
					Path      string `json:"path"`
					Content   string `json:"content"`
					SHA       string `json:"sha"`
				} `json:"files"`
			}
			if err := json.Unmarshal(raw, &payload); err != nil {
				t.Fatal(err)
			}
			if payload.Branch != "main" || len(payload.Files) == 0 {
				t.Fatalf("invalid atomic publish payload: %+v", payload)
			}
			for _, op := range payload.Files {
				if op.Operation != "create" && op.Operation != "update" {
					t.Fatalf("unexpected operation: %+v", op)
				}
				decoded, err := base64.StdEncoding.DecodeString(op.Content)
				if err != nil {
					t.Fatal(err)
				}
				files[op.Path] = string(decoded)
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"commit": map[string]string{"sha": "0123456789abcdef0123456789abcdef01234567"}})
		case len(r.URL.Path) > len("/api/v1/repos/platform/desired-state/contents/") && r.URL.Path[:len("/api/v1/repos/platform/desired-state/contents/")] == "/api/v1/repos/platform/desired-state/contents/":
			filePath := r.URL.Path[len("/api/v1/repos/platform/desired-state/contents/"):]
			if r.Method == http.MethodGet {
				content, ok := files[filePath]
				if !ok {
					http.NotFound(w, r)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]string{"sha": "file-sha", "content": base64.StdEncoding.EncodeToString([]byte(content))})
				return
			}
			if r.Method == http.MethodPost || r.Method == http.MethodPut {
				raw, _ := io.ReadAll(r.Body)
				var payload map[string]any
				_ = json.Unmarshal(raw, &payload)
				decoded, _ := base64.StdEncoding.DecodeString(payload["content"].(string))
				files[filePath] = string(decoded)
				if r.Method == http.MethodPost {
					w.WriteHeader(http.StatusCreated)
				} else {
					w.WriteHeader(http.StatusOK)
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"content": map[string]string{"path": filePath}})
				return
			}
		case r.URL.Path == "/api/v1/repos/platform/desired-state/branches/main" && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{"commit": map[string]string{"id": "0123456789abcdef0123456789abcdef01234567"}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer forgejo.Close()
	zot := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Docker-Distribution-Api-Version", "registry/2.0")
		w.WriteHeader(http.StatusOK)
	}))
	defer zot.Close()
	keycloak := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/realms/platform/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": "https://auth.example.test/realms/platform"})
	}))
	defer keycloak.Close()
	os.Setenv("PF_TEST_FORGEJO_PASSWORD", "secret")
	defer os.Unsetenv("PF_TEST_FORGEJO_PASSWORD")
	resolver := func(context.Context) (GitConnection, error) {
		return GitConnection{ProviderID: "gitp_test", ProviderName: "test", BaseURL: forgejo.URL, CredentialID: "gitcred_test", Username: "admin", SecretRef: "env://PF_TEST_FORGEJO_PASSWORD"}, nil
	}
	client := New(Config{GitConnectionResolver: resolver, ZotURL: zot.URL, KeycloakURL: keycloak.URL, ArgoCDURL: keycloak.URL, ArgoCDToken: "status-token"})
	statuses := client.Status(context.Background())
	if len(statuses) != 4 || !statuses[0].Healthy || !statuses[1].Healthy || !statuses[2].Healthy {
		t.Fatalf("statuses=%+v", statuses)
	}
	result, err := client.EnsureRepository(context.Background(), RepositoryRequest{Organization: "platform", Name: "desired-state", Private: true})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Created || !result.Seeded || !organization || !repository || !seeded {
		t.Fatalf("result=%+v", result)
	}
	result, err = client.EnsureRepository(context.Background(), RepositoryRequest{Organization: "platform", Name: "desired-state", Private: true})
	if err != nil {
		t.Fatal(err)
	}
	if result.Created {
		t.Fatalf("second call should be idempotent: %+v", result)
	}
	if atomicPublishes != 0 {
		t.Fatalf("repository bootstrap must not publish a managed revision, got %d", atomicPublishes)
	}

}

func TestUnsafeRepositoryNameRejected(t *testing.T) {
	os.Setenv("PF_TEST_FORGEJO_PASSWORD", "secret")
	defer os.Unsetenv("PF_TEST_FORGEJO_PASSWORD")
	client := New(Config{GitConnectionResolver: func(context.Context) (GitConnection, error) {
		return GitConnection{ProviderID: "gitp_test", ProviderName: "test", BaseURL: "http://127.0.0.1", CredentialID: "gitcred_test", Username: "admin", SecretRef: "env://PF_TEST_FORGEJO_PASSWORD"}, nil
	}})
	if _, err := client.EnsureRepository(context.Background(), RepositoryRequest{Organization: "../bad", Name: "repo"}); err == nil {
		t.Fatal("expected rejection")
	}
}

func repeatTest(value string, count int) string {
	out := ""
	for i := 0; i < count; i++ {
		out += value
	}
	return out
}

func TestMirrorReferenceAndStatus(t *testing.T) {
	manifest := []byte(`{"schemaVersion":2}`)
	sum := sha256.Sum256(manifest)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	var seen string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.URL.Path
		if r.Method == http.MethodHead && strings.HasSuffix(r.URL.Path, "/manifests/"+digest) {
			w.Header().Set("Docker-Content-Digest", digest)
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	client := New(Config{ZotURL: srv.URL})
	ref := "registry.k8s.io/sig-storage/snapshot-controller@" + digest
	status := client.CheckMirroredImage(context.Background(), ref)
	if !status.Available || !strings.Contains(status.MirrorReference, "/mirror/registry.k8s.io/sig-storage/snapshot-controller@") {
		t.Fatalf("bad mirror status: %+v", status)
	}
	if !strings.Contains(seen, "/v2/mirror/registry.k8s.io/sig-storage/snapshot-controller/manifests/") {
		t.Fatalf("unexpected registry path %s", seen)
	}
}

func TestObserveGitOpsApplicationAuthority(t *testing.T) {
	argo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/applications/platform-appliance" {
			http.NotFound(w, r)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer observer-token" {
			http.Error(w, "missing observer authority", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"metadata": map[string]string{"name": "platform-appliance"},
			"status": map[string]any{
				"sync":   map[string]string{"status": "Synced", "revision": "0123456789abcdef0123456789abcdef01234567"},
				"health": map[string]string{"status": "Healthy"},
			},
		})
	}))
	defer argo.Close()
	client := New(Config{ArgoCDURL: argo.URL, ArgoCDToken: "observer-token"})
	obs, err := client.ObserveGitOpsApplication(context.Background(), "platform-appliance")
	if err != nil {
		t.Fatal(err)
	}
	if obs.Application != "platform-appliance" || obs.SyncStatus != "Synced" || obs.HealthStatus != "Healthy" || obs.Revision != "0123456789abcdef0123456789abcdef01234567" {
		t.Fatalf("observation=%+v", obs)
	}
}

func TestObserveGitOpsApplicationRequiresObserverToken(t *testing.T) {
	client := New(Config{ArgoCDURL: "http://argocd.invalid"})
	if _, err := client.ObserveGitOpsApplication(context.Background(), "platform-appliance"); err == nil || !strings.Contains(err.Error(), "observation token") {
		t.Fatalf("expected missing observation token to fail closed, got %v", err)
	}
	status := client.Status(context.Background())[3]
	if status.Healthy || !strings.Contains(status.Error, "observation token") {
		t.Fatalf("missing observer token must degrade managed GitOps status: %+v", status)
	}
}

func TestInspectGitRevisionCompareFailureFailsClosed(t *testing.T) {
	os.Setenv("PF_TEST_COMPARE_PASSWORD", "secret")
	defer os.Unsetenv("PF_TEST_COMPARE_PASSWORD")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/branches/main"):
			_ = json.NewEncoder(w).Encode(map[string]any{"commit": map[string]string{"id": strings.Repeat("a", 40)}})
		case strings.Contains(r.URL.Path, "/contents/"):
			_ = json.NewEncoder(w).Encode(map[string]string{"content": base64.StdEncoding.EncodeToString([]byte("{}"))})
		case strings.Contains(r.URL.Path, "/compare/"):
			http.Error(w, "compare unavailable", http.StatusServiceUnavailable)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	client := New(Config{GitConnectionResolver: func(context.Context) (GitConnection, error) {
		return GitConnection{ProviderID: "gitp_compare", ProviderName: "test", BaseURL: srv.URL, CredentialID: "cred", Username: "admin", SecretRef: "env://PF_TEST_COMPARE_PASSWORD"}, nil
	}})
	if _, err := client.InspectGitRevision(context.Background(), "platform", "desired-state", "main", strings.Repeat("b", 40), ""); err == nil || !strings.Contains(err.Error(), "compare Git revisions") {
		t.Fatalf("expected compare failure to fail closed, got %v", err)
	}
}

func TestBranchCommitRejectsAbbreviatedCommitID(t *testing.T) {
	os.Setenv("PF_TEST_SHORT_SHA_PASSWORD", "secret")
	defer os.Unsetenv("PF_TEST_SHORT_SHA_PASSWORD")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"commit": map[string]string{"id": "0123456"}})
	}))
	defer srv.Close()
	client := New(Config{GitConnectionResolver: func(context.Context) (GitConnection, error) {
		return GitConnection{ProviderID: "gitp_short", ProviderName: "test", BaseURL: srv.URL, CredentialID: "cred", Username: "admin", SecretRef: "env://PF_TEST_SHORT_SHA_PASSWORD"}, nil
	}})
	if _, err := client.branchCommit(context.Background(), "platform", "desired-state", "main"); err == nil || !strings.Contains(err.Error(), "full immutable commit id") {
		t.Fatalf("expected abbreviated commit rejection, got %v", err)
	}
}

func TestRestoreRevisionRejectsAbbreviatedSourceCommit(t *testing.T) {
	client := New(Config{})
	if _, err := client.RestoreRevision(context.Background(), "platform", "desired-state", "0123456", "main", strings.Repeat("a", 40), ""); err == nil {
		t.Fatal("expected abbreviated source commit rejection")
	}
}

func TestChangeRepositoryFilesAtomicUsesFileSHAAndSingleCommit(t *testing.T) {
	os.Setenv("PF_TEST_ATOMIC_PASSWORD", "secret")
	defer os.Unsetenv("PF_TEST_ATOMIC_PASSWORD")
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/contents/existing.yaml"):
			_ = json.NewEncoder(w).Encode(map[string]string{"sha": "blob-sha", "content": base64.StdEncoding.EncodeToString([]byte("old"))})
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/contents/new.yaml"):
			http.NotFound(w, r)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/contents"):
			calls++
			var payload struct {
				Branch string `json:"branch"`
				Files  []struct {
					Operation string `json:"operation"`
					Path      string `json:"path"`
					SHA       string `json:"sha"`
				} `json:"files"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			if payload.Branch != "main" || len(payload.Files) != 2 {
				t.Fatalf("payload=%+v", payload)
			}
			seenUpdate := false
			seenCreate := false
			for _, op := range payload.Files {
				switch op.Path {
				case "existing.yaml":
					seenUpdate = op.Operation == "update" && op.SHA == "blob-sha"
				case "new.yaml":
					seenCreate = op.Operation == "create" && op.SHA == ""
				}
			}
			if !seenUpdate || !seenCreate {
				t.Fatalf("operations did not preserve create/update preconditions: %+v", payload.Files)
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"commit": map[string]string{"sha": strings.Repeat("c", 40)}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	client := New(Config{GitConnectionResolver: func(context.Context) (GitConnection, error) {
		return GitConnection{ProviderID: "gitp_atomic", ProviderName: "test", BaseURL: srv.URL, CredentialID: "cred", Username: "admin", SecretRef: "env://PF_TEST_ATOMIC_PASSWORD"}, nil
	}})
	changed, commit, err := client.changeRepositoryFilesAtomic(context.Background(), "platform", "desired-state", "main", map[string][]byte{"existing.yaml": []byte("new"), "new.yaml": []byte("created")}, "atomic")
	if err != nil {
		t.Fatal(err)
	}
	if changed != 2 || commit != strings.Repeat("c", 40) || calls != 1 {
		t.Fatalf("changed=%d commit=%s calls=%d", changed, commit, calls)
	}
}

func TestPullRequestManagedChangeGateRejectsUnmanagedPath(t *testing.T) {
	if err := validateManagedRevisionChangedFiles([]string{".platform/revision.json", "clusters/appliance/kustomization.yaml"}); err != nil {
		t.Fatalf("managed paths rejected: %v", err)
	}
	if err := validateManagedRevisionChangedFiles([]string{".platform/revision.json", "README-ATTACK.md"}); err == nil || !strings.Contains(err.Error(), "unmanaged change") {
		t.Fatalf("unmanaged path accepted: %v", err)
	}
}

func TestFindPullRequestByHeadDoesNotAdoptMergedOrClosedHistory(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/version" {
			_ = json.NewEncoder(w).Encode(map[string]string{"version": "1.20.0"})
			return
		}
		if r.URL.Path != "/api/v1/repos/platform/desired-state/pulls" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"number": 1, "state": "closed", "merged": true, "base": map[string]string{"ref": "main"}, "head": map[string]string{"ref": "platform-rev"}},
			{"number": 2, "state": "open", "merged": false, "html_url": "https://git/pr/2", "base": map[string]string{"ref": "main"}, "head": map[string]string{"ref": "platform-rev"}},
		})
	}))
	defer server.Close()
	t.Setenv("PF_PR_RECOVERY_SECRET", "secret")
	c := New(Config{GitConnectionResolver: func(context.Context) (GitConnection, error) {
		return GitConnection{ProviderID: "gitp-test", ProviderName: "test", BaseURL: server.URL, CredentialID: "cred-test", Username: "admin", SecretRef: "env://PF_PR_RECOVERY_SECRET"}, nil
	}})
	pr, err := c.findPullRequestByHead(context.Background(), "platform", "desired-state", "main", "platform-rev")
	if err != nil {
		t.Fatal(err)
	}
	if pr.ExternalNumber != 2 {
		t.Fatalf("recovered historical PR instead of open exact PR: %+v", pr)
	}
}

func TestManagedGitBranchNamesRespectForgejoLimitAndRemainDeterministic(t *testing.T) {
	long := strings.Repeat("REVISION_WITH_LONG_ID_", 12)
	for _, got := range []string{PullRequestHeadBranch(long), directStageBranch(long), restoreStageBranch(long)} {
		if len(got) > 100 {
			t.Fatalf("branch length=%d exceeds Forgejo API limit: %q", len(got), got)
		}
		if !safeName(got) {
			t.Fatalf("branch is not safe: %q", got)
		}
	}
	if PullRequestHeadBranch(long) != PullRequestHeadBranch(long) {
		t.Fatal("managed branch naming must be deterministic")
	}
}
