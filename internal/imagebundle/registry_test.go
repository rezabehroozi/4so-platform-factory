package imagebundle

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

type fakeRegistry struct {
	mu        sync.Mutex
	blobs     map[string][]byte
	manifests map[string][]byte
}

func (f *fakeRegistry) handler(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := r.URL.Path
	if strings.Contains(p, "/blobs/uploads/") && r.Method == http.MethodPost {
		w.Header().Set("Location", p+"u1")
		w.WriteHeader(http.StatusAccepted)
		return
	}
	if strings.Contains(p, "/blobs/uploads/u1") && r.Method == http.MethodPut {
		dg := r.URL.Query().Get("digest")
		raw, _ := io.ReadAll(r.Body)
		f.blobs[dg] = raw
		w.WriteHeader(http.StatusCreated)
		return
	}
	if strings.Contains(p, "/blobs/") && r.Method == http.MethodHead {
		dg := p[strings.LastIndex(p, "/")+1:]
		if _, ok := f.blobs[dg]; ok {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
		return
	}
	if strings.Contains(p, "/manifests/") {
		dg := p[strings.LastIndex(p, "/")+1:]
		if r.Method == http.MethodPut {
			raw := make([]byte, r.ContentLength)
			_, _ = r.Body.Read(raw)
			f.manifests[dg] = raw
			w.Header().Set("Docker-Content-Digest", dg)
			w.WriteHeader(http.StatusCreated)
			return
		}
		if r.Method == http.MethodHead {
			if _, ok := f.manifests[dg]; ok {
				w.Header().Set("Docker-Content-Digest", dg)
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
			return
		}
	}
	w.WriteHeader(http.StatusNotFound)
}
func TestRegistryPushVerify(t *testing.T) {
	root, ref := fixture(t)
	raw, v, err := Assemble(root, ref)
	if err != nil {
		t.Fatal(err)
	}
	v, err = Verify(raw)
	if err != nil {
		t.Fatal(err)
	}
	fr := &fakeRegistry{blobs: map[string][]byte{}, manifests: map[string][]byte{}}
	srv := httptest.NewServer(http.HandlerFunc(fr.handler))
	defer srv.Close()
	c, _ := NewRegistryClient(srv.URL)
	result, err := c.Push(context.Background(), v)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Verified || result.UploadedBlobs != 2 || result.UploadedManifests != 1 {
		t.Fatalf("bad push result %+v", result)
	}
	u, _ := url.Parse(srv.URL)
	want := u.Host + "/mirror/registry.example/team/app@" + v.Manifest.RootDigest
	if result.MirrorReference != want {
		t.Fatalf("mirror=%s want=%s", result.MirrorReference, want)
	}
}

func TestRegistryPushRejectsHTTPSUploadLocationDowngrade(t *testing.T) {
	var insecureRequests int
	insecure := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		insecureRequests++
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusCreated)
	}))
	defer insecure.Close()

	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodHead && strings.Contains(r.URL.Path, "/blobs/"):
			w.WriteHeader(http.StatusNotFound)
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/blobs/uploads/"):
			w.Header().Set("Location", insecure.URL+"/upload/session")
			w.WriteHeader(http.StatusAccepted)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer secure.Close()

	client, err := NewRegistryClient(secure.URL)
	if err != nil {
		t.Fatal(err)
	}
	client.HTTP = secure.Client()
	obj := Object{Digest: digestBytes([]byte("secret-layer")), Raw: []byte("secret-layer")}
	if err = client.pushBlob(context.Background(), "mirror/example/repo", obj); err == nil {
		t.Fatal("expected HTTPS registry upload location downgrade to be rejected")
	}
	if insecureRequests != 0 {
		t.Fatalf("plaintext upload endpoint received %d requests", insecureRequests)
	}
}

func TestRegistryClientRejectsEndpointAuthorityDecoration(t *testing.T) {
	for _, endpoint := range []string{
		"https://user:pass@registry.example",
		"https://registry.example/v2",
		"https://registry.example?token=secret",
		"https://registry.example#fragment",
	} {
		if _, err := NewRegistryClient(endpoint); err == nil {
			t.Fatalf("expected registry endpoint %q to be rejected", endpoint)
		}
	}
}

func TestRegistryPushPreservesOpaqueUploadLocationQuery(t *testing.T) {
	payload := []byte("signed-layer")
	digest := digestBytes(payload)
	var putQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodHead && strings.Contains(r.URL.Path, "/blobs/"):
			w.WriteHeader(http.StatusNotFound)
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/blobs/uploads/"):
			w.Header().Set("Location", "/upload/session?token=a%20b&z=1")
			w.WriteHeader(http.StatusAccepted)
		case r.Method == http.MethodPut && r.URL.Path == "/upload/session":
			putQuery = r.URL.RawQuery
			if putQuery != "token=a%20b&z=1&digest="+url.QueryEscape(digest) {
				http.Error(w, "signed query changed", http.StatusForbidden)
				return
			}
			w.WriteHeader(http.StatusCreated)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client, err := NewRegistryClient(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err = client.pushBlob(context.Background(), "mirror/example/repo", Object{Digest: digest, Raw: payload}); err != nil {
		t.Fatalf("push blob with opaque signed query: %v (query=%q)", err, putQuery)
	}
}

func TestRegistryClientRejectsHTTPSRedirectDowngrade(t *testing.T) {
	var insecureRequests int
	insecure := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		insecureRequests++
		w.WriteHeader(http.StatusOK)
	}))
	defer insecure.Close()

	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, insecure.URL+"/downgraded", http.StatusTemporaryRedirect)
	}))
	defer secure.Close()

	client, err := NewRegistryClient(secure.URL)
	if err != nil {
		t.Fatal(err)
	}
	client.HTTP = secure.Client()
	if _, err = client.do(context.Background(), http.MethodHead, secure.URL+"/v2/repo/blobs/sha256:test", "", nil, http.StatusOK); err == nil {
		t.Fatal("expected HTTPS registry redirect downgrade to be rejected")
	}
	if insecureRequests != 0 {
		t.Fatalf("plaintext redirect target received %d requests", insecureRequests)
	}
}

func TestRegistryPushResolvesRelativeLocationAgainstFinalRedirectURL(t *testing.T) {
	payload := []byte("redirected-layer")
	digest := digestBytes(payload)
	var uploaded bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodHead && strings.Contains(r.URL.Path, "/blobs/"):
			w.WriteHeader(http.StatusNotFound)
		case r.Method == http.MethodPost && r.URL.Path == "/v2/mirror/example/repo/blobs/uploads/":
			w.Header().Set("Location", "/session/root/")
			w.WriteHeader(http.StatusTemporaryRedirect)
		case r.Method == http.MethodPost && r.URL.Path == "/session/root/":
			w.Header().Set("Location", "next?token=opaque%20value")
			w.WriteHeader(http.StatusAccepted)
		case r.Method == http.MethodPut && r.URL.Path == "/session/root/next":
			if r.URL.RawQuery != "token=opaque%20value&digest="+url.QueryEscape(digest) {
				http.Error(w, "query changed", http.StatusForbidden)
				return
			}
			uploaded = true
			w.WriteHeader(http.StatusCreated)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client, err := NewRegistryClient(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err = client.pushBlob(context.Background(), "mirror/example/repo", Object{Digest: digest, Raw: payload}); err != nil {
		t.Fatal(err)
	}
	if !uploaded {
		t.Fatal("expected upload to resolve relative Location against final redirect URL")
	}
}
