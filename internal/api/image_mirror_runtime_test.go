package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"platform.4so.io/factory/catalog"
	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/integrations"
)

func TestRuntimeCatalogRequiresVerifiedImageMirrorAndRewritesRender(t *testing.T) {
	components, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	snapshot, ok := components["snapshot-controller"]
	if !ok {
		t.Fatal("snapshot-controller missing")
	}
	foundation, ok := components["secure-namespace-foundation"]
	if !ok {
		t.Fatal("secure-namespace-foundation missing")
	}
	refs, err := catalog.ImageReferences(snapshot)
	if err != nil || len(refs) != 1 {
		t.Fatalf("image refs=%v err=%v", refs, err)
	}
	sourceImage := refs[0]
	_, _, sourceDigest, err := parseImageRefForTest(sourceImage)
	if err != nil {
		t.Fatal(err)
	}

	var mirrorAvailable atomic.Bool
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead && strings.Contains(r.URL.Path, "/manifests/") && strings.HasSuffix(r.URL.Path, "/"+sourceDigest) {
			if !mirrorAvailable.Load() {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Docker-Content-Digest", sourceDigest)
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer registry.Close()

	store := controlplane.NewMemoryStore()
	org, err := store.CreateOrganization(context.Background(), controlplane.Organization{Name: "mirror-runtime", DisplayName: "Mirror Runtime"}, "owner")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(context.Background(), controlplane.Project{OrganizationID: org.ID, Name: "cert", DisplayName: "Certification"}, "owner")
	if err != nil {
		t.Fatal(err)
	}
	cluster, agentToken, _ := seedAPICluster(t, store, project, "mirror-runtime-cert", 136)
	s := New("0.0.56", components, nil, store)
	s.ConfigureSystemServices(integrations.New(integrations.Config{ZotURL: registry.URL}))
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s.ConfigureCatalogSigner(priv, "test")
	h := s.Handler()

	keyBody, _ := json.Marshal(map[string]any{"organizationId": org.ID, "name": "mirror-signer", "publicKey": base64.StdEncoding.EncodeToString(pub)})
	w := apiRequest(t, h, http.MethodPost, "/api/v1/catalog-trust-keys", string(keyBody), map[string]string{"X-Actor-ID": "owner"})
	if w.Code != http.StatusCreated {
		t.Fatalf("trust=%d body=%s", w.Code, w.Body.String())
	}

	createBody, _ := json.Marshal(map[string]any{"organizationId": org.ID, "catalogName": "mirror-runtime", "catalogVersion": "1.0.0", "visibility": "PRIVATE", "channel": "CANDIDATE", "components": []catalog.Component{foundation, snapshot}})
	w = apiRequest(t, h, http.MethodPost, "/api/v1/catalog-releases", string(createBody), map[string]string{"X-Actor-ID": "author"})
	if w.Code != http.StatusCreated {
		t.Fatalf("create=%d body=%s", w.Code, w.Body.String())
	}
	var created struct {
		Release controlplane.CatalogRelease `json:"release"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}

	publishLifecycle := func(release controlplane.CatalogRelease) controlplane.CatalogRelease {
		w := apiRequest(t, h, http.MethodPost, "/api/v1/catalog-releases/"+release.ID+"/review", `{}`, map[string]string{"X-Actor-ID": "author", "If-Match": fmt.Sprintf("\"%d\"", release.Revision)})
		if w.Code != http.StatusOK {
			t.Fatalf("review=%d body=%s", w.Code, w.Body.String())
		}
		var reviewed controlplane.CatalogRelease
		if err := json.Unmarshal(w.Body.Bytes(), &reviewed); err != nil {
			t.Fatal(err)
		}
		w = apiRequest(t, h, http.MethodPost, "/api/v1/catalog-releases/"+reviewed.ID+"/publish", `{}`, map[string]string{"X-Actor-ID": "approver", "If-Match": fmt.Sprintf("\"%d\"", reviewed.Revision)})
		if w.Code != http.StatusOK {
			t.Fatalf("publish=%d body=%s", w.Code, w.Body.String())
		}
		var published controlplane.CatalogRelease
		if err := json.Unmarshal(w.Body.Bytes(), &published); err != nil {
			t.Fatal(err)
		}
		return published
	}
	promote := func(release controlplane.CatalogRelease, channel string) controlplane.CatalogRelease {
		body := `{"channel":"` + channel + `"}`
		w := apiRequest(t, h, http.MethodPost, "/api/v1/catalog-releases/"+release.ID+"/promote", body, map[string]string{"X-Actor-ID": "author"})
		if w.Code != http.StatusCreated {
			t.Fatalf("promote %s=%d body=%s", channel, w.Code, w.Body.String())
		}
		var out struct {
			Release controlplane.CatalogRelease `json:"release"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out.Release
	}

	candidate := publishLifecycle(created.Release)
	renderDraft := promote(candidate, "RENDER")
	renderPublished := publishLifecycle(renderDraft)
	run, _ := seedAuthoritativeTargetRuntimeCertification(t, store, s, project, cluster, agentToken, renderPublished, "mirror-runtime-authority")
	runtimeDraft := promote(renderPublished, "RUNTIME")
	for _, component := range []*catalog.Component{&foundation, &snapshot} {
		component.Spec.Certification.Status = "target-runtime-certified"
		component.Spec.Certification.Profiles = []string{"TARGET_RUNTIME_V1"}
		component.Spec.Certification.EvidenceDigest = run.EvidenceDigest
	}
	draftBody, _ := json.Marshal(map[string]any{"components": []catalog.Component{foundation, snapshot}})
	w = apiRequest(t, h, http.MethodPut, "/api/v1/catalog-releases/"+runtimeDraft.ID+"/draft", string(draftBody), map[string]string{"X-Actor-ID": "author", "If-Match": fmt.Sprintf("\"%d\"", runtimeDraft.Revision)})
	if w.Code != http.StatusOK {
		t.Fatalf("runtime draft certification binding=%d body=%s", w.Code, w.Body.String())
	}
	var runtimeDraftDetail struct {
		Release controlplane.CatalogRelease `json:"release"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &runtimeDraftDetail); err != nil {
		t.Fatal(err)
	}
	runtimeDraft = runtimeDraftDetail.Release

	w = apiRequest(t, h, http.MethodPost, "/api/v1/catalog-releases/"+runtimeDraft.ID+"/review", `{}`, map[string]string{"X-Actor-ID": "author", "If-Match": fmt.Sprintf("\"%d\"", runtimeDraft.Revision)})
	if w.Code != http.StatusOK {
		t.Fatalf("runtime review=%d body=%s", w.Code, w.Body.String())
	}
	var runtimeReview controlplane.CatalogRelease
	_ = json.Unmarshal(w.Body.Bytes(), &runtimeReview)
	w = apiRequest(t, h, http.MethodPost, "/api/v1/catalog-releases/"+runtimeReview.ID+"/publish", `{}`, map[string]string{"X-Actor-ID": "approver", "If-Match": fmt.Sprintf("\"%d\"", runtimeReview.Revision)})
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "managed registry") {
		t.Fatalf("expected mirror admission rejection, got %d body=%s", w.Code, w.Body.String())
	}

	mirrorAvailable.Store(true)
	w = apiRequest(t, h, http.MethodPost, "/api/v1/catalog-releases/"+runtimeReview.ID+"/publish", `{}`, map[string]string{"X-Actor-ID": "approver", "If-Match": fmt.Sprintf("\"%d\"", runtimeReview.Revision)})
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "component-specific runtime certification authority is required") {
		t.Fatalf("image mirror availability incorrectly bypassed missing component runtime certification=%d body=%s", w.Code, w.Body.String())
	}

	// Mirror discovery and rewrite remain independently testable, but a mirrored
	// image must not turn target-capability evidence into component certification.
	statuses, mirrorBlockers := s.catalogImageMirrorAdmission(httptest.NewRequest(http.MethodGet, "/mirror-admission", nil), runtimeReview, map[string]catalog.Component{foundation.Metadata.Name: foundation, snapshot.Metadata.Name: snapshot})
	if len(mirrorBlockers) != 0 {
		t.Fatalf("available mirror unexpectedly blocked image admission: %v", mirrorBlockers)
	}
	mirrorMap := map[string]string{}
	for _, status := range statuses {
		source, _ := status["sourceReference"].(string)
		mirror, _ := status["mirrorReference"].(string)
		available, _ := status["available"].(bool)
		if available && source != "" && mirror != "" {
			mirrorMap[source] = mirror
		}
	}
	mirror := mirrorMap[sourceImage]
	wantPrefix := strings.TrimPrefix(strings.TrimPrefix(registry.URL, "http://"), "https://") + "/mirror/registry.k8s.io/"
	if mirror == "" || !strings.HasPrefix(mirror, wantPrefix) {
		t.Fatalf("mirror mapping invalid: %q want prefix %q", mirror, wantPrefix)
	}
	if !strings.HasSuffix(mirror, "@"+sourceDigest) {
		t.Fatalf("mirror digest mismatch %q", mirror)
	}
	rendered, renderErr := catalog.RenderComponent(snapshot, "tenant-a", runtimeReview.ID)
	if renderErr != nil {
		t.Fatal(renderErr)
	}
	for _, resource := range rendered.Resources {
		if err = rewriteRuntimeImages(resource, mirrorMap); err != nil {
			t.Fatal(err)
		}
	}
	images := collectRenderedImagesForTest(rendered.Resources)
	if len(images) != 1 || images[0] != mirror {
		t.Fatalf("rendered images=%v mirror=%s", images, mirror)
	}
}

func parseImageRefForTest(ref string) (string, string, string, error) {
	at := strings.LastIndex(ref, "@")
	slash := strings.Index(ref, "/")
	if at <= 0 || slash <= 0 || slash > at {
		return "", "", "", fmt.Errorf("bad image ref")
	}
	return ref[:slash], ref[slash+1 : at], ref[at+1:], nil
}

func collectRenderedImagesForTest(resources []map[string]any) []string {
	out := []string{}
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case []any:
			for _, item := range x {
				walk(item)
			}
		case map[string]any:
			for k, value := range x {
				if k == "image" {
					if s, ok := value.(string); ok {
						out = append(out, s)
					}
				}
				walk(value)
			}
		}
	}
	for _, r := range resources {
		walk(r)
	}
	return out
}
