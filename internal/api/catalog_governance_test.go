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
	"os"
	"strings"
	"testing"
	"time"

	"platform.4so.io/factory/catalog"
	"platform.4so.io/factory/internal/controlplane"
)

func TestCatalogGovernanceSignedPrivatePromotionAndImpact(t *testing.T) {
	store := controlplane.NewMemoryStore()
	org, err := store.CreateOrganization(context.Background(), controlplane.Organization{Name: "catalog-api", DisplayName: "Catalog API"}, "owner")
	if err != nil {
		t.Fatal(err)
	}
	components, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	s := New("0.0.42", components, nil, store)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s.ConfigureCatalogSigner(privateKey, "test")
	h := s.Handler()

	keyBody, _ := json.Marshal(map[string]any{"organizationId": org.ID, "name": "release-signer", "publicKey": base64.StdEncoding.EncodeToString(publicKey)})
	w := apiRequest(t, h, http.MethodPost, "/api/v1/catalog-trust-keys", string(keyBody), map[string]string{"X-Actor-ID": "owner"})
	if w.Code != http.StatusCreated {
		t.Fatalf("create trust=%d body=%s", w.Code, w.Body.String())
	}
	var key controlplane.CatalogTrustKey
	if err = json.Unmarshal(w.Body.Bytes(), &key); err != nil {
		t.Fatal(err)
	}

	createBody, _ := json.Marshal(map[string]any{"organizationId": org.ID, "catalogName": "private-standard", "catalogVersion": "1.0.0", "visibility": "PRIVATE", "channel": "CANDIDATE", "components": catalog.Sorted(components)})
	w = apiRequest(t, h, http.MethodPost, "/api/v1/catalog-releases", string(createBody), map[string]string{"X-Actor-ID": "author"})
	if w.Code != http.StatusCreated {
		t.Fatalf("create release=%d body=%s", w.Code, w.Body.String())
	}
	var created struct {
		Release controlplane.CatalogRelease `json:"release"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Release.State != controlplane.CatalogDraft {
		t.Fatalf("state=%s", created.Release.State)
	}

	w = apiRequest(t, h, http.MethodPost, "/api/v1/catalog-releases/"+created.Release.ID+"/review", `{}`, map[string]string{"X-Actor-ID": "author", "If-Match": fmt.Sprintf("\"%d\"", created.Release.Revision)})
	if w.Code != http.StatusOK {
		t.Fatalf("review=%d body=%s", w.Code, w.Body.String())
	}
	var review controlplane.CatalogRelease
	if err = json.Unmarshal(w.Body.Bytes(), &review); err != nil {
		t.Fatal(err)
	}
	if review.SigningKeyID != key.ID || review.Signature == "" {
		t.Fatalf("review signature missing: %+v", review)
	}

	w = apiRequest(t, h, http.MethodPost, "/api/v1/catalog-releases/"+review.ID+"/publish", `{}`, map[string]string{"X-Actor-ID": "approver", "If-Match": fmt.Sprintf("\"%d\"", review.Revision)})
	if w.Code != http.StatusOK {
		t.Fatalf("publish candidate=%d body=%s", w.Code, w.Body.String())
	}
	var published controlplane.CatalogRelease
	if err = json.Unmarshal(w.Body.Bytes(), &published); err != nil {
		t.Fatal(err)
	}

	badPromote := apiRequest(t, h, http.MethodPost, "/api/v1/catalog-releases/"+published.ID+"/promote", `{`, map[string]string{"X-Actor-ID": "author"})
	if badPromote.Code != http.StatusBadRequest {
		t.Fatalf("invalid promote JSON must fail closed: %d body=%s", badPromote.Code, badPromote.Body.String())
	}

	w = apiRequest(t, h, http.MethodPost, "/api/v1/catalog-releases/"+published.ID+"/promote", `{"channel":"RENDER"}`, map[string]string{"X-Actor-ID": "author"})
	if w.Code != http.StatusCreated {
		t.Fatalf("promote=%d body=%s", w.Code, w.Body.String())
	}
	var promoted struct {
		Release controlplane.CatalogRelease `json:"release"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &promoted); err != nil {
		t.Fatal(err)
	}
	if promoted.Release.Channel != controlplane.CatalogChannelRender || promoted.Release.SourceReleaseID != published.ID {
		t.Fatalf("bad promotion: %+v", promoted.Release)
	}

	w = apiRequest(t, h, http.MethodPost, "/api/v1/catalog-releases/"+promoted.Release.ID+"/review", `{}`, map[string]string{"X-Actor-ID": "author", "If-Match": fmt.Sprintf("\"%d\"", promoted.Release.Revision)})
	if w.Code != http.StatusOK {
		t.Fatalf("render review=%d body=%s", w.Code, w.Body.String())
	}
	var renderReview controlplane.CatalogRelease
	_ = json.Unmarshal(w.Body.Bytes(), &renderReview)
	w = apiRequest(t, h, http.MethodPost, "/api/v1/catalog-releases/"+renderReview.ID+"/publish", `{}`, map[string]string{"X-Actor-ID": "approver", "If-Match": fmt.Sprintf("\"%d\"", renderReview.Revision)})
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected unresolved render admission failure, got %d body=%s", w.Code, w.Body.String())
	}

	w = apiRequest(t, h, http.MethodGet, "/api/v1/catalog-trust-keys/"+key.ID+"/impact", "", map[string]string{"X-Actor-ID": "owner"})
	if w.Code != http.StatusOK {
		t.Fatalf("impact=%d body=%s", w.Code, w.Body.String())
	}
	var impact struct {
		CatalogReleases []controlplane.CatalogRelease `json:"catalogReleases"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &impact); err != nil {
		t.Fatal(err)
	}
	if len(impact.CatalogReleases) < 2 {
		t.Fatalf("impact missing signed releases: %s", w.Body.String())
	}

	w = apiRequest(t, h, http.MethodPost, "/api/v1/catalog-trust-keys/"+key.ID+"/revoke", `{}`, map[string]string{"X-Actor-ID": "owner", "If-Match": fmt.Sprintf("\"%d\"", key.Revision)})
	if w.Code != http.StatusOK {
		t.Fatalf("revoke key=%d body=%s", w.Code, w.Body.String())
	}
}

func TestCatalogRuntimeCertificationAuthorityRejectsDigestOnlyClaims(t *testing.T) {
	ctx := context.Background()
	store := controlplane.NewMemoryStore()
	org, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "catalog-cert-authority", DisplayName: "Catalog Certification Authority"}, "owner")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "cert", DisplayName: "Certification"}, "owner")
	if err != nil {
		t.Fatal(err)
	}
	components, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	s := New("0.0.136", components, nil, store)
	render := seedPublishedRenderCatalogForCertification(t, store, org, s)

	certified := map[string]catalog.Component{}
	for _, name := range []string{"secure-namespace-foundation", "gateway-api"} {
		component := components[name]
		component.Spec.Certification.Status = "target-runtime-certified"
		component.Spec.Certification.EvidenceDigest = "sha256:" + strings.Repeat("a", 64)
		component.Spec.Certification.Profiles = []string{"TARGET_RUNTIME_V1"}
		certified[name] = component
	}
	runtimeRelease := controlplane.CatalogRelease{OrganizationID: org.ID, Visibility: controlplane.CatalogVisibilityPrivate, Channel: controlplane.CatalogChannelRuntime, SourceReleaseID: render.ID}
	r := httptest.NewRequest(http.MethodGet, "/catalog-certification-authority", nil)
	blockers := s.catalogCertificationAuthorityAdmission(r, runtimeRelease, certified)
	if len(blockers) != len(certified) || !strings.Contains(strings.Join(blockers, "\n"), "not backed by an active TARGET_RUNTIME_V1") {
		t.Fatalf("digest-only runtime certification claim was not rejected: %v", blockers)
	}

	cluster, agentToken, _ := seedAPICluster(t, store, project, "catalog-cert-authority", 135)
	targetCaps := controlplane.RuntimeCertificationRequiredCapabilities(controlplane.RuntimeCertificationTargetV1)
	cluster, inventory, err := upsertMutationReadyInventoryForAPITest(t, store, ctx, cluster.ID, credentialDigest(agentToken), cluster.ExternalUID, controlplane.ClusterInventory{ObservedAt: time.Now().UTC(), Distribution: "rke2", Capabilities: append(append([]string(nil), targetCaps...), controlplane.TargetMutationRBACActiveCapability), KubernetesVersion: "v1.34.9", Digest: digestValue("catalog-cert-authority-inventory")})
	if err != nil {
		t.Fatal(err)
	}
	namespace := "catalog-cert-authority"
	rendered, err := s.runtimeCertificationRenderContext(r, render, namespace)
	if err != nil {
		t.Fatal(err)
	}
	installChecks := []controlplane.RuntimeCheck{{Key: "fresh-install-target", Status: "PASS"}}
	for i := range rendered.Resources {
		installChecks = append(installChecks, controlplane.RuntimeCheck{Key: fmt.Sprintf("apply/%d", i+1), Status: "PASS"})
	}
	verifyChecks := []controlplane.RuntimeCheck{{Key: "durable-install-checkpoint", Status: "PASS"}}
	for i := range rendered.Resources {
		verifyChecks = append(verifyChecks, controlplane.RuntimeCheck{Key: fmt.Sprintf("verify/%d", i+1), Status: "PASS"})
	}
	for _, key := range []string{"nodes-ready", "cluster-dns-service", "kubernetes-api-tls", "target-runtime/metrics-query", "target-runtime/logs-push", "target-runtime/logs-query", "target-runtime/alert-fire", "target-runtime/alert-query", "target-runtime/network-namespaces", "target-runtime/network-default-deny", "target-runtime/network-dns-tenant-a", "target-runtime/network-dns-tenant-b", "target-runtime/network-intra-tenant-allow", "target-runtime/network-cross-tenant-deny", "target-runtime/network-cross-tenant-explicit-allow", "target-runtime/pvc-bind", "target-runtime/pvc-io", "target-runtime/snapshot-create", "target-runtime/snapshot-restore-pvc", "target-runtime/snapshot-restore-io", "target-runtime/backup-create", "target-runtime/restore-validate"} {
		verifyChecks = append(verifyChecks, controlplane.RuntimeCheck{Key: key, Status: "PASS"})
	}
	now := time.Now().UTC()
	installAt := now.Add(-2 * time.Minute)
	finishedAt := now.Add(-time.Minute)
	expires := finishedAt.Add(controlplane.RuntimeCertificationValidity)
	run := controlplane.RuntimeCertificationRun{
		ResourceMeta: controlplane.ResourceMeta{ID: "rtc_authoritative", Revision: 3, CreatedAt: now.Add(-3 * time.Minute), UpdatedAt: finishedAt},
		ProjectID:    project.ID, ClusterID: cluster.ID, CatalogReleaseID: render.ID, CatalogRevisionID: render.CurrentRevisionID,
		Profile: controlplane.RuntimeCertificationTargetV1, State: controlplane.RuntimeCertificationSucceeded, Phase: controlplane.RuntimeCertificationPhaseVerify, Namespace: namespace,
		InventoryDigest: inventory.Digest, EnvironmentFingerprint: controlplane.RuntimeEnvironmentFingerprint(inventory), ManifestDigest: render.ManifestDigest, SourceLockDigest: rendered.SourceLockDigest, RenderedDigest: rendered.RenderedDigest, ResourceCount: len(rendered.Resources),
		Checks: append(append([]controlplane.RuntimeCheck(nil), installChecks...), verifyChecks...), InstallCheckpointAt: &installAt, FinishedAt: &finishedAt, ExpiresAt: &expires,
	}
	run.InstallCheckpointDigest = controlplane.RuntimeCertificationCheckpointDigest(run, installChecks)
	run.EvidenceDigest = controlplane.RuntimeCertificationEvidenceDigest(run)
	for name, component := range certified {
		component.Spec.Certification.EvidenceDigest = run.EvidenceDigest
		certified[name] = component
	}
	snap, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	snap.RuntimeCertifications = append(snap.RuntimeCertifications, run)
	if err = store.Restore(snap); err != nil {
		t.Fatal(err)
	}
	if blockers = s.catalogCertificationAuthorityAdmission(r, runtimeRelease, certified); len(blockers) != 1 || !strings.Contains(blockers[0], "gateway-api: TARGET_RUNTIME_V1 evidence proves the target capability harness") {
		t.Fatalf("catalog-wide TARGET_RUNTIME_V1 evidence incorrectly authorized a component that was not installed by the certification run: %v", blockers)
	}
	_, _, err = upsertMutationReadyInventoryForAPITest(t, store, ctx, cluster.ID, credentialDigest(agentToken), cluster.ExternalUID, controlplane.ClusterInventory{ObservedAt: time.Now().UTC().Add(time.Second), Distribution: "rke2", Capabilities: append(append([]string(nil), targetCaps...), controlplane.TargetMutationRBACActiveCapability), KubernetesVersion: "v1.34.10", Digest: digestValue("catalog-cert-authority-inventory-new")})
	if err != nil {
		t.Fatal(err)
	}
	if blockers = s.catalogCertificationAuthorityAdmission(r, runtimeRelease, certified); !strings.Contains(strings.Join(blockers, "\n"), "secure-namespace-foundation: target runtime certification evidence is not backed") {
		t.Fatalf("stale target-runtime evidence remained authoritative after cluster inventory changed: %v", blockers)
	}

	snap, err = store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for i := range snap.RuntimeCertifications {
		if snap.RuntimeCertifications[i].ID == run.ID {
			snap.RuntimeCertifications[i].State = controlplane.RuntimeCertificationRevoked
		}
	}
	if err = store.Restore(snap); err != nil {
		t.Fatal(err)
	}
	if blockers = s.catalogCertificationAuthorityAdmission(r, runtimeRelease, certified); !strings.Contains(strings.Join(blockers, "\n"), "secure-namespace-foundation: target runtime certification evidence is not backed") {
		t.Fatalf("revoked runtime certification still authorized RUNTIME catalog evidence: %v", blockers)
	}

	// PUBLIC visibility must not let another organization inject its own target
	// run as the publisher's channel-promotion authority. Consumers may certify a
	// public RENDER locally, but only evidence owned by the Catalog owner can
	// authorize that owner's RUNTIME release.
	foreignOrg, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "foreign-certifier", DisplayName: "Foreign Certifier"}, "foreign-owner")
	if err != nil {
		t.Fatal(err)
	}
	foreignProject, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: foreignOrg.ID, Name: "foreign", DisplayName: "Foreign"}, "foreign-owner")
	if err != nil {
		t.Fatal(err)
	}
	foreignCluster, foreignToken, _ := seedAPICluster(t, store, foreignProject, "foreign-certifier", 9135)
	foreignRun, _ := seedAuthoritativeTargetRuntimeCertification(t, store, s, foreignProject, foreignCluster, foreignToken, render, "foreign-certifier")
	for name, component := range certified {
		component.Spec.Certification.EvidenceDigest = foreignRun.EvidenceDigest
		certified[name] = component
	}
	publicRuntime := runtimeRelease
	publicRuntime.Visibility = controlplane.CatalogVisibilityPlatform
	if blockers = s.catalogCertificationAuthorityAdmission(r, publicRuntime, certified); !strings.Contains(strings.Join(blockers, "\n"), "secure-namespace-foundation: target runtime certification evidence is not backed") {
		t.Fatalf("foreign organization injected certification authority into public catalog: %v", blockers)
	}

	production := runtimeRelease
	production.Channel = controlplane.CatalogChannelProduction
	for name, component := range certified {
		component.Spec.Certification.Status = "upgrade-certified"
		component.Spec.Certification.EvidenceDigest = "sha256:" + strings.Repeat("b", 64)
		certified[name] = component
	}
	blockers = s.catalogCertificationAuthorityAdmission(r, production, certified)
	if len(blockers) != len(certified) || !strings.Contains(strings.Join(blockers, "\n"), "upgrade certification evidence is not backed") {
		t.Fatalf("digest-only production certification claim was not rejected: %v", blockers)
	}

	// Simulate a legacy RUNTIME release published by an older control plane that
	// accepted digest-shaped certification metadata. The current control plane
	// must fail closed when that release is later bound to a Blueprint.
	for name, component := range certified {
		component.Spec.Certification.Status = "target-runtime-certified"
		component.Spec.Certification.EvidenceDigest = "sha256:" + strings.Repeat("a", 64)
		component.Spec.Certification.Profiles = []string{"TARGET_RUNTIME_V1"}
		certified[name] = component
	}
	h := s.Handler()
	promoteBody := `{"channel":"RUNTIME"}`
	w := apiRequest(t, h, http.MethodPost, "/api/v1/catalog-releases/"+render.ID+"/promote", promoteBody, map[string]string{"X-Actor-ID": "author"})
	if w.Code != http.StatusCreated {
		t.Fatalf("promote legacy runtime=%d body=%s", w.Code, w.Body.String())
	}
	var promoted struct {
		Release controlplane.CatalogRelease `json:"release"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &promoted); err != nil {
		t.Fatal(err)
	}
	draftBody, _ := json.Marshal(map[string]any{"components": catalog.Sorted(certified)})
	w = apiRequest(t, h, http.MethodPut, "/api/v1/catalog-releases/"+promoted.Release.ID+"/draft", string(draftBody), map[string]string{"X-Actor-ID": "author", "If-Match": fmt.Sprintf("\"%d\"", promoted.Release.Revision)})
	if w.Code != http.StatusOK {
		t.Fatalf("update legacy runtime=%d body=%s", w.Code, w.Body.String())
	}
	var draftDetail struct {
		Release controlplane.CatalogRelease `json:"release"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &draftDetail); err != nil {
		t.Fatal(err)
	}
	w = apiRequest(t, h, http.MethodPost, "/api/v1/catalog-releases/"+promoted.Release.ID+"/review", `{}`, map[string]string{"X-Actor-ID": "author", "If-Match": fmt.Sprintf("\"%d\"", draftDetail.Release.Revision)})
	if w.Code != http.StatusOK {
		t.Fatalf("review legacy runtime=%d body=%s", w.Code, w.Body.String())
	}
	legacyReview := decodeBody[controlplane.CatalogRelease](t, w)
	legacyPublished, err := store.TransitionCatalogRelease(ctx, legacyReview.ID, legacyReview.Revision, controlplane.CatalogPublished, "legacy-control-plane")
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = s.blueprintCatalogComponents(httptest.NewRequest(http.MethodGet, "/legacy-runtime-blueprint-bind", nil), project.ID, legacyPublished.ID)
	if err == nil || !strings.Contains(err.Error(), "catalog release admission is no longer valid") || !strings.Contains(err.Error(), "not backed by an active TARGET_RUNTIME_V1") {
		t.Fatalf("legacy fake-certified RUNTIME catalog remained blueprint-bindable: %v", err)
	}
}

func TestBlueprintBindingRejectsRevokedCatalogTrust(t *testing.T) {
	store := controlplane.NewMemoryStore()
	org, err := store.CreateOrganization(context.Background(), controlplane.Organization{Name: "catalog-blueprint", DisplayName: "Catalog Blueprint"}, "owner")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(context.Background(), controlplane.Project{OrganizationID: org.ID, Name: "platform", DisplayName: "Platform"}, "owner")
	if err != nil {
		t.Fatal(err)
	}
	components, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	s := New("0.0.42", components, nil, store)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s.ConfigureCatalogSigner(privateKey, "test")
	h := s.Handler()

	keyBody, _ := json.Marshal(map[string]any{"organizationId": org.ID, "name": "blueprint-signer", "publicKey": base64.StdEncoding.EncodeToString(publicKey)})
	w := apiRequest(t, h, http.MethodPost, "/api/v1/catalog-trust-keys", string(keyBody), map[string]string{"X-Actor-ID": "owner"})
	if w.Code != http.StatusCreated {
		t.Fatalf("create trust=%d body=%s", w.Code, w.Body.String())
	}
	var key controlplane.CatalogTrustKey
	if err = json.Unmarshal(w.Body.Bytes(), &key); err != nil {
		t.Fatal(err)
	}

	createBody, _ := json.Marshal(map[string]any{"organizationId": org.ID, "catalogName": "blueprint-standard", "catalogVersion": "1.0.0", "visibility": "PRIVATE", "channel": "CANDIDATE", "components": catalog.Sorted(components)})
	w = apiRequest(t, h, http.MethodPost, "/api/v1/catalog-releases", string(createBody), map[string]string{"X-Actor-ID": "author"})
	if w.Code != http.StatusCreated {
		t.Fatalf("create catalog=%d body=%s", w.Code, w.Body.String())
	}
	var draft struct {
		Release controlplane.CatalogRelease `json:"release"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &draft); err != nil {
		t.Fatal(err)
	}
	w = apiRequest(t, h, http.MethodPost, "/api/v1/catalog-releases/"+draft.Release.ID+"/review", `{}`, map[string]string{"X-Actor-ID": "author", "If-Match": fmt.Sprintf("\"%d\"", draft.Release.Revision)})
	if w.Code != http.StatusOK {
		t.Fatalf("review catalog=%d body=%s", w.Code, w.Body.String())
	}
	var review controlplane.CatalogRelease
	_ = json.Unmarshal(w.Body.Bytes(), &review)
	w = apiRequest(t, h, http.MethodPost, "/api/v1/catalog-releases/"+review.ID+"/publish", `{}`, map[string]string{"X-Actor-ID": "approver", "If-Match": fmt.Sprintf("\"%d\"", review.Revision)})
	if w.Code != http.StatusOK {
		t.Fatalf("publish catalog=%d body=%s", w.Code, w.Body.String())
	}
	var published controlplane.CatalogRelease
	_ = json.Unmarshal(w.Body.Bytes(), &published)

	raw, err := os.ReadFile("../../blueprints/enterprise-private-cloud.json")
	if err != nil {
		t.Fatal(err)
	}
	var blueprint any
	if err = json.Unmarshal(raw, &blueprint); err != nil {
		t.Fatal(err)
	}
	blueprintBody, _ := json.Marshal(map[string]any{"projectId": project.ID, "catalogReleaseId": published.ID, "blueprint": blueprint})
	w = apiRequest(t, h, http.MethodPost, "/api/v1/blueprint-releases", string(blueprintBody), map[string]string{"X-Actor-ID": "author"})
	if w.Code != http.StatusCreated {
		t.Fatalf("create blueprint=%d body=%s", w.Code, w.Body.String())
	}
	var bpDraft struct {
		Release controlplane.BlueprintRelease `json:"release"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &bpDraft); err != nil {
		t.Fatal(err)
	}
	if bpDraft.Release.CatalogReleaseID != published.ID {
		t.Fatalf("catalog binding=%q", bpDraft.Release.CatalogReleaseID)
	}
	w = apiRequest(t, h, http.MethodPost, "/api/v1/blueprint-releases/"+bpDraft.Release.ID+"/review", `{}`, map[string]string{"X-Actor-ID": "author", "If-Match": fmt.Sprintf("\"%d\"", bpDraft.Release.Revision)})
	if w.Code != http.StatusOK {
		t.Fatalf("review blueprint=%d body=%s", w.Code, w.Body.String())
	}
	var bpReview controlplane.BlueprintRelease
	_ = json.Unmarshal(w.Body.Bytes(), &bpReview)

	w = apiRequest(t, h, http.MethodGet, "/api/v1/catalog-trust-keys/"+key.ID+"/impact", "", map[string]string{"X-Actor-ID": "owner"})
	if w.Code != http.StatusOK {
		t.Fatalf("impact=%d body=%s", w.Code, w.Body.String())
	}
	var impact struct {
		BlueprintReleases []controlplane.BlueprintRelease `json:"blueprintReleases"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &impact); err != nil {
		t.Fatal(err)
	}
	if len(impact.BlueprintReleases) != 1 || impact.BlueprintReleases[0].ID != bpDraft.Release.ID {
		t.Fatalf("blueprint impact missing: %s", w.Body.String())
	}

	w = apiRequest(t, h, http.MethodPost, "/api/v1/catalog-trust-keys/"+key.ID+"/revoke", `{}`, map[string]string{"X-Actor-ID": "owner", "If-Match": fmt.Sprintf("\"%d\"", key.Revision)})
	if w.Code != http.StatusOK {
		t.Fatalf("revoke trust=%d body=%s", w.Code, w.Body.String())
	}
	w = apiRequest(t, h, http.MethodPost, "/api/v1/blueprint-releases/"+bpReview.ID+"/publish", `{}`, map[string]string{"X-Actor-ID": "approver", "If-Match": fmt.Sprintf("\"%d\"", bpReview.Revision)})
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected revoked trust to block blueprint publish, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestResolvedEmbeddedCatalogPromotesAndRenders(t *testing.T) {
	store := controlplane.NewMemoryStore()
	org, err := store.CreateOrganization(context.Background(), controlplane.Organization{Name: "render-api", DisplayName: "Render API"}, "owner")
	if err != nil {
		t.Fatal(err)
	}
	components, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	resolved, ok := components["secure-namespace-foundation"]
	if !ok {
		t.Fatal("resolved embedded component missing")
	}
	s := New("0.0.42", components, nil, store)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s.ConfigureCatalogSigner(privateKey, "test")
	h := s.Handler()

	keyBody, _ := json.Marshal(map[string]any{"organizationId": org.ID, "name": "render-signer", "publicKey": base64.StdEncoding.EncodeToString(publicKey)})
	w := apiRequest(t, h, http.MethodPost, "/api/v1/catalog-trust-keys", string(keyBody), map[string]string{"X-Actor-ID": "owner"})
	if w.Code != http.StatusCreated {
		t.Fatalf("create trust=%d body=%s", w.Code, w.Body.String())
	}

	createBody, _ := json.Marshal(map[string]any{"organizationId": org.ID, "catalogName": "embedded-render", "catalogVersion": "1.0.0", "visibility": "PRIVATE", "channel": "CANDIDATE", "components": []catalog.Component{resolved}})
	w = apiRequest(t, h, http.MethodPost, "/api/v1/catalog-releases", string(createBody), map[string]string{"X-Actor-ID": "author"})
	if w.Code != http.StatusCreated {
		t.Fatalf("create=%d body=%s", w.Code, w.Body.String())
	}
	var candidate struct {
		Release controlplane.CatalogRelease `json:"release"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &candidate); err != nil {
		t.Fatal(err)
	}

	w = apiRequest(t, h, http.MethodPost, "/api/v1/catalog-releases/"+candidate.Release.ID+"/review", `{}`, map[string]string{"X-Actor-ID": "author", "If-Match": fmt.Sprintf("\"%d\"", candidate.Release.Revision)})
	if w.Code != http.StatusOK {
		t.Fatalf("candidate review=%d body=%s", w.Code, w.Body.String())
	}
	var candidateReview controlplane.CatalogRelease
	_ = json.Unmarshal(w.Body.Bytes(), &candidateReview)
	w = apiRequest(t, h, http.MethodPost, "/api/v1/catalog-releases/"+candidateReview.ID+"/publish", `{}`, map[string]string{"X-Actor-ID": "approver", "If-Match": fmt.Sprintf("\"%d\"", candidateReview.Revision)})
	if w.Code != http.StatusOK {
		t.Fatalf("candidate publish=%d body=%s", w.Code, w.Body.String())
	}
	var published controlplane.CatalogRelease
	_ = json.Unmarshal(w.Body.Bytes(), &published)

	w = apiRequest(t, h, http.MethodPost, "/api/v1/catalog-releases/"+published.ID+"/promote", `{"channel":"RENDER"}`, map[string]string{"X-Actor-ID": "author"})
	if w.Code != http.StatusCreated {
		t.Fatalf("promote=%d body=%s", w.Code, w.Body.String())
	}
	var renderDraft struct {
		Release controlplane.CatalogRelease `json:"release"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &renderDraft)
	w = apiRequest(t, h, http.MethodPost, "/api/v1/catalog-releases/"+renderDraft.Release.ID+"/review", `{}`, map[string]string{"X-Actor-ID": "author", "If-Match": fmt.Sprintf("\"%d\"", renderDraft.Release.Revision)})
	if w.Code != http.StatusOK {
		t.Fatalf("render review=%d body=%s", w.Code, w.Body.String())
	}
	var renderReview controlplane.CatalogRelease
	_ = json.Unmarshal(w.Body.Bytes(), &renderReview)
	w = apiRequest(t, h, http.MethodPost, "/api/v1/catalog-releases/"+renderReview.ID+"/publish", `{}`, map[string]string{"X-Actor-ID": "approver", "If-Match": fmt.Sprintf("\"%d\"", renderReview.Revision)})
	if w.Code != http.StatusOK {
		t.Fatalf("render publish=%d body=%s", w.Code, w.Body.String())
	}
	var renderPublished controlplane.CatalogRelease
	_ = json.Unmarshal(w.Body.Bytes(), &renderPublished)

	w = apiRequest(t, h, http.MethodPost, "/api/v1/catalog-releases/"+renderPublished.ID+"/render", `{"namespace":"tenant-a"}`, map[string]string{"X-Actor-ID": "viewer"})
	if w.Code != http.StatusOK {
		t.Fatalf("render=%d body=%s", w.Code, w.Body.String())
	}
	var result struct {
		RenderedDigest string           `json:"renderedDigest"`
		ResourceCount  int              `json:"resourceCount"`
		Resources      []map[string]any `json:"resources"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.ResourceCount != 6 || result.RenderedDigest == "" || len(result.Resources) != 6 {
		t.Fatalf("bad render=%s", w.Body.String())
	}
	raw, _ := json.Marshal(result.Resources)
	if strings.Contains(string(raw), "${") || strings.Contains(string(raw), "example.invalid") {
		t.Fatalf("render contains placeholder=%s", raw)
	}
}
