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
	"testing"
	"time"

	"platform.4so.io/factory/catalog"
	"platform.4so.io/factory/internal/controlplane"
)

func seedPublishedRenderCatalogForCertification(t *testing.T, store *controlplane.MemoryStore, org controlplane.Organization, s *Server) controlplane.CatalogRelease {
	t.Helper()
	components, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	resolved, ok := components["secure-namespace-foundation"]
	if !ok {
		t.Fatal("resolved embedded component missing")
	}
	gateway, ok := components["gateway-api"]
	if !ok || !gateway.Spec.Source.Resolved {
		t.Fatal("resolved external component missing")
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s.ConfigureCatalogSigner(privateKey, "runtime-certification-test")
	h := s.Handler()
	keyBody, _ := json.Marshal(map[string]any{"organizationId": org.ID, "name": "cert-signer", "publicKey": base64.StdEncoding.EncodeToString(publicKey)})
	w := apiRequest(t, h, http.MethodPost, "/api/v1/catalog-trust-keys", string(keyBody), map[string]string{"X-Actor-ID": "owner"})
	if w.Code != http.StatusCreated {
		t.Fatalf("trust=%d %s", w.Code, w.Body.String())
	}
	createBody, _ := json.Marshal(map[string]any{"organizationId": org.ID, "catalogName": "cert-foundation", "catalogVersion": "1.0.0", "visibility": "PRIVATE", "channel": "CANDIDATE", "components": []catalog.Component{resolved, gateway}})
	w = apiRequest(t, h, http.MethodPost, "/api/v1/catalog-releases", string(createBody), map[string]string{"X-Actor-ID": "author"})
	if w.Code != http.StatusCreated {
		t.Fatalf("candidate=%d %s", w.Code, w.Body.String())
	}
	var created struct {
		Release controlplane.CatalogRelease `json:"release"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	w = apiRequest(t, h, http.MethodPost, "/api/v1/catalog-releases/"+created.Release.ID+"/review", `{}`, map[string]string{"X-Actor-ID": "author", "If-Match": fmt.Sprintf("\"%d\"", created.Release.Revision)})
	if w.Code != http.StatusOK {
		t.Fatalf("review candidate=%d %s", w.Code, w.Body.String())
	}
	candidateReview := decodeBody[controlplane.CatalogRelease](t, w)
	w = apiRequest(t, h, http.MethodPost, "/api/v1/catalog-releases/"+candidateReview.ID+"/publish", `{}`, map[string]string{"X-Actor-ID": "approver", "If-Match": fmt.Sprintf("\"%d\"", candidateReview.Revision)})
	if w.Code != http.StatusOK {
		t.Fatalf("publish candidate=%d %s", w.Code, w.Body.String())
	}
	candidatePublished := decodeBody[controlplane.CatalogRelease](t, w)
	w = apiRequest(t, h, http.MethodPost, "/api/v1/catalog-releases/"+candidatePublished.ID+"/promote", `{"channel":"RENDER"}`, map[string]string{"X-Actor-ID": "author"})
	if w.Code != http.StatusCreated {
		t.Fatalf("promote=%d %s", w.Code, w.Body.String())
	}
	var promoted struct {
		Release controlplane.CatalogRelease `json:"release"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &promoted); err != nil {
		t.Fatal(err)
	}
	w = apiRequest(t, h, http.MethodPost, "/api/v1/catalog-releases/"+promoted.Release.ID+"/review", `{}`, map[string]string{"X-Actor-ID": "author", "If-Match": fmt.Sprintf("\"%d\"", promoted.Release.Revision)})
	if w.Code != http.StatusOK {
		t.Fatalf("review render=%d %s", w.Code, w.Body.String())
	}
	renderReview := decodeBody[controlplane.CatalogRelease](t, w)
	w = apiRequest(t, h, http.MethodPost, "/api/v1/catalog-releases/"+renderReview.ID+"/publish", `{}`, map[string]string{"X-Actor-ID": "approver", "If-Match": fmt.Sprintf("\"%d\"", renderReview.Revision)})
	if w.Code != http.StatusOK {
		t.Fatalf("publish render=%d %s", w.Code, w.Body.String())
	}
	return decodeBody[controlplane.CatalogRelease](t, w)
}

func seedAuthoritativeTargetRuntimeCertification(t *testing.T, store *controlplane.MemoryStore, s *Server, project controlplane.Project, cluster controlplane.ManagedCluster, agentToken string, source controlplane.CatalogRelease, namespace string) (controlplane.RuntimeCertificationRun, controlplane.ManagedCluster) {
	t.Helper()
	ctx := context.Background()
	targetCaps := controlplane.RuntimeCertificationRequiredCapabilities(controlplane.RuntimeCertificationTargetV1)
	cluster, inventory, err := upsertMutationReadyInventoryForAPITest(t, store, ctx, cluster.ID, credentialDigest(agentToken), cluster.ExternalUID, controlplane.ClusterInventory{ObservedAt: time.Now().UTC(), Distribution: "rke2", Capabilities: append(append([]string(nil), targetCaps...), controlplane.TargetMutationRBACActiveCapability), KubernetesVersion: "v1.34.9", Digest: digestValue("target-runtime-authority-" + cluster.ID + "-" + namespace)})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/target-runtime-authority", nil)
	rendered, err := s.runtimeCertificationRenderContext(r, source, namespace)
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
		ResourceMeta: controlplane.ResourceMeta{ID: "rtc_authoritative_" + cluster.ID, Revision: 3, CreatedAt: now.Add(-3 * time.Minute), UpdatedAt: finishedAt},
		ProjectID:    project.ID, ClusterID: cluster.ID, CatalogReleaseID: source.ID, CatalogRevisionID: source.CurrentRevisionID,
		Profile: controlplane.RuntimeCertificationTargetV1, State: controlplane.RuntimeCertificationSucceeded, Phase: controlplane.RuntimeCertificationPhaseVerify, Namespace: namespace,
		InventoryDigest: inventory.Digest, EnvironmentFingerprint: controlplane.RuntimeEnvironmentFingerprint(inventory), ManifestDigest: source.ManifestDigest, SourceLockDigest: rendered.SourceLockDigest, RenderedDigest: rendered.RenderedDigest, ResourceCount: len(rendered.Resources),
		Checks: append(append([]controlplane.RuntimeCheck(nil), installChecks...), verifyChecks...), InstallCheckpointAt: &installAt, FinishedAt: &finishedAt, ExpiresAt: &expires,
	}
	run.InstallCheckpointDigest = controlplane.RuntimeCertificationCheckpointDigest(run, installChecks)
	run.EvidenceDigest = controlplane.RuntimeCertificationEvidenceDigest(run)
	snap, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	snap.RuntimeCertifications = append(snap.RuntimeCertifications, run)
	if err = store.Restore(snap); err != nil {
		t.Fatal(err)
	}
	return run, cluster
}

func TestRuntimeCertificationFoundationCheckpointVerifyAndBlockTarget(t *testing.T) {
	ctx := context.Background()
	store := controlplane.NewMemoryStore()
	org, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "cert-org", DisplayName: "Certification Org"}, "owner")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "prod", DisplayName: "Production"}, "owner")
	if err != nil {
		t.Fatal(err)
	}
	cluster, agentToken, _ := seedAPICluster(t, store, project, "cert-cluster", 81)
	components, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	s := New("0.0.51", components, nil, store)
	release := seedPublishedRenderCatalogForCertification(t, store, org, s)
	h := s.Handler()

	body, _ := json.Marshal(map[string]any{"projectId": project.ID, "clusterId": cluster.ID, "catalogReleaseId": release.ID, "profile": "FOUNDATION_V1", "namespace": "4so-cert-foundation"})
	w := apiRequest(t, h, http.MethodPost, "/api/v1/runtime-certifications", string(body), map[string]string{"X-Actor-ID": "owner", "Idempotency-Key": "foundation-run-1"})
	if w.Code != http.StatusCreated {
		t.Fatalf("create foundation=%d %s", w.Code, w.Body.String())
	}
	var created struct {
		Run                   controlplane.RuntimeCertificationRun `json:"run"`
		ExternalLiveCertified bool                                 `json:"externalLiveCertified"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Run.State != controlplane.RuntimeCertificationQueued || created.ExternalLiveCertified {
		t.Fatalf("unexpected created run: %+v", created)
	}

	w = apiRequest(t, h, http.MethodGet, "/agent/v1/clusters/"+cluster.ID+"/runtime-certification-tasks/next", "", map[string]string{"Authorization": "Bearer " + agentToken})
	if w.Code != http.StatusOK {
		t.Fatalf("claim install=%d %s", w.Code, w.Body.String())
	}
	installTask := decodeBody[controlplane.RuntimeCertificationTask](t, w)
	if installTask.Phase != controlplane.RuntimeCertificationPhaseInstall || len(installTask.Resources) != 6 {
		t.Fatalf("bad install task: %+v", installTask)
	}
	if installTask.CleanupToken == "" || len(installTask.PriorCleanupGenerations) != 0 {
		t.Fatalf("install task cleanup authority missing or polluted: token=%q prior=%+v", installTask.CleanupToken, installTask.PriorCleanupGenerations)
	}
	result, _ := json.Marshal(controlplane.RuntimeCertificationResult{Phase: installTask.Phase, TaskFenceToken: installTask.TaskFenceToken, Success: true, InventoryDigest: installTask.InventoryDigest, RenderedDigest: installTask.RenderedDigest, Checks: []controlplane.RuntimeCheck{{Key: "fresh-install-target", Status: "PASS"}, {Key: "apply/1", Status: "PASS"}, {Key: "apply/2", Status: "PASS"}, {Key: "apply/3", Status: "PASS"}, {Key: "apply/4", Status: "PASS"}, {Key: "apply/5", Status: "PASS"}, {Key: "apply/6", Status: "PASS"}}})
	w = apiRequest(t, h, http.MethodPost, "/agent/v1/clusters/"+cluster.ID+"/runtime-certification-tasks/"+installTask.RunID+"/result", string(result), map[string]string{"Authorization": "Bearer " + agentToken, "If-Match": fmt.Sprintf("\"%d\"", installTask.RunRevision)})
	if w.Code != http.StatusOK {
		t.Fatalf("report install=%d %s", w.Code, w.Body.String())
	}
	checkpointed := decodeBody[controlplane.RuntimeCertificationRun](t, w)
	if checkpointed.State != controlplane.RuntimeCertificationVerifying || checkpointed.InstallCheckpointDigest == "" || checkpointed.InstallCheckpointAt == nil {
		t.Fatalf("checkpoint missing: %+v", checkpointed)
	}

	w = apiRequest(t, h, http.MethodGet, "/agent/v1/clusters/"+cluster.ID+"/runtime-certification-tasks/next", "", map[string]string{"Authorization": "Bearer " + agentToken})
	if w.Code != http.StatusOK {
		t.Fatalf("claim verify=%d %s", w.Code, w.Body.String())
	}
	verifyTask := decodeBody[controlplane.RuntimeCertificationTask](t, w)
	if verifyTask.Phase != controlplane.RuntimeCertificationPhaseVerify || verifyTask.InstallCheckpointDigest != checkpointed.InstallCheckpointDigest {
		t.Fatalf("bad verify task: %+v", verifyTask)
	}
	if verifyTask.CleanupToken == "" || verifyTask.CleanupToken == installTask.CleanupToken || len(verifyTask.PriorCleanupGenerations) != 1 || verifyTask.PriorCleanupGenerations[0].Token != installTask.CleanupToken || verifyTask.PriorCleanupGenerations[0].Phase != controlplane.RuntimeCertificationPhaseInstall {
		t.Fatalf("verify task cleanup generations are not durably chained: current=%q prior=%+v", verifyTask.CleanupToken, verifyTask.PriorCleanupGenerations)
	}
	verifyResult, _ := json.Marshal(controlplane.RuntimeCertificationResult{Phase: verifyTask.Phase, TaskFenceToken: verifyTask.TaskFenceToken, Success: true, InventoryDigest: verifyTask.InventoryDigest, RenderedDigest: verifyTask.RenderedDigest, Checks: []controlplane.RuntimeCheck{{Key: "durable-install-checkpoint", Status: "PASS"}, {Key: "verify/1", Status: "PASS"}, {Key: "verify/2", Status: "PASS"}, {Key: "verify/3", Status: "PASS"}, {Key: "verify/4", Status: "PASS"}, {Key: "verify/5", Status: "PASS"}, {Key: "verify/6", Status: "PASS"}, {Key: "nodes-ready", Status: "PASS"}, {Key: "cluster-dns-service", Status: "PASS"}, {Key: "kubernetes-api-tls", Status: "PASS"}}})
	w = apiRequest(t, h, http.MethodPost, "/agent/v1/clusters/"+cluster.ID+"/runtime-certification-tasks/"+verifyTask.RunID+"/result", string(verifyResult), map[string]string{"Authorization": "Bearer " + agentToken, "If-Match": fmt.Sprintf("\"%d\"", verifyTask.RunRevision)})
	if w.Code != http.StatusOK {
		t.Fatalf("report verify=%d %s", w.Code, w.Body.String())
	}
	succeeded := decodeBody[controlplane.RuntimeCertificationRun](t, w)
	if succeeded.State != controlplane.RuntimeCertificationSucceeded || succeeded.EvidenceDigest == "" || succeeded.ExpiresAt == nil || time.Until(*succeeded.ExpiresAt) < 29*24*time.Hour {
		t.Fatalf("success evidence invalid: %+v", succeeded)
	}

	w = apiRequest(t, h, http.MethodGet, "/api/v1/runtime-certifications/"+succeeded.ID+"/report", "", map[string]string{"X-Actor-ID": "owner"})
	if w.Code != http.StatusOK || !containsAll(w.Body.String(), `"externalLiveCertified":false`, `"productionReady":false`) {
		t.Fatalf("report claims=%d %s", w.Code, w.Body.String())
	}

	body, _ = json.Marshal(map[string]any{"projectId": project.ID, "clusterId": cluster.ID, "catalogReleaseId": release.ID, "profile": "TARGET_RUNTIME_V1", "namespace": "4so-cert-target"})
	w = apiRequest(t, h, http.MethodPost, "/api/v1/runtime-certifications", string(body), map[string]string{"X-Actor-ID": "owner", "Idempotency-Key": "target-run-1"})
	if w.Code != http.StatusCreated {
		t.Fatalf("create target=%d %s", w.Code, w.Body.String())
	}
	var target struct {
		Run controlplane.RuntimeCertificationRun `json:"run"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &target); err != nil {
		t.Fatal(err)
	}
	if target.Run.State != controlplane.RuntimeCertificationBlocked || len(target.Run.Checks) != 11 {
		t.Fatalf("target must block without real capabilities: %+v", target.Run)
	}

	// OBSERVABILITY_V1 is independently executable when the authoritative inventory reports all three adapters.
	obsInventory := controlplane.ClusterInventory{ObservedAt: time.Now(), Distribution: "rke2", KubernetesVersion: "1.34.0", Digest: "sha256:" + strings.Repeat("9", 64), Capabilities: []string{controlplane.TargetMutationRBACActiveCapability, "cert.metrics", "cert.logs", "cert.alerts"}}
	cluster, _, err = upsertMutationReadyInventoryForAPITest(t, store, ctx, cluster.ID, credentialDigest(agentToken), cluster.ExternalUID, obsInventory)
	if err != nil {
		t.Fatal(err)
	}
	body, _ = json.Marshal(map[string]any{"projectId": project.ID, "clusterId": cluster.ID, "catalogReleaseId": release.ID, "profile": "OBSERVABILITY_V1", "namespace": "4so-cert-observability"})
	w = apiRequest(t, h, http.MethodPost, "/api/v1/runtime-certifications", string(body), map[string]string{"X-Actor-ID": "owner", "Idempotency-Key": "observability-run-1"})
	if w.Code != http.StatusCreated {
		t.Fatalf("create observability=%d %s", w.Code, w.Body.String())
	}
	var observability struct {
		Run controlplane.RuntimeCertificationRun `json:"run"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &observability); err != nil {
		t.Fatal(err)
	}
	if observability.Run.State != controlplane.RuntimeCertificationQueued {
		t.Fatalf("observability run not queued: %+v", observability.Run)
	}
	w = apiRequest(t, h, http.MethodGet, "/agent/v1/clusters/"+cluster.ID+"/runtime-certification-tasks/next", "", map[string]string{"Authorization": "Bearer " + agentToken})
	obsInstall := decodeBody[controlplane.RuntimeCertificationTask](t, w)
	installChecks := []controlplane.RuntimeCheck{{Key: "fresh-install-target", Status: "PASS"}}
	for i := 1; i <= 6; i++ {
		installChecks = append(installChecks, controlplane.RuntimeCheck{Key: fmt.Sprintf("apply/%d", i), Status: "PASS"})
	}
	obsInstallResult, _ := json.Marshal(controlplane.RuntimeCertificationResult{Phase: obsInstall.Phase, TaskFenceToken: obsInstall.TaskFenceToken, Success: true, InventoryDigest: obsInstall.InventoryDigest, RenderedDigest: obsInstall.RenderedDigest, Checks: installChecks})
	w = apiRequest(t, h, http.MethodPost, "/agent/v1/clusters/"+cluster.ID+"/runtime-certification-tasks/"+obsInstall.RunID+"/result", string(obsInstallResult), map[string]string{"Authorization": "Bearer " + agentToken, "If-Match": fmt.Sprintf("\"%d\"", obsInstall.RunRevision)})
	if w.Code != http.StatusOK {
		t.Fatalf("obs install result=%d %s", w.Code, w.Body.String())
	}
	w = apiRequest(t, h, http.MethodGet, "/agent/v1/clusters/"+cluster.ID+"/runtime-certification-tasks/next", "", map[string]string{"Authorization": "Bearer " + agentToken})
	obsVerify := decodeBody[controlplane.RuntimeCertificationTask](t, w)
	verifyChecks := []controlplane.RuntimeCheck{{Key: "durable-install-checkpoint", Status: "PASS"}}
	for i := 1; i <= 6; i++ {
		verifyChecks = append(verifyChecks, controlplane.RuntimeCheck{Key: fmt.Sprintf("verify/%d", i), Status: "PASS"})
	}
	for _, key := range []string{"nodes-ready", "cluster-dns-service", "kubernetes-api-tls", "target-runtime/metrics-query", "target-runtime/logs-push", "target-runtime/logs-query", "target-runtime/alert-fire", "target-runtime/alert-query"} {
		verifyChecks = append(verifyChecks, controlplane.RuntimeCheck{Key: key, Status: "PASS"})
	}
	// The authority rejects semantically incomplete success, even when every submitted check is PASS.
	tampered := append([]controlplane.RuntimeCheck(nil), verifyChecks[:len(verifyChecks)-1]...)
	tamperedResult, _ := json.Marshal(controlplane.RuntimeCertificationResult{Phase: obsVerify.Phase, TaskFenceToken: obsVerify.TaskFenceToken, Success: true, InventoryDigest: obsVerify.InventoryDigest, RenderedDigest: obsVerify.RenderedDigest, Checks: tampered})
	w = apiRequest(t, h, http.MethodPost, "/agent/v1/clusters/"+cluster.ID+"/runtime-certification-tasks/"+obsVerify.RunID+"/result", string(tamperedResult), map[string]string{"Authorization": "Bearer " + agentToken, "If-Match": fmt.Sprintf("\"%d\"", obsVerify.RunRevision)})
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "required runtime certification check") {
		t.Fatalf("tampered observability success accepted: %d %s", w.Code, w.Body.String())
	}
	obsVerifyResult, _ := json.Marshal(controlplane.RuntimeCertificationResult{Phase: obsVerify.Phase, TaskFenceToken: obsVerify.TaskFenceToken, Success: true, InventoryDigest: obsVerify.InventoryDigest, RenderedDigest: obsVerify.RenderedDigest, Checks: verifyChecks})
	w = apiRequest(t, h, http.MethodPost, "/agent/v1/clusters/"+cluster.ID+"/runtime-certification-tasks/"+obsVerify.RunID+"/result", string(obsVerifyResult), map[string]string{"Authorization": "Bearer " + agentToken, "If-Match": fmt.Sprintf("\"%d\"", obsVerify.RunRevision)})
	if w.Code != http.StatusOK {
		t.Fatalf("obs verify result=%d %s", w.Code, w.Body.String())
	}
	obsSucceeded := decodeBody[controlplane.RuntimeCertificationRun](t, w)
	if obsSucceeded.State != controlplane.RuntimeCertificationSucceeded || obsSucceeded.Profile != controlplane.RuntimeCertificationObservabilityV1 {
		t.Fatalf("observability did not succeed: %+v", obsSucceeded)
	}

	// TARGET_RUNTIME_V1 queues only when all executable capability surfaces are reported,
	// and the authority independently requires the complete storage/backup + observability check set.
	targetInventory := controlplane.ClusterInventory{ObservedAt: time.Now(), Distribution: "rke2", KubernetesVersion: "1.34.0", Digest: "sha256:" + strings.Repeat("8", 64), Capabilities: []string{controlplane.TargetMutationRBACActiveCapability, "cert.dns", "cert.tls", "cert.network", "cert.tenant-isolation", "cert.pvc", "cert.snapshot", "cert.backup", "cert.restore", "cert.metrics", "cert.logs", "cert.alerts"}}
	cluster, _, err = upsertMutationReadyInventoryForAPITest(t, store, ctx, cluster.ID, credentialDigest(agentToken), cluster.ExternalUID, targetInventory)
	if err != nil {
		t.Fatal(err)
	}
	body, _ = json.Marshal(map[string]any{"projectId": project.ID, "clusterId": cluster.ID, "catalogReleaseId": release.ID, "profile": "TARGET_RUNTIME_V1", "namespace": "4so-cert-target-executable"})
	w = apiRequest(t, h, http.MethodPost, "/api/v1/runtime-certifications", string(body), map[string]string{"X-Actor-ID": "owner", "Idempotency-Key": "target-run-executable-1"})
	if w.Code != http.StatusCreated {
		t.Fatalf("create executable target=%d %s", w.Code, w.Body.String())
	}
	var executableTarget struct {
		Run controlplane.RuntimeCertificationRun `json:"run"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &executableTarget); err != nil {
		t.Fatal(err)
	}
	if executableTarget.Run.State != controlplane.RuntimeCertificationQueued {
		t.Fatalf("target run not queued with complete capabilities: %+v", executableTarget.Run)
	}
	w = apiRequest(t, h, http.MethodGet, "/agent/v1/clusters/"+cluster.ID+"/runtime-certification-tasks/next", "", map[string]string{"Authorization": "Bearer " + agentToken})
	targetInstall := decodeBody[controlplane.RuntimeCertificationTask](t, w)
	targetInstallChecks := []controlplane.RuntimeCheck{{Key: "fresh-install-target", Status: "PASS"}}
	for i := 1; i <= 6; i++ {
		targetInstallChecks = append(targetInstallChecks, controlplane.RuntimeCheck{Key: fmt.Sprintf("apply/%d", i), Status: "PASS"})
	}
	targetInstallResult, _ := json.Marshal(controlplane.RuntimeCertificationResult{Phase: targetInstall.Phase, TaskFenceToken: targetInstall.TaskFenceToken, Success: true, InventoryDigest: targetInstall.InventoryDigest, RenderedDigest: targetInstall.RenderedDigest, Checks: targetInstallChecks})
	w = apiRequest(t, h, http.MethodPost, "/agent/v1/clusters/"+cluster.ID+"/runtime-certification-tasks/"+targetInstall.RunID+"/result", string(targetInstallResult), map[string]string{"Authorization": "Bearer " + agentToken, "If-Match": fmt.Sprintf("\"%d\"", targetInstall.RunRevision)})
	if w.Code != http.StatusOK {
		t.Fatalf("target install=%d %s", w.Code, w.Body.String())
	}
	w = apiRequest(t, h, http.MethodGet, "/agent/v1/clusters/"+cluster.ID+"/runtime-certification-tasks/next", "", map[string]string{"Authorization": "Bearer " + agentToken})
	targetVerify := decodeBody[controlplane.RuntimeCertificationTask](t, w)
	targetChecks := []controlplane.RuntimeCheck{{Key: "durable-install-checkpoint", Status: "PASS"}}
	for i := 1; i <= 6; i++ {
		targetChecks = append(targetChecks, controlplane.RuntimeCheck{Key: fmt.Sprintf("verify/%d", i), Status: "PASS"})
	}
	for _, key := range []string{"nodes-ready", "cluster-dns-service", "kubernetes-api-tls", "target-runtime/metrics-query", "target-runtime/logs-push", "target-runtime/logs-query", "target-runtime/alert-fire", "target-runtime/alert-query", "target-runtime/network-namespaces", "target-runtime/network-default-deny", "target-runtime/network-dns-tenant-a", "target-runtime/network-dns-tenant-b", "target-runtime/network-intra-tenant-allow", "target-runtime/network-cross-tenant-deny", "target-runtime/network-cross-tenant-explicit-allow", "target-runtime/pvc-bind", "target-runtime/pvc-io", "target-runtime/snapshot-create", "target-runtime/snapshot-restore-pvc", "target-runtime/snapshot-restore-io", "target-runtime/backup-create", "target-runtime/restore-validate"} {
		targetChecks = append(targetChecks, controlplane.RuntimeCheck{Key: key, Status: "PASS"})
	}
	// Omit the negative cross-tenant evidence once: TARGET must not certify without an active isolation proof.
	tamperedNetwork := make([]controlplane.RuntimeCheck, 0, len(targetChecks)-1)
	for _, item := range targetChecks {
		if item.Key != "target-runtime/network-cross-tenant-deny" {
			tamperedNetwork = append(tamperedNetwork, item)
		}
	}
	tamperedNetworkResult, _ := json.Marshal(controlplane.RuntimeCertificationResult{Phase: targetVerify.Phase, TaskFenceToken: targetVerify.TaskFenceToken, Success: true, InventoryDigest: targetVerify.InventoryDigest, RenderedDigest: targetVerify.RenderedDigest, Checks: tamperedNetwork})
	w = apiRequest(t, h, http.MethodPost, "/agent/v1/clusters/"+cluster.ID+"/runtime-certification-tasks/"+targetVerify.RunID+"/result", string(tamperedNetworkResult), map[string]string{"Authorization": "Bearer " + agentToken, "If-Match": fmt.Sprintf("\"%d\"", targetVerify.RunRevision)})
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "target-runtime/network-cross-tenant-deny") {
		t.Fatalf("target success without negative isolation evidence accepted: %d %s", w.Code, w.Body.String())
	}

	// Omit restore-validate once: the server must reject a semantically incomplete success.
	tamperedTarget, _ := json.Marshal(controlplane.RuntimeCertificationResult{Phase: targetVerify.Phase, TaskFenceToken: targetVerify.TaskFenceToken, Success: true, InventoryDigest: targetVerify.InventoryDigest, RenderedDigest: targetVerify.RenderedDigest, Checks: targetChecks[:len(targetChecks)-1]})
	w = apiRequest(t, h, http.MethodPost, "/agent/v1/clusters/"+cluster.ID+"/runtime-certification-tasks/"+targetVerify.RunID+"/result", string(tamperedTarget), map[string]string{"Authorization": "Bearer " + agentToken, "If-Match": fmt.Sprintf("\"%d\"", targetVerify.RunRevision)})
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "target-runtime/restore-validate") {
		t.Fatalf("incomplete target success accepted: %d %s", w.Code, w.Body.String())
	}
	targetVerifyResult, _ := json.Marshal(controlplane.RuntimeCertificationResult{Phase: targetVerify.Phase, TaskFenceToken: targetVerify.TaskFenceToken, Success: true, InventoryDigest: targetVerify.InventoryDigest, RenderedDigest: targetVerify.RenderedDigest, Checks: targetChecks})
	w = apiRequest(t, h, http.MethodPost, "/agent/v1/clusters/"+cluster.ID+"/runtime-certification-tasks/"+targetVerify.RunID+"/result", string(targetVerifyResult), map[string]string{"Authorization": "Bearer " + agentToken, "If-Match": fmt.Sprintf("\"%d\"", targetVerify.RunRevision)})
	if w.Code != http.StatusOK {
		t.Fatalf("target verify=%d %s", w.Code, w.Body.String())
	}
	targetSucceeded := decodeBody[controlplane.RuntimeCertificationRun](t, w)
	if targetSucceeded.State != controlplane.RuntimeCertificationSucceeded || targetSucceeded.Profile != controlplane.RuntimeCertificationTargetV1 || targetSucceeded.EvidenceDigest == "" {
		t.Fatalf("target did not succeed: %+v", targetSucceeded)
	}

	w = apiRequest(t, h, http.MethodPost, "/api/v1/runtime-certifications/"+succeeded.ID+"/revoke", `{}`, map[string]string{"X-Actor-ID": "owner", "If-Match": fmt.Sprintf("\"%d\"", succeeded.Revision)})
	if w.Code != http.StatusOK {
		t.Fatalf("revoke=%d %s", w.Code, w.Body.String())
	}
	revoked := decodeBody[controlplane.RuntimeCertificationRun](t, w)
	if revoked.State != controlplane.RuntimeCertificationRevoked || revoked.RevokedAt == nil {
		t.Fatalf("bad revoke: %+v", revoked)
	}
}

func containsAll(s string, parts ...string) bool {
	for _, p := range parts {
		if !strings.Contains(s, p) {
			return false
		}
	}
	return true
}
