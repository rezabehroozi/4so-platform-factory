package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"platform.4so.io/factory/catalog"
	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/domain"
	"platform.4so.io/factory/internal/integrations"
	"strings"
	"testing"
	"time"
)

func testServer(t *testing.T) *Server {
	t.Helper()
	cs, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	return New("test", cs, slog.New(slog.NewTextHandler(io.Discard, nil)))
}
func TestHealth(t *testing.T) {
	s := testServer(t)
	r := httptest.NewRequest("GET", "/healthz", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("status=%d", w.Code)
	}
	if w.Header().Get("X-Request-ID") == "" {
		t.Fatal("request id missing")
	}
}
func TestReadyAndSecurityHeaders(t *testing.T) {
	s := testServer(t)
	r := httptest.NewRequest("GET", "/readyz", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("status=%d", w.Code)
	}
	for _, h := range []string{"X-Content-Type-Options", "Content-Security-Policy", "Permissions-Policy", "Cache-Control"} {
		if w.Header().Get(h) == "" {
			t.Fatalf("security header %s missing", h)
		}
	}
}
func TestCatalogSummary(t *testing.T) {
	s := testServer(t)
	r := httptest.NewRequest("GET", "/api/v1/catalog/summary", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("status=%d", w.Code)
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["digest"] == "" {
		t.Fatal("catalog digest missing")
	}
	admission, ok := got["upstreamAdmission"].(map[string]any)
	if !ok {
		t.Fatal("upstream admission summary missing")
	}
	if admission["total"].(float64) < 1 || admission["readyForAcquisition"].(float64) < 1 {
		t.Fatalf("upstream admission summary is empty: %+v", admission)
	}
	rows, ok := admission["components"].([]any)
	if !ok || len(rows) != int(admission["total"].(float64)) {
		t.Fatalf("upstream admission rows mismatch: %+v", admission)
	}
	runtimeAuthority, ok := got["runtimeCertificationAuthority"].(map[string]any)
	if !ok || runtimeAuthority["authority"] != catalog.ComponentRuntimeCertificationAuthority {
		t.Fatalf("runtime certification authority missing: %+v", got)
	}
	stats, ok := runtimeAuthority["stats"].(map[string]any)
	if !ok || stats["total"] != float64(20) || stats["sourceReady"] != float64(3) || stats["lifecycleComplete"] != float64(0) {
		t.Fatalf("runtime certification stats drift: %+v", runtimeAuthority)
	}
}

func TestComponentRuntimeCertificationAuthority(t *testing.T) {
	s := testServer(t)
	r := httptest.NewRequest("GET", "/api/v1/catalog/runtime-certification-authority", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var got struct {
		Authority         string                                          `json:"authority"`
		Stats             catalog.ComponentRuntimeCertificationStats      `json:"stats"`
		Components        []catalog.ComponentRuntimeCertificationContract `json:"components"`
		ProductionReady   bool                                            `json:"productionReady"`
		PhysicalCertified bool                                            `json:"physicalCertified"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Authority != catalog.ComponentRuntimeCertificationAuthority || got.Stats.Total != 20 || got.Stats.SourceReady != 3 || got.Stats.LifecycleComplete != 0 || len(got.Components) != 20 || got.ProductionReady || got.PhysicalCertified {
		t.Fatalf("unexpected component runtime authority: %#v", got)
	}
}
func TestPlanIsHonestPlanningOnly(t *testing.T) {
	s := testServer(t)
	raw, err := os.ReadFile("../../blueprints/enterprise-private-cloud.json")
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/api/v1/plans", bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/json; charset=utf-8")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 201 {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var p domain.DeploymentPlan
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if p.Executable || p.Status != "planning-only" || len(p.Blockers) == 0 {
		t.Fatalf("unexpected plan %#v", p)
	}
	if p.BlueprintDigest == "" || p.CatalogDigest == "" {
		t.Fatal("plan digests missing")
	}
}
func TestRejectUnknownJSONField(t *testing.T) {
	s := testServer(t)
	r := httptest.NewRequest("POST", "/api/v1/blueprints/validate", bytes.NewBufferString(`{"unknown":true}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatalf("status=%d", w.Code)
	}
}
func TestRejectWrongContentType(t *testing.T) {
	s := testServer(t)
	r := httptest.NewRequest("POST", "/api/v1/blueprints/validate", bytes.NewBufferString(`{}`))
	r.Header.Set("Content-Type", "application/yaml")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatalf("status=%d", w.Code)
	}
}
func TestRejectOversizedBody(t *testing.T) {
	s := testServer(t)
	body := strings.NewReader(strings.Repeat(" ", (2<<20)+32))
	r := httptest.NewRequest("POST", "/api/v1/blueprints/validate", body)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatalf("status=%d", w.Code)
	}
}

func TestDurableControlPlaneHTTPWorkflow(t *testing.T) {
	s := testServer(t)
	create := func(path string, body string, headers map[string]string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", path, bytes.NewBufferString(body))
		r.Header.Set("Content-Type", "application/json")
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}
	w := create("/api/v1/organizations", `{"name":"acme","displayName":"Acme"}`, map[string]string{"X-Actor-ID": "user-1"})
	if w.Code != http.StatusCreated {
		t.Fatalf("organization status=%d body=%s", w.Code, w.Body.String())
	}
	var org controlplane.Organization
	if err := json.Unmarshal(w.Body.Bytes(), &org); err != nil {
		t.Fatal(err)
	}
	if w.Header().Get("ETag") != "\"1\"" {
		t.Fatalf("etag=%q", w.Header().Get("ETag"))
	}
	w = create("/api/v1/projects", fmt.Sprintf(`{"organizationId":%q,"name":"platform","displayName":"Platform"}`, org.ID), map[string]string{"X-Actor-ID": "user-1"})
	if w.Code != http.StatusCreated {
		t.Fatalf("project status=%d body=%s", w.Code, w.Body.String())
	}
	var prj controlplane.Project
	if err := json.Unmarshal(w.Body.Bytes(), &prj); err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(`{"projectId":%q,"kind":"blueprint.plan","targetRef":"cluster/demo","desiredRevision":"sha256:abc","risk":"high"}`, prj.ID)
	headers := map[string]string{"X-Actor-ID": "user-1", "Idempotency-Key": "stable-key"}
	w = create("/api/v1/operations", body, headers)
	if w.Code != http.StatusCreated {
		t.Fatalf("operation status=%d body=%s", w.Code, w.Body.String())
	}
	var op controlplane.Operation
	if err := json.Unmarshal(w.Body.Bytes(), &op); err != nil {
		t.Fatal(err)
	}
	w = create("/api/v1/operations", body, headers)
	if w.Code != http.StatusOK || w.Header().Get("Idempotent-Replay") != "true" {
		t.Fatalf("replay status=%d header=%q body=%s", w.Code, w.Header().Get("Idempotent-Replay"), w.Body.String())
	}
	r := httptest.NewRequest("GET", "/api/v1/operations/"+op.ID, nil)
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("get operation status=%d", w.Code)
	}
	r = httptest.NewRequest("GET", "/api/v1/control-plane/summary", nil)
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("summary status=%d", w.Code)
	}
}

func TestOrganizationExpectedRevision(t *testing.T) {
	s := testServer(t)
	r := httptest.NewRequest("POST", "/api/v1/organizations", bytes.NewBufferString(`{"name":"acme","displayName":"Acme"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Actor-ID", "actor")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	var org controlplane.Organization
	_ = json.Unmarshal(w.Body.Bytes(), &org)
	r = httptest.NewRequest("PUT", "/api/v1/organizations/"+org.ID, bytes.NewBufferString(`{"name":"acme","displayName":"New"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Actor-ID", "actor")
	r.Header.Set("If-Match", "\"99\"")
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestInstallationProfilesExposeDefaultStandardHA(t *testing.T) {
	s := testServer(t)
	r := httptest.NewRequest("GET", "/api/v1/installations/profiles", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var profiles []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &profiles); err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 3 {
		t.Fatalf("profiles=%d", len(profiles))
	}
	found := false
	for _, p := range profiles {
		if p["id"] == "production-standard-ha" && p["default"] == true {
			found = true
		}
	}
	if !found {
		t.Fatal("default production-standard-ha profile missing")
	}
}

func TestInstallationPlanDefaultsToManagedGitAndRegistryAndNeverExecutes(t *testing.T) {
	s := testServer(t)
	body := `{
	  "profileId":"production-standard-ha",
	  "connectivity":"connected",
	  "infrastructure":{"provider":"existing-hosts","existingCluster":false,"nodeAddresses":["10.0.0.1","10.0.0.2","10.0.0.3"],"credentialRef":"secret://infra/admin"},
	  "network":{"publicEndpoint":"https://platform.example.test","dnsZone":"example.test","tlsMode":"managed-acme"},
	  "services":{
	    "git":{},
	    "registry":{},
	    "database":{},
	    "objectStorage":{"mode":"external","provider":"s3-compatible","url":"https://s3.example.test","credentialRef":"secret://storage/backup"},
	    "identity":{"adminEmail":"admin@example.test"}
	  },
	  "acceptRisk":true
	}`
	r := httptest.NewRequest("POST", "/api/v1/installations/plans", bytes.NewBufferString(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var result map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	services := result["effectiveServices"].(map[string]any)
	git := services["git"].(map[string]any)
	registry := services["registry"].(map[string]any)
	if git["mode"] != "managed-internal" || git["provider"] != "forgejo" {
		t.Fatalf("git=%v", git)
	}
	if registry["mode"] != "managed-internal" || registry["provider"] != "zot" {
		t.Fatalf("registry=%v", registry)
	}
	if result["executable"] != false || result["status"] != "planning-only" {
		t.Fatalf("result=%v", result)
	}
	if result["authorityGate"] != "blocked-pending-postgresql-runtime" {
		t.Fatalf("gate=%v", result["authorityGate"])
	}
}

func TestSystemServicesEndpoint(t *testing.T) {
	forgejo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/version" {
			_ = json.NewEncoder(w).Encode(map[string]string{"version": "15.0.5"})
			return
		}
		http.NotFound(w, r)
	}))
	defer forgejo.Close()
	zot := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/" {
			w.Header().Set("Docker-Distribution-Api-Version", "registry/2.0")
			w.WriteHeader(http.StatusOK)
			return
		}
		http.NotFound(w, r)
	}))
	defer zot.Close()
	s := testServer(t)
	s.ConfigureSystemServices(integrations.New(integrations.Config{GitConnectionResolver: func(context.Context) (integrations.GitConnection, error) {
		return integrations.GitConnection{ProviderID: "gitp_test", ProviderName: "test", BaseURL: forgejo.URL, CredentialID: "gitcred_test", Username: "admin", SecretRef: "env://PF_TEST_FORGEJO_PASSWORD"}, nil
	}, ZotURL: zot.URL}))
	r := httptest.NewRequest(http.MethodGet, "/api/v1/system-services", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var statuses []integrations.ServiceStatus
	if err := json.Unmarshal(w.Body.Bytes(), &statuses); err != nil {
		t.Fatal(err)
	}
	if len(statuses) != 4 || !statuses[0].Healthy || !statuses[1].Healthy || statuses[2].Configured {
		t.Fatalf("statuses=%+v", statuses)
	}
}

func TestSecureClusterImportAndReadOnlyInventoryWorkflow(t *testing.T) {
	s := testServer(t)
	s.ConfigureFleetImport("registry.local/platform-agent@sha256:"+strings.Repeat("9", 64), "registry.local/platform-probe@sha256:"+strings.Repeat("8", 64), "https://platform.example.test", "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----")
	post := func(path, body string, headers map[string]string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(body))
		r.Header.Set("Content-Type", "application/json")
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}
	w := post("/api/v1/organizations", `{"name":"fleet","displayName":"Fleet"}`, map[string]string{"X-Actor-ID": "admin"})
	if w.Code != http.StatusCreated {
		t.Fatalf("organization: %d %s", w.Code, w.Body.String())
	}
	var org controlplane.Organization
	_ = json.Unmarshal(w.Body.Bytes(), &org)
	w = post("/api/v1/projects", fmt.Sprintf(`{"organizationId":%q,"name":"clusters","displayName":"Clusters"}`, org.ID), map[string]string{"X-Actor-ID": "admin"})
	if w.Code != http.StatusCreated {
		t.Fatalf("project: %d %s", w.Code, w.Body.String())
	}
	var project controlplane.Project
	_ = json.Unmarshal(w.Body.Bytes(), &project)
	w = post("/api/v1/cluster-imports", fmt.Sprintf(`{"projectId":%q,"name":"edge-1","displayName":"Edge 1"}`, project.ID), map[string]string{"X-Actor-ID": "operator"})
	if w.Code != http.StatusCreated {
		t.Fatalf("create import: %d %s", w.Code, w.Body.String())
	}
	var created struct {
		Import          controlplane.ClusterImport `json:"import"`
		EnrollmentToken string                     `json:"enrollmentToken"`
		Manifest        string                     `json:"manifest"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Import.AgentServiceAccount == "" || created.Import.AgentServiceAccount != controlplane.FleetAgentServiceAccountName(created.Import.ID) || !strings.Contains(created.Manifest, "serviceAccountName: "+created.Import.AgentServiceAccount) {
		t.Fatalf("cluster import did not persist/render the import-scoped agent principal: %+v", created)
	}
	if created.Import.State != controlplane.ClusterImportPendingApproval || created.EnrollmentToken == "" || !strings.Contains(created.Manifest, "platform-agent@sha256:") || !strings.Contains(created.Manifest, "4so-platform-agent-credential") || !strings.Contains(created.Manifest, "https://platform.example.test") || !strings.Contains(created.Manifest, "4so-platform-agent-readonly") || !strings.Contains(created.Manifest, `resources: ["clusterversions"]`) || !strings.Contains(created.Manifest, `resources: ["pods"]`) || !strings.Contains(created.Manifest, "strategy:\n    type: Recreate") || strings.Contains(created.Manifest, "4so-platform-baseline-manager") || strings.Contains(created.Manifest, "4so-platform-provider-manager") || strings.Contains(created.Manifest, "4so-platform-agent-maintenance-manager") || strings.Contains(created.Manifest, "4so-platform-agent-tenant-manager") || strings.Contains(created.Manifest, "kubeconfig") || strings.Contains(created.Manifest, `resources: ["*"]`) || strings.Contains(created.Manifest, "cluster-admin") {
		t.Fatalf("initial import manifest is not read-only: %+v", created)
	}
	w = post("/api/v1/cluster-imports/"+created.Import.ID+"/approve", `{}`, map[string]string{"X-Actor-ID": "approver", "X-Actor-Role": "platform-admin", "If-Match": "\"1\""})
	if w.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", w.Code, w.Body.String())
	}
	claimBody := fmt.Sprintf(`{"token":%q,"externalUid":"cluster-uid-1","agentVersion":"0.0.14"}`, created.EnrollmentToken)
	w = post("/agent/v1/cluster-imports/"+created.Import.ID+"/claim", claimBody, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("claim: %d %s", w.Code, w.Body.String())
	}
	var claimed struct {
		Cluster    controlplane.ManagedCluster `json:"cluster"`
		AgentToken string                      `json:"agentToken"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &claimed); err != nil {
		t.Fatal(err)
	}
	if claimed.Cluster.ID == "" || claimed.AgentToken == "" {
		t.Fatalf("claimed=%+v", claimed)
	}
	inventory := `{"observedAt":"2026-08-06T00:00:00Z","externalUid":"cluster-uid-1","distribution":"rke2","kubernetesVersion":"v1.34.1+rke2r1","nodes":[{"name":"node-1","uid":"node-uid","roles":["control-plane"],"os":"Ubuntu","architecture":"amd64","kubeletVersion":"v1.34.1+rke2r1","ready":true}],"addOns":[{"name":"cilium","namespace":"kube-system","version":"1.18","healthy":true}],"networking":{"cni":"cilium","gatewayApi":false},"capabilities":["read-only-inventory","outbound-agent","target-enrollment-principal-isolated","controlled-baseline-deployment","cni-inventory","runtime-probe-image-digest-pinned","api-surface-inventory","crd-inventory","openapi-schema-authority","strict-schema-dry-run"],"apiResources":[{"apiVersion":"v1","version":"v1","kind":"ResourceQuota","resource":"resourcequotas","namespaced":true,"verbs":["get","list","patch"]},{"apiVersion":"v1","version":"v1","kind":"LimitRange","resource":"limitranges","namespaced":true,"verbs":["get","list","patch"]},{"apiVersion":"v1","version":"v1","kind":"ServiceAccount","resource":"serviceaccounts","namespaced":true,"verbs":["get","list","patch"]},{"apiVersion":"v1","version":"v1","kind":"ConfigMap","resource":"configmaps","namespaced":true,"verbs":["get","list","patch"]},{"apiVersion":"networking.k8s.io/v1","group":"networking.k8s.io","version":"v1","kind":"NetworkPolicy","resource":"networkpolicies","namespaced":true,"verbs":["get","list","patch"]}],"crds":[],"apiDiscoveryComplete":true,"crdDiscoveryComplete":true,"schemaDiscoveryVersion":"OPENAPI_V3","schemaDiscoveryDigest":"sha256:9999999999999999999999999999999999999999999999999999999999999999","schemaDiscoveryComplete":true}`
	inventory = strings.Replace(inventory, "2026-08-06T00:00:00Z", time.Now().UTC().Format(time.RFC3339Nano), 1)
	legacyInventory := strings.Replace(inventory, `"externalUid":"cluster-uid-1",`, "", 1)
	w = post("/agent/v1/clusters/"+claimed.Cluster.ID+"/inventory", legacyInventory, map[string]string{"Authorization": "Bearer " + claimed.AgentToken})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"identityContinuityVerified":false`) || strings.Contains(w.Body.String(), `"target-mutation-rbac-active"`) {
		t.Fatalf("legacy inventory must remain observable but read-only: %d %s", w.Code, w.Body.String())
	}
	r := httptest.NewRequest(http.MethodGet, "/api/v1/clusters/"+claimed.Cluster.ID+"/mutation-rbac-manifest", nil)
	r.Header.Set("X-Actor-ID", "operator")
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusConflict {
		t.Fatalf("mutation activation was issued without identity continuity attestation: %d %s", w.Code, w.Body.String())
	}
	mismatchedInventory := strings.Replace(inventory, `"externalUid":"cluster-uid-1"`, `"externalUid":"other-cluster-uid"`, 1)
	w = post("/agent/v1/clusters/"+claimed.Cluster.ID+"/inventory", mismatchedInventory, map[string]string{"Authorization": "Bearer " + claimed.AgentToken})
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "CLUSTER_IDENTITY_MISMATCH") {
		t.Fatalf("mismatched physical cluster identity was accepted: %d %s", w.Code, w.Body.String())
	}
	w = post("/agent/v1/clusters/"+claimed.Cluster.ID+"/heartbeat", `{"agentVersion":"0.0.205","externalUid":"other-cluster-uid"}`, map[string]string{"Authorization": "Bearer " + claimed.AgentToken})
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "CLUSTER_IDENTITY_MISMATCH") {
		t.Fatalf("mismatched heartbeat physical identity was accepted: %d %s", w.Code, w.Body.String())
	}
	w = post("/agent/v1/clusters/"+claimed.Cluster.ID+"/inventory", inventory, map[string]string{"Authorization": "Bearer " + claimed.AgentToken})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"identityContinuityVerified":true`) {
		t.Fatalf("identity-attested inventory: %d %s", w.Code, w.Body.String())
	}
	forgedActivatedInventory := strings.Replace(inventory, `"capabilities":[`, `"capabilities":["target-mutation-rbac-active","target-mutation-rbac-activation-issued",`, 1)
	w = post("/agent/v1/clusters/"+claimed.Cluster.ID+"/inventory", forgedActivatedInventory, map[string]string{"Authorization": "Bearer " + claimed.AgentToken})
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), `"target-mutation-rbac-active"`) || strings.Contains(w.Body.String(), `"target-mutation-rbac-activation-issued"`) {
		t.Fatalf("agent self-authorized mutation before server issuance: %d %s", w.Code, w.Body.String())
	}
	r = httptest.NewRequest(http.MethodGet, "/api/v1/clusters/"+claimed.Cluster.ID, nil)
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"mutationEnabled":false`) || !strings.Contains(w.Body.String(), `"mutationRBACActivationIssued":false`) || !strings.Contains(w.Body.String(), `"mutationRBACActivationRequired":true`) || !strings.Contains(w.Body.String(), `"mutationRBACProofPending":false`) || !strings.Contains(w.Body.String(), `"distribution":"rke2"`) {
		t.Fatalf("cluster before RBAC activation: %d %s", w.Code, w.Body.String())
	}
	// GET is intentionally read-only. Before explicit issuance it must not create
	// mutation authority as a side effect of a cache/prefetch/read request.
	r = httptest.NewRequest(http.MethodGet, "/api/v1/clusters/"+claimed.Cluster.ID+"/mutation-rbac-manifest", nil)
	r.Header.Set("X-Actor-ID", "operator")
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "TARGET_MUTATION_ACTIVATION_NOT_ISSUED") {
		t.Fatalf("read-only activation lookup unexpectedly issued authority: %d %s", w.Code, w.Body.String())
	}
	r = httptest.NewRequest(http.MethodGet, "/api/v1/clusters/"+claimed.Cluster.ID, nil)
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"mutationRBACActivationRequired":true`) {
		t.Fatalf("GET activation lookup mutated cluster authority: %d %s", w.Code, w.Body.String())
	}
	r = httptest.NewRequest(http.MethodPost, "/api/v1/clusters/"+claimed.Cluster.ID+"/mutation-rbac-manifest", bytes.NewBufferString(`{}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Actor-ID", "operator")
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"activationIssued":true`) || !strings.Contains(w.Body.String(), "4so-platform-baseline-manager") || !strings.Contains(w.Body.String(), "4so-platform-provider-manager") || !strings.Contains(w.Body.String(), "4so-platform-agent-maintenance-manager") || !strings.Contains(w.Body.String(), "4so-platform-agent-tenant-manager") || !strings.Contains(w.Body.String(), "4so-platform-mutation-activation") || !strings.Contains(w.Body.String(), "cluster-uid-1") {
		t.Fatalf("mutation activation issuance: %d %s", w.Code, w.Body.String())
	}
	r = httptest.NewRequest(http.MethodGet, "/api/v1/clusters/"+claimed.Cluster.ID, nil)
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"mutationEnabled":false`) || !strings.Contains(w.Body.String(), `"mutationRBACActivationIssued":true`) || !strings.Contains(w.Body.String(), `"mutationRBACActivationRequired":false`) || !strings.Contains(w.Body.String(), `"mutationRBACProofPending":true`) {
		t.Fatalf("issued activation without agent proof was not represented truthfully: %d %s", w.Code, w.Body.String())
	}
	// Once issued, GET may retrieve the exact current manifest but still has no
	// authority side effect of its own.
	r = httptest.NewRequest(http.MethodGet, "/api/v1/clusters/"+claimed.Cluster.ID+"/mutation-rbac-manifest", nil)
	r.Header.Set("X-Actor-ID", "operator")
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"activationIssued":true`) {
		t.Fatalf("issued mutation activation manifest was not retrievable: %d %s", w.Code, w.Body.String())
	}
	activatedInventory := strings.Replace(inventory, `"capabilities":[`, `"capabilities":["target-mutation-rbac-active",`, 1)
	w = post("/agent/v1/clusters/"+claimed.Cluster.ID+"/inventory", activatedInventory, map[string]string{"Authorization": "Bearer " + claimed.AgentToken})
	if w.Code != http.StatusOK {
		t.Fatalf("activated inventory: %d %s", w.Code, w.Body.String())
	}
	r = httptest.NewRequest(http.MethodGet, "/api/v1/clusters/"+claimed.Cluster.ID, nil)
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"mutationEnabled":true`) || !strings.Contains(w.Body.String(), `"mutationRBACActivationIssued":true`) || !strings.Contains(w.Body.String(), `"mutationRBACProofPending":false`) {
		t.Fatalf("cluster after RBAC activation: %d %s", w.Code, w.Body.String())
	}
	w = post("/agent/v1/clusters/"+claimed.Cluster.ID+"/inventory", activatedInventory, map[string]string{"Authorization": "Bearer wrong-token-value-that-is-long-enough"})
	if w.Code == http.StatusOK {
		t.Fatal("wrong agent token accepted")
	}

	deploymentBody := fmt.Sprintf(`{"projectId":%q,"clusterId":%q,"baselineId":"secure-namespace-foundation"}`, project.ID, claimed.Cluster.ID)
	w = post("/api/v1/baseline-deployments", deploymentBody, map[string]string{"X-Actor-ID": "operator", "Idempotency-Key": "baseline-edge-1"})
	if w.Code != http.StatusCreated {
		t.Fatalf("deployment create: %d %s", w.Code, w.Body.String())
	}
	var createdDeployment struct {
		Deployment controlplane.BaselineDeployment `json:"deployment"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &createdDeployment); err != nil {
		t.Fatal(err)
	}
	d := createdDeployment.Deployment
	getTask := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/agent/v1/clusters/"+claimed.Cluster.ID+"/baseline-tasks/next", nil)
		r.Header.Set("Authorization", "Bearer "+claimed.AgentToken)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}
	w = getTask()
	if w.Code != http.StatusOK {
		t.Fatalf("plan task: %d %s", w.Code, w.Body.String())
	}
	var planTask controlplane.BaselineTask
	if err := json.Unmarshal(w.Body.Bytes(), &planTask); err != nil {
		t.Fatal(err)
	}
	if planTask.Action != "PLAN" || len(planTask.Resources) != 5 || planTask.DeploymentRev <= d.Revision {
		t.Fatalf("plan task=%+v", planTask)
	}
	changes := []controlplane.BaselinePlanChange{{Resource: "ConfigMap/4so-baseline-revision", Action: "ADD", Desired: d.DesiredDigest}}
	impactRaw, _ := json.Marshal(apiTestPlanningImpactForTask(planTask, changes))
	planResult := fmt.Sprintf(`{"action":"PLAN","success":true,"taskFenceToken":%d,"changes":[{"resource":"ConfigMap/4so-baseline-revision","action":"ADD","desiredDigest":%q}],"impact":%s}`, planTask.TaskFenceToken, d.DesiredDigest, string(impactRaw))
	w = post("/agent/v1/clusters/"+claimed.Cluster.ID+"/baseline-tasks/"+d.ID+"/result", planResult, map[string]string{"Authorization": "Bearer " + claimed.AgentToken, "If-Match": fmt.Sprintf("\"%d\"", planTask.DeploymentRev)})
	if w.Code != http.StatusOK {
		t.Fatalf("plan result: %d %s", w.Code, w.Body.String())
	}
	var planned controlplane.BaselineDeployment
	_ = json.Unmarshal(w.Body.Bytes(), &planned)
	if planned.State != controlplane.BaselineDeploymentAwaitingApproval {
		t.Fatalf("planned=%+v", planned)
	}
	w = post("/api/v1/baseline-deployments/"+d.ID+"/approve", `{}`, map[string]string{"X-Actor-ID": "approver", "X-Actor-Role": "platform-admin", "If-Match": fmt.Sprintf("\"%d\"", planned.Revision)})
	if w.Code != http.StatusOK {
		t.Fatalf("deployment approve: %d %s", w.Code, w.Body.String())
	}
	w = getTask()
	if w.Code != http.StatusOK {
		t.Fatalf("apply task: %d %s", w.Code, w.Body.String())
	}
	var applyTask controlplane.BaselineTask
	_ = json.Unmarshal(w.Body.Bytes(), &applyTask)
	if applyTask.Action != "APPLY" || applyTask.DeploymentRev < 4 {
		t.Fatalf("apply task=%+v", applyTask)
	}
	applyResult := apiTestApplyResultJSON(applyTask)
	w = post("/agent/v1/clusters/"+claimed.Cluster.ID+"/baseline-tasks/"+d.ID+"/result", applyResult, map[string]string{"Authorization": "Bearer " + claimed.AgentToken, "If-Match": fmt.Sprintf("\"%d\"", applyTask.DeploymentRev)})
	if w.Code != http.StatusOK {
		t.Fatalf("apply result: %d %s", w.Code, w.Body.String())
	}
	var applied controlplane.BaselineDeployment
	_ = json.Unmarshal(w.Body.Bytes(), &applied)
	if applied.State != controlplane.BaselineDeploymentSucceeded {
		t.Fatalf("applied=%+v", applied)
	}
	if len(applied.Evidence) == 0 || applied.EvidenceDigest == "" {
		t.Fatalf("completion evidence missing: %+v", applied)
	}
	evidencePath := applied.Evidence[0].Location
	r = httptest.NewRequest(http.MethodGet, evidencePath, nil)
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK || w.Header().Get("X-Evidence-Digest") != applied.Evidence[0].Digest || w.Header().Get("X-Evidence-Authority") != applied.Evidence[0].Authority || !strings.Contains(w.Body.String(), `"status":"PASS"`) {
		t.Fatalf("evidence payload: %d headers=%v body=%s", w.Code, w.Header(), w.Body.String())
	}
	verificationBody := fmt.Sprintf(`{"projectId":%q,"clusterId":%q,"baselineDeploymentId":%q}`, project.ID, claimed.Cluster.ID, d.ID)
	w = post("/api/v1/runtime-verifications", verificationBody, map[string]string{"X-Actor-ID": "operator", "Idempotency-Key": "verify-edge-1"})
	if w.Code != http.StatusCreated {
		t.Fatalf("verification create: %d %s", w.Code, w.Body.String())
	}
	var verificationCreated struct {
		Verification controlplane.RuntimeVerification `json:"verification"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &verificationCreated)
	r = httptest.NewRequest(http.MethodGet, "/agent/v1/clusters/"+claimed.Cluster.ID+"/runtime-verification-tasks/next", nil)
	r.Header.Set("Authorization", "Bearer "+claimed.AgentToken)
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("verification task: %d %s", w.Code, w.Body.String())
	}
	var verificationTask controlplane.RuntimeVerificationTask
	_ = json.Unmarshal(w.Body.Bytes(), &verificationTask)
	if verificationTask.ProbeImage == "" || verificationTask.DesiredDigest != applied.DesiredDigest {
		t.Fatalf("verification task=%+v", verificationTask)
	}
	verificationResult := fmt.Sprintf(`{"success":true,"taskFenceToken":%d,"observedDigest":%q,"checks":[{"key":"nodes-ready","status":"PASS"},{"key":"baseline-digest-equality","status":"PASS"},{"key":"probe-job-completed","status":"PASS"},{"key":"cluster-dns","status":"PASS"},{"key":"kubernetes-api-service-tcp","status":"PASS"}]}`, verificationTask.TaskFenceToken, applied.DesiredDigest)
	w = post("/agent/v1/clusters/"+claimed.Cluster.ID+"/runtime-verification-tasks/"+verificationTask.VerificationID+"/result", verificationResult, map[string]string{"Authorization": "Bearer " + claimed.AgentToken, "If-Match": fmt.Sprintf("\"%d\"", verificationTask.VerificationRevision)})
	if w.Code != http.StatusOK {
		t.Fatalf("verification result: %d %s", w.Code, w.Body.String())
	}
	var verified controlplane.RuntimeVerification
	_ = json.Unmarshal(w.Body.Bytes(), &verified)
	if verified.State != controlplane.RuntimeVerificationSucceeded || verified.ReportDigest == "" {
		t.Fatalf("verified=%+v", verified)
	}
	r = httptest.NewRequest(http.MethodGet, "/api/v1/runtime-verifications/"+verified.ID+"/report", nil)
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"runtimeVerified":true`) {
		t.Fatalf("report: %d %s", w.Code, w.Body.String())
	}
	cp, err := s.store.CreateRecoveryCheckpoint(context.Background(), controlplane.RecoveryCheckpoint{ProjectID: project.ID, ClusterID: claimed.Cluster.ID, Provider: "s3", Reference: "baseline-rollback-backup", EvidenceDigest: "sha256:" + strings.Repeat("b", 64), CompletedAt: time.Now().Add(-5 * time.Minute), ExpiresAt: time.Now().Add(4 * time.Hour)}, "operator")
	if err != nil {
		t.Fatalf("recovery checkpoint: %v", err)
	}
	w = post("/api/v1/baseline-deployments/"+d.ID+"/rollback", fmt.Sprintf(`{"recoveryCheckpointId":%q}`, cp.ID), map[string]string{"X-Actor-ID": "operator", "If-Match": fmt.Sprintf("\"%d\"", applied.Revision)})
	if w.Code != http.StatusAccepted {
		t.Fatalf("rollback queue: %d %s", w.Code, w.Body.String())
	}
	w = getTask()
	if w.Code != http.StatusOK {
		t.Fatalf("rollback task: %d %s", w.Code, w.Body.String())
	}
	var rollbackTask controlplane.BaselineTask
	_ = json.Unmarshal(w.Body.Bytes(), &rollbackTask)
	if rollbackTask.Action != "ROLLBACK" {
		t.Fatalf("rollback task=%+v", rollbackTask)
	}
	w = post("/agent/v1/clusters/"+claimed.Cluster.ID+"/baseline-tasks/"+d.ID+"/result", fmt.Sprintf(`{"action":"ROLLBACK","success":true,"taskFenceToken":%d}`, rollbackTask.TaskFenceToken), map[string]string{"Authorization": "Bearer " + claimed.AgentToken, "If-Match": fmt.Sprintf("\"%d\"", rollbackTask.DeploymentRev)})
	if w.Code != http.StatusOK {
		t.Fatalf("rollback result: %d %s", w.Code, w.Body.String())
	}
	var rolled controlplane.BaselineDeployment
	_ = json.Unmarshal(w.Body.Bytes(), &rolled)
	if rolled.State != controlplane.BaselineDeploymentRolledBack {
		t.Fatalf("rolled=%+v", rolled)
	}
	currentCluster, err := s.store.GetManagedCluster(context.Background(), claimed.Cluster.ID)
	if err != nil {
		t.Fatal(err)
	}
	w = post("/api/v1/clusters/"+claimed.Cluster.ID+"/revoke", `{}`, map[string]string{"X-Actor-ID": "admin-2", "X-Actor-Role": "platform-admin", "If-Match": fmt.Sprintf("\"%d\"", currentCluster.Revision), "X-Confirm-Revoke": "revoke-cluster-agent"})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"agentCredentialRevoked":true`) || !strings.Contains(w.Body.String(), `"hubAgentCredentialRevoked":true`) || !strings.Contains(w.Body.String(), `"targetRBACRevocationStatus":"APPLY_REQUIRED"`) || !strings.Contains(w.Body.String(), `subjects: []`) {
		t.Fatalf("revoke: %d %s", w.Code, w.Body.String())
	}
	r = httptest.NewRequest(http.MethodGet, "/api/v1/clusters/"+claimed.Cluster.ID+"/revocation-rbac-manifest", nil)
	r.Header.Set("X-Actor-ID", "admin-2")
	r.Header.Set("X-Actor-Role", "platform-admin")
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"targetRBACRevocationStatus":"APPLY_REQUIRED"`) || !strings.Contains(w.Body.String(), `revoked: \"true\"`) || !strings.Contains(w.Body.String(), `subjects: []`) {
		t.Fatalf("revocation fence retrieval: %d %s", w.Code, w.Body.String())
	}
	var revocationFence struct {
		FenceDigest string `json:"targetRBACRevocationFenceDigest"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &revocationFence); err != nil || !strings.HasPrefix(revocationFence.FenceDigest, "sha256:") {
		t.Fatalf("revocation fence digest missing: err=%v body=%s", err, w.Body.String())
	}
	revokedCluster, err := s.store.GetManagedCluster(context.Background(), claimed.Cluster.ID)
	if err != nil {
		t.Fatal(err)
	}
	w = post("/api/v1/clusters/"+claimed.Cluster.ID+"/revocation-rbac-acknowledgement", `{"fenceDigest":"sha256:`+strings.Repeat("0", 64)+`"}`, map[string]string{"X-Actor-ID": "admin-2", "X-Actor-Role": "platform-admin", "If-Match": fmt.Sprintf("\"%d\"", revokedCluster.Revision)})
	if w.Code != http.StatusPreconditionFailed {
		t.Fatalf("wrong revocation fence digest was accepted: %d %s", w.Code, w.Body.String())
	}
	w = post("/api/v1/clusters/"+claimed.Cluster.ID+"/revocation-rbac-acknowledgement", fmt.Sprintf(`{"fenceDigest":%q}`, revocationFence.FenceDigest), map[string]string{"X-Actor-ID": "admin-2", "X-Actor-Role": "platform-admin", "If-Match": fmt.Sprintf("\"%d\"", revokedCluster.Revision)})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"targetRBACRevocationStatus":"ACKNOWLEDGED"`) || !strings.Contains(w.Body.String(), `"acknowledgementIsPhysicalProof":false`) {
		t.Fatalf("revocation fence acknowledgement failed: %d %s", w.Code, w.Body.String())
	}
	w = post("/agent/v1/clusters/"+claimed.Cluster.ID+"/heartbeat", `{"agentVersion":"0.0.34"}`, map[string]string{"Authorization": "Bearer " + claimed.AgentToken})
	if w.Code == http.StatusOK {
		t.Fatalf("revoked agent token remained usable: %s", w.Body.String())
	}
}

type readyzSnapshotRejectStore struct{ controlplane.Store }

func (readyzSnapshotRejectStore) Snapshot(context.Context) (controlplane.Snapshot, error) {
	return controlplane.Snapshot{}, fmt.Errorf("readyz must not load canonical snapshot")
}

func TestReadyDoesNotLoadCanonicalSnapshot(t *testing.T) {
	base := controlplane.NewMemoryStore()
	if _, err := base.CreateOrganization(context.Background(), controlplane.Organization{Name: "ready-org", DisplayName: "Ready Org"}, "test"); err != nil {
		t.Fatal(err)
	}
	cs, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	s := New("test", cs, slog.New(slog.NewTextHandler(io.Discard, nil)), readyzSnapshotRejectStore{Store: base})
	r := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["organizations"] != float64(1) {
		t.Fatalf("organizations=%v", got["organizations"])
	}
}
