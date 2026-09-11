package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"platform.4so.io/factory/internal/controlplane"
)

func apiHealthyOKDInventory(now time.Time) controlplane.ClusterInventory {
	return controlplane.ClusterInventory{
		ObservedAt: now, Distribution: "okd", DistributionEvidenceMethod: controlplane.DistributionEvidenceOKDClusterV1,
		DistributionEvidenceUID: "cv-uid-api", DistributionEvidenceVersion: "4.19.0-okd-scos.0", KubernetesVersion: "v1.32.0",
		APIDiscoveryComplete: true, CRDDiscoveryComplete: true, SchemaDiscoveryComplete: true, SchemaDiscoveryVersion: "OPENAPI_V3", SchemaDiscoveryDigest: "sha256:" + strings.Repeat("b", 64),
		Networking: controlplane.ClusterNetworking{CNI: "OVNKubernetes"},
		APIResources: []controlplane.ClusterAPIResourceObservation{
			{APIVersion: "config.openshift.io/v1", Group: "config.openshift.io", Version: "v1", Kind: "ClusterVersion", Resource: "clusterversions"},
			{APIVersion: "operators.coreos.com/v1alpha1", Group: "operators.coreos.com", Version: "v1alpha1", Kind: "ClusterServiceVersion", Resource: "clusterserviceversions", Namespaced: true},
			{APIVersion: "security.openshift.io/v1", Group: "security.openshift.io", Version: "v1", Kind: "SecurityContextConstraints", Resource: "securitycontextconstraints"},
			{APIVersion: "project.openshift.io/v1", Group: "project.openshift.io", Version: "v1", Kind: "Project", Resource: "projects"},
		},
		AddOns: []controlplane.ClusterAddOn{
			{Name: "version", Kind: "cluster-version", Version: "4.19.0-okd-scos.0", Healthy: true, Available: "True", Progressing: "False", Degraded: "False", Upgradeable: "True"},
			{Name: "network", Kind: "cluster-operator", Version: "4.19.0", Healthy: true, Available: "True", Progressing: "False", Degraded: "False", Upgradeable: "True"},
			{Name: "monitoring", Kind: "cluster-operator", Version: "4.19.0", Healthy: true, Available: "True", Progressing: "False", Degraded: "False", Upgradeable: "True"},
			{Name: "operator-lifecycle-manager", Kind: "cluster-operator", Version: "4.19.0", Healthy: true, Available: "True", Progressing: "False", Degraded: "False", Upgradeable: "True"},
		},
		Capabilities: []string{controlplane.TargetEnrollmentPrincipalIsolatedCapability, "volume-snapshot-controller"},
	}
}

func TestOKDImportedClusterDetailExposesHealthProfileAndReconnectAuthority(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	org, err := s.store.CreateOrganization(ctx, controlplane.Organization{Name: "okd-org", DisplayName: "OKD Org"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	project, err := s.store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "okd-project", DisplayName: "OKD Project"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	enrollment := "sha256:" + strings.Repeat("1", 64)
	agent := "sha256:" + strings.Repeat("2", 64)
	imp, err := s.store.CreateClusterImport(ctx, controlplane.ClusterImport{ProjectID: project.ID, Name: "okd-a", DisplayName: "OKD A", TokenDigest: enrollment, ExpiresAt: time.Now().Add(time.Hour)}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	imp, err = s.store.ApproveClusterImport(ctx, imp.ID, imp.Revision, "approver")
	if err != nil {
		t.Fatal(err)
	}
	_, cluster, err := s.store.ClaimClusterImport(ctx, imp.ID, enrollment, agent, "okd-physical-uid", "0.0.291")
	if err != nil {
		t.Fatal(err)
	}
	cluster, _, err = s.store.UpsertClusterInventory(ctx, cluster.ID, agent, cluster.ExternalUID, apiHealthyOKDInventory(time.Now().UTC()))
	if err != nil {
		t.Fatal(err)
	}
	if !controlplane.ClusterHasCapability(cluster, controlplane.OKDImportAdmissionCapability) {
		t.Fatalf("healthy OKD import did not gain admission marker: %+v", cluster)
	}

	r := httptest.NewRequest(http.MethodGet, "/api/v1/clusters/"+cluster.ID, nil)
	r.Header.Set("X-Actor-ID", "admin")
	r.Header.Set("X-Actor-Role", "platform-admin")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var body struct {
		OKDImportAdmitted              bool                                  `json:"okdImportAdmitted"`
		OKDHealth                      controlplane.OKDHealthSummary         `json:"okdHealth"`
		TargetProfile                  controlplane.TargetProfileCompilation `json:"targetProfile"`
		Reconnect                      controlplane.ClusterReconnectSummary  `json:"reconnect"`
		MutationRBACActivationRequired bool                                  `json:"mutationRBACActivationRequired"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.OKDImportAdmitted || body.OKDHealth.Status != "HEALTHY" || body.TargetProfile.Status != "CONVERGED" || body.Reconnect.Status != "CONNECTED" || !body.MutationRBACActivationRequired {
		t.Fatalf("unexpected OKD product detail: %+v body=%s", body, w.Body.String())
	}
}
