package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"platform.4so.io/factory/internal/auth"
	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/reliability"
)

func seedReliabilityCluster(t *testing.T, store controlplane.Store, projectID, name string) controlplane.ManagedCluster {
	t.Helper()
	ctx := context.Background()
	token := "sha256:" + strings.Repeat("a", 64)
	imp, err := store.CreateClusterImport(ctx, controlplane.ClusterImport{ProjectID: projectID, Name: name, DisplayName: name, TokenDigest: token, ExpiresAt: time.Now().Add(time.Hour)}, "seed")
	if err != nil {
		t.Fatal(err)
	}
	imp, err = store.ApproveClusterImport(ctx, imp.ID, imp.Revision, "seed-approver")
	if err != nil {
		t.Fatal(err)
	}
	_, cluster, err := store.ClaimClusterImport(ctx, imp.ID, token, "sha256:"+strings.Repeat("b", 64), "uid-"+name, "0.0.test")
	if err != nil {
		t.Fatal(err)
	}
	return cluster
}
func TestReliabilityServiceHealthIsProjectScopedBoundedAndFailsClosedOnCoverage(t *testing.T) {
	now := time.Date(2026, 9, 13, 9, 0, 0, 0, time.UTC)
	store := controlplane.NewMemoryStoreWith(func() time.Time { return now }, nil)
	ctx := context.Background()
	orgA, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "reliability-a", DisplayName: "Reliability A"}, "seed")
	if err != nil {
		t.Fatal(err)
	}
	projectA, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: orgA.ID, Name: "primary", DisplayName: "Primary"}, "seed")
	if err != nil {
		t.Fatal(err)
	}
	recent := seedReliabilityCluster(t, store, projectA.ID, "recent")
	stale := seedReliabilityCluster(t, store, projectA.ID, "stale")
	orgB, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "reliability-b", DisplayName: "Reliability B"}, "seed")
	if err != nil {
		t.Fatal(err)
	}
	projectB, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: orgB.ID, Name: "primary", DisplayName: "Primary"}, "seed")
	if err != nil {
		t.Fatal(err)
	}
	foreign := seedReliabilityCluster(t, store, projectB.ID, "foreign")

	for _, observation := range []reliability.HealthObservation{
		{OrganizationID: orgA.ID, ProjectID: projectA.ID, ClusterID: recent.ID, Health: "HEALTHY", ObservedAt: now.Add(-time.Minute), SourceDigest: "sha256:recent-secret-like-digest"},
		{OrganizationID: orgA.ID, ProjectID: projectA.ID, ClusterID: stale.ID, Health: "HEALTHY", ObservedAt: now.Add(-10 * time.Minute), SourceDigest: "sha256:stale-secret-like-digest"},
		{OrganizationID: orgB.ID, ProjectID: projectB.ID, ClusterID: foreign.ID, Health: "CRITICAL", ObservedAt: now.Add(-time.Minute), SourceDigest: "sha256:foreign-secret-like-digest"},
	} {
		if _, _, err = store.CreateHealthObservation(ctx, observation); err != nil {
			t.Fatal(err)
		}
	}
	srv := New("0.0.test", nil, slog.New(slog.NewTextHandler(io.Discard, nil)), store)
	principal := auth.Principal{Subject: "viewer-a", Roles: []string{"platform-viewer"}, ProjectRoles: map[string]string{projectA.ID: "project-viewer"}}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/reliability/service-health?projectId="+projectA.ID, nil)
	req = req.WithContext(auth.WithPrincipal(req.Context(), principal))
	w := httptest.NewRecorder()
	srv.serviceHealthAt(w, req, now)
	if w.Code != http.StatusOK {
		t.Fatalf("service health status=%d body=%s", w.Code, w.Body.String())
	}
	if w.Header().Get("X-4SO-Result-Limit") != "200" {
		t.Fatalf("bounded result header=%q", w.Header().Get("X-4SO-Result-Limit"))
	}
	body := w.Body.String()
	for _, want := range []string{reliability.ServiceHealthAuthority, recent.ID, stale.ID, `"coverageStatus":"UNKNOWN"`, `"health":"HEALTHY"`, `"health":"UNKNOWN"`, "MISSING_OR_STALE"} {
		if !strings.Contains(body, want) {
			t.Fatalf("service health missing %q: %s", want, body)
		}
	}
	for _, forbidden := range []string{foreign.ID, "SourceDigest", "sourceDigest", "recent-secret-like-digest", "stale-secret-like-digest"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("service health leaked %q: %s", forbidden, body)
		}
	}
	var decoded map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["bounded"] != true || decoded["projectId"] != projectA.ID {
		t.Fatalf("unexpected service health envelope: %#v", decoded)
	}
	foreignReq := httptest.NewRequest(http.MethodGet, "/api/v1/reliability/service-health?projectId="+projectB.ID, nil)
	foreignReq = foreignReq.WithContext(auth.WithPrincipal(foreignReq.Context(), principal))
	foreignW := httptest.NewRecorder()
	srv.serviceHealthAt(foreignW, foreignReq, now)
	if foreignW.Code != http.StatusForbidden {
		t.Fatalf("cross-project service health status=%d body=%s", foreignW.Code, foreignW.Body.String())
	}

	missingReq := httptest.NewRequest(http.MethodGet, "/api/v1/reliability/service-health", nil)
	missingReq = missingReq.WithContext(auth.WithPrincipal(missingReq.Context(), principal))
	missingW := httptest.NewRecorder()
	srv.serviceHealthAt(missingW, missingReq, now)
	if missingW.Code != http.StatusUnprocessableEntity {
		t.Fatalf("missing project scope status=%d body=%s", missingW.Code, missingW.Body.String())
	}
}
