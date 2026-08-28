package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"platform.4so.io/factory/internal/controlplane"
)

func TestClusterImportRevokeRequiresExplicitConfirmation(t *testing.T) {
	s := testServer(t)
	org, err := s.store.CreateOrganization(context.Background(), controlplane.Organization{Name: "cancel-import-org", DisplayName: "Cancel Import Org"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	project, err := s.store.CreateProject(context.Background(), controlplane.Project{OrganizationID: org.ID, Name: "clusters", DisplayName: "Clusters"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	imp, err := s.store.CreateClusterImport(context.Background(), controlplane.ClusterImport{ProjectID: project.ID, Name: "lost-token", DisplayName: "Lost Token", TokenDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ExpiresAt: time.Now().Add(time.Hour)}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	call := func(confirm bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/cluster-imports/"+imp.ID+"/revoke", bytes.NewBufferString(`{}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Actor-ID", "operator")
		req.Header.Set("If-Match", `"1"`)
		if confirm {
			req.Header.Set("X-Confirm-Revoke", "revoke-cluster-import")
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, req)
		return w
	}
	if w := call(false); w.Code != http.StatusPreconditionRequired {
		t.Fatalf("missing confirmation status=%d body=%s", w.Code, w.Body.String())
	}
	if w := call(true); w.Code != http.StatusOK {
		t.Fatalf("revoke status=%d body=%s", w.Code, w.Body.String())
	}
}
