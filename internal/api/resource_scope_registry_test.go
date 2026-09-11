package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"platform.4so.io/factory/internal/controlplane"
)

func TestResourceScopeRegistryExposesExplicitOwnershipWithoutGuessing(t *testing.T) {
	srv := New("0.0.test", nil, slog.New(slog.NewTextHandler(io.Discard, nil)), controlplane.NewMemoryStore())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/access/resource-scopes", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var body resourceScopeRegistry
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Authority != resourceScopeRegistryAuthority || body.FamilyCount == 0 || len(body.Families) != body.FamilyCount {
		t.Fatalf("registry=%+v", body)
	}
	byFamily := map[string]resourceScopeFamily{}
	for _, family := range body.Families {
		byFamily[family.Family] = family
		if family.Status == "OWNER_REVIEW_REQUIRED" && family.Scope != "UNCLASSIFIED" {
			t.Fatalf("unreviewed family %q was guessed as scope %q", family.Family, family.Scope)
		}
	}
	for family, want := range map[string]string{
		"projects":          "ORGANIZATION_SCOPED",
		"workspaces":        "PROJECT_SCOPED",
		"provider-profiles": "PROJECT_SCOPED",
		"provider-clusters": "PROJECT_SCOPED",
	} {
		got := byFamily[family]
		if got.Status != "OWNER_CLASSIFIED" || got.Scope != want {
			t.Fatalf("family %s got=%+v want scope=%s", family, got, want)
		}
	}
}
