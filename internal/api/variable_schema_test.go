package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"platform.4so.io/factory/internal/controlplane"
)

func TestVariableSchemaHTTPAuthorityAndProjectScope(t *testing.T) {
	s := testServer(t)
	h := s.Handler()

	w := apiRequest(t, h, http.MethodPost, "/api/v1/organizations", `{"name":"schema-org","displayName":"Schema Org"}`, map[string]string{"X-Actor-ID": "owner"})
	if w.Code != http.StatusCreated {
		t.Fatalf("organization status=%d body=%s", w.Code, w.Body.String())
	}
	org := decodeBody[controlplane.Organization](t, w)
	w = apiRequest(t, h, http.MethodPost, "/api/v1/projects", fmt.Sprintf(`{"organizationId":%q,"name":"platform","displayName":"Platform"}`, org.ID), map[string]string{"X-Actor-ID": "owner"})
	if w.Code != http.StatusCreated {
		t.Fatalf("project status=%d body=%s", w.Code, w.Body.String())
	}
	project := decodeBody[controlplane.Project](t, w)

	body := fmt.Sprintf(`{"projectId":%q,"name":"production","version":"1.0.0","variables":[{"name":"replicas","type":"INTEGER","required":true,"minimum":1,"maximum":9},{"name":"region","type":"STRING","default":"hel1","allowedValues":["hel1","hel2"]}]}`, project.ID)
	w = apiRequest(t, h, http.MethodPost, "/api/v1/variable-schemas", body, map[string]string{"X-Actor-ID": "owner"})
	if w.Code != http.StatusCreated {
		t.Fatalf("create variable schema status=%d body=%s", w.Code, w.Body.String())
	}
	created := decodeBody[controlplane.VariableSchema](t, w)
	if created.ProjectID != project.ID || created.Digest == "" || created.Revision != 1 {
		t.Fatalf("unexpected variable schema: %#v", created)
	}

	w = apiRequest(t, h, http.MethodGet, "/api/v1/variable-schemas?projectId="+project.ID, "", map[string]string{"X-Actor-ID": "owner"})
	if w.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", w.Code, w.Body.String())
	}
	var listed []controlplane.VariableSchema
	if err := json.Unmarshal(w.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].ID != created.ID {
		t.Fatalf("listed=%#v", listed)
	}

	w = apiRequest(t, h, http.MethodGet, "/api/v1/variable-schemas/"+created.ID, "", map[string]string{"X-Actor-ID": "owner"})
	if w.Code != http.StatusOK {
		t.Fatalf("get status=%d body=%s", w.Code, w.Body.String())
	}

	w = apiRequest(t, h, http.MethodPost, "/api/v1/variable-schemas", body, map[string]string{"X-Actor-ID": "owner"})
	if w.Code != http.StatusConflict {
		t.Fatalf("duplicate immutable identity status=%d body=%s", w.Code, w.Body.String())
	}
}
