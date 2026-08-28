package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"

	"platform.4so.io/factory/internal/controlplane"
)

func TestBlueprintLifecycleAPICloneCompareAndPublish(t *testing.T) {
	store := controlplane.NewMemoryStore()
	org, err := store.CreateOrganization(context.Background(), controlplane.Organization{Name: "blueprint-api", DisplayName: "Blueprint API"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(context.Background(), controlplane.Project{OrganizationID: org.ID, Name: "platform", DisplayName: "Platform"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	h := scopedServer(t, store).Handler()
	raw, err := os.ReadFile("../../blueprints/enterprise-private-cloud.json")
	if err != nil {
		t.Fatal(err)
	}
	var blueprint any
	if err := json.Unmarshal(raw, &blueprint); err != nil {
		t.Fatal(err)
	}
	bodyRaw, _ := json.Marshal(map[string]any{"projectId": project.ID, "blueprint": blueprint})
	w := apiRequest(t, h, http.MethodPost, "/api/v1/blueprint-releases", string(bodyRaw), map[string]string{"X-Actor-ID": "author"})
	if w.Code != http.StatusCreated {
		t.Fatalf("create=%d body=%s", w.Code, w.Body.String())
	}
	var created struct {
		Release controlplane.BlueprintRelease `json:"release"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Release.State != controlplane.BlueprintDraft {
		t.Fatalf("state=%s", created.Release.State)
	}

	w = apiRequest(t, h, http.MethodPost, "/api/v1/blueprint-releases/"+created.Release.ID+"/review", `{}`, map[string]string{"X-Actor-ID": "author", "If-Match": fmt.Sprintf("\"%d\"", created.Release.Revision)})
	if w.Code != http.StatusOK {
		t.Fatalf("review=%d body=%s", w.Code, w.Body.String())
	}
	var review controlplane.BlueprintRelease
	if err := json.Unmarshal(w.Body.Bytes(), &review); err != nil {
		t.Fatal(err)
	}

	w = apiRequest(t, h, http.MethodPost, "/api/v1/blueprint-releases/"+review.ID+"/publish", `{}`, map[string]string{"X-Actor-ID": "author", "If-Match": fmt.Sprintf("\"%d\"", review.Revision)})
	if w.Code != http.StatusForbidden {
		t.Fatalf("self publish=%d body=%s", w.Code, w.Body.String())
	}
	w = apiRequest(t, h, http.MethodPost, "/api/v1/blueprint-releases/"+review.ID+"/publish", `{}`, map[string]string{"X-Actor-ID": "approver", "If-Match": fmt.Sprintf("\"%d\"", review.Revision)})
	if w.Code != http.StatusOK {
		t.Fatalf("publish=%d body=%s", w.Code, w.Body.String())
	}
	var published controlplane.BlueprintRelease
	if err := json.Unmarshal(w.Body.Bytes(), &published); err != nil {
		t.Fatal(err)
	}

	cloneBody := `{"name":"enterprise-private-cloud","version":"0.0.2"}`
	w = apiRequest(t, h, http.MethodPost, "/api/v1/blueprint-releases/"+published.ID+"/clone", cloneBody, map[string]string{"X-Actor-ID": "author"})
	if w.Code != http.StatusCreated {
		t.Fatalf("clone=%d body=%s", w.Code, w.Body.String())
	}
	var cloned struct {
		Release controlplane.BlueprintRelease `json:"release"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &cloned); err != nil {
		t.Fatal(err)
	}
	if len(cloned.Release.UpgradeFromIDs) != 1 || cloned.Release.UpgradeFromIDs[0] != published.ID {
		t.Fatalf("clone edges=%v", cloned.Release.UpgradeFromIDs)
	}

	compareBody := fmt.Sprintf(`{"leftReleaseId":%q,"rightReleaseId":%q}`, published.ID, cloned.Release.ID)
	w = apiRequest(t, h, http.MethodPost, "/api/v1/blueprint-releases/compare", compareBody, map[string]string{"X-Actor-ID": "author"})
	if w.Code != http.StatusOK {
		t.Fatalf("compare=%d body=%s", w.Code, w.Body.String())
	}
	var comparison struct {
		Equal           bool `json:"equal"`
		DifferenceCount int  `json:"differenceCount"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &comparison); err != nil {
		t.Fatal(err)
	}
	if comparison.Equal || comparison.DifferenceCount == 0 {
		t.Fatalf("comparison=%s", w.Body.String())
	}

	updateRaw, _ := json.Marshal(map[string]any{"blueprint": blueprint})
	w = apiRequest(t, h, http.MethodPut, "/api/v1/blueprint-releases/"+published.ID+"/draft", string(updateRaw), map[string]string{"X-Actor-ID": "author", "If-Match": fmt.Sprintf("\"%d\"", published.Revision)})
	if w.Code != http.StatusConflict {
		t.Fatalf("published edit=%d body=%s", w.Code, w.Body.String())
	}
}
