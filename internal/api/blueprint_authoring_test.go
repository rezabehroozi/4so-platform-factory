package api

import (
	"encoding/json"
	"net/http"
	"os"
	"testing"

	"platform.4so.io/factory/internal/controlplane"
)

func TestBlueprintAuthoringContractAndRoundTrip(t *testing.T) {
	h := scopedServer(t, controlplane.NewMemoryStore()).Handler()
	w := apiRequest(t, h, http.MethodGet, "/api/v1/blueprints/authoring-contract", "", map[string]string{"X-Actor-ID": "author"})
	if w.Code != http.StatusOK {
		t.Fatalf("contract=%d %s", w.Code, w.Body.String())
	}
	var contract struct {
		Method     string `json:"method"`
		FieldCount int    `json:"fieldCount"`
		Strict     bool   `json:"strictUnknownFields"`
		Fields     []struct {
			Path        string   `json:"path"`
			UIControlID string   `json:"uiControlId"`
			Options     []string `json:"options"`
		} `json:"fields"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &contract); err != nil {
		t.Fatal(err)
	}
	if contract.Method != blueprintAuthoringMethod || !contract.Strict || contract.FieldCount != len(blueprintAuthoringFields) || contract.FieldCount < 27 {
		t.Fatalf("contract=%#v", contract)
	}
	seen := map[string]bool{}
	var k8sMinOptions []string
	for _, f := range contract.Fields {
		if f.Path == "" || f.UIControlID == "" {
			t.Fatalf("invalid field=%#v", f)
		}
		seen[f.Path] = true
		if f.Path == "spec.compatibility.kubernetes.minVersion" {
			k8sMinOptions = append([]string(nil), f.Options...)
		}
	}
	if len(k8sMinOptions) != 2 || k8sMinOptions[0] != "1.34" || k8sMinOptions[1] != "1.35" {
		t.Fatalf("unexpected Kubernetes authoring options: %#v", k8sMinOptions)
	}
	for _, path := range []string{"spec.components[].settings", "spec.governance.approvalRequiredFor", "spec.tenancy.deletionPolicy", "spec.delivery.mode"} {
		if !seen[path] {
			t.Fatalf("missing %s", path)
		}
	}

	raw, err := os.ReadFile("../../blueprints/enterprise-private-cloud.json")
	if err != nil {
		t.Fatal(err)
	}
	w = apiRequest(t, h, http.MethodPost, "/api/v1/blueprints/authoring-roundtrip", string(raw), map[string]string{"X-Actor-ID": "author"})
	if w.Code != http.StatusOK {
		t.Fatalf("roundtrip=%d %s", w.Code, w.Body.String())
	}
	var out struct {
		Method, Digest, CanonicalJSON string
		FieldCount                    int `json:"fieldCount"`
		Validation                    struct {
			Valid bool `json:"valid"`
		} `json:"validation"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Method != blueprintAuthoringMethod || out.Digest == "" || !out.Validation.Valid || out.FieldCount != len(blueprintAuthoringFields) {
		t.Fatalf("out=%#v", out)
	}

	w = apiRequest(t, h, http.MethodPost, "/api/v1/blueprints/authoring-roundtrip", `{"apiVersion":"platform.4so.io/v1alpha1","kind":"PlatformBlueprint","metadata":{"name":"x","version":"1.0.0"},"spec":{},"unknown":true}`, map[string]string{"X-Actor-ID": "author"})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("unknown field should fail: %d %s", w.Code, w.Body.String())
	}
}
