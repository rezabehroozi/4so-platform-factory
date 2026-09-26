package api

import (
	"encoding/json"
	"net/http"
	"testing"

	"platform.4so.io/factory/internal/managedinstall"
)

func TestManagedOKDInstallRuntimeTruthReflectsExecutorConfiguration(t *testing.T) {
	s := testServer(t)
	w := apiRequest(t, s.Handler(), http.MethodGet, "/api/v1/managed-okd-installs/runtime", "", map[string]string{"X-Actor-ID": "operator"})
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var before map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &before); err != nil {
		t.Fatal(err)
	}
	if before["configured"] != false || before["requestCreationAllowed"] != false || before["physicalCertificationImplied"] != false {
		t.Fatalf("unexpected disabled runtime truth: %#v", before)
	}
	incomplete := &managedinstall.Executor{}
	s.ConfigureManagedOKDInstallExecutor(incomplete)
	w = apiRequest(t, s.Handler(), http.MethodGet, "/api/v1/managed-okd-installs/runtime", "", map[string]string{"X-Actor-ID": "operator"})
	var after map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &after); err != nil {
		t.Fatal(err)
	}
	if after["configured"] != false || after["requestCreationAllowed"] != false || after["requiresExactWorkspace"] != true {
		t.Fatalf("incomplete executor was advertised as ready: %#v", after)
	}
	s.ConfigureManagedOKDInstallExecutor(managedInstallReadyExecutor(&managedInstallFakeInstaller{}))
	w = apiRequest(t, s.Handler(), http.MethodGet, "/api/v1/managed-okd-installs/runtime", "", map[string]string{"X-Actor-ID": "operator"})
	if err := json.Unmarshal(w.Body.Bytes(), &after); err != nil {
		t.Fatal(err)
	}
	if after["configured"] != true || after["requestCreationAllowed"] != true || after["connectedRequestAllowed"] != true || after["requiresExactWorkspace"] != true {
		t.Fatalf("unexpected ready runtime truth: %#v", after)
	}
}
