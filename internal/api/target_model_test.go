package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"platform.4so.io/factory/internal/targetmodel"
)

func TestTargetArchitectureModelSeparatesDistributionFromProvisioning(t *testing.T) {
	s := testServer(t)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/target-architecture-model", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var model targetmodel.Model
	if err := json.Unmarshal(w.Body.Bytes(), &model); err != nil {
		t.Fatal(err)
	}
	if model.Authority != targetmodel.AuthorityMethod {
		t.Fatalf("authority=%q", model.Authority)
	}
	if model.LegacyDistributionMap["kubespray"] != targetmodel.DistributionKubernetes || model.LegacyDistributionMap["generic-imported"] != targetmodel.DistributionKubernetes {
		t.Fatalf("legacy distribution mapping=%v", model.LegacyDistributionMap)
	}
	if model.LegacyAdapterMap["cluster-api-topology-v1beta2"] != targetmodel.ProvisioningClusterAPI {
		t.Fatalf("legacy adapter mapping=%v", model.LegacyAdapterMap)
	}
	if model.ManagementPlane.DistributionIdentity != targetmodel.DistributionRKE2 || model.ManagementPlane.ProvisioningMode != targetmodel.ProvisioningManagedInstall {
		t.Fatalf("management plane=%#v", model.ManagementPlane)
	}
	if model.CapabilityResolver.Authority != targetmodel.CapabilityResolverAuthority || model.ProgramRoadmap.CurrentPhase != "S1-exact-supply-chain-acquisition-closure" {
		t.Fatalf("target program authority=%#v resolver=%#v", model.ProgramRoadmap, model.CapabilityResolver)
	}
}

func TestMCPDelegationArchitectureEndpointExposesV27Rebaseline(t *testing.T) {
	s := testServer(t)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/mcp/delegation-architecture", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var model targetmodel.MCPRemoteOAuthDescriptor
	if err := json.Unmarshal(w.Body.Bytes(), &model); err != nil {
		t.Fatal(err)
	}
	if model.Authority != "MCP_REMOTE_OAUTH_DELEGATION_ARCHITECTURE_V1" || model.AuthorizationAuthority != "self-hosted-keycloak-oidc-oauth" || model.PasswordOrSecretToModel || !model.EveryWriteCreatesDurableJob {
		t.Fatalf("unexpected MCP delegation architecture: %#v", model)
	}
}
