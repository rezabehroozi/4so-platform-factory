package provider

import (
	"testing"

	factorysdk "platform.4so.io/factory/sdk/go"
)

func TestVersionRouteUsesGeneratedOwnerClassifiedAuthority(t *testing.T) {
	route, err := productRoute("get", "/api/v1/version")
	if err != nil {
		t.Fatal(err)
	}
	if route.Mutation {
		t.Fatal("version route unexpectedly classified as mutation")
	}
	if route.ResourceScopeStatus != "OWNER_CLASSIFIED" {
		t.Fatalf("version route scope status = %q", route.ResourceScopeStatus)
	}
}

func TestProductRouteRejectsAbsentRoute(t *testing.T) {
	if _, err := productRoute("GET", "/api/v1/not-a-real-route"); err == nil {
		t.Fatal("missing route was accepted")
	}
}

func TestGeneratedProductRoutesAreUnique(t *testing.T) {
	seen := map[string]struct{}{}
	for _, route := range factorysdk.Routes {
		key := route.Method + " " + route.Path
		if _, exists := seen[key]; exists {
			t.Fatalf("duplicate generated route %s", key)
		}
		seen[key] = struct{}{}
	}
	if len(seen) != factorysdk.ProductAPIRouteCount {
		t.Fatalf("route count = %d, authority count = %d", len(seen), factorysdk.ProductAPIRouteCount)
	}
}
