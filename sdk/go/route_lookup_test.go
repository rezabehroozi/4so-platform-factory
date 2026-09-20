package factorysdk

import (
	"strings"
	"testing"
)

func TestStableRouteResolvesGeneratedOwnerClassifiedRoute(t *testing.T) {
	var candidate Route
	found := false
	for _, route := range Routes {
		if route.ResourceScopeStatus == "OWNER_CLASSIFIED" {
			candidate = route
			found = true
			break
		}
	}
	if !found {
		t.Fatal("generated Product API contract has no owner-classified route")
	}
	got, err := StableRoute(strings.ToLower(candidate.Method), "  "+candidate.Path+"  ")
	if err != nil {
		t.Fatal(err)
	}
	if got.Method != candidate.Method || got.Path != candidate.Path || got.ResourceScopeStatus != "OWNER_CLASSIFIED" {
		t.Fatalf("unexpected route: %#v", got)
	}
}

func TestStableRouteRejectsMissingRoute(t *testing.T) {
	_, err := StableRoute("GET", "/api/v1/definitely-not-a-real-route")
	if err == nil || !strings.Contains(err.Error(), "absent from") {
		t.Fatalf("missing route was not rejected: %v", err)
	}
}
