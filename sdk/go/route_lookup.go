package factorysdk

import (
	"fmt"
	"strings"
)

// StableRoute resolves one exact stable Product API route from the generated
// contract and refuses unclassified ownership. Downstream automation clients
// such as Terraform and Crossplane must consume this shared authority instead
// of re-deriving route or scope semantics.
func StableRoute(method, path string) (Route, error) {
	method = strings.ToUpper(strings.TrimSpace(method))
	path = strings.TrimSpace(path)
	var match *Route
	for i := range Routes {
		route := Routes[i]
		if route.Method != method || route.Path != path {
			continue
		}
		if match != nil {
			return Route{}, fmt.Errorf("Product API route %s %s is ambiguous", method, path)
		}
		copy := route
		match = &copy
	}
	if match == nil {
		return Route{}, fmt.Errorf("Product API route %s %s is absent from %s", method, path, ProductAPIContractAuthority)
	}
	if match.ResourceScopeStatus != "OWNER_CLASSIFIED" {
		return Route{}, fmt.Errorf("Product API route %s %s is not owner-classified", method, path)
	}
	return *match, nil
}
