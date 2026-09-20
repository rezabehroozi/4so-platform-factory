package provider

import (
	"fmt"
	"strings"

	factorysdk "platform.4so.io/factory/sdk/go"
)

func productRoute(method, path string) (factorysdk.Route, error) {
	method = strings.ToUpper(strings.TrimSpace(method))
	path = strings.TrimSpace(path)
	var match *factorysdk.Route
	for i := range factorysdk.Routes {
		route := factorysdk.Routes[i]
		if route.Method != method || route.Path != path {
			continue
		}
		if match != nil {
			return factorysdk.Route{}, fmt.Errorf("Product API route %s %s is ambiguous", method, path)
		}
		copy := route
		match = &copy
	}
	if match == nil {
		return factorysdk.Route{}, fmt.Errorf("Product API route %s %s is absent from %s", method, path, factorysdk.ProductAPIContractAuthority)
	}
	if match.ResourceScopeStatus != "OWNER_CLASSIFIED" {
		return factorysdk.Route{}, fmt.Errorf("Product API route %s %s is not owner-classified", method, path)
	}
	return *match, nil
}
