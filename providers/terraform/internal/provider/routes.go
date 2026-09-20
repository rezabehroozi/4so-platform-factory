package provider

import (
	factorysdk "platform.4so.io/factory/sdk/go"
)

func productRoute(method, path string) (factorysdk.Route, error) {
	return factorysdk.StableRoute(method, path)
}
