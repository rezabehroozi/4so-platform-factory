package api

import (
	"net/http"

	"platform.4so.io/factory/catalog"
)

func (s *Server) componentRuntimeCertificationAuthority(w http.ResponseWriter, _ *http.Request) {
	registry, err := catalog.LoadComponentRuntimeCertificationRegistry()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "COMPONENT_RUNTIME_CERTIFICATION_AUTHORITY_UNAVAILABLE", "component runtime certification authority is unavailable")
		return
	}
	if err = catalog.ValidateComponentRuntimeCertificationRegistry(registry, s.components); err != nil {
		writeError(w, http.StatusInternalServerError, "COMPONENT_RUNTIME_CERTIFICATION_AUTHORITY_INVALID", "component runtime certification authority failed validation")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"authority":         registry.Metadata.Name,
		"policy":            registry.Spec.Policy,
		"stats":             catalog.ComponentRuntimeCertificationStatistics(registry),
		"components":        catalog.SortedComponentRuntimeCertificationContracts(registry),
		"productionReady":   false,
		"physicalCertified": false,
	})
}
