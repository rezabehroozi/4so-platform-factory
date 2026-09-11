package api

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
)

const resourceScopeRegistryAuthority = "RESOURCE_SCOPE_REGISTRY_V1"

type resourceScopeFamily struct {
	Evidence string `json:"evidence"`
	Family   string `json:"family"`
	Scope    string `json:"scope"`
	Status   string `json:"status"`
}

type resourceScopeRegistry struct {
	Authority                string                `json:"authority"`
	ClassificationAuthority  string                `json:"classificationAuthority"`
	ClassifiedCount          int                   `json:"classifiedCount"`
	Families                 []resourceScopeFamily `json:"families"`
	FamilyCount              int                   `json:"familyCount"`
	OwnerReviewRequiredCount int                   `json:"ownerReviewRequiredCount"`
	Policy                   map[string]any        `json:"policy"`
	SourceAuthority          string                `json:"sourceAuthority"`
}

//go:embed resource_scope_registry.json
var rawResourceScopeRegistry []byte

func loadResourceScopeRegistry() resourceScopeRegistry {
	var registry resourceScopeRegistry
	if err := json.Unmarshal(rawResourceScopeRegistry, &registry); err != nil {
		panic(fmt.Errorf("decode resource scope registry: %w", err))
	}
	if registry.Authority != resourceScopeRegistryAuthority || registry.FamilyCount != len(registry.Families) {
		panic("invalid resource scope registry")
	}
	return registry
}

func (s *Server) resourceScopeRegistry(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, loadResourceScopeRegistry())
}
