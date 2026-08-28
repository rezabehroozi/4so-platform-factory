package marketplace

import (
	"sort"
	"strings"

	"platform.4so.io/factory/internal/baseline"
	"platform.4so.io/factory/internal/controlplane"
)

const SourceType = controlplane.BaselineSourceMarketplace

type Offer struct {
	ID                          string   `json:"id"`
	Version                     string   `json:"version"`
	DisplayName                 string   `json:"displayName"`
	Description                 string   `json:"description"`
	Category                    string   `json:"category"`
	Scope                       string   `json:"scope"`
	Risk                        string   `json:"risk"`
	BaselineID                  string   `json:"baselineId"`
	BaselineVersion             string   `json:"baselineVersion"`
	Capabilities                []string `json:"capabilities"`
	RequiredClusterCapabilities []string `json:"requiredClusterCapabilities"`
	Rollback                    string   `json:"rollback"`
	AIAdvisoryEnabled           bool     `json:"aiAdvisoryEnabled"`
}

func Catalog() []Offer {
	return []Offer{{
		ID:                          "secure-namespace-foundation",
		Version:                     "1.0.0",
		DisplayName:                 "Secure Namespace Foundation",
		Description:                 "Installs the product-owned namespace governance baseline with quota, default limits, default-deny ingress and an immutable revision marker.",
		Category:                    "cluster-security",
		Scope:                       "cluster",
		Risk:                        "medium",
		BaselineID:                  baseline.SecureNamespaceID,
		BaselineVersion:             baseline.SecureNamespaceVersion,
		Capabilities:                []string{"namespace-governance", "resource-quota", "default-limits", "network-policy", "rollback"},
		RequiredClusterCapabilities: []string{"controlled-baseline-deployment"},
		Rollback:                    "Remove only the five 4SO-managed baseline resources while preserving the namespace.",
		AIAdvisoryEnabled:           true,
	}}
}

func Get(id, version string) (Offer, bool) {
	id, version = strings.TrimSpace(id), strings.TrimSpace(version)
	for _, offer := range Catalog() {
		if offer.ID == id && (version == "" || offer.Version == version) {
			return offer, true
		}
	}
	return Offer{}, false
}

func Eligible(capabilities []string, installed map[string]bool) []Offer {
	available := map[string]bool{}
	for _, capability := range capabilities {
		available[strings.TrimSpace(capability)] = true
	}
	out := []Offer{}
	for _, offer := range Catalog() {
		if !offer.AIAdvisoryEnabled || installed[offer.ID+"@"+offer.Version] {
			continue
		}
		ok := true
		for _, required := range offer.RequiredClusterCapabilities {
			if !available[required] {
				ok = false
				break
			}
		}
		if ok {
			out = append(out, offer)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
