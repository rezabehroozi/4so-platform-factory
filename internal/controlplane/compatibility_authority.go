package controlplane

import (
	"fmt"
	"sort"
	"strings"

	"platform.4so.io/factory/catalog"
	compatauth "platform.4so.io/factory/internal/compatibility"
	"platform.4so.io/factory/internal/targetmodel"
)

const CompatibilityMatrixAuthorityMethod = compatauth.AuthorityMethod

func baselineCompatibilityConstraints() []compatauth.Constraint {
	components, err := catalog.Load()
	if err != nil {
		return []compatauth.Constraint{{Name: "component/secure-namespace-foundation"}}
	}
	c, ok := components["secure-namespace-foundation"]
	if !ok {
		return []compatauth.Constraint{{Name: "component/secure-namespace-foundation"}}
	}
	return []compatauth.Constraint{{
		Name:                 "component/secure-namespace-foundation",
		KubernetesMinVersion: c.Spec.Compatibility.Kubernetes.MinVersion,
		KubernetesMaxVersion: c.Spec.Compatibility.Kubernetes.MaxVersion,
		Architectures:        append([]string(nil), c.Spec.Compatibility.Architectures...),
		Distributions:        append([]string(nil), c.Spec.Compatibility.DistributionProfiles...),
		Providers:            append([]string(nil), c.Spec.Compatibility.Providers...),
	}}
}

func distributionProfile(raw string) string {
	return targetmodel.CanonicalDistribution(raw)
}

func inventoryArchitecture(inv ClusterInventory) string {
	set := map[string]bool{}
	for _, node := range inv.Nodes {
		arch := strings.ToLower(strings.TrimSpace(node.Architecture))
		if arch != "" {
			set[arch] = true
		}
	}
	if len(set) != 1 {
		if len(set) > 1 {
			return "mixed"
		}
		return ""
	}
	for arch := range set {
		return arch
	}
	return ""
}

func BaselineCompatibilityDecision(inv ClusterInventory) compatauth.Decision {
	return compatauth.Evaluate(compatauth.Target{
		KubernetesVersion: inv.KubernetesVersion,
		Architecture:      inventoryArchitecture(inv),
		Distribution:      distributionProfile(inv.Distribution),
		Provider:          "imported",
	}, baselineCompatibilityConstraints())
}

func ValidateBaselineCompatibilityDecisionContract(v compatauth.Decision) error {
	if err := compatauth.Validate(v, baselineCompatibilityConstraints()); err != nil {
		return fmt.Errorf("%w: %v", ErrValidation, err)
	}
	return nil
}

func ValidateBaselineCompatibilityDecision(v compatauth.Decision, inv ClusterInventory) error {
	if err := compatauth.Validate(v, baselineCompatibilityConstraints()); err != nil {
		return fmt.Errorf("%w: %v", ErrValidation, err)
	}
	expected := BaselineCompatibilityDecision(inv)
	if v.Digest != expected.Digest || v.Target != expected.Target {
		return fmt.Errorf("%w: compatibility decision is not bound to the target inventory", ErrValidation)
	}
	return nil
}

func providerProfileCompatibilityConstraint(profile ProviderProfile) compatauth.Constraint {
	min, max := providerSeriesRange(profile.KubernetesSeries)
	return compatauth.Constraint{
		Name:                 "providerProfile/" + profile.ID,
		KubernetesMinVersion: min,
		KubernetesMaxVersion: max,
		Architectures:        append([]string(nil), profile.Architectures...),
		Distributions:        append([]string(nil), profile.DistributionProfiles...),
		Providers:            []string{profile.Adapter},
	}
}

func providerSeriesRange(series []string) (string, string) {
	minMinor, maxMinor := 999, -1
	for _, item := range series {
		parts := strings.Split(strings.TrimPrefix(item, "v1."), ".")
		var minor int
		if len(parts) > 0 {
			_, _ = fmt.Sscanf(parts[0], "%d", &minor)
		}
		if minor < minMinor {
			minMinor = minor
		}
		if minor > maxMinor {
			maxMinor = minor
		}
	}
	if maxMinor < 0 {
		return "1.0", "1.0"
	}
	return fmt.Sprintf("1.%d", minMinor), fmt.Sprintf("1.%d", maxMinor)
}

func ProviderCompatibilityDecision(profile ProviderProfile, spec ProviderClusterSpec) compatauth.Decision {
	return compatauth.Evaluate(compatauth.Target{
		KubernetesVersion: spec.KubernetesVersion,
		Architecture:      spec.Architecture,
		Distribution:      spec.Distribution,
		Provider:          profile.Adapter,
	}, []compatauth.Constraint{providerProfileCompatibilityConstraint(profile)})
}

func NormalizeProviderCompatibility(profile *ProviderProfile, spec *ProviderClusterSpec) {
	if len(profile.Architectures) == 0 {
		profile.Architectures = []string{"amd64"}
	}
	if len(profile.DistributionProfiles) == 0 {
		profile.DistributionProfiles = []string{targetmodel.DistributionKubernetes}
	}
	profile.Architectures = normalizedCompatibilitySet(profile.Architectures)
	profile.DistributionProfiles = targetmodel.CanonicalDistributionSet(profile.DistributionProfiles)
	if strings.TrimSpace(spec.Architecture) == "" && len(profile.Architectures) > 0 {
		spec.Architecture = profile.Architectures[0]
	}
	legacyDistribution := targetmodel.CanonicalDistribution(spec.Distribution)
	explicitIdentity := targetmodel.CanonicalDistribution(spec.DistributionIdentity)
	if legacyDistribution != "" && explicitIdentity != "" && legacyDistribution != explicitIdentity {
		// Preserve both values so providerSpecAllowed can reject contradictory clients.
		spec.Distribution = legacyDistribution
		spec.DistributionIdentity = explicitIdentity
	} else {
		identity := explicitIdentity
		if identity == "" {
			identity = legacyDistribution
		}
		if identity == "" && len(profile.DistributionProfiles) > 0 {
			identity = profile.DistributionProfiles[0]
		}
		spec.Distribution = identity
		spec.DistributionIdentity = identity
	}
	spec.Architecture = strings.ToLower(strings.TrimSpace(spec.Architecture))
	spec.ProvisioningMode = targetmodel.ProvisioningModeFromAdapter(profile.Adapter)
	if profile.InfrastructureProvider == "" {
		profile.InfrastructureProvider = targetmodel.InfrastructureUnspecified
	}
	spec.InfrastructureProvider = profile.InfrastructureProvider
}

func normalizedCompatibilitySet(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, item := range in {
		item = strings.ToLower(strings.TrimSpace(item))
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}
