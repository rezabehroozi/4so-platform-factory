package baseline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"platform.4so.io/factory/internal/controlplane"
	"sort"
	"strings"
)

const (
	SecureNamespaceID             = "secure-namespace-foundation"
	SecureNamespaceVersion        = "1.0.0"
	SecureNamespaceUpgradeVersion = "1.1.0"
	ManagedNamespace              = "4so-platform-baseline"
)

type Definition struct {
	ID              string   `json:"id"`
	Version         string   `json:"version"`
	DisplayName     string   `json:"displayName"`
	Description     string   `json:"description"`
	Risk            string   `json:"risk"`
	TargetNamespace string   `json:"targetNamespace"`
	Capabilities    []string `json:"capabilities"`
	Rollback        string   `json:"rollback"`
	UpgradeFrom     []string `json:"upgradeFrom,omitempty"`
}

func Catalog() []Definition {
	return []Definition{
		{
			ID: SecureNamespaceID, Version: SecureNamespaceVersion,
			DisplayName: "Secure Namespace Foundation",
			Description: "Creates a product-owned namespace foundation with quota, default limits, default-deny ingress and a revision marker without changing customer workloads.",
			Risk:        "medium", TargetNamespace: ManagedNamespace,
			Capabilities: []string{"namespace-governance", "resource-quota", "default-limits", "network-policy", "rollback"},
			Rollback:     "execute the Plan-bound rollback strategy: delete resources created by the deployment, restore pre-existing updated resources from the validated pre-image, and preserve the namespace",
		},
		{
			ID: SecureNamespaceID, Version: SecureNamespaceUpgradeVersion,
			DisplayName: "Secure Namespace Foundation 1.1",
			Description: "Upgrades the product-owned namespace foundation with larger quota and revised default requests/limits while preserving the same constrained ownership boundary.",
			Risk:        "medium", TargetNamespace: ManagedNamespace,
			Capabilities: []string{"namespace-governance", "resource-quota", "default-limits", "network-policy", "rollback", "fleet-upgrade"},
			Rollback:     "execute the Plan-bound rollback strategy with validated pre-images for updated resources and controlled deletion for resources introduced by the target revision",
			UpgradeFrom:  []string{SecureNamespaceVersion},
		},
	}
}

// Get returns the default baseline revision used by the single-cluster workflow.
// Explicit fleet upgrades use GetVersion so an existing default does not silently change.
func Get(id string) (Definition, bool) {
	return GetVersion(id, SecureNamespaceVersion)
}

func GetVersion(id, version string) (Definition, bool) {
	id = strings.TrimSpace(id)
	version = strings.TrimSpace(version)
	for _, d := range Catalog() {
		if d.ID == id && d.Version == version {
			return d, true
		}
	}
	return Definition{}, false
}

func Latest(id string) (Definition, bool) {
	var found Definition
	ok := false
	for _, d := range Catalog() {
		if d.ID == strings.TrimSpace(id) && (!ok || d.Version > found.Version) {
			found, ok = d, true
		}
	}
	return found, ok
}

func Resources(deploymentID, desiredDigest string) []controlplane.BaselineTaskResource {
	return ResourcesForVersion(deploymentID, desiredDigest, SecureNamespaceVersion)
}

func ResourcesForVersion(deploymentID, desiredDigest, version string) []controlplane.BaselineTaskResource {
	def, ok := GetVersion(SecureNamespaceID, version)
	if !ok {
		return nil
	}
	annotations := map[string]any{
		"platform.4so.io/managed":          "true",
		"platform.4so.io/deployment-id":    deploymentID,
		"platform.4so.io/desired-digest":   desiredDigest,
		"platform.4so.io/baseline-id":      SecureNamespaceID,
		"platform.4so.io/baseline-version": def.Version,
	}
	labels := map[string]any{"app.kubernetes.io/managed-by": "4so-platform-factory", "platform.4so.io/baseline": SecureNamespaceID}
	meta := func(name string) map[string]any {
		return map[string]any{"name": name, "namespace": ManagedNamespace, "annotations": annotations, "labels": labels}
	}
	quota := map[string]any{"pods": "50", "requests.cpu": "4", "requests.memory": "8Gi", "limits.cpu": "8", "limits.memory": "16Gi"}
	defaults := map[string]any{"cpu": "500m", "memory": "512Mi"}
	requests := map[string]any{"cpu": "100m", "memory": "128Mi"}
	if def.Version == SecureNamespaceUpgradeVersion {
		quota = map[string]any{"pods": "75", "requests.cpu": "6", "requests.memory": "12Gi", "limits.cpu": "12", "limits.memory": "24Gi"}
		defaults = map[string]any{"cpu": "750m", "memory": "768Mi"}
		requests = map[string]any{"cpu": "150m", "memory": "192Mi"}
	}
	return []controlplane.BaselineTaskResource{
		{APIVersion: "v1", Kind: "ResourceQuota", Namespace: ManagedNamespace, Name: "4so-baseline-quota", Object: map[string]any{
			"apiVersion": "v1", "kind": "ResourceQuota", "metadata": meta("4so-baseline-quota"),
			"spec": map[string]any{"hard": quota},
		}},
		{APIVersion: "v1", Kind: "LimitRange", Namespace: ManagedNamespace, Name: "4so-baseline-limits", Object: map[string]any{
			"apiVersion": "v1", "kind": "LimitRange", "metadata": meta("4so-baseline-limits"),
			"spec": map[string]any{"limits": []any{map[string]any{"type": "Container", "default": defaults, "defaultRequest": requests}}},
		}},
		{APIVersion: "networking.k8s.io/v1", Kind: "NetworkPolicy", Namespace: ManagedNamespace, Name: "4so-default-deny-ingress", Object: map[string]any{
			"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": meta("4so-default-deny-ingress"),
			"spec": map[string]any{"podSelector": map[string]any{}, "policyTypes": []any{"Ingress"}},
		}},
		{APIVersion: "v1", Kind: "ServiceAccount", Namespace: ManagedNamespace, Name: "4so-baseline-observer", Object: map[string]any{
			"apiVersion": "v1", "kind": "ServiceAccount", "metadata": meta("4so-baseline-observer"), "automountServiceAccountToken": false,
		}},
		{APIVersion: "v1", Kind: "ConfigMap", Namespace: ManagedNamespace, Name: "4so-baseline-revision", Object: map[string]any{
			"apiVersion": "v1", "kind": "ConfigMap", "metadata": meta("4so-baseline-revision"),
			"data": map[string]any{"baselineId": SecureNamespaceID, "baselineVersion": def.Version, "deploymentId": deploymentID, "desiredDigest": desiredDigest},
		}},
	}
}

func DesiredDigest(projectID, clusterID, baselineID string) (string, error) {
	return DesiredDigestVersion(projectID, clusterID, baselineID, SecureNamespaceVersion)
}

func DesiredDigestVersion(projectID, clusterID, baselineID, version string) (string, error) {
	def, ok := GetVersion(baselineID, version)
	if !ok {
		return "", fmt.Errorf("unknown baseline %q version %q", baselineID, version)
	}
	identity := struct {
		ProjectID string `json:"projectId"`
		ClusterID string `json:"clusterId"`
		Baseline  string `json:"baseline"`
		Version   string `json:"version"`
		Namespace string `json:"namespace"`
	}{projectID, clusterID, def.ID, def.Version, def.TargetNamespace}
	raw, err := json.Marshal(identity)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func ResourceDigest(v controlplane.BaselineTaskResource) string {
	raw, _ := json.Marshal(v.Object)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func SortChanges(changes []controlplane.BaselinePlanChange) {
	sort.Slice(changes, func(i, j int) bool { return changes[i].Resource < changes[j].Resource })
}
