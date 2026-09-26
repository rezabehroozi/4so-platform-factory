package catalog

import (
	"fmt"
	"sort"
	"strings"
)

const KyvernoCRDNormalizationAuthority = "KYVERNO_3_8_2_GITOPS_CRD_NORMALIZATION_V1"

var kyverno382PoliciesCRDs = map[string]struct{}{
	"deletingpolicies.policies.kyverno.io": {},
	"generatingpolicies.policies.kyverno.io": {},
	"imagevalidatingpolicies.policies.kyverno.io": {},
	"mutatingpolicies.policies.kyverno.io": {},
	"namespaceddeletingpolicies.policies.kyverno.io": {},
	"namespacedgeneratingpolicies.policies.kyverno.io": {},
	"namespacedimagevalidatingpolicies.policies.kyverno.io": {},
	"namespacedmutatingpolicies.policies.kyverno.io": {},
	"namespacedvalidatingpolicies.policies.kyverno.io": {},
	"policyexceptions.policies.kyverno.io": {},
	"validatingpolicies.policies.kyverno.io": {},
}

type RuntimeNormalizationEvidence struct {
	Authority                string   `json:"authority,omitempty"`
	Component                string   `json:"component,omitempty"`
	Version                  string   `json:"version,omitempty"`
	Applied                  bool     `json:"applied"`
	ResourceNames            []string `json:"resourceNames,omitempty"`
	RemovedEmptyLabels       int      `json:"removedEmptyLabels,omitempty"`
	RemovedEmptyAnnotations  int      `json:"removedEmptyAnnotations,omitempty"`
	ServerSideApplyAnnotated int      `json:"serverSideApplyAnnotated,omitempty"`
	ServerSideApplyResources []string `json:"serverSideApplyResources,omitempty"`
}

// normalizeRuntimeResources keeps upstream source evidence immutable while
// applying narrowly-scoped product runtime normalization. Kyverno 3.8.2 has a
// known upstream chart defect that emits literal empty metadata maps on the
// policies.kyverno.io CRDs. Kubernetes drops those maps, so desired/live state
// can never converge. The pinned source bytes are still verified unchanged;
// only these exact 11 CRDs may be normalized before runtime application.
func normalizeRuntimeResources(c Component, resources []map[string]any) (RuntimeNormalizationEvidence, error) {
	if c.Metadata.Name != "kyverno" || c.Spec.Release != "3.8.2" {
		return RuntimeNormalizationEvidence{}, nil
	}
	ev := RuntimeNormalizationEvidence{
		Authority: KyvernoCRDNormalizationAuthority,
		Component: c.Metadata.Name,
		Version: c.Spec.Release,
		Applied: true,
	}
	seen := map[string]bool{}
	for _, resource := range resources {
		if strings.TrimSpace(fmt.Sprint(resource["kind"])) != "CustomResourceDefinition" {
			continue
		}
		metadata, ok := resource["metadata"].(map[string]any)
		if !ok {
			return RuntimeNormalizationEvidence{}, fmt.Errorf("kyverno runtime normalization found CRD without metadata object")
		}
		name, _ := metadata["name"].(string)
		if strings.HasSuffix(name, ".policies.kyverno.io") {
			if _, ok := kyverno382PoliciesCRDs[name]; !ok {
				return RuntimeNormalizationEvidence{}, fmt.Errorf("kyverno runtime normalization found unexpected policies CRD %q", name)
			}
			if seen[name] {
				return RuntimeNormalizationEvidence{}, fmt.Errorf("kyverno runtime normalization found duplicate policies CRD %q", name)
			}
			seen[name] = true
			labels, ok := metadata["labels"]
			if !ok {
				return RuntimeNormalizationEvidence{}, fmt.Errorf("kyverno runtime normalization expected empty labels on %q", name)
			}
			labelMap, ok := labels.(map[string]any)
			if !ok || len(labelMap) != 0 {
				return RuntimeNormalizationEvidence{}, fmt.Errorf("kyverno runtime normalization refuses non-empty labels on %q", name)
			}
			annotations, ok := metadata["annotations"]
			if !ok {
				return RuntimeNormalizationEvidence{}, fmt.Errorf("kyverno runtime normalization expected empty annotations on %q", name)
			}
			annotationMap, ok := annotations.(map[string]any)
			if !ok || len(annotationMap) != 0 {
				return RuntimeNormalizationEvidence{}, fmt.Errorf("kyverno runtime normalization refuses non-empty annotations on %q", name)
			}
			delete(metadata, "labels")
			delete(metadata, "annotations")
			ev.RemovedEmptyLabels++
			ev.RemovedEmptyAnnotations++
			ev.ResourceNames = append(ev.ResourceNames, name)
		}
		annotations, ok := metadata["annotations"]
		if !ok {
			annotations = map[string]any{}
			metadata["annotations"] = annotations
		}
		annotationMap, ok := annotations.(map[string]any)
		if !ok {
			return RuntimeNormalizationEvidence{}, fmt.Errorf("kyverno runtime normalization found non-object annotations on CRD %q", name)
		}
		const syncKey = "argocd.argoproj.io/sync-options"
		const syncValue = "ServerSideApply=true"
		current, exists := annotationMap[syncKey]
		if exists {
			currentText, ok := current.(string)
			if !ok {
				return RuntimeNormalizationEvidence{}, fmt.Errorf("kyverno runtime normalization found invalid Argo CD sync option on CRD %q", name)
			}
			options := strings.Split(currentText, ",")
			found := false
			for _, option := range options {
				if strings.TrimSpace(option) == syncValue {
					found = true
					break
				}
			}
			if !found {
				if strings.TrimSpace(currentText) == "" {
					annotationMap[syncKey] = syncValue
				} else {
					annotationMap[syncKey] = currentText + "," + syncValue
				}
			}
		} else {
			annotationMap[syncKey] = syncValue
		}
		ev.ServerSideApplyAnnotated++
		ev.ServerSideApplyResources = append(ev.ServerSideApplyResources, name)
	}
	if len(seen) != len(kyverno382PoliciesCRDs) {
		missing := make([]string, 0)
		for name := range kyverno382PoliciesCRDs {
			if !seen[name] {
				missing = append(missing, name)
			}
		}
		sort.Strings(missing)
		return RuntimeNormalizationEvidence{}, fmt.Errorf("kyverno runtime normalization CRD coverage mismatch missing=%v", missing)
	}
	sort.Strings(ev.ResourceNames)
	sort.Strings(ev.ServerSideApplyResources)
	if ev.ServerSideApplyAnnotated == 0 {
		return RuntimeNormalizationEvidence{}, fmt.Errorf("kyverno runtime normalization found no CRDs for server-side apply")
	}
	return ev, nil
}
