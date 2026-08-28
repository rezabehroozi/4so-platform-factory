package api

import (
	"net/http"
	"strings"

	bp "platform.4so.io/factory/internal/blueprint"
	compatauth "platform.4so.io/factory/internal/compatibility"
	"platform.4so.io/factory/internal/domain"
	"platform.4so.io/factory/internal/targetmodel"
)

type compatibilityEvaluateInput struct {
	Blueprint domain.Blueprint  `json:"blueprint"`
	Target    compatauth.Target `json:"target"`
}

func (s *Server) evaluateCompatibility(w http.ResponseWriter, r *http.Request) {
	var in compatibilityEvaluateInput
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	validation := bp.Validate(in.Blueprint, s.components)
	if !validation.Valid {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"validation": validation})
		return
	}
	constraints := []compatauth.Constraint{{
		Name:                 "blueprint/" + in.Blueprint.Metadata.Name,
		KubernetesMinVersion: in.Blueprint.Spec.Compatibility.Kubernetes.MinVersion,
		KubernetesMaxVersion: in.Blueprint.Spec.Compatibility.Kubernetes.MaxVersion,
		Architectures:        append([]string(nil), in.Blueprint.Spec.Compatibility.Architectures...),
		Distributions:        append([]string(nil), in.Blueprint.Spec.Compatibility.DistributionProfiles...),
		Providers:            []string{"*"},
	}}
	for _, sel := range in.Blueprint.Spec.Components {
		if !sel.Enabled {
			continue
		}
		component, ok := s.components[sel.Name]
		if !ok {
			continue
		}
		constraints = append(constraints, compatauth.Constraint{
			Name:                 "component/" + sel.Name,
			KubernetesMinVersion: component.Spec.Compatibility.Kubernetes.MinVersion,
			KubernetesMaxVersion: component.Spec.Compatibility.Kubernetes.MaxVersion,
			Architectures:        append([]string(nil), component.Spec.Compatibility.Architectures...),
			Distributions:        append([]string(nil), component.Spec.Compatibility.DistributionProfiles...),
			Providers:            append([]string(nil), component.Spec.Compatibility.Providers...),
		})
	}
	decision := compatauth.Evaluate(in.Target, constraints)
	status := http.StatusOK
	if decision.Status != "PASS" {
		status = http.StatusUnprocessableEntity
	}
	writeJSON(w, status, map[string]any{
		"authority":                    compatauth.AuthorityMethod,
		"decision":                     decision,
		"targetModelAuthority":         targetmodel.AuthorityMethod,
		"targetModel":                  targetmodel.AdapterTarget(decision.Target.Distribution, decision.Target.Provider),
		"constraintCount":              len(constraints),
		"providerDimension":            strings.TrimSpace(in.Target.Provider) != "",
		"provisioningAdapterDimension": strings.TrimSpace(in.Target.Provider) != "",
		"serverReconstructed":          true,
	})
}
