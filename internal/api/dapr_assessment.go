package api

import (
	"net/http"
	"strings"

	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/targetmodel"
)

type daprAssessmentInput struct {
	ProjectID    string `json:"projectId"`
	ClusterID    string `json:"clusterId"`
	Disconnected bool   `json:"disconnected"`
}

func (s *Server) assessDaprApplicationRuntime(w http.ResponseWriter, r *http.Request) {
	var input daprAssessmentInput
	if err := decodeJSON(w, r, &input); err != nil {
		return
	}
	input.ProjectID = strings.TrimSpace(input.ProjectID)
	input.ClusterID = strings.TrimSpace(input.ClusterID)
	if input.ProjectID == "" || input.ClusterID == "" {
		writeError(w, http.StatusUnprocessableEntity, "TARGET_SCOPE_REQUIRED", "projectId and clusterId are required")
		return
	}
	if _, err := s.requireProjectAccess(r, input.ProjectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	cluster, err := s.store.GetManagedCluster(r.Context(), input.ClusterID)
	if err != nil || cluster.ProjectID != input.ProjectID {
		writeStoreError(w, controlplane.ErrNotFound)
		return
	}

	admissionInput := targetmodel.DaprTargetAdmissionInput{
		DistributionIdentity: cluster.Distribution,
		TargetAdmitted:       cluster.ConnectionState != "REVOKED",
		Disconnected:         input.Disconnected,
		// The source decision is intentionally ahead of runtime acquisition.
		// Product-managed installation stays blocked until exact Dapr chart/image
		// authority and durable lifecycle execution are separately implemented.
		ExactSourceAdmitted:        false,
		DisconnectedMirrorAdmitted: false,
		DurableLifecycleReady:      false,
	}
	inventory, invErr := s.store.GetLatestClusterInventory(r.Context(), cluster.ID)
	if invErr == nil {
		admissionInput.DistributionIdentity = inventory.Distribution
		admissionInput.TargetMutationReady = openChoreoInventoryCapability(inventory, controlplane.TargetMutationRBACActiveCapability)
		admissionInput.CapabilityDiscoveryComplete = inventory.APIDiscoveryComplete && inventory.CRDDiscoveryComplete && inventory.SchemaDiscoveryComplete
		admissionInput.ObservedCapabilities = append([]string(nil), inventory.Capabilities...)
	}
	out := targetmodel.EvaluateDaprTargetAdmission(admissionInput)
	writeJSON(w, http.StatusOK, map[string]any{
		"authority":                     targetmodel.DaprTargetAdmissionAuthority,
		"profileAuthority":              targetmodel.DaprApplicationRuntimeAuthority,
		"reviewedRuntimeVersion":        targetmodel.DaprReviewedRuntimeVersion,
		"assessment":                    out,
		"runtimeInstallImplemented":     false,
		"physicalCertificationInferred": false,
	})
}
