package api

import (
	"errors"
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
		// Exact source/mirror readiness remains external evidence, while the
		// product-owned durable lifecycle path is now source-implemented.
		ExactSourceAdmitted:        s.daprRuntimeReady,
		DisconnectedMirrorAdmitted: s.daprRuntimeReady,
		DurableLifecycleReady:      true,
	}
	inventory, invErr := s.store.GetLatestClusterInventory(r.Context(), cluster.ID)
	if invErr != nil && !errors.Is(invErr, controlplane.ErrNotFound) {
		writeStoreError(w, invErr)
		return
	}
	if invErr == nil {
		admissionInput.DistributionIdentity = inventory.Distribution
		admissionInput.TargetMutationReady = openChoreoInventoryCapability(inventory, controlplane.TargetMutationRBACActiveCapability)
		admissionInput.ExecutorRBACReady = openChoreoInventoryCapability(inventory, controlplane.DaprExecutorRBACCapability)
		admissionInput.CapabilityDiscoveryComplete = inventory.APIDiscoveryComplete && inventory.CRDDiscoveryComplete && inventory.SchemaDiscoveryComplete
		admissionInput.ObservedCapabilities = append([]string(nil), inventory.Capabilities...)
	}
	out := targetmodel.EvaluateDaprTargetAdmission(admissionInput)
	observed, observedErr := s.latestDaprObserved(r.Context(), input.ProjectID, input.ClusterID)
	if observedErr != nil {
		writeStoreError(w, observedErr)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"authority":                     targetmodel.DaprTargetAdmissionAuthority,
		"profileAuthority":              targetmodel.DaprApplicationRuntimeAuthority,
		"sourcePlan":                    targetmodel.DaprRuntimeSourcePlanModel(),
		"supplyChainAuthority":          targetmodel.DaprRuntimeSupplyChainAuthority,
		"supplyChainAdmitted":           s.daprRuntimeReady,
		"supplyChainDigest":             s.daprRuntimeDigest,
		"reviewedRuntimeVersion":        targetmodel.DaprReviewedRuntimeVersion,
		"assessment":                    out,
		"observed":                      observed,
		"runtimeInstallImplemented":     true,
		"physicalCertificationInferred": false,
	})
}


type daprWorkloadPlanRequest struct {
	ProjectID       string   `json:"projectId"`
	TraitID         string   `json:"traitId"`
	Namespace       string   `json:"namespace"`
	AppID           string   `json:"appId"`
	AppPort         int      `json:"appPort,omitempty"`
	AppProtocol     string   `json:"appProtocol,omitempty"`
	CPURequest      string   `json:"cpuRequest"`
	CPULimit        string   `json:"cpuLimit"`
	MemoryRequest   string   `json:"memoryRequest"`
	MemoryLimit     string   `json:"memoryLimit"`
	ComponentNames  []string `json:"componentNames,omitempty"`
	EnablePubSub    bool     `json:"enablePubSub"`
	EnableBindings  bool     `json:"enableBindings"`
	EnableInvocation bool    `json:"enableInvocation"`
}

func (s *Server) resolveDaprWorkloadPlan(w http.ResponseWriter, r *http.Request) {
	store, ok := s.applicationPlatformAuthority(w)
	if !ok { return }
	var input daprWorkloadPlanRequest
	if err := decodeJSON(w, r, &input); err != nil { return }
	input.ProjectID = strings.TrimSpace(input.ProjectID)
	input.TraitID = strings.TrimSpace(input.TraitID)
	if input.ProjectID == "" || input.TraitID == "" {
		writeError(w, http.StatusUnprocessableEntity, "DAPR_TRAIT_SCOPE_REQUIRED", "projectId and traitId are required")
		return
	}
	if !s.applicationProjectRead(w, r, input.ProjectID) { return }
	trait, err := store.GetCapabilityTrait(r.Context(), input.TraitID)
	if err != nil || trait.ProjectID != input.ProjectID {
		if err == nil { err = controlplane.ErrNotFound }
		writeStoreError(w, err)
		return
	}
	if trait.Kind != "sidecar" || trait.Capability != controlplane.ApplicationRuntimeDaprCapability {
		writeError(w, http.StatusUnprocessableEntity, "DAPR_TRAIT_REQUIRED", "trait must be the application-runtime.dapr sidecar capability")
		return
	}
	plan, err := targetmodel.ResolveDaprWorkloadRuntimePlan(targetmodel.DaprWorkloadPlanInput{
		Namespace: input.Namespace, AppID: input.AppID, AppPort: input.AppPort, AppProtocol: input.AppProtocol,
		CPURequest: input.CPURequest, CPULimit: input.CPULimit, MemoryRequest: input.MemoryRequest, MemoryLimit: input.MemoryLimit,
		ComponentNames: append([]string(nil), input.ComponentNames...),
		EnablePubSub: input.EnablePubSub, EnableBindings: input.EnableBindings, EnableInvocation: input.EnableInvocation,
	})
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error(), "Dapr workload plan admission failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"authority": targetmodel.DaprWorkloadRuntimePlanAuthority,
		"traitId": trait.ID, "traitDigest": trait.Digest,
		"plan": plan, "runtimeMutationPerformed": false, "physicalCertificationInferred": false,
	})
}
