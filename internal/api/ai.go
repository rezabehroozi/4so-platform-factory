package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"platform.4so.io/factory/internal/airuntime"
	"platform.4so.io/factory/internal/auth"
	"platform.4so.io/factory/internal/controlplane"
)

var errCapabilityAccessDenied = errors.New("capability access denied")

func principalHasPermission(principal auth.Principal, wanted string) bool {
	wanted = strings.TrimSpace(wanted)
	for _, permission := range principal.Permissions {
		if strings.TrimSpace(permission) == wanted {
			return true
		}
	}
	return false
}

// requireCapabilityAuthorization adds capability-specific authorization after the
// product authentication boundary. This is intentionally separate from HTTP
// method authorization because read-only MCP and advisory AI both use POST.
func (s *Server) requireCapabilityAuthorization(r *http.Request, permission string, allowViewer bool) error {
	principal, ok := requestPrincipal(r)
	if !ok {
		return nil
	} // direct internal handler tests
	allowed := false
	reason := "CAPABILITY_PERMISSION_REQUIRED"
	if principal.Authentication == "api-token" {
		allowed = principalHasPermission(principal, permission)
	} else if allowViewer {
		allowed = auth.HasAnyRole(principal, "platform-admin", "platform-operator", "platform-viewer")
		reason = "PRODUCT_ROLE_REQUIRED"
	} else {
		allowed = auth.HasAnyRole(principal, "platform-admin", "platform-operator")
		reason = "OPERATOR_ROLE_REQUIRED"
	}
	decision := "DENY"
	status := http.StatusForbidden
	if allowed {
		decision = "ALLOW"
		status = http.StatusOK
		reason = "CAPABILITY_AUTHORIZED"
	}
	if _, err := s.store.AppendSecurityAudit(r.Context(), controlplane.SecurityAuditInput{Category: "CAPABILITY_AUTHORIZATION", Decision: decision, ActorID: principal.Subject, Authentication: principal.Authentication, Method: r.Method, Path: r.URL.Path, StatusCode: status, ReasonCode: reason, RequestID: r.Header.Get("X-Request-ID"), EffectiveRole: auth.CanonicalRole(principal.Roles), MappingDigest: principal.MappingDigest}); err != nil {
		return fmt.Errorf("security audit unavailable: %w", err)
	}
	if !allowed {
		return errCapabilityAccessDenied
	}
	return nil
}

func writeCapabilityAuthorizationError(w http.ResponseWriter, permission string, err error) {
	if errors.Is(err, errCapabilityAccessDenied) {
		writeError(w, http.StatusForbidden, "CAPABILITY_PERMISSION_REQUIRED", fmt.Sprintf("%s capability permission is required", permission))
		return
	}
	writeError(w, http.StatusServiceUnavailable, "SECURITY_AUDIT_UNAVAILABLE", "capability authorization could not be durably audited")
}

type aiDiagnosisInput struct {
	ProjectID   string `json:"projectId"`
	Question    string `json:"question"`
	OperationID string `json:"operationId,omitempty"`
	ClusterID   string `json:"clusterId,omitempty"`
}

func (s *Server) getAIPolicy(w http.ResponseWriter, _ *http.Request) {
	if s.aiRuntime == nil {
		writeJSON(w, http.StatusOK, map[string]any{"runtimeAuthority": airuntime.RuntimeAuthority, "enabled": false, "provider": airuntime.ProviderNone, "redactionRequired": true, "structuredOutputRequired": true, "rawPromptPersisted": false, "advisoryOnly": true, "canDecidePass": false, "canDecidePhysicalPass": false})
		return
	}
	writeJSON(w, http.StatusOK, s.aiRuntime.Policy())
}

func (s *Server) diagnoseAI(w http.ResponseWriter, r *http.Request) {
	if err := s.requireCapabilityAuthorization(r, controlplane.APITokenPermissionAIDiagnose, false); err != nil {
		writeCapabilityAuthorizationError(w, controlplane.APITokenPermissionAIDiagnose, err)
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if key == "" || len(key) > 200 {
		writeError(w, http.StatusBadRequest, "IDEMPOTENCY_KEY_REQUIRED", "Idempotency-Key is required and must be at most 200 characters")
		return
	}
	var in aiDiagnosisInput
	if err = decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	in.ProjectID = strings.TrimSpace(in.ProjectID)
	in.Question = strings.TrimSpace(in.Question)
	in.OperationID = strings.TrimSpace(in.OperationID)
	in.ClusterID = strings.TrimSpace(in.ClusterID)
	if in.ProjectID == "" || in.Question == "" || len(in.Question) > 1000 || (in.OperationID == "" && in.ClusterID == "") {
		writeError(w, http.StatusUnprocessableEntity, "AI_DIAGNOSIS_CONTEXT_REQUIRED", "projectId, a question up to 1000 characters, and operationId or clusterId are required")
		return
	}
	if _, err = s.requireProjectAccess(r, in.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}

	items := []map[string]any{{"source": "operator", "trust": "OPERATOR_INPUT", "value": map[string]any{"question": in.Question}}}
	revisions := map[string]int64{}
	linkedType, linkedID := "", ""
	if in.OperationID != "" {
		operation, e := s.store.GetOperation(r.Context(), in.OperationID)
		if e != nil || operation.ProjectID != in.ProjectID {
			writeStoreError(w, controlplane.ErrNotFound)
			return
		}
		revisions["operation"] = operation.Revision
		linkedType, linkedID = "operation", operation.ID
		items = append(items, map[string]any{"source": "control-plane", "trust": "PRODUCT_AUTHORITY", "value": map[string]any{"type": "operation", "id": operation.ID, "revision": operation.Revision, "kind": operation.Kind, "targetRef": operation.TargetRef, "desiredRevision": operation.DesiredRevision, "state": operation.State, "risk": operation.Risk, "class": operation.Class, "attempt": operation.Attempt, "lastFailureClass": operation.LastFailureClass, "retryExhausted": operation.RetryExhausted, "lastError": operation.LastError, "recoveryEvidenceDigest": operation.RecoveryEvidenceDigest}})
	}
	if in.ClusterID != "" {
		cluster, e := s.store.GetManagedCluster(r.Context(), in.ClusterID)
		if e != nil || cluster.ProjectID != in.ProjectID {
			writeStoreError(w, controlplane.ErrNotFound)
			return
		}
		revisions["cluster"] = cluster.Revision
		if linkedType == "" {
			linkedType, linkedID = "managedCluster", cluster.ID
		}
		value := map[string]any{"type": "managedCluster", "id": cluster.ID, "revision": cluster.Revision, "name": cluster.Name, "connectionState": cluster.ConnectionState, "distribution": cluster.Distribution, "kubernetesVersion": cluster.KubernetesVersion, "agentVersion": cluster.AgentVersion, "lastSeenAt": cluster.LastSeenAt, "inventoryObservedAt": cluster.InventoryObservedAt, "capabilities": cluster.Capabilities, "inventoryDigest": cluster.InventoryDigest, "mutationRbacBasisDigest": cluster.MutationRBACBasisDigest, "mutationRbacIssuedForDigest": cluster.MutationRBACIssuedForDigest}
		if inventory, e := s.store.GetLatestClusterInventory(r.Context(), cluster.ID); e == nil {
			value["inventory"] = map[string]any{"observedAt": inventory.ObservedAt, "distribution": inventory.Distribution, "kubernetesVersion": inventory.KubernetesVersion, "nodeCount": len(inventory.Nodes), "addOnCount": len(inventory.AddOns), "storageClassCount": len(inventory.StorageClasses), "apiDiscoveryComplete": inventory.APIDiscoveryComplete, "crdDiscoveryComplete": inventory.CRDDiscoveryComplete, "schemaDiscoveryComplete": inventory.SchemaDiscoveryComplete, "capabilities": inventory.Capabilities, "digest": inventory.Digest}
		}
		items = append(items, map[string]any{"source": "control-plane", "trust": "PRODUCT_AUTHORITY", "value": value})
	}
	requestDigest := digestValue(map[string]any{"projectId": in.ProjectID, "question": in.Question, "operationId": in.OperationID, "clusterId": in.ClusterID, "revisions": revisions})
	if existing, e := s.store.GetAIRunByIdempotencyKey(r.Context(), in.ProjectID, key); e == nil {
		if existing.RequestDigest != requestDigest {
			writeError(w, http.StatusConflict, "AI_IDEMPOTENCY_CONFLICT", "Idempotency-Key already belongs to a different AI diagnosis request")
			return
		}
		diagnosis, e := airuntime.ParseDiagnosis(existing.Output)
		if e != nil {
			writeError(w, http.StatusInternalServerError, "AI_RUN_OUTPUT_INVALID", "persisted AI run output is invalid")
			return
		}
		setRevisionETag(w, existing.Revision)
		writeJSON(w, http.StatusOK, map[string]any{"run": existing, "diagnosis": diagnosis, "idempotentReplay": true, "advisoryOnly": true, "executionAllowed": false})
		return
	} else if !errors.Is(e, controlplane.ErrNotFound) {
		writeStoreError(w, e)
		return
	}
	if s.aiRuntime == nil || !s.aiRuntime.Enabled() {
		writeError(w, http.StatusServiceUnavailable, "AI_RUNTIME_DISABLED", "no AI provider is configured; deterministic platform operations remain available")
		return
	}
	generated, e := s.aiRuntime.Generate(r.Context(), airuntime.Request{Purpose: "operator-diagnosis", PromptID: airuntime.PromptOperatorDiagnosis, System: airuntime.DiagnosisSystem(), Input: map[string]any{"contextItems": items, "constraints": []string{"advisory-only", "no mutation authority", "no PASS authority", "no Physical PASS authority"}}, JSONSchema: airuntime.DiagnosisSchema()})
	if e != nil {
		writeError(w, http.StatusBadGateway, "AI_DIAGNOSIS_FAILED", e.Error())
		return
	}
	diagnosis, e := airuntime.ParseDiagnosis(generated.JSON)
	if e != nil {
		writeError(w, http.StatusBadGateway, "AI_OUTPUT_REJECTED", e.Error())
		return
	}
	run, replay, e := s.store.CreateAIRun(r.Context(), controlplane.AIRun{ProjectID: in.ProjectID, Purpose: generated.Purpose, Provider: generated.Provider, Model: generated.Model, PromptID: generated.PromptID, PromptDigest: generated.PromptDigest, ContextDigest: generated.ContextDigest, OutputDigest: generated.OutputDigest, RedactionCount: generated.RedactionCount, InputBytes: generated.InputBytes, InputTokens: generated.Usage.InputTokens, CachedTokens: generated.Usage.CachedTokens, OutputTokens: generated.Usage.OutputTokens, Output: generated.JSON, LinkedResourceType: linkedType, LinkedResourceID: linkedID, IdempotencyKey: key, RequestDigest: requestDigest, AdvisoryOnly: true}, actor)
	if e != nil {
		writeStoreError(w, e)
		return
	}
	status := http.StatusCreated
	if replay {
		status = http.StatusOK
	}
	setRevisionETag(w, run.Revision)
	writeJSON(w, status, map[string]any{"run": run, "diagnosis": diagnosis, "idempotentReplay": replay, "advisoryOnly": true, "executionAllowed": false})
}

func (s *Server) listAIRuns(w http.ResponseWriter, r *http.Request) {
	projectID := strings.TrimSpace(r.URL.Query().Get("projectId"))
	if projectID != "" {
		if _, err := s.requireProjectAccess(r, projectID, organizationRead); err != nil {
			writeScopeError(w, err)
			return
		}
	}
	values, err := s.store.ListAIRuns(r.Context(), projectID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	allowed, all, err := s.accessibleProjectSet(r)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	values = filterProjectScoped(values, allowed, all, func(v controlplane.AIRun) string { return v.ProjectID })
	writeJSON(w, http.StatusOK, values)
}

func (s *Server) getAIRun(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.GetAIRun(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, v.ProjectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusOK, v)
}
