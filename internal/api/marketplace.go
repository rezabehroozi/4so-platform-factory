package api

import (
	"errors"
	"net/http"
	"strings"

	"platform.4so.io/factory/internal/baseline"
	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/marketplace"
)

type createMarketplaceInstallationInput struct {
	ProjectID    string `json:"projectId"`
	ClusterID    string `json:"clusterId"`
	OfferID      string `json:"offerId"`
	OfferVersion string `json:"offerVersion,omitempty"`
}

type createMarketplaceRecommendationInput struct {
	ProjectID string `json:"projectId"`
	ClusterID string `json:"clusterId"`
	Objective string `json:"objective"`
}

func (s *Server) listMarketplaceOffers(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, marketplace.Catalog())
}

func clusterHasCapabilities(cluster controlplane.ManagedCluster, required []string) bool {
	available := map[string]bool{}
	for _, capability := range cluster.Capabilities {
		available[strings.TrimSpace(capability)] = true
	}
	for _, capability := range required {
		if !available[capability] {
			return false
		}
	}
	return true
}

func marketplaceInstallationView(v controlplane.BaselineDeployment) map[string]any {
	offer, _ := marketplace.Get(v.SourceID, v.SourceVersion)
	return map[string]any{
		"installation": v,
		"offer":        offer,
		"advisoryOnly": false,
		"next":         marketplaceNext(v),
	}
}

func marketplaceNext(v controlplane.BaselineDeployment) string {
	switch v.State {
	case controlplane.BaselineDeploymentPlanning:
		return "agent-plan"
	case controlplane.BaselineDeploymentAwaitingApproval:
		return "approve"
	case controlplane.BaselineDeploymentQueued, controlplane.BaselineDeploymentApplying:
		return "agent-apply"
	case controlplane.BaselineDeploymentSucceeded:
		return "uninstall-when-needed"
	case controlplane.BaselineDeploymentFailed:
		return "retry-or-uninstall"
	case controlplane.BaselineDeploymentRollbackQueued, controlplane.BaselineDeploymentRollingBack:
		return "agent-rollback"
	default:
		return "complete"
	}
}

func (s *Server) createMarketplaceInstallation(w http.ResponseWriter, r *http.Request) {
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
	var in createMarketplaceInstallationInput
	if err = decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	if _, err = s.requireProjectAccess(r, in.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	offer, ok := marketplace.Get(in.OfferID, in.OfferVersion)
	if !ok {
		writeError(w, http.StatusUnprocessableEntity, "MARKETPLACE_OFFER_NOT_FOUND", "the selected published offer and version are not available")
		return
	}
	cluster, err := s.store.GetManagedCluster(r.Context(), strings.TrimSpace(in.ClusterID))
	if err != nil || cluster.ProjectID != strings.TrimSpace(in.ProjectID) {
		writeStoreError(w, controlplane.ErrNotFound)
		return
	}
	if !clusterHasCapabilities(cluster, offer.RequiredClusterCapabilities) {
		writeError(w, http.StatusUnprocessableEntity, "MARKETPLACE_CAPABILITY_MISSING", "the target cluster has not reported every capability required by this offer")
		return
	}
	def, ok := baseline.GetVersion(offer.BaselineID, offer.BaselineVersion)
	if !ok {
		writeError(w, http.StatusInternalServerError, "MARKETPLACE_BASELINE_UNAVAILABLE", "the published offer does not resolve to an admitted baseline revision")
		return
	}
	desired, err := baseline.DesiredDigestVersion(in.ProjectID, in.ClusterID, def.ID, def.Version)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "MARKETPLACE_DIGEST_FAILED", err.Error())
		return
	}
	requestDigest := digestValue(map[string]any{"projectId": in.ProjectID, "clusterId": in.ClusterID, "offerId": offer.ID, "offerVersion": offer.Version})
	v, replay, err := s.store.CreateBaselineDeployment(r.Context(), controlplane.BaselineDeployment{
		ProjectID: in.ProjectID, ClusterID: in.ClusterID, BaselineID: def.ID, BaselineVersion: def.Version,
		TargetNamespace: def.TargetNamespace, Risk: def.Risk, DesiredDigest: desired,
		RequestDigest: requestDigest, IdempotencyKey: key,
		SourceType: marketplace.SourceType, SourceID: offer.ID, SourceVersion: offer.Version,
	}, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	status := http.StatusCreated
	if replay {
		status = http.StatusOK
	}
	setRevisionETag(w, v.Revision)
	view := marketplaceInstallationView(v)
	view["idempotentReplay"] = replay
	writeJSON(w, status, view)
}

func (s *Server) listMarketplaceInstallations(w http.ResponseWriter, r *http.Request) {
	projectID := strings.TrimSpace(r.URL.Query().Get("projectId"))
	if projectID != "" {
		if _, err := s.requireProjectAccess(r, projectID, organizationRead); err != nil {
			writeScopeError(w, err)
			return
		}
	}
	clusterID := strings.TrimSpace(r.URL.Query().Get("clusterId"))
	var page func([]string, bool, *controlplane.CollectionCursor, int) ([]controlplane.BaselineDeployment, error)
	if pager, ok := s.store.(marketplaceInstallationPageStore); ok {
		page = func(ids []string, all bool, cursor *controlplane.CollectionCursor, limit int) ([]controlplane.BaselineDeployment, error) {
			return pager.ListMarketplaceInstallationsPage(r.Context(), ids, all, clusterID, cursor, limit)
		}
	}
	items, err := boundedProjectCollection(s, w, r, projectID, func() ([]controlplane.BaselineDeployment, error) {
		values, e := s.store.ListBaselineDeployments(r.Context(), projectID, clusterID)
		if e != nil {
			return nil, e
		}
		out := make([]controlplane.BaselineDeployment, 0, len(values))
		for _, item := range values {
			if item.SourceType == marketplace.SourceType {
				out = append(out, item)
			}
		}
		return out, nil
	}, page, func(item controlplane.BaselineDeployment) string { return item.ProjectID })
	if err != nil {
		writeStoreError(w, err)
		return
	}
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		out = append(out, marketplaceInstallationView(item))
	}
	writeOperatorCollectionJSON(w, r, http.StatusOK, out)
}

func (s *Server) marketplaceInstallation(w http.ResponseWriter, r *http.Request) (controlplane.BaselineDeployment, bool) {
	v, err := s.store.GetBaselineDeployment(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return controlplane.BaselineDeployment{}, false
	}
	if v.SourceType != marketplace.SourceType {
		writeError(w, http.StatusNotFound, "MARKETPLACE_INSTALLATION_NOT_FOUND", "marketplace installation not found")
		return controlplane.BaselineDeployment{}, false
	}
	return v, true
}

func (s *Server) getMarketplaceInstallation(w http.ResponseWriter, r *http.Request) {
	v, ok := s.marketplaceInstallation(w, r)
	if !ok {
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusOK, marketplaceInstallationView(v))
}

func (s *Server) mutateMarketplaceInstallation(w http.ResponseWriter, r *http.Request, action string) {
	current, ok := s.marketplaceInstallation(w, r)
	if !ok {
		return
	}
	if _, err := s.requireProjectAccess(r, current.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	actor, err := actorID(r)
	if action == "approve" {
		actor, err = approvalActor(r, current.RequestedBy)
	}
	if err != nil {
		if action == "approve" {
			writeApprovalError(w, err)
		} else {
			writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		}
		return
	}
	rev, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, 428, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	if current.Revision != rev {
		writeStoreError(w, controlplane.ErrConflict)
		return
	}
	var v controlplane.BaselineDeployment
	switch action {
	case "approve":
		v, err = s.store.ApproveBaselineDeployment(r.Context(), current.ID, rev, actor)
	case "uninstall":
		if strings.TrimSpace(r.Header.Get("X-Confirm-Uninstall")) != "remove-marketplace-installation" {
			writeError(w, 428, "UNINSTALL_CONFIRMATION_REQUIRED", "X-Confirm-Uninstall: remove-marketplace-installation is required")
			return
		}
		var in destructiveRecoveryInput
		if err = decodeJSON(w, r, &in); err != nil {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
			return
		}
		if err = in.validate(); err != nil {
			writeError(w, http.StatusBadRequest, "RECOVERY_CHECKPOINT_REQUIRED", err.Error())
			return
		}
		v, err = s.store.QueueBaselineRollback(r.Context(), current.ID, rev, actor, in.RecoveryCheckpointID, digestValue(in))
	case "retry":
		v, err = s.store.RetryBaselineDeployment(r.Context(), current.ID, rev, actor)
	default:
		err = controlplane.ErrValidation
	}
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusOK, marketplaceInstallationView(v))
}

func (s *Server) approveMarketplaceInstallation(w http.ResponseWriter, r *http.Request) {
	s.mutateMarketplaceInstallation(w, r, "approve")
}
func (s *Server) uninstallMarketplaceInstallation(w http.ResponseWriter, r *http.Request) {
	s.mutateMarketplaceInstallation(w, r, "uninstall")
}
func (s *Server) retryMarketplaceInstallation(w http.ResponseWriter, r *http.Request) {
	s.mutateMarketplaceInstallation(w, r, "retry")
}

func (s *Server) createMarketplaceRecommendation(w http.ResponseWriter, r *http.Request) {
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
	var in createMarketplaceRecommendationInput
	if err = decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	if _, err = s.requireProjectAccess(r, in.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	in.ProjectID, in.ClusterID, in.Objective = strings.TrimSpace(in.ProjectID), strings.TrimSpace(in.ClusterID), strings.TrimSpace(in.Objective)
	if in.Objective == "" || len(in.Objective) > 1000 {
		writeError(w, http.StatusUnprocessableEntity, "MARKETPLACE_OBJECTIVE_INVALID", "objective must contain 1-1000 characters")
		return
	}
	cluster, err := s.store.GetManagedCluster(r.Context(), in.ClusterID)
	if err != nil || cluster.ProjectID != in.ProjectID {
		writeStoreError(w, controlplane.ErrNotFound)
		return
	}
	installedDeployments, err := s.store.ListBaselineDeployments(r.Context(), in.ProjectID, in.ClusterID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	installed := map[string]bool{}
	for _, deployment := range installedDeployments {
		if deployment.SourceType == marketplace.SourceType && deployment.State != controlplane.BaselineDeploymentRolledBack {
			installed[deployment.SourceID+"@"+deployment.SourceVersion] = true
		}
	}
	eligible := marketplace.Eligible(cluster.Capabilities, installed)
	contextValue := map[string]any{"projectId": in.ProjectID, "clusterId": in.ClusterID, "objective": in.Objective, "kubernetesVersion": cluster.KubernetesVersion, "capabilities": cluster.Capabilities, "eligibleOffers": eligible}
	contextDigest := digestValue(contextValue)
	requestDigest := digestValue(map[string]any{"projectId": in.ProjectID, "clusterId": in.ClusterID, "objective": in.Objective, "contextDigest": contextDigest})
	if existing, existingErr := s.store.GetMarketplaceRecommendationByIdempotencyKey(r.Context(), in.ProjectID, key); existingErr == nil {
		if existing.RequestDigest != requestDigest {
			writeError(w, http.StatusConflict, "MARKETPLACE_IDEMPOTENCY_CONFLICT", "Idempotency-Key already belongs to a different recommendation context")
			return
		}
		setRevisionETag(w, existing.Revision)
		writeJSON(w, http.StatusOK, map[string]any{"recommendation": existing, "idempotentReplay": true, "advisoryOnly": true, "executionAllowed": false})
		return
	} else if !errors.Is(existingErr, controlplane.ErrNotFound) {
		writeStoreError(w, existingErr)
		return
	}
	aiRunKey := "marketplace:" + strings.TrimPrefix(digestValue(map[string]any{"projectId": in.ProjectID, "idempotencyKey": key}), "sha256:")
	advisor := s.marketplaceAdvisor
	if advisor == nil {
		advisor = marketplace.NewControlledAdvisor(marketplace.Config{})
	}
	var result marketplace.AdvisoryOutput
	if priorRun, runErr := s.store.GetAIRunByIdempotencyKey(r.Context(), in.ProjectID, aiRunKey); runErr == nil {
		if priorRun.RequestDigest != requestDigest || priorRun.Purpose != "marketplace-recommendation" {
			writeError(w, http.StatusConflict, "AI_IDEMPOTENCY_CONFLICT", "durable AI advisory key belongs to a different recommendation request")
			return
		}
		recommendations, parseErr := marketplace.RecommendationsFromAIJSON(priorRun.Output, eligible)
		if parseErr != nil {
			writeError(w, http.StatusInternalServerError, "AI_RUN_OUTPUT_INVALID", "persisted marketplace AI output is invalid for the current eligible offer set")
			return
		}
		result = marketplace.AdvisoryOutput{Engine: "model", Model: priorRun.Model, Recommendations: recommendations}
	} else if !errors.Is(runErr, controlplane.ErrNotFound) {
		writeStoreError(w, runErr)
		return
	} else {
		modelBacked := advisor.UsesAIRuntime() && len(eligible) > 0
		if modelBacked {
			claim, acquired, claimErr := s.store.ClaimAIExecution(r.Context(), controlplane.AIExecutionClaim{ProjectID: in.ProjectID, Purpose: "marketplace-recommendation", IdempotencyKey: aiRunKey, RequestDigest: requestDigest}, actor)
			if claimErr != nil {
				if errors.Is(claimErr, controlplane.ErrIdempotencyConflict) {
					writeError(w, http.StatusConflict, "AI_IDEMPOTENCY_CONFLICT", "durable AI advisory key belongs to a different recommendation request")
				} else {
					writeStoreError(w, claimErr)
				}
				return
			}
			if !acquired {
				switch claim.State {
				case controlplane.AIExecutionDispatched:
					writeError(w, http.StatusConflict, "AI_EXECUTION_ALREADY_DISPATCHED", "this recommendation's AI dispatch has already occurred and will not be sent again automatically")
				case controlplane.AIExecutionFailed:
					writeError(w, http.StatusConflict, "AI_EXECUTION_PREVIOUSLY_FAILED", "this recommendation's AI dispatch already failed; use a new Idempotency-Key to explicitly retry")
				default:
					writeError(w, http.StatusInternalServerError, "AI_EXECUTION_AUTHORITY_INVALID", "AI execution claim is inconsistent with durable recommendation state")
				}
				return
			}
		}
		result, err = advisor.Recommend(r.Context(), marketplace.AdvisoryInput{Objective: in.Objective, KubernetesVersion: cluster.KubernetesVersion, Capabilities: append([]string(nil), cluster.Capabilities...)}, eligible)
		if err != nil {
			if modelBacked {
				if _, failErr := s.store.FailAIExecution(r.Context(), in.ProjectID, aiRunKey, requestDigest, "PROVIDER_REQUEST_FAILED", actor); failErr != nil {
					writeStoreError(w, failErr)
					return
				}
			}
			writeError(w, http.StatusBadGateway, "CONTROLLED_AI_ADVISOR_FAILED", err.Error())
			return
		}
		if modelBacked && result.AIRuntime == nil {
			_, _ = s.store.FailAIExecution(r.Context(), in.ProjectID, aiRunKey, requestDigest, "MODEL_RESULT_MISSING", actor)
			writeError(w, http.StatusBadGateway, "CONTROLLED_AI_OUTPUT_REJECTED", "model-backed advisor returned no durable AI runtime result")
			return
		}
		if result.AIRuntime != nil {
			if !modelBacked {
				writeError(w, http.StatusInternalServerError, "AI_EXECUTION_AUTHORITY_INVALID", "marketplace advisor returned an AI runtime result without declaring provider dispatch authority")
				return
			}
			generated := result.AIRuntime
			if _, _, _, finalizeErr := s.store.FinalizeAIExecution(r.Context(), controlplane.AIRun{ProjectID: in.ProjectID, Purpose: generated.Purpose, Provider: generated.Provider, Model: generated.Model, PromptID: generated.PromptID, PromptDigest: generated.PromptDigest, ContextDigest: generated.ContextDigest, OutputDigest: generated.OutputDigest, RedactionCount: generated.RedactionCount, InputBytes: generated.InputBytes, InputTokens: generated.Usage.InputTokens, CachedTokens: generated.Usage.CachedTokens, OutputTokens: generated.Usage.OutputTokens, Output: generated.JSON, LinkedResourceType: "managedCluster", LinkedResourceID: cluster.ID, IdempotencyKey: aiRunKey, RequestDigest: requestDigest, AdvisoryOnly: true}, actor); finalizeErr != nil {
				writeStoreError(w, finalizeErr)
				return
			}
		}
	}
	allowed := map[string]marketplace.Offer{}
	for _, offer := range eligible {
		allowed[offer.ID+"@"+offer.Version] = offer
	}
	items := make([]controlplane.MarketplaceRecommendationItem, 0, len(result.Recommendations))
	for _, item := range result.Recommendations {
		offer, ok := allowed[item.OfferID+"@"+item.OfferVersion]
		if !ok {
			writeError(w, http.StatusBadGateway, "CONTROLLED_AI_OUTPUT_REJECTED", "advisor selected an offer outside the eligible allowlist")
			return
		}
		items = append(items, controlplane.MarketplaceRecommendationItem{OfferID: item.OfferID, OfferVersion: item.OfferVersion, Score: item.Score, Reason: item.Reason, Risk: offer.Risk})
	}
	responseDigest := digestValue(items)
	v, replay, err := s.store.CreateMarketplaceRecommendation(r.Context(), controlplane.MarketplaceRecommendation{
		ProjectID: in.ProjectID, ClusterID: in.ClusterID, Objective: in.Objective,
		Engine: result.Engine, Model: result.Model, ContextDigest: contextDigest, ResponseDigest: responseDigest,
		Items: items, IdempotencyKey: key, RequestDigest: requestDigest,
	}, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	status := http.StatusCreated
	if replay {
		status = http.StatusOK
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, status, map[string]any{"recommendation": v, "idempotentReplay": replay, "advisoryOnly": true, "executionAllowed": false})
}

func (s *Server) listMarketplaceRecommendations(w http.ResponseWriter, r *http.Request) {
	projectID := strings.TrimSpace(r.URL.Query().Get("projectId"))
	if projectID != "" {
		if _, err := s.requireProjectAccess(r, projectID, organizationRead); err != nil {
			writeScopeError(w, err)
			return
		}
	}
	clusterID := strings.TrimSpace(r.URL.Query().Get("clusterId"))
	var page func([]string, bool, *controlplane.CollectionCursor, int) ([]controlplane.MarketplaceRecommendation, error)
	if pager, ok := s.store.(marketplaceRecommendationPageStore); ok {
		page = func(ids []string, all bool, cursor *controlplane.CollectionCursor, limit int) ([]controlplane.MarketplaceRecommendation, error) {
			return pager.ListMarketplaceRecommendationsPage(r.Context(), ids, all, clusterID, cursor, limit)
		}
	}
	v, err := boundedProjectCollection(s, w, r, projectID, func() ([]controlplane.MarketplaceRecommendation, error) {
		return s.store.ListMarketplaceRecommendations(r.Context(), projectID, clusterID)
	}, page, func(item controlplane.MarketplaceRecommendation) string { return item.ProjectID })
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeOperatorCollectionJSON(w, r, http.StatusOK, v)
}

func (s *Server) getMarketplaceRecommendation(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.GetMarketplaceRecommendation(r.Context(), r.PathValue("id"))
	if errors.Is(err, controlplane.ErrNotFound) {
		writeStoreError(w, err)
		return
	}
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, v.ProjectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusOK, map[string]any{"recommendation": v, "advisoryOnly": true, "executionAllowed": false})
}
