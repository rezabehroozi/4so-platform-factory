package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/evidence"
)

type createRuntimeClosureCampaignInput struct {
	ProjectID            string `json:"projectId"`
	ClusterID            string `json:"clusterId"`
	BaselineDeploymentID string `json:"baselineDeploymentId"`
}

func closureStateForBaseline(v controlplane.BaselineDeployment) (controlplane.RuntimeClosureCampaignState, string, string, string, error) {
	switch v.State {
	case controlplane.BaselineDeploymentPlanning:
		return controlplane.RuntimeClosureWaitingBaseline, "wait-agent-plan", "Waiting for the connected agent to return the read-only plan.", "", nil
	case controlplane.BaselineDeploymentAwaitingApproval:
		return controlplane.RuntimeClosureWaitingApproval, "approve-baseline-deployment", "The exact baseline revision requires explicit approval before mutation.", "", nil
	case controlplane.BaselineDeploymentQueued, controlplane.BaselineDeploymentApplying:
		return controlplane.RuntimeClosureWaitingBaseline, "wait-agent-apply", "Waiting for the connected agent to apply and verify the approved baseline.", "", nil
	case controlplane.BaselineDeploymentSucceeded:
		if !controlplane.BaselineCompletionEvidenceReady(v, time.Now().UTC()) {
			return "", "", "", "", fmt.Errorf("baseline completion evidence is missing, invalid or expired; re-plan and apply before runtime verification")
		}
		return controlplane.RuntimeClosureWaitingVerification, "advance-create-runtime-verification", "Baseline digest converged with sealed completion evidence; runtime verification is the next step.", "", nil
	case controlplane.BaselineDeploymentFailed:
		lastError := strings.TrimSpace(v.LastError)
		if lastError == "" {
			lastError = "baseline deployment failed"
		}
		return controlplane.RuntimeClosureFailed, "retry-baseline-deployment", "Baseline execution failed; retry resumes its exact pending action.", lastError, nil
	default:
		return "", "", "", "", fmt.Errorf("baseline state %s cannot enter runtime closure", v.State)
	}
}

func (s *Server) createRuntimeClosureCampaign(w http.ResponseWriter, r *http.Request) {
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
	var in createRuntimeClosureCampaignInput
	if err = decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	if _, err = s.requireProjectAccess(r, in.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	in.ProjectID = strings.TrimSpace(in.ProjectID)
	in.ClusterID = strings.TrimSpace(in.ClusterID)
	in.BaselineDeploymentID = strings.TrimSpace(in.BaselineDeploymentID)
	baseline, err := s.store.GetBaselineDeployment(r.Context(), in.BaselineDeploymentID)
	if err != nil || baseline.ProjectID != in.ProjectID || baseline.ClusterID != in.ClusterID {
		writeStoreError(w, controlplane.ErrNotFound)
		return
	}
	cluster, err := s.store.GetManagedCluster(r.Context(), in.ClusterID)
	if err != nil || cluster.ProjectID != in.ProjectID {
		writeStoreError(w, controlplane.ErrNotFound)
		return
	}
	if !evidence.IsSHA256Digest(s.runtimeClosureReleaseDigest) || !evidence.IsSHA256Digest(s.runtimeClosureProducerDigest) {
		writeError(w, http.StatusServiceUnavailable, "RUNTIME_CLOSURE_EXACT_RELEASE_IDENTITY_UNAVAILABLE", "runtime closure requires an exact release artifact digest and running platform-api binary digest")
		return
	}
	state, nextAction, summary, lastError, err := closureStateForBaseline(baseline)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "RUNTIME_CLOSURE_BASELINE_STATE_INVALID", err.Error())
		return
	}
	requestDigest := digestValue(struct {
		Input                 createRuntimeClosureCampaignInput `json:"input"`
		EvidenceSchemaVersion int                               `json:"evidenceSchemaVersion"`
		ReleaseArtifactDigest string                            `json:"releaseArtifactDigest"`
		ProducerBinaryDigest  string                            `json:"producerBinaryDigest"`
	}{in, evidence.RuntimeClosureEvidenceSchema, s.runtimeClosureReleaseDigest, s.runtimeClosureProducerDigest})
	campaign, replay, err := s.store.CreateRuntimeClosureCampaign(r.Context(), controlplane.RuntimeClosureCampaign{
		ProjectID: in.ProjectID, ClusterID: in.ClusterID, BaselineDeploymentID: in.BaselineDeploymentID,
		State: state, DesiredDigest: baseline.DesiredDigest, NextAction: nextAction, Summary: summary,
		LastError: lastError, IdempotencyKey: key, RequestDigest: requestDigest,
		EvidenceSchemaVersion: evidence.RuntimeClosureEvidenceSchema, ReleaseArtifactDigest: s.runtimeClosureReleaseDigest, ProducerBinaryDigest: s.runtimeClosureProducerDigest,
	}, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	status := http.StatusCreated
	if replay {
		status = http.StatusOK
	}
	setRevisionETag(w, campaign.Revision)
	writeJSON(w, status, map[string]any{"campaign": campaign, "idempotentReplay": replay})
}

func (s *Server) listRuntimeClosureCampaigns(w http.ResponseWriter, r *http.Request) {
	projectID := strings.TrimSpace(r.URL.Query().Get("projectId"))
	if projectID != "" {
		if _, err := s.requireProjectAccess(r, projectID, organizationRead); err != nil {
			writeScopeError(w, err)
			return
		}
	}
	clusterID := strings.TrimSpace(r.URL.Query().Get("clusterId"))
	var page func([]string, bool, *controlplane.CollectionCursor, int) ([]controlplane.RuntimeClosureCampaign, error)
	if pager, ok := s.store.(runtimeClosurePageStore); ok {
		page = func(ids []string, all bool, cursor *controlplane.CollectionCursor, limit int) ([]controlplane.RuntimeClosureCampaign, error) {
			return pager.ListRuntimeClosureCampaignsPage(r.Context(), ids, all, clusterID, cursor, limit)
		}
	}
	v, err := boundedProjectCollection(s, w, r, projectID, func() ([]controlplane.RuntimeClosureCampaign, error) {
		return s.store.ListRuntimeClosureCampaigns(r.Context(), projectID, clusterID)
	}, page, func(item controlplane.RuntimeClosureCampaign) string { return item.ProjectID })
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeOperatorCollectionJSON(w, r, http.StatusOK, v)
}

func (s *Server) getRuntimeClosureCampaign(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.GetRuntimeClosureCampaign(r.Context(), r.PathValue("id"))
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

func (s *Server) advanceRuntimeClosureCampaign(w http.ResponseWriter, r *http.Request) {
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	expected, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, http.StatusPreconditionRequired, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	campaign, err := s.store.GetRuntimeClosureCampaign(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if campaign.Revision != expected {
		writeStoreError(w, controlplane.ErrConflict)
		return
	}
	if campaign.State == controlplane.RuntimeClosureSucceeded {
		setRevisionETag(w, campaign.Revision)
		writeJSON(w, http.StatusOK, campaign)
		return
	}
	if campaign.EvidenceSchemaVersion != evidence.RuntimeClosureEvidenceSchema || !evidence.IsSHA256Digest(campaign.ReleaseArtifactDigest) || !evidence.IsSHA256Digest(campaign.ProducerBinaryDigest) {
		writeError(w, http.StatusConflict, "RUNTIME_CLOSURE_LEGACY_CAMPAIGN_RECREATE_REQUIRED", "legacy runtime closure campaigns cannot be promoted to exact-release-bound evidence; create a new campaign")
		return
	}
	if _, err = s.requireProjectAccess(r, campaign.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	baseline, err := s.store.GetBaselineDeployment(r.Context(), campaign.BaselineDeploymentID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	state, nextAction, summary, lastError, err := closureStateForBaseline(baseline)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "RUNTIME_CLOSURE_BASELINE_STATE_INVALID", err.Error())
		return
	}
	update := controlplane.RuntimeClosureCampaignUpdate{State: state, ObservedDigest: baseline.ObservedDigest, NextAction: nextAction, Summary: summary, LastError: lastError}
	if baseline.State == controlplane.BaselineDeploymentSucceeded {
		if campaign.RuntimeVerificationID == "" {
			if !strings.Contains(s.runtimeProbeImage, "@sha256:") {
				writeError(w, http.StatusServiceUnavailable, "RUNTIME_PROBE_UNAVAILABLE", "digest-pinned runtime probe image is not configured")
				return
			}
			verificationRequest := map[string]string{"projectId": campaign.ProjectID, "clusterId": campaign.ClusterID, "baselineDeploymentId": campaign.BaselineDeploymentID, "campaignId": campaign.ID}
			verification, _, createErr := s.store.CreateRuntimeVerification(r.Context(), controlplane.RuntimeVerification{
				ProjectID: campaign.ProjectID, ClusterID: campaign.ClusterID, BaselineDeploymentID: campaign.BaselineDeploymentID,
				ProbeImage: s.runtimeProbeImage, RequestDigest: digestValue(verificationRequest), IdempotencyKey: "runtime-closure-" + campaign.ID,
			}, actor)
			if createErr != nil {
				writeStoreError(w, createErr)
				return
			}
			update = controlplane.RuntimeClosureCampaignUpdate{
				State: controlplane.RuntimeClosureWaitingVerification, RuntimeVerificationID: verification.ID,
				ObservedDigest: baseline.ObservedDigest, NextAction: "wait-agent-runtime-verification",
				Summary: "Runtime verification was queued for the same converged baseline revision.",
			}
		} else {
			verification, getErr := s.store.GetRuntimeVerification(r.Context(), campaign.RuntimeVerificationID)
			if getErr != nil {
				writeStoreError(w, getErr)
				return
			}
			switch verification.State {
			case controlplane.RuntimeVerificationQueued, controlplane.RuntimeVerificationRunning:
				update = controlplane.RuntimeClosureCampaignUpdate{
					State: controlplane.RuntimeClosureWaitingVerification, RuntimeVerificationID: verification.ID,
					ObservedDigest: baseline.ObservedDigest, NextAction: "wait-agent-runtime-verification",
					Summary: "Waiting for the connected agent to complete the runtime probe.",
				}
			case controlplane.RuntimeVerificationFailed:
				update = controlplane.RuntimeClosureCampaignUpdate{
					State: controlplane.RuntimeClosureFailed, RuntimeVerificationID: verification.ID,
					ObservedDigest: verification.ObservedDigest, NextAction: "retry-runtime-verification",
					Summary: "Runtime verification failed; retry preserves the baseline and verification identity.", LastError: verification.LastError,
				}
			case controlplane.RuntimeVerificationSucceeded:
				cluster, clusterErr := s.store.GetManagedCluster(r.Context(), campaign.ClusterID)
				if clusterErr != nil {
					writeStoreError(w, clusterErr)
					return
				}
				if !strings.HasPrefix(cluster.InventoryDigest, "sha256:") {
					update = controlplane.RuntimeClosureCampaignUpdate{
						State: controlplane.RuntimeClosureFailed, RuntimeVerificationID: verification.ID,
						ObservedDigest: verification.ObservedDigest, NextAction: "report-fresh-cluster-inventory",
						Summary: "Runtime checks passed, but no digest-bearing cluster inventory is available.", LastError: "fresh cluster inventory digest is required for closure evidence",
					}
				} else if baseline.DesiredDigest != baseline.ObservedDigest || verification.DesiredDigest != verification.ObservedDigest || verification.DesiredDigest != baseline.DesiredDigest || !strings.HasPrefix(verification.ReportDigest, "sha256:") {
					update = controlplane.RuntimeClosureCampaignUpdate{
						State: controlplane.RuntimeClosureFailed, RuntimeVerificationID: verification.ID,
						ObservedDigest: verification.ObservedDigest, NextAction: "resolve-digest-mismatch",
						Summary: "Runtime records did not preserve desired/observed equality.", LastError: "runtime closure digest equality failed",
					}
				} else {
					inputs := evidence.RuntimeClosureInputs{
						CampaignID: campaign.ID, ProjectID: campaign.ProjectID, ClusterID: campaign.ClusterID,
						ClusterInventoryDigest: cluster.InventoryDigest, BaselineDeploymentID: baseline.ID,
						BaselineDesiredDigest: baseline.DesiredDigest, BaselineObservedDigest: baseline.ObservedDigest,
						RuntimeVerificationID: verification.ID, RuntimeReportDigest: verification.ReportDigest,
						RuntimeDesiredDigest: verification.DesiredDigest, RuntimeObservedDigest: verification.ObservedDigest,
						ReleaseArtifactDigest: campaign.ReleaseArtifactDigest, ProducerBinaryDigest: campaign.ProducerBinaryDigest,
					}
					evidenceDigest, digestErr := inputs.Digest()
					if digestErr != nil {
						writeError(w, http.StatusConflict, "RUNTIME_CLOSURE_EVIDENCE_INVALID", digestErr.Error())
						return
					}
					update = controlplane.RuntimeClosureCampaignUpdate{
						State: controlplane.RuntimeClosureSucceeded, RuntimeVerificationID: verification.ID,
						ObservedDigest: verification.ObservedDigest, EvidenceDigest: evidenceDigest, NextAction: "download-runtime-closure-report",
						Summary: "Baseline convergence, fresh inventory and runtime verification are evidence-bound and complete.",
					}
				}
			default:
				writeError(w, http.StatusConflict, "RUNTIME_VERIFICATION_STATE_INVALID", "runtime verification is in an unsupported state")
				return
			}
		}
	}
	updated, err := s.store.UpdateRuntimeClosureCampaign(r.Context(), campaign.ID, expected, update, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, updated.Revision)
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) retryRuntimeClosureCampaign(w http.ResponseWriter, r *http.Request) {
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	expected, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, http.StatusPreconditionRequired, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	campaign, err := s.store.GetRuntimeClosureCampaign(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if campaign.Revision != expected {
		writeStoreError(w, controlplane.ErrConflict)
		return
	}
	if campaign.State != controlplane.RuntimeClosureFailed {
		writeStoreError(w, controlplane.ErrInvalidTransition)
		return
	}
	if _, err = s.requireProjectAccess(r, campaign.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	baseline, err := s.store.GetBaselineDeployment(r.Context(), campaign.BaselineDeploymentID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if baseline.State == controlplane.BaselineDeploymentFailed {
		baseline, err = s.store.RetryBaselineDeployment(r.Context(), baseline.ID, baseline.Revision, actor)
		if err != nil {
			writeStoreError(w, err)
			return
		}
	}
	if campaign.RuntimeVerificationID != "" {
		verification, getErr := s.store.GetRuntimeVerification(r.Context(), campaign.RuntimeVerificationID)
		if getErr != nil && !errors.Is(getErr, controlplane.ErrNotFound) {
			writeStoreError(w, getErr)
			return
		}
		if getErr == nil && verification.State == controlplane.RuntimeVerificationFailed && baseline.State == controlplane.BaselineDeploymentSucceeded {
			verification, err = s.store.RetryRuntimeVerification(r.Context(), verification.ID, verification.Revision, actor)
			if err != nil {
				writeStoreError(w, err)
				return
			}
			updated, updateErr := s.store.UpdateRuntimeClosureCampaign(r.Context(), campaign.ID, expected, controlplane.RuntimeClosureCampaignUpdate{
				State: controlplane.RuntimeClosureWaitingVerification, RuntimeVerificationID: verification.ID,
				ObservedDigest: baseline.ObservedDigest, NextAction: "wait-agent-runtime-verification",
				Summary: "The failed runtime verification was re-queued without changing the baseline revision.",
			}, actor)
			if updateErr != nil {
				writeStoreError(w, updateErr)
				return
			}
			setRevisionETag(w, updated.Revision)
			writeJSON(w, http.StatusAccepted, updated)
			return
		}
	}
	state, nextAction, summary, lastError, stateErr := closureStateForBaseline(baseline)
	if stateErr != nil {
		writeError(w, http.StatusUnprocessableEntity, "RUNTIME_CLOSURE_BASELINE_STATE_INVALID", stateErr.Error())
		return
	}
	if state == controlplane.RuntimeClosureFailed {
		writeStoreError(w, controlplane.ErrInvalidTransition)
		return
	}
	updated, err := s.store.UpdateRuntimeClosureCampaign(r.Context(), campaign.ID, expected, controlplane.RuntimeClosureCampaignUpdate{
		State: state, RuntimeVerificationID: campaign.RuntimeVerificationID, ObservedDigest: baseline.ObservedDigest,
		NextAction: nextAction, Summary: summary, LastError: lastError,
	}, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, updated.Revision)
	writeJSON(w, http.StatusAccepted, updated)
}

func (s *Server) runtimeClosureCampaignReport(w http.ResponseWriter, r *http.Request) {
	campaign, err := s.store.GetRuntimeClosureCampaign(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, campaign.ProjectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	cluster, err := s.store.GetManagedCluster(r.Context(), campaign.ClusterID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	baseline, err := s.store.GetBaselineDeployment(r.Context(), campaign.BaselineDeploymentID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	var verification any
	if campaign.RuntimeVerificationID != "" {
		value, getErr := s.store.GetRuntimeVerification(r.Context(), campaign.RuntimeVerificationID)
		if getErr != nil {
			writeStoreError(w, getErr)
			return
		}
		verification = value
	}
	var closureEvidence any
	if campaign.State == controlplane.RuntimeClosureSucceeded {
		if value, ok := verification.(controlplane.RuntimeVerification); ok {
			inputs := evidence.RuntimeClosureInputs{
				CampaignID: campaign.ID, ProjectID: campaign.ProjectID, ClusterID: campaign.ClusterID,
				ClusterInventoryDigest: cluster.InventoryDigest, BaselineDeploymentID: baseline.ID,
				BaselineDesiredDigest: baseline.DesiredDigest, BaselineObservedDigest: baseline.ObservedDigest,
				RuntimeVerificationID: value.ID, RuntimeReportDigest: value.ReportDigest,
				RuntimeDesiredDigest: value.DesiredDigest, RuntimeObservedDigest: value.ObservedDigest,
				ReleaseArtifactDigest: campaign.ReleaseArtifactDigest, ProducerBinaryDigest: campaign.ProducerBinaryDigest,
			}
			if campaign.EvidenceSchemaVersion == evidence.RuntimeClosureEvidenceSchema {
				digest, digestErr := inputs.Digest()
				if digestErr == nil && digest == campaign.EvidenceDigest {
					closureEvidence = evidence.RuntimeClosureEvidence{
						SchemaVersion: evidence.RuntimeClosureEvidenceSchema, Algorithm: "sha256", Canonicalization: evidence.RuntimeClosureCanonicalization,
						BindingAuthority: evidence.RuntimeClosureExactReleaseBindingAuthority, Inputs: inputs, Digest: digest,
					}
				}
			} else if campaign.EvidenceSchemaVersion == 0 {
				inputs.ReleaseArtifactDigest = ""
				inputs.ProducerBinaryDigest = ""
				digest, digestErr := inputs.LegacyDigest()
				if digestErr == nil && digest == campaign.EvidenceDigest {
					closureEvidence = evidence.RuntimeClosureEvidence{SchemaVersion: evidence.RuntimeClosureLegacyEvidenceSchema, Algorithm: "sha256", Canonicalization: evidence.RuntimeClosureLegacyCanonicalization, Inputs: inputs, Digest: digest}
				}
			}
		}
	}
	if campaign.State == controlplane.RuntimeClosureSucceeded && closureEvidence == nil {
		writeError(w, http.StatusConflict, "RUNTIME_CLOSURE_EVIDENCE_INCONSISTENT", "successful runtime closure evidence could not be reconstructed")
		return
	}
	report := map[string]any{
		"apiVersion": evidence.RuntimeClosureAPIVersion, "kind": evidence.RuntimeClosureKind,
		"metadata":            map[string]any{"id": campaign.ID, "evidenceDigest": campaign.EvidenceDigest, "state": campaign.State},
		"product":             map[string]any{"name": "4SO Platform Factory", "version": s.version},
		"target":              map[string]any{"cluster": cluster, "baselineDeployment": baseline},
		"runtimeVerification": verification,
		"result":              map[string]any{"state": campaign.State, "summary": campaign.Summary, "nextAction": campaign.NextAction, "lastError": campaign.LastError},
		"claims": map[string]any{
			"runtimeClosed":    campaign.State == controlplane.RuntimeClosureSucceeded,
			"runtimeCertified": false, "productionReady": false, "haCertified": false,
		},
		"evidence": closureEvidence,
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", "4so-runtime-closure-"+campaign.ID+".json"))
	writeJSON(w, http.StatusOK, report)
}
