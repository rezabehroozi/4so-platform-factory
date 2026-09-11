package controlplane

import (
	"context"
	"fmt"
	"strings"
)

const AIProviderDispatchAuthority = "AI_PROVIDER_DISPATCH_AUTHORITY_V1"
const AIProviderResultCommitAuthority = "AI_PROVIDER_RESULT_COMMIT_AUTHORITY_V2"

func ValidateAIExecutionClaim(v *AIExecutionClaim) error {
	v.ProjectID = strings.TrimSpace(v.ProjectID)
	v.Purpose = strings.TrimSpace(v.Purpose)
	v.IdempotencyKey = strings.TrimSpace(v.IdempotencyKey)
	v.RequestDigest = strings.TrimSpace(v.RequestDigest)
	v.AIRunID = strings.TrimSpace(v.AIRunID)
	v.FailureCode = strings.TrimSpace(v.FailureCode)
	if v.ProjectID == "" || v.Purpose == "" || v.IdempotencyKey == "" || v.RequestDigest == "" {
		return fmt.Errorf("%w: AI execution projectId, purpose, idempotencyKey and requestDigest are required", ErrValidation)
	}
	if len(v.IdempotencyKey) > 200 || len(v.Purpose) > 100 || len(v.FailureCode) > 100 || !strings.HasPrefix(v.RequestDigest, "sha256:") || len(v.RequestDigest) != 71 {
		return fmt.Errorf("%w: invalid AI execution claim fields", ErrValidation)
	}
	switch v.State {
	case AIExecutionDispatched:
		if v.AIRunID != "" || v.FailureCode != "" {
			return fmt.Errorf("%w: dispatched AI execution cannot have terminal fields", ErrValidation)
		}
	case AIExecutionCompleted:
		if v.AIRunID == "" || v.FailureCode != "" {
			return fmt.Errorf("%w: completed AI execution requires aiRunId only", ErrValidation)
		}
	case AIExecutionFailed:
		if v.FailureCode == "" || v.AIRunID != "" {
			return fmt.Errorf("%w: failed AI execution requires failureCode only", ErrValidation)
		}
	default:
		return fmt.Errorf("%w: invalid AI execution state", ErrValidation)
	}
	return nil
}

func (s *MemoryStore) ClaimAIExecution(_ context.Context, v AIExecutionClaim, actor string) (AIExecutionClaim, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v.State = AIExecutionDispatched
	v.AIRunID = ""
	v.FailureCode = ""
	if err := ValidateAIExecutionClaim(&v); err != nil {
		return AIExecutionClaim{}, false, err
	}
	if _, ok := s.projects[v.ProjectID]; !ok {
		return AIExecutionClaim{}, false, ErrNotFound
	}
	for _, existing := range s.aiExecutionClaims {
		if existing.ProjectID == v.ProjectID && existing.IdempotencyKey == v.IdempotencyKey {
			if existing.RequestDigest != v.RequestDigest || existing.Purpose != v.Purpose {
				return AIExecutionClaim{}, false, ErrIdempotencyConflict
			}
			return existing, false, nil
		}
	}
	now := nowUTC(s.now)
	v.ResourceMeta = ResourceMeta{ID: s.id("aic"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	v.RequestedBy = strings.TrimSpace(actor)
	s.aiExecutionClaims[v.ID] = v
	s.appendAuditLocked(actor, "ai_execution.dispatched", "aiExecutionClaim", v.ID, v.Revision, map[string]any{"projectId": v.ProjectID, "purpose": v.Purpose})
	return v, true, nil
}

func (s *MemoryStore) FinalizeAIExecution(_ context.Context, run AIRun, actor string) (AIRun, bool, AIExecutionClaim, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ValidateAIRun(&run); err != nil {
		return AIRun{}, false, AIExecutionClaim{}, err
	}
	var claimID string
	var claim AIExecutionClaim
	for id, candidate := range s.aiExecutionClaims {
		if candidate.ProjectID == run.ProjectID && candidate.IdempotencyKey == run.IdempotencyKey {
			claimID, claim = id, candidate
			break
		}
	}
	if claimID == "" {
		return AIRun{}, false, AIExecutionClaim{}, ErrNotFound
	}
	if claim.RequestDigest != run.RequestDigest || claim.Purpose != run.Purpose {
		return AIRun{}, false, AIExecutionClaim{}, ErrIdempotencyConflict
	}
	if claim.State == AIExecutionFailed {
		return AIRun{}, false, AIExecutionClaim{}, ErrIdempotencyConflict
	}
	if claim.State == AIExecutionCompleted {
		existing, ok := s.aiRuns[claim.AIRunID]
		if !ok || existing.ProjectID != claim.ProjectID || existing.IdempotencyKey != claim.IdempotencyKey || existing.RequestDigest != claim.RequestDigest {
			return AIRun{}, false, AIExecutionClaim{}, ErrValidation
		}
		return cloneAIRun(existing), true, claim, nil
	}
	if claim.State != AIExecutionDispatched {
		return AIRun{}, false, AIExecutionClaim{}, ErrIdempotencyConflict
	}
	if _, ok := s.projects[run.ProjectID]; !ok {
		return AIRun{}, false, AIExecutionClaim{}, ErrNotFound
	}
	if run.LinkedResourceType == "operation" {
		linked, ok := s.operations[run.LinkedResourceID]
		if !ok || linked.ProjectID != run.ProjectID {
			return AIRun{}, false, AIExecutionClaim{}, ErrNotFound
		}
	}
	if run.LinkedResourceType == "managedCluster" {
		linked, ok := s.managedClusters[run.LinkedResourceID]
		if !ok || linked.ProjectID != run.ProjectID {
			return AIRun{}, false, AIExecutionClaim{}, ErrNotFound
		}
	}
	replay := false
	var persisted AIRun
	for _, existing := range s.aiRuns {
		if existing.ProjectID == run.ProjectID && existing.IdempotencyKey == run.IdempotencyKey {
			if existing.RequestDigest != run.RequestDigest || existing.Purpose != run.Purpose {
				return AIRun{}, false, AIExecutionClaim{}, ErrIdempotencyConflict
			}
			persisted = cloneAIRun(existing)
			replay = true
			break
		}
	}
	if persisted.ID == "" {
		now := nowUTC(s.now)
		run.ResourceMeta = ResourceMeta{ID: s.id("air"), Revision: 1, CreatedAt: now, UpdatedAt: now}
		run.RequestedBy = strings.TrimSpace(actor)
		run.AdvisoryOnly = true
		persisted = cloneAIRun(run)
		s.aiRuns[run.ID] = persisted
		s.appendAuditLocked(actor, "ai_run.created", "aiRun", run.ID, run.Revision, map[string]any{"projectId": run.ProjectID, "purpose": run.Purpose, "provider": run.Provider, "model": run.Model, "redactionCount": run.RedactionCount, "linkedResourceType": run.LinkedResourceType, "linkedResourceId": run.LinkedResourceID})
		s.appendOutboxLocked("aiRun", run.ID, "ai_run.created", run)
	}
	claim.State = AIExecutionCompleted
	claim.AIRunID = persisted.ID
	claim.FailureCode = ""
	claim.Revision++
	claim.UpdatedAt = nowUTC(s.now)
	if err := ValidateAIExecutionClaim(&claim); err != nil {
		return AIRun{}, false, AIExecutionClaim{}, err
	}
	s.aiExecutionClaims[claimID] = claim
	s.appendAuditLocked(actor, "ai_execution.completed", "aiExecutionClaim", claim.ID, claim.Revision, map[string]any{"projectId": claim.ProjectID, "aiRunId": persisted.ID})
	return cloneAIRun(persisted), replay, claim, nil
}

func (s *MemoryStore) FailAIExecution(_ context.Context, projectID, key, requestDigest, failureCode, actor string) (AIExecutionClaim, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, v := range s.aiExecutionClaims {
		if v.ProjectID == strings.TrimSpace(projectID) && v.IdempotencyKey == strings.TrimSpace(key) {
			if v.RequestDigest != strings.TrimSpace(requestDigest) {
				return AIExecutionClaim{}, ErrIdempotencyConflict
			}
			if v.State == AIExecutionFailed {
				return v, nil
			}
			if v.State != AIExecutionDispatched {
				return AIExecutionClaim{}, ErrIdempotencyConflict
			}
			v.State = AIExecutionFailed
			v.FailureCode = strings.TrimSpace(failureCode)
			v.AIRunID = ""
			v.Revision++
			v.UpdatedAt = nowUTC(s.now)
			if err := ValidateAIExecutionClaim(&v); err != nil {
				return AIExecutionClaim{}, err
			}
			s.aiExecutionClaims[id] = v
			s.appendAuditLocked(actor, "ai_execution.failed", "aiExecutionClaim", v.ID, v.Revision, map[string]any{"projectId": v.ProjectID, "failureCode": v.FailureCode})
			return v, nil
		}
	}
	return AIExecutionClaim{}, ErrNotFound
}
