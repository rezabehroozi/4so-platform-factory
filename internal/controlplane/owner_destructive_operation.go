package controlplane

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// OwnerDestructiveOperationKind names product-owned destructive workflows that
// use the generic Operation + RecoveryCheckpoint authority instead of a
// parallel, weaker safety path.
const (
	OwnerOperationBaselineRollback      = "baseline.rollback"
	OwnerOperationTenantDelete          = "tenant.delete"
	OwnerOperationProviderClusterDelete = "provider-cluster.delete"
)

func OwnerDestructiveDesiredRevision(kind, ownerID string, ownerRevision int64, desiredDigest, recoveryCheckpointID string) string {
	raw, _ := json.Marshal(map[string]any{
		"kind":                 kind,
		"ownerId":              ownerID,
		"ownerRevision":        ownerRevision,
		"desiredDigest":        strings.TrimSpace(desiredDigest),
		"recoveryCheckpointId": strings.TrimSpace(recoveryCheckpointID),
	})
	return sha256Digest(raw)
}

func sha256Digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (s *MemoryStore) transitionOwnerOperationLocked(op *Operation, to OperationState, actor, event string, payload map[string]any) error {
	if !CanTransition(op.State, to) {
		return ErrInvalidTransition
	}
	op.State = to
	op.Revision++
	op.UpdatedAt = nowUTC(s.now)
	s.operations[op.ID] = *op
	if event == "" {
		event = "operation.transitioned"
	}
	if payload == nil {
		payload = map[string]any{}
	}
	payload["state"] = to
	s.appendAuditLocked(actor, event, "operation", op.ID, op.Revision, payload)
	s.appendOutboxLocked("operation", op.ID, event, *op)
	return nil
}

func (s *MemoryStore) cancelOwnerDestructiveOperationLocked(operationID, actor, reason string) error {
	operationID = strings.TrimSpace(operationID)
	if operationID == "" {
		return nil
	}
	op, ok := s.operations[operationID]
	if !ok || op.Class != OperationClassDestructive {
		return fmt.Errorf("%w: previous owner destructive operation binding is missing", ErrPrerequisite)
	}
	if op.State == OperationCancelled {
		return nil
	}
	if !CanTransition(op.State, OperationCancelled) {
		return fmt.Errorf("%w: previous destructive operation %s cannot be superseded from %s", ErrPrerequisite, op.ID, op.State)
	}
	return s.transitionOwnerOperationLocked(&op, OperationCancelled, actor, "operation.owner_superseded", map[string]any{"reason": strings.TrimSpace(reason)})
}

func (s *MemoryStore) createOwnerDestructiveOperationLocked(projectID, clusterID, kind, ownerID string, ownerRevision int64, desiredDigest, recoveryCheckpointID, actor, requestDigest string, awaitApproval bool) (Operation, error) {
	projectID, clusterID, kind, ownerID = strings.TrimSpace(projectID), strings.TrimSpace(clusterID), strings.TrimSpace(kind), strings.TrimSpace(ownerID)
	recoveryCheckpointID = strings.TrimSpace(recoveryCheckpointID)
	if projectID == "" || clusterID == "" || kind == "" || ownerID == "" || recoveryCheckpointID == "" || strings.TrimSpace(actor) == "" {
		return Operation{}, fmt.Errorf("%w: destructive owner workflow requires project, cluster, owner, actor and recovery checkpoint", ErrPrerequisite)
	}
	desiredRevision := OwnerDestructiveDesiredRevision(kind, ownerID, ownerRevision, desiredDigest, recoveryCheckpointID)
	key := fmt.Sprintf("owner:%s:%s:%d", kind, ownerID, ownerRevision)
	request := OperationRequest{ProjectID: projectID, Kind: kind, TargetRef: "cluster:" + clusterID, DesiredRevision: desiredRevision, Risk: "critical", Class: OperationClassDestructive, RecoveryCheckpointID: recoveryCheckpointID}
	digest := operationDigest(request)
	scope := projectID + ":" + key
	if existingID, ok := s.idempotency[scope]; ok {
		existing := s.operations[existingID]
		if existing.RequestDigest != digest {
			return Operation{}, ErrIdempotencyConflict
		}
		return existing, nil
	}
	now := nowUTC(s.now)
	op := Operation{
		ResourceMeta:         ResourceMeta{ID: s.id("op"), Revision: 1, CreatedAt: now, UpdatedAt: now},
		ProjectID:            projectID,
		Kind:                 kind,
		TargetRef:            "cluster:" + clusterID,
		DesiredRevision:      desiredRevision,
		State:                OperationDraft,
		Risk:                 "critical",
		Class:                OperationClassDestructive,
		RetryPolicy:          RetryPolicyForOperationClass(OperationClassDestructive),
		RecoveryCheckpointID: recoveryCheckpointID,
		IdempotencyKey:       key,
		RequestDigest:        digest,
		ActorID:              actor,
	}
	checkpoint, ok := s.recoveryCheckpoints[recoveryCheckpointID]
	if !ok {
		return Operation{}, fmt.Errorf("%w: destructive owner workflow requires a verified recovery checkpoint", ErrPrerequisite)
	}
	op.RecoveryEvidenceDigest = checkpoint.EvidenceDigest
	op.RecoveryInventoryDigest = checkpoint.InventoryDigest
	if err := s.validateDestructiveRecoveryLocked(op, now); err != nil {
		return Operation{}, err
	}
	s.operations[op.ID] = op
	s.idempotency[scope] = op.ID
	s.appendAuditLocked(actor, "operation.created", "operation", op.ID, op.Revision, map[string]any{"ownerKind": kind, "ownerId": ownerID, "requestDigest": requestDigest, "state": op.State})
	s.appendOutboxLocked("operation", op.ID, "operation.created", op)
	if err := s.transitionOwnerOperationLocked(&op, OperationPlanning, actor, "operation.owner_planning", map[string]any{"ownerKind": kind, "ownerId": ownerID}); err != nil {
		return Operation{}, err
	}
	if err := s.transitionOwnerOperationLocked(&op, OperationAwaitingApproval, actor, "operation.owner_approval_required", map[string]any{"ownerKind": kind, "ownerId": ownerID}); err != nil {
		return Operation{}, err
	}
	if !awaitApproval {
		if err := s.transitionOwnerOperationLocked(&op, OperationApproved, actor, "operation.owner_approved", map[string]any{"ownerKind": kind, "ownerId": ownerID, "approval": "explicit-destructive-request"}); err != nil {
			return Operation{}, err
		}
		if err := s.transitionOwnerOperationLocked(&op, OperationQueued, actor, "operation.owner_queued", map[string]any{"ownerKind": kind, "ownerId": ownerID}); err != nil {
			return Operation{}, err
		}
	}
	return op, nil
}

func (s *MemoryStore) approveOwnerDestructiveOperationLocked(operationID, projectID, clusterID, actor string) (Operation, error) {
	op, ok := s.operations[strings.TrimSpace(operationID)]
	if !ok || op.ProjectID != projectID || OperationTargetClusterID(op.TargetRef) != clusterID || op.Class != OperationClassDestructive {
		return Operation{}, fmt.Errorf("%w: owner destructive operation binding is missing", ErrPrerequisite)
	}
	if op.State != OperationAwaitingApproval {
		return Operation{}, ErrInvalidTransition
	}
	if err := s.validateDestructiveRecoveryLocked(op, nowUTC(s.now)); err != nil {
		return Operation{}, err
	}
	if err := s.transitionOwnerOperationLocked(&op, OperationApproved, actor, "operation.owner_approved", nil); err != nil {
		return Operation{}, err
	}
	if err := s.transitionOwnerOperationLocked(&op, OperationQueued, actor, "operation.owner_queued", nil); err != nil {
		return Operation{}, err
	}
	return op, nil
}

func (s *MemoryStore) startOwnerDestructiveOperationLocked(operationID, projectID, clusterID, actor string) (Operation, error) {
	op, ok := s.operations[strings.TrimSpace(operationID)]
	if !ok || op.ProjectID != projectID || OperationTargetClusterID(op.TargetRef) != clusterID || op.Class != OperationClassDestructive {
		return Operation{}, fmt.Errorf("%w: owner destructive operation binding is missing", ErrPrerequisite)
	}
	if op.State != OperationQueued {
		return Operation{}, fmt.Errorf("%w: owner destructive operation is not queued", ErrPrerequisite)
	}
	now := nowUTC(s.now)
	if err := s.validateDestructiveRecoveryLocked(op, now); err != nil {
		return Operation{}, err
	}
	if op.Attempt >= op.RetryPolicy.MaxAttempts {
		return Operation{}, fmt.Errorf("%w: owner destructive operation retry budget exhausted; submit a fresh recovery-bound request", ErrPrerequisite)
	}
	op.Attempt++
	op.State = OperationRunning
	op.LastFailureClass = ""
	op.RetryExhausted = false
	op.NextAttemptAt = nil
	op.Revision++
	op.UpdatedAt = now
	s.operations[op.ID] = op
	s.appendAuditLocked(actor, "operation.owner_attempt_started", "operation", op.ID, op.Revision, map[string]any{"attempt": op.Attempt, "owner": op.Kind})
	s.appendOutboxLocked("operation", op.ID, "operation.owner_attempt_started", op)
	return op, nil
}

func (s *MemoryStore) finishOwnerDestructiveOperationLocked(operationID string, success bool, lastError, actor string) (Operation, error) {
	op, ok := s.operations[strings.TrimSpace(operationID)]
	if !ok || op.Class != OperationClassDestructive {
		return Operation{}, fmt.Errorf("%w: owner destructive operation binding is missing", ErrPrerequisite)
	}
	if op.State != OperationRunning {
		return Operation{}, ErrInvalidTransition
	}
	now := nowUTC(s.now)
	if !success {
		op.State = OperationFailed
		op.LastError = strings.TrimSpace(lastError)
		if op.LastError == "" {
			op.LastError = "owner destructive workflow failed"
		}
		op.LastFailureClass = OperationFailureUnknown
		op.RetryExhausted = true // owner retry must be a new explicit recovery-bound request.
		op.Revision++
		op.UpdatedAt = now
		s.operations[op.ID] = op
		s.appendAuditLocked(actor, "operation.owner_failed", "operation", op.ID, op.Revision, map[string]any{"attempt": op.Attempt, "error": op.LastError})
		s.appendOutboxLocked("operation", op.ID, "operation.owner_failed", op)
		return op, nil
	}
	op.State = OperationVerifying
	op.Revision++
	op.UpdatedAt = now
	s.operations[op.ID] = op
	s.appendAuditLocked(actor, "operation.owner_verification_started", "operation", op.ID, op.Revision, map[string]any{"attempt": op.Attempt})
	s.appendOutboxLocked("operation", op.ID, "operation.owner_verification_started", op)
	op.State = OperationSucceeded
	op.Revision++
	op.UpdatedAt = nowUTC(s.now)
	s.operations[op.ID] = op
	s.appendAuditLocked(actor, "operation.owner_succeeded", "operation", op.ID, op.Revision, map[string]any{"attempt": op.Attempt})
	s.appendOutboxLocked("operation", op.ID, "operation.owner_succeeded", op)
	return op, nil
}

func ownerDestructiveRetryRequiresFreshRequest(operationID string) error {
	if strings.TrimSpace(operationID) == "" {
		return fmt.Errorf("%w: destructive owner workflow cannot use generic retry; submit a recovery-bound destructive request", ErrPrerequisite)
	}
	return fmt.Errorf("%w: destructive owner workflow failure must be resubmitted with a valid recovery checkpoint instead of generic retry", ErrPrerequisite)
}
