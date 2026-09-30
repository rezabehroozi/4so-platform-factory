package controlplane

import (
	"context"
	"fmt"
	"strings"
)

const OperationUnknownOutcomeRecoveryAuthority = "OPERATION_UNKNOWN_OUTCOME_RECOVERY_V1"

type OperationUnknownOutcomeResolution string

const (
	OperationUnknownOutcomeConfirmedSuccess  OperationUnknownOutcomeResolution = "CONFIRMED_SUCCESS"
	OperationUnknownOutcomeConfirmedNoEffect OperationUnknownOutcomeResolution = "CONFIRMED_NO_EFFECT"
)

func normalizeUnknownOutcomeResolution(value OperationUnknownOutcomeResolution) (OperationUnknownOutcomeResolution, error) {
	switch OperationUnknownOutcomeResolution(strings.ToUpper(strings.TrimSpace(string(value)))) {
	case OperationUnknownOutcomeConfirmedSuccess:
		return OperationUnknownOutcomeConfirmedSuccess, nil
	case OperationUnknownOutcomeConfirmedNoEffect:
		return OperationUnknownOutcomeConfirmedNoEffect, nil
	default:
		return "", fmt.Errorf("%w: invalid unknown-outcome resolution", ErrValidation)
	}
}

func validRecoveryEvidenceDigest(value string) bool {
	value = strings.TrimSpace(strings.ToLower(value))
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, ch := range value[len("sha256:"):] {
		if !strings.ContainsRune("0123456789abcdef", ch) {
			return false
		}
	}
	return true
}

func applyUnknownOutcomeResolution(op Operation, expected int64, resolution OperationUnknownOutcomeResolution, evidenceDigest, actor string) (Operation, error) {
	if op.Revision != expected {
		return Operation{}, ErrConflict
	}
	if op.State != OperationFailed || op.LastFailureClass != OperationFailureUnknown {
		return Operation{}, fmt.Errorf("%w: operation is not FAILED/UNKNOWN", ErrPrerequisite)
	}
	resolution, err := normalizeUnknownOutcomeResolution(resolution)
	if err != nil {
		return Operation{}, err
	}
	evidenceDigest = strings.ToLower(strings.TrimSpace(evidenceDigest))
	actor = strings.TrimSpace(actor)
	if !validRecoveryEvidenceDigest(evidenceDigest) || actor == "" {
		return Operation{}, fmt.Errorf("%w: recovery evidence digest and actor are required", ErrValidation)
	}
	op.RecoveryEvidenceDigest = evidenceDigest
	op.LeaseOwner = ""
	op.LeaseExpiresAt = nil
	op.NextAttemptAt = nil
	op.Revision++
	switch resolution {
	case OperationUnknownOutcomeConfirmedSuccess:
		op.State = OperationSucceeded
		op.LastFailureClass = ""
		op.LastError = ""
		op.RetryExhausted = false
	case OperationUnknownOutcomeConfirmedNoEffect:
		op.State = OperationFailed
		op.LastFailureClass = OperationFailurePermanent
		op.LastError = "authoritative recovery readback confirmed no external effect"
		op.RetryExhausted = true
	}
	return op, nil
}

func (s *MemoryStore) ResolveUnknownOperationOutcome(_ context.Context, id string, expected int64, resolution OperationUnknownOutcomeResolution, evidenceDigest, actor string) (Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	op, ok := s.operations[id]
	if !ok {
		return Operation{}, ErrNotFound
	}
	next, err := applyUnknownOutcomeResolution(op, expected, resolution, evidenceDigest, actor)
	if err != nil {
		return Operation{}, err
	}
	next.UpdatedAt = nowUTC(s.now)
	s.operations[id] = next
	s.appendAuditLocked(actor, "operation.unknown_outcome_resolved", "operation", id, next.Revision, map[string]any{
		"authority": OperationUnknownOutcomeRecoveryAuthority,
		"resolution": resolution,
		"recoveryEvidenceDigest": next.RecoveryEvidenceDigest,
	})
	s.appendOutboxLocked("operation", id, "operation.unknown_outcome_resolved", next)
	return next, nil
}
