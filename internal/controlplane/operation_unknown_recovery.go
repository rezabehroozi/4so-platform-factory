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

func ApplyUnknownOutcomeResolution(op Operation, expected int64, resolution OperationUnknownOutcomeResolution, evidenceDigest, actor string) (Operation, error) {
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
	next, err := ApplyUnknownOutcomeResolution(op, expected, resolution, evidenceDigest, actor)
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


func (s *MemoryStore) ResolveUnknownOperationOutcomeWithEvidence(_ context.Context, id string, expected int64, resolution OperationUnknownOutcomeResolution, in EvidenceMetadata, payload []byte, actor string) (Operation, EvidenceMetadata, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id = strings.TrimSpace(id)
	actor = strings.TrimSpace(actor)
	in.OperationID = strings.TrimSpace(in.OperationID)
	in.Kind = strings.TrimSpace(in.Kind)
	in.MediaType = strings.TrimSpace(in.MediaType)
	in.Location = strings.TrimSpace(in.Location)
	if id == "" || in.OperationID != id || in.Kind == "" || in.MediaType == "" || actor == "" || len(payload) == 0 || len(payload) > 16<<20 {
		return Operation{}, EvidenceMetadata{}, fmt.Errorf("%w: operation, kind, mediaType, actor and bounded payload are required", ErrValidation)
	}
	digest := OperationEvidencePayloadDigest(payload)
	if in.Digest != "" && strings.TrimSpace(strings.ToLower(in.Digest)) != digest {
		return Operation{}, EvidenceMetadata{}, fmt.Errorf("%w: recovery evidence payload digest mismatch", ErrValidation)
	}
	if in.Size != 0 && in.Size != int64(len(payload)) {
		return Operation{}, EvidenceMetadata{}, fmt.Errorf("%w: recovery evidence payload size mismatch", ErrValidation)
	}
	op, ok := s.operations[id]
	if !ok {
		return Operation{}, EvidenceMetadata{}, ErrNotFound
	}
	resolution, err := normalizeUnknownOutcomeResolution(resolution)
	if err != nil {
		return Operation{}, EvidenceMetadata{}, err
	}
	for _, existing := range s.evidence {
		if existing.OperationID != id || existing.Digest != digest || existing.Phase != "" || existing.StepKey != "" {
			continue
		}
		stored, exists := s.evidencePayloads[existing.ID]
		if !exists || !existing.HasPayload || !existing.Sealed || OperationEvidencePayloadDigest(stored) != digest || int64(len(stored)) != existing.Size {
			return Operation{}, EvidenceMetadata{}, fmt.Errorf("%w: existing recovery evidence payload integrity mismatch", ErrConflict)
		}
		if op.RecoveryEvidenceDigest == digest {
			successReplay := resolution == OperationUnknownOutcomeConfirmedSuccess && op.State == OperationSucceeded
			noEffectReplay := resolution == OperationUnknownOutcomeConfirmedNoEffect && op.State == OperationFailed && op.LastFailureClass == OperationFailurePermanent
			if successReplay || noEffectReplay {
				return op, existing, nil
			}
		}
		return Operation{}, EvidenceMetadata{}, fmt.Errorf("%w: recovery evidence already exists without matching operation resolution", ErrConflict)
	}
	next, err := ApplyUnknownOutcomeResolution(op, expected, resolution, digest, actor)
	if err != nil {
		return Operation{}, EvidenceMetadata{}, err
	}
	now := nowUTC(s.now)
	evidenceID := s.id("evd")
	location := in.Location
	if location == "" {
		location = fmt.Sprintf("authority://operations/%s/recovery/%s", id, evidenceID)
	}
	evidence := EvidenceMetadata{
		ResourceMeta: ResourceMeta{ID: evidenceID, Revision: 1, CreatedAt: now, UpdatedAt: now},
		OperationID: id, Kind: in.Kind, Digest: digest, MediaType: in.MediaType,
		Location: location, Size: int64(len(payload)), HasPayload: true, Sealed: true,
	}
	next.UpdatedAt = now
	s.evidence[evidenceID] = evidence
	s.evidencePayloads[evidenceID] = append([]byte(nil), payload...)
	s.operations[id] = next
	s.appendAuditLocked(actor, "evidence.payload_sealed", "evidence", evidenceID, 1, map[string]any{"operationId": id, "digest": digest, "kind": in.Kind, "recovery": true})
	s.appendOutboxLocked("evidence", evidenceID, "evidence.payload_sealed", evidence)
	s.appendAuditLocked(actor, "operation.unknown_outcome_resolved", "operation", id, next.Revision, map[string]any{
		"authority": OperationUnknownOutcomeRecoveryAuthority,
		"resolution": resolution,
		"recoveryEvidenceDigest": digest,
		"evidenceId": evidenceID,
	})
	s.appendOutboxLocked("operation", id, "operation.unknown_outcome_resolved", next)
	return next, evidence, nil
}
