package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

const OperationStepTraceMethod = "OPERATION_STEP_TRACE_EVIDENCE_V1"
const maxOperationStepTracePayloadBytes = 1024 * 1024

func validOperationStepPhase(v OperationStepPhase) bool {
	return v == OperationStepPhaseForward || v == OperationStepPhaseCompensation
}

func validOperationStepLogLevel(v OperationStepLogLevel) bool {
	switch v {
	case OperationStepLogDebug, OperationStepLogInfo, OperationStepLogWarn, OperationStepLogError:
		return true
	default:
		return false
	}
}

func operationStepPayloadDigest(payload []byte) string {
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func operationStepTraceMapKey(operationID string, phase OperationStepPhase, stepKey string, attempt int, traceKey string) string {
	return fmt.Sprintf("%s:%s:%s:%d:%s", operationID, phase, stepKey, attempt, traceKey)
}

func (s *MemoryStore) validateOperationStepTraceLocked(in OperationStepTraceInput, worker string, fence int64) (Operation, int, error) {
	op, ok := s.operations[in.OperationID]
	if !ok {
		return Operation{}, 0, ErrNotFound
	}
	if strings.TrimSpace(worker) == "" || fence <= 0 || op.LeaseOwner != worker || op.FenceToken != fence || op.LeaseExpiresAt == nil || !op.LeaseExpiresAt.After(nowUTC(s.now)) {
		return Operation{}, 0, ErrStaleFence
	}
	switch in.Phase {
	case OperationStepPhaseForward:
		if op.State != OperationRunning && op.State != OperationVerifying && op.State != OperationCancelRequested {
			return Operation{}, 0, ErrInvalidTransition
		}
		if op.Attempt < 1 {
			return Operation{}, 0, fmt.Errorf("%w: operation attempt has not started", ErrPrerequisite)
		}
		key := fmt.Sprintf("%s:%d:%s", op.ID, op.Attempt, in.StepKey)
		if _, ok := s.steps[key]; !ok {
			return Operation{}, 0, fmt.Errorf("%w: forward operation step does not exist for current attempt", ErrPrerequisite)
		}
		return op, op.Attempt, nil
	case OperationStepPhaseCompensation:
		if op.State != OperationRollingBack {
			return Operation{}, 0, ErrInvalidTransition
		}
		step, ok := s.compensationSteps[op.ID+":"+in.StepKey]
		if !ok {
			return Operation{}, 0, ErrNotFound
		}
		if step.State != CompensationStepRunning || step.FenceToken != fence || step.Attempt < 1 {
			return Operation{}, 0, fmt.Errorf("%w: compensation step is not running under this fence", ErrPrerequisite)
		}
		return op, step.Attempt, nil
	default:
		return Operation{}, 0, fmt.Errorf("%w: unsupported operation step phase", ErrValidation)
	}
}

func normalizeOperationStepTraceInput(in OperationStepTraceInput) (OperationStepTraceInput, error) {
	in.OperationID = strings.TrimSpace(in.OperationID)
	in.StepKey = strings.TrimSpace(in.StepKey)
	in.TraceKey = strings.TrimSpace(in.TraceKey)
	in.EventType = strings.TrimSpace(in.EventType)
	in.Message = strings.TrimSpace(in.Message)
	in.EvidenceKind = strings.TrimSpace(in.EvidenceKind)
	in.MediaType = strings.TrimSpace(in.MediaType)
	in.Location = strings.TrimSpace(in.Location)
	if in.OperationID == "" || in.StepKey == "" || in.TraceKey == "" || in.EventType == "" || in.Message == "" {
		return OperationStepTraceInput{}, fmt.Errorf("%w: operationId, stepKey, traceKey, eventType and message are required", ErrValidation)
	}
	if !validOperationStepPhase(in.Phase) {
		return OperationStepTraceInput{}, fmt.Errorf("%w: phase must be FORWARD or COMPENSATION", ErrValidation)
	}
	if !validOperationStepLogLevel(in.Level) {
		return OperationStepTraceInput{}, fmt.Errorf("%w: unsupported log level", ErrValidation)
	}
	if in.EvidenceKind == "" || in.MediaType == "" || len(in.Payload) == 0 {
		return OperationStepTraceInput{}, fmt.Errorf("%w: evidenceKind, mediaType and non-empty payload are required", ErrValidation)
	}
	if len(in.Payload) > maxOperationStepTracePayloadBytes {
		return OperationStepTraceInput{}, fmt.Errorf("%w: step evidence payload exceeds 1 MiB", ErrValidation)
	}
	in.Payload = append([]byte(nil), in.Payload...)
	return in, nil
}

// AppendOperationStepTrace atomically seals one evidence payload, creates one
// append-only trace/log event and emits audit/outbox records that reference both.
func (s *MemoryStore) AppendOperationStepTrace(_ context.Context, in OperationStepTraceInput, worker string, fence int64, actor string) (OperationStepTrace, EvidenceMetadata, error) {
	normalized, err := normalizeOperationStepTraceInput(in)
	if err != nil {
		return OperationStepTrace{}, EvidenceMetadata{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, attempt, err := s.validateOperationStepTraceLocked(normalized, strings.TrimSpace(worker), fence)
	if err != nil {
		return OperationStepTrace{}, EvidenceMetadata{}, err
	}
	digest := operationStepPayloadDigest(normalized.Payload)
	traceMapKey := operationStepTraceMapKey(normalized.OperationID, normalized.Phase, normalized.StepKey, attempt, normalized.TraceKey)
	if existing, ok := s.stepTraces[traceMapKey]; ok {
		evidence := s.evidence[existing.EvidenceID]
		if existing.Level != normalized.Level || existing.EventType != normalized.EventType || existing.Message != normalized.Message || existing.EvidenceDigest != digest || evidence.Kind != normalized.EvidenceKind || evidence.MediaType != normalized.MediaType {
			return OperationStepTrace{}, EvidenceMetadata{}, ErrIdempotencyConflict
		}
		return existing, evidence, nil
	}
	var sequence int64 = 1
	for _, existing := range s.stepTraces {
		if existing.OperationID == normalized.OperationID && existing.Phase == normalized.Phase && existing.StepKey == normalized.StepKey && existing.Attempt == attempt && existing.Sequence >= sequence {
			sequence = existing.Sequence + 1
		}
	}
	now := nowUTC(s.now)
	evidenceID := s.id("evd")
	location := normalized.Location
	if location == "" {
		location = fmt.Sprintf("authority://operations/%s/steps/%s/%s/attempts/%d/evidence/%s", normalized.OperationID, strings.ToLower(string(normalized.Phase)), normalized.StepKey, attempt, evidenceID)
	}
	trace := OperationStepTrace{
		ResourceMeta: ResourceMeta{ID: s.id("trc"), Revision: 1, CreatedAt: now, UpdatedAt: now},
		OperationID:  normalized.OperationID, Phase: normalized.Phase, StepKey: normalized.StepKey, Attempt: attempt,
		Sequence: sequence, TraceKey: normalized.TraceKey, Level: normalized.Level, EventType: normalized.EventType, Message: normalized.Message,
		EvidenceID: evidenceID, EvidenceDigest: digest,
	}
	evidence := EvidenceMetadata{
		ResourceMeta: ResourceMeta{ID: evidenceID, Revision: 1, CreatedAt: now, UpdatedAt: now},
		OperationID:  normalized.OperationID, Phase: normalized.Phase, StepKey: normalized.StepKey, Attempt: attempt, TraceID: trace.ID,
		Kind: normalized.EvidenceKind, Digest: digest, MediaType: normalized.MediaType, Location: location, Size: int64(len(normalized.Payload)), HasPayload: true, Sealed: true,
	}
	s.stepTraces[traceMapKey] = trace
	s.evidence[evidence.ID] = evidence
	s.evidencePayloads[evidence.ID] = append([]byte(nil), normalized.Payload...)
	metadata := map[string]any{
		"method": OperationStepTraceMethod, "operationId": normalized.OperationID, "phase": normalized.Phase, "stepKey": normalized.StepKey,
		"attempt": attempt, "sequence": sequence, "traceId": trace.ID, "traceKey": trace.TraceKey, "eventType": trace.EventType,
		"level": trace.Level, "evidenceId": evidence.ID, "evidenceDigest": evidence.Digest,
	}
	s.appendAuditLocked(actor, "operation_step.trace_sealed", "operationStepTrace", trace.ID, trace.Revision, metadata)
	s.appendOutboxLocked("operationStepTrace", trace.ID, "operation_step.trace_sealed", trace)
	return trace, evidence, nil
}

func (s *MemoryStore) ListOperationStepTraces(_ context.Context, operationID string) ([]OperationStepTrace, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []OperationStepTrace{}
	for _, trace := range s.stepTraces {
		if operationID == "" || trace.OperationID == operationID {
			out = append(out, trace)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Attempt != out[j].Attempt {
			return out[i].Attempt < out[j].Attempt
		}
		if out[i].Phase != out[j].Phase {
			return out[i].Phase < out[j].Phase
		}
		if out[i].StepKey != out[j].StepKey {
			return out[i].StepKey < out[j].StepKey
		}
		if out[i].Sequence != out[j].Sequence {
			return out[i].Sequence < out[j].Sequence
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

func (s *MemoryStore) GetEvidencePayload(_ context.Context, evidenceID string) (EvidenceMetadata, []byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	evidence, ok := s.evidence[strings.TrimSpace(evidenceID)]
	if !ok {
		return EvidenceMetadata{}, nil, ErrNotFound
	}
	payload, ok := s.evidencePayloads[evidence.ID]
	if !ok || !evidence.HasPayload {
		return EvidenceMetadata{}, nil, ErrNotFound
	}
	if operationStepPayloadDigest(payload) != evidence.Digest || int64(len(payload)) != evidence.Size {
		return EvidenceMetadata{}, nil, fmt.Errorf("%w: sealed evidence payload integrity mismatch", ErrConflict)
	}
	return evidence, append([]byte(nil), payload...), nil
}

func (s *MemoryStore) hasSealedStepEvidenceLocked(operationID string, phase OperationStepPhase, stepKey string, attempt int, digest string) bool {
	for _, evidence := range s.evidence {
		if evidence.OperationID == operationID && evidence.Phase == phase && evidence.StepKey == stepKey && evidence.Attempt == attempt && evidence.Digest == digest && evidence.Sealed && evidence.HasPayload {
			payload, ok := s.evidencePayloads[evidence.ID]
			if ok && operationStepPayloadDigest(payload) == digest && int64(len(payload)) == evidence.Size {
				return true
			}
		}
	}
	return false
}
