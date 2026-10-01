package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

const OperationRequestPayloadAuthority = "DURABLE_OPERATION_REQUEST_PAYLOAD_AUTHORITY_V1"

type OperationRequestPayload struct {
	OperationID   string    `json:"operationId"`
	PayloadDigest string    `json:"payloadDigest"`
	MediaType     string    `json:"mediaType"`
	Payload       []byte    `json:"payload"`
	CreatedAt     time.Time `json:"createdAt"`
}

func OperationRequestPayloadDigest(payload []byte) string {
	h := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(h[:])
}

func validateOperationRequestPayload(mediaType string, payload []byte) error {
	mediaType = strings.TrimSpace(mediaType)
	if mediaType == "" || len(mediaType) > 160 {
		return fmt.Errorf("%w: bounded mediaType is required", ErrValidation)
	}
	if len(payload) == 0 || len(payload) > 1024*1024 {
		return fmt.Errorf("%w: request payload must be 1..1048576 bytes", ErrValidation)
	}
	return nil
}

// CreateOperationAwaitingApprovalWithPayload atomically binds a sealed request
// payload to a new durable operation and advances only the orchestration states
// needed to stop at AWAITING_APPROVAL. Execution cannot be claimed until a
// distinct actor explicitly approves and queues the operation.
func (s *MemoryStore) CreateOperationAwaitingApprovalWithPayload(_ context.Context, r OperationRequest, key, actor, requestID, mediaType string, payload []byte) (Operation, bool, error) {
	if err := validateOperationRequestPayload(mediaType, payload); err != nil {
		return Operation{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	op, replay, err := s.createOperationLocked(r, key, actor, requestID)
	if err != nil {
		return Operation{}, false, err
	}
	digest := OperationRequestPayloadDigest(payload)
	if replay {
		stored, ok := s.operationRequestPayloads[op.ID]
		if !ok || stored.PayloadDigest != digest || stored.MediaType != strings.TrimSpace(mediaType) {
			return Operation{}, false, ErrIdempotencyConflict
		}
		return op, true, nil
	}
	op, err = s.transitionOperationLocked(op.ID, op.Revision, OperationPlanning, "", actor)
	if err != nil {
		delete(s.operations, op.ID)
		delete(s.idempotency, r.ProjectID+":"+strings.TrimSpace(key))
		return Operation{}, false, err
	}
	op, err = s.transitionOperationLocked(op.ID, op.Revision, OperationAwaitingApproval, "", actor)
	if err != nil {
		delete(s.operations, op.ID)
		delete(s.idempotency, r.ProjectID+":"+strings.TrimSpace(key))
		return Operation{}, false, err
	}
	s.operationRequestPayloads[op.ID] = OperationRequestPayload{
		OperationID: op.ID, PayloadDigest: digest, MediaType: strings.TrimSpace(mediaType),
		Payload: append([]byte(nil), payload...), CreatedAt: nowUTC(s.now),
	}
	s.appendAuditLocked(actor, "operation.request_payload.sealed", "operation", op.ID, op.Revision, map[string]any{"authority": OperationRequestPayloadAuthority, "payloadDigest": digest, "mediaType": strings.TrimSpace(mediaType)})
	return op, false, nil
}


func OperationBlocksExclusiveTargetMutation(op Operation) bool {
	if op.State == OperationFailed {
		return op.LastFailureClass == OperationFailureUnknown
	}
	return !IsTerminal(op.State)
}

// CreateExclusiveOperationAwaitingApprovalWithPayload atomically combines the
// idempotency check, exact-target mutation fence, operation creation and sealed
// request payload. This closes the check-then-create race across concurrent API
// requests while allowing known terminal failures to be superseded explicitly.
func (s *MemoryStore) CreateExclusiveOperationAwaitingApprovalWithPayload(_ context.Context, r OperationRequest, key, actor, requestID, mediaType string, payload []byte) (Operation, bool, *Operation, error) {
	if err := validateOperationRequestPayload(mediaType, payload); err != nil {
		return Operation{}, false, nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	scope := r.ProjectID + ":" + key
	if _, replayKeyExists := s.idempotency[scope]; !replayKeyExists {
		for _, candidate := range s.operations {
			if candidate.ProjectID != r.ProjectID || candidate.Kind != r.Kind || candidate.TargetRef != r.TargetRef {
				continue
			}
			if OperationBlocksExclusiveTargetMutation(candidate) {
				blocker := candidate
				return Operation{}, false, &blocker, nil
			}
		}
	}

	op, replay, err := s.createOperationLocked(r, key, actor, requestID)
	if err != nil {
		return Operation{}, false, nil, err
	}
	digest := OperationRequestPayloadDigest(payload)
	if replay {
		stored, ok := s.operationRequestPayloads[op.ID]
		if !ok || stored.PayloadDigest != digest || stored.MediaType != strings.TrimSpace(mediaType) {
			return Operation{}, false, nil, ErrIdempotencyConflict
		}
		return op, true, nil, nil
	}
	op, err = s.transitionOperationLocked(op.ID, op.Revision, OperationPlanning, "", actor)
	if err != nil {
		delete(s.operations, op.ID)
		delete(s.idempotency, r.ProjectID+":"+strings.TrimSpace(key))
		return Operation{}, false, nil, err
	}
	op, err = s.transitionOperationLocked(op.ID, op.Revision, OperationAwaitingApproval, "", actor)
	if err != nil {
		delete(s.operations, op.ID)
		delete(s.idempotency, r.ProjectID+":"+strings.TrimSpace(key))
		return Operation{}, false, nil, err
	}
	s.operationRequestPayloads[op.ID] = OperationRequestPayload{
		OperationID: op.ID, PayloadDigest: digest, MediaType: strings.TrimSpace(mediaType),
		Payload: append([]byte(nil), payload...), CreatedAt: nowUTC(s.now),
	}
	s.appendAuditLocked(actor, "operation.request_payload.sealed", "operation", op.ID, op.Revision, map[string]any{"authority": OperationRequestPayloadAuthority, "payloadDigest": digest, "mediaType": strings.TrimSpace(mediaType), "exclusiveTarget": true})
	return op, false, nil, nil
}

// CreateOperationQueuedWithPayload atomically binds an immutable request
// payload to a read-only durable operation and advances it directly to QUEUED.
// It is intentionally separate from approval-gated mutation creation: callers
// must use this only for operations whose target action is demonstrably
// non-mutating (for example Kubernetes server-side dry-run admission).
func (s *MemoryStore) CreateOperationQueuedWithPayload(_ context.Context, r OperationRequest, key, actor, requestID, mediaType string, payload []byte) (Operation, bool, error) {
	if err := validateOperationRequestPayload(mediaType, payload); err != nil {
		return Operation{}, false, err
	}
	class, err := NormalizeOperationClass(r.Class)
	if err != nil {
		return Operation{}, false, err
	}
	if class != OperationClassReadOnly {
		return Operation{}, false, fmt.Errorf("%w: queued request payload creation is read-only only", ErrValidation)
	}
	r.Class = class
	s.mu.Lock()
	defer s.mu.Unlock()
	op, replay, err := s.createOperationLocked(r, key, actor, requestID)
	if err != nil {
		return Operation{}, false, err
	}
	digest := OperationRequestPayloadDigest(payload)
	if replay {
		stored, ok := s.operationRequestPayloads[op.ID]
		if !ok || stored.PayloadDigest != digest || stored.MediaType != strings.TrimSpace(mediaType) {
			return Operation{}, false, ErrIdempotencyConflict
		}
		return op, true, nil
	}
	op, err = s.transitionOperationLocked(op.ID, op.Revision, OperationPlanning, "", actor)
	if err == nil {
		op, err = s.transitionOperationLocked(op.ID, op.Revision, OperationQueued, "", actor)
	}
	if err != nil {
		delete(s.operations, op.ID)
		delete(s.idempotency, r.ProjectID+":"+strings.TrimSpace(key))
		return Operation{}, false, err
	}
	s.operationRequestPayloads[op.ID] = OperationRequestPayload{
		OperationID: op.ID, PayloadDigest: digest, MediaType: strings.TrimSpace(mediaType),
		Payload: append([]byte(nil), payload...), CreatedAt: nowUTC(s.now),
	}
	s.appendAuditLocked(actor, "operation.request_payload.sealed", "operation", op.ID, op.Revision, map[string]any{
		"authority": OperationRequestPayloadAuthority, "payloadDigest": digest, "mediaType": strings.TrimSpace(mediaType),
		"readOnlyQueued": true,
	})
	return op, false, nil
}

func (s *MemoryStore) GetOperationRequestPayload(_ context.Context, operationID string) (OperationRequestPayload, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.operationRequestPayloads[strings.TrimSpace(operationID)]
	if !ok {
		return OperationRequestPayload{}, ErrNotFound
	}
	v.Payload = append([]byte(nil), v.Payload...)
	return v, nil
}

// ApproveOperation is the generic separation-of-duties transition for durable
// product operations. API surfaces remain responsible for checking that the
// caller has domain approval authority for the specific operation family.
func (s *MemoryStore) ApproveOperationAndQueue(_ context.Context, id string, expected int64, actor string) (Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	op, ok := s.operations[strings.TrimSpace(id)]
	if !ok {
		return Operation{}, ErrNotFound
	}
	actor = strings.TrimSpace(actor)
	if op.Revision != expected {
		return Operation{}, ErrConflict
	}
	if op.State != OperationAwaitingApproval || actor == "" || actor == op.ActorID {
		return Operation{}, ErrPrerequisite
	}
	op.State = OperationApproved
	op.Revision++
	op.UpdatedAt = nowUTC(s.now)
	s.appendAuditLocked(actor, "operation.approved", "operation", op.ID, op.Revision, map[string]any{"requester": op.ActorID, "separationOfDuties": true})
	op.State = OperationQueued
	op.Revision++
	op.UpdatedAt = nowUTC(s.now)
	s.operations[op.ID] = op
	s.appendAuditLocked(actor, "operation.queued_after_approval", "operation", op.ID, op.Revision, map[string]any{"separationOfDuties": true})
	s.appendOutboxLocked("operation", op.ID, "operation.queued", op)
	return op, nil
}
