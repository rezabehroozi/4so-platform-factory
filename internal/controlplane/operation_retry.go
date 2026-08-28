package controlplane

import (
	"context"
	"fmt"
	"strings"
	"time"
)

func NormalizeOperationClass(v OperationClass) (OperationClass, error) {
	if v == "" {
		return OperationClassMutating, nil
	}
	switch v {
	case OperationClassReadOnly, OperationClassMutating, OperationClassDestructive:
		return v, nil
	default:
		return "", fmt.Errorf("%w: invalid operation class", ErrValidation)
	}
}

func RetryPolicyForOperationClass(v OperationClass) OperationRetryPolicy {
	switch v {
	case OperationClassReadOnly:
		return OperationRetryPolicy{MaxAttempts: 5, InitialBackoffSeconds: 2, MaxBackoffSeconds: 30, RetryableClasses: []OperationFailureClass{OperationFailureTransientNetwork, OperationFailureRateLimited, OperationFailureDependencyUnavailable, OperationFailureConflict}}
	case OperationClassDestructive:
		return OperationRetryPolicy{MaxAttempts: 2, InitialBackoffSeconds: 10, MaxBackoffSeconds: 120, RetryableClasses: []OperationFailureClass{OperationFailureTransientNetwork, OperationFailureRateLimited, OperationFailureDependencyUnavailable}}
	default:
		return OperationRetryPolicy{MaxAttempts: 3, InitialBackoffSeconds: 5, MaxBackoffSeconds: 60, RetryableClasses: []OperationFailureClass{OperationFailureTransientNetwork, OperationFailureRateLimited, OperationFailureDependencyUnavailable}}
	}
}

func IsRetryableOperationFailure(policy OperationRetryPolicy, class OperationFailureClass) bool {
	for _, candidate := range policy.RetryableClasses {
		if candidate == class {
			return true
		}
	}
	return false
}

func ValidOperationFailureClass(v OperationFailureClass) bool {
	switch v {
	case OperationFailureTransientNetwork, OperationFailureRateLimited, OperationFailureDependencyUnavailable, OperationFailureConflict, OperationFailurePermanent, OperationFailureUnknown:
		return true
	default:
		return false
	}
}

func OperationBackoff(policy OperationRetryPolicy, attempt, retryAfter int) time.Duration {
	seconds := policy.InitialBackoffSeconds
	if seconds < 1 {
		seconds = 1
	}
	for i := 1; i < attempt; i++ {
		if seconds >= policy.MaxBackoffSeconds {
			seconds = policy.MaxBackoffSeconds
			break
		}
		seconds *= 2
	}
	if policy.MaxBackoffSeconds > 0 && seconds > policy.MaxBackoffSeconds {
		seconds = policy.MaxBackoffSeconds
	}
	if retryAfter > seconds {
		seconds = retryAfter
		if policy.MaxBackoffSeconds > 0 && seconds > policy.MaxBackoffSeconds {
			seconds = policy.MaxBackoffSeconds
		}
	}
	return time.Duration(seconds) * time.Second
}

func OperationTargetClusterID(target string) string {
	target = strings.TrimSpace(target)
	for _, prefix := range []string{"cluster:", "cluster/"} {
		if strings.HasPrefix(target, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(target, prefix))
		}
	}
	return ""
}

func (s *MemoryStore) validateDestructiveRecoveryLocked(op Operation, at time.Time) error {
	if op.Class != OperationClassDestructive {
		return nil
	}
	clusterID := OperationTargetClusterID(op.TargetRef)
	if clusterID == "" {
		return fmt.Errorf("%w: destructive operations require a cluster:<id> target", ErrPrerequisite)
	}
	checkpoint, ok := s.recoveryCheckpoints[op.RecoveryCheckpointID]
	if !ok || checkpoint.ProjectID != op.ProjectID || checkpoint.ClusterID != clusterID {
		return fmt.Errorf("%w: destructive operation requires a recovery checkpoint for the target cluster", ErrPrerequisite)
	}
	if checkpoint.State != RecoveryCheckpointVerified || !checkpoint.ExpiresAt.After(at) {
		return fmt.Errorf("%w: recovery checkpoint is revoked or expired", ErrPrerequisite)
	}
	cluster, ok := s.managedClusters[clusterID]
	if !ok || strings.TrimSpace(cluster.InventoryDigest) == "" || cluster.InventoryDigest != checkpoint.InventoryDigest {
		return fmt.Errorf("%w: recovery checkpoint is stale for current target inventory", ErrPrerequisite)
	}
	return nil
}

func (s *MemoryStore) StartOperationAttempt(_ context.Context, id string, expected int64, worker string, fence int64, actor string) (Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	op, ok := s.operations[id]
	if !ok {
		return Operation{}, ErrNotFound
	}
	if op.Revision != expected {
		return Operation{}, ErrConflict
	}
	if op.State != OperationQueued {
		return Operation{}, ErrInvalidTransition
	}
	if op.LeaseOwner != worker || op.FenceToken != fence || op.LeaseExpiresAt == nil || !op.LeaseExpiresAt.After(nowUTC(s.now)) {
		return Operation{}, ErrStaleFence
	}
	if err := s.validateDestructiveRecoveryLocked(op, nowUTC(s.now)); err != nil {
		return Operation{}, err
	}
	if op.Attempt >= op.RetryPolicy.MaxAttempts {
		return Operation{}, fmt.Errorf("%w: operation retry budget exhausted", ErrPrerequisite)
	}
	op.Attempt++
	op.State = OperationRunning
	op.NextAttemptAt = nil
	op.LastFailureClass = ""
	op.RetryExhausted = false
	op.Revision++
	op.UpdatedAt = nowUTC(s.now)
	s.operations[id] = op
	s.appendAuditLocked(actor, "operation.attempt_started", "operation", id, op.Revision, map[string]any{"attempt": op.Attempt, "maxAttempts": op.RetryPolicy.MaxAttempts, "class": op.Class, "fenceToken": fence})
	s.appendOutboxLocked("operation", id, "operation.attempt_started", op)
	return op, nil
}

func (s *MemoryStore) BeginOperationVerification(_ context.Context, id string, expected int64, worker string, fence int64, actor string) (Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	op, ok := s.operations[id]
	if !ok {
		return Operation{}, ErrNotFound
	}
	if op.Revision != expected {
		return Operation{}, ErrConflict
	}
	if op.State != OperationRunning {
		return Operation{}, ErrInvalidTransition
	}
	if op.LeaseOwner != worker || op.FenceToken != fence {
		return Operation{}, ErrStaleFence
	}
	op.State = OperationVerifying
	op.Revision++
	op.UpdatedAt = nowUTC(s.now)
	s.operations[id] = op
	s.appendAuditLocked(actor, "operation.verification_started", "operation", id, op.Revision, map[string]any{"attempt": op.Attempt})
	s.appendOutboxLocked("operation", id, "operation.verification_started", op)
	return op, nil
}

func (s *MemoryStore) ReportOperationFailure(_ context.Context, id string, expected int64, worker string, fence int64, report OperationFailureReport, actor string) (Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	op, ok := s.operations[id]
	if !ok {
		return Operation{}, ErrNotFound
	}
	if op.Revision != expected {
		return Operation{}, ErrConflict
	}
	if op.State != OperationRunning && op.State != OperationVerifying && op.State != OperationRollingBack {
		return Operation{}, ErrInvalidTransition
	}
	if op.LeaseOwner != worker || op.FenceToken != fence {
		return Operation{}, ErrStaleFence
	}
	if !ValidOperationFailureClass(report.Class) || strings.TrimSpace(report.Message) == "" || report.RetryAfterSeconds < 0 {
		return Operation{}, fmt.Errorf("%w: failure class and message are required", ErrValidation)
	}
	now := nowUTC(s.now)
	op.LastError = strings.TrimSpace(report.Message)
	op.LastFailureClass = report.Class
	op.LeaseOwner = ""
	op.LeaseExpiresAt = nil
	retryable := IsRetryableOperationFailure(op.RetryPolicy, report.Class)
	if retryable && op.Attempt < op.RetryPolicy.MaxAttempts {
		next := now.Add(OperationBackoff(op.RetryPolicy, op.Attempt, report.RetryAfterSeconds))
		op.State = OperationRetryWait
		op.NextAttemptAt = &next
		op.RetryExhausted = false
	} else {
		op.State = OperationFailed
		op.NextAttemptAt = nil
		op.RetryExhausted = retryable && op.Attempt >= op.RetryPolicy.MaxAttempts
	}
	op.Revision++
	op.UpdatedAt = now
	s.operations[id] = op
	s.appendAuditLocked(actor, "operation.failure_reported", "operation", id, op.Revision, map[string]any{"attempt": op.Attempt, "failureClass": report.Class, "code": report.Code, "retryable": retryable, "retryExhausted": op.RetryExhausted, "nextAttemptAt": op.NextAttemptAt})
	s.appendOutboxLocked("operation", id, "operation.failure_reported", op)
	return op, nil
}

func (s *MemoryStore) CompleteOperation(_ context.Context, id string, expected int64, worker string, fence int64, actor string) (Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	op, ok := s.operations[id]
	if !ok {
		return Operation{}, ErrNotFound
	}
	if op.Revision != expected {
		return Operation{}, ErrConflict
	}
	if op.State != OperationVerifying {
		return Operation{}, fmt.Errorf("%w: operation success requires VERIFYING postconditions", ErrPrerequisite)
	}
	if op.LeaseOwner != worker || op.FenceToken != fence {
		return Operation{}, ErrStaleFence
	}
	now := nowUTC(s.now)
	op.State = OperationSucceeded
	op.LeaseOwner = ""
	op.LeaseExpiresAt = nil
	op.NextAttemptAt = nil
	op.Revision++
	op.UpdatedAt = now
	s.operations[id] = op
	s.appendAuditLocked(actor, "operation.succeeded", "operation", id, op.Revision, map[string]any{"attempt": op.Attempt})
	s.appendOutboxLocked("operation", id, "operation.succeeded", op)
	return op, nil
}

func (s *MemoryStore) RequestOperationCancellation(_ context.Context, id string, expected int64, actor, reason string) (Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	op, ok := s.operations[id]
	if !ok {
		return Operation{}, ErrNotFound
	}
	if op.Revision != expected {
		return Operation{}, ErrConflict
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return Operation{}, fmt.Errorf("%w: cancellation reason is required", ErrValidation)
	}
	if IsTerminal(op.State) || op.State == OperationCancelRequested {
		return Operation{}, ErrInvalidTransition
	}
	now := nowUTC(s.now)
	op.CancelRequestedBy = actor
	op.CancelRequestedAt = &now
	op.CancelReason = reason
	switch op.State {
	case OperationRunning, OperationVerifying, OperationRollingBack:
		op.State = OperationCancelRequested
	default:
		op.State = OperationCancelled
		op.LeaseOwner = ""
		op.LeaseExpiresAt = nil
		op.NextAttemptAt = nil
	}
	op.Revision++
	op.UpdatedAt = now
	s.operations[id] = op
	s.appendAuditLocked(actor, "operation.cancellation_requested", "operation", id, op.Revision, map[string]any{"state": op.State, "reason": reason})
	s.appendOutboxLocked("operation", id, "operation.cancellation_requested", op)
	return op, nil
}

func (s *MemoryStore) AcknowledgeOperationCancellation(_ context.Context, id string, expected int64, worker string, fence int64, actor string) (Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	op, ok := s.operations[id]
	if !ok {
		return Operation{}, ErrNotFound
	}
	if op.Revision != expected {
		return Operation{}, ErrConflict
	}
	if op.State != OperationCancelRequested {
		return Operation{}, ErrInvalidTransition
	}
	if s.hasCompensatableForwardLocked(id) {
		return Operation{}, fmt.Errorf("%w: completed mutating steps require compensation before cancellation can complete", ErrPrerequisite)
	}
	if op.LeaseOwner != worker || op.FenceToken != fence {
		return Operation{}, ErrStaleFence
	}
	now := nowUTC(s.now)
	op.State = OperationCancelled
	op.LeaseOwner = ""
	op.LeaseExpiresAt = nil
	op.NextAttemptAt = nil
	op.Revision++
	op.UpdatedAt = now
	s.operations[id] = op
	s.appendAuditLocked(actor, "operation.cancelled_at_safe_boundary", "operation", id, op.Revision, map[string]any{"attempt": op.Attempt, "reason": op.CancelReason})
	s.appendOutboxLocked("operation", id, "operation.cancelled", op)
	return op, nil
}
