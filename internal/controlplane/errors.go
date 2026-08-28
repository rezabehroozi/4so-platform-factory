package controlplane

import "errors"

var (
	ErrNotFound            = errors.New("not found")
	ErrConflict            = errors.New("revision conflict")
	ErrDuplicateName       = errors.New("duplicate name")
	ErrIdempotencyConflict = errors.New("idempotency key used with a different request")
	ErrInvalidTransition   = errors.New("invalid operation transition")
	ErrLeaseHeld           = errors.New("operation lease is held by another worker")
	ErrNotClaimable        = errors.New("operation state is not claimable")
	ErrStaleFence          = errors.New("stale fencing token")
	ErrImmutable           = errors.New("resource is immutable")
	ErrPlanStale           = errors.New("execution plan is stale and must be revalidated")
	ErrMaintenanceWindow   = errors.New("operation is outside its maintenance window")
	ErrPrerequisite        = errors.New("operation prerequisite is not satisfied")
	ErrValidation          = errors.New("validation failed")
)
