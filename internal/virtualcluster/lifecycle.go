package virtualcluster

import (
	"errors"
	"fmt"
	"strings"
)

const LifecycleAuthority = "VIRTUAL_CLUSTER_LIFECYCLE_AUTHORITY_V1"

type State string

const (
	StateRequested        State = "REQUESTED"
	StateProvisioning     State = "PROVISIONING"
	StateActive           State = "ACTIVE"
	StateSuspending       State = "SUSPENDING"
	StateSuspended        State = "SUSPENDED"
	StateResuming         State = "RESUMING"
	StateDeleting         State = "DELETING"
	StateDeleted          State = "DELETED"
	StateRecoveryRequired State = "RECOVERY_REQUIRED"
	StateFailed           State = "FAILED"
)

type Action string

const (
	ActionProvision Action = "PROVISION"
	ActionSuspend   Action = "SUSPEND"
	ActionResume    Action = "RESUME"
	ActionDelete    Action = "DELETE"
)

type Outcome string

const (
	OutcomeApplied Outcome = "APPLIED"
	OutcomePending Outcome = "PENDING"
	OutcomeUnknown Outcome = "UNKNOWN"
	OutcomeFailed  Outcome = "FAILED"
)

type ExecutionEnvelope struct {
	Authority       string
	OperationID     string
	IdempotencyKey  string
	FenceToken      int64
	Action          Action
	CurrentState    State
	DesiredDigest   string
	BindingID       string
	BindingRevision int64
	WorkspaceID     string
	ProjectID       string
}

type ExecutionResult struct {
	State            State
	RecoveryRequired bool
	RetryAllowed     bool
	Message          string
}

func NewExecutionEnvelope(plan Plan, operationID, idempotencyKey string, fenceToken int64, action Action, current State) (ExecutionEnvelope, error) {
	if plan.Authority != Authority || !plan.MutationEligible || !strings.HasPrefix(plan.DesiredDigest, "sha256:") {
		return ExecutionEnvelope{}, errors.New("virtual cluster plan is not mutation-eligible")
	}
	env := ExecutionEnvelope{
		Authority: LifecycleAuthority,
		OperationID: strings.TrimSpace(operationID),
		IdempotencyKey: strings.TrimSpace(idempotencyKey),
		FenceToken: fenceToken,
		Action: action,
		CurrentState: current,
		DesiredDigest: plan.DesiredDigest,
		BindingID: plan.BindingID,
		BindingRevision: plan.BindingRevision,
		WorkspaceID: plan.WorkspaceID,
		ProjectID: plan.ProjectID,
	}
	if err := ValidateExecutionEnvelope(env); err != nil {
		return ExecutionEnvelope{}, err
	}
	return env, nil
}

func ValidateExecutionEnvelope(v ExecutionEnvelope) error {
	if v.Authority != LifecycleAuthority {
		return errors.New("virtual cluster lifecycle authority is invalid")
	}
	if v.OperationID == "" || v.IdempotencyKey == "" || v.FenceToken <= 0 {
		return errors.New("operationId, idempotencyKey and positive fenceToken are required")
	}
	if !strings.HasPrefix(v.DesiredDigest, "sha256:") || v.BindingID == "" || v.BindingRevision <= 0 || v.WorkspaceID == "" || v.ProjectID == "" {
		return errors.New("workspace/binding/digest execution fence is incomplete")
	}
	switch v.Action {
	case ActionProvision:
		if v.CurrentState != StateRequested && v.CurrentState != StateFailed {
			return fmt.Errorf("PROVISION cannot execute from %s", v.CurrentState)
		}
	case ActionSuspend:
		if v.CurrentState != StateActive {
			return fmt.Errorf("SUSPEND cannot execute from %s", v.CurrentState)
		}
	case ActionResume:
		if v.CurrentState != StateSuspended {
			return fmt.Errorf("RESUME cannot execute from %s", v.CurrentState)
		}
	case ActionDelete:
		if v.CurrentState != StateRequested && v.CurrentState != StateActive && v.CurrentState != StateSuspended && v.CurrentState != StateFailed {
			return fmt.Errorf("DELETE cannot execute from %s", v.CurrentState)
		}
	default:
		return fmt.Errorf("unsupported lifecycle action %q", v.Action)
	}
	return nil
}

func BeginState(action Action) State {
	switch action {
	case ActionProvision:
		return StateProvisioning
	case ActionSuspend:
		return StateSuspending
	case ActionResume:
		return StateResuming
	case ActionDelete:
		return StateDeleting
	default:
		return StateFailed
	}
}

func ResolveOutcome(action Action, outcome Outcome, authoritativeConverged bool, message string) ExecutionResult {
	message = strings.TrimSpace(message)
	switch outcome {
	case OutcomeUnknown:
		if authoritativeConverged {
			return successFor(action, "ambiguous mutation resolved by authoritative readback")
		}
		if message == "" {
			message = "mutation outcome is ambiguous; authoritative readback is required"
		}
		return ExecutionResult{State: StateRecoveryRequired, RecoveryRequired: true, RetryAllowed: false, Message: message}
	case OutcomeFailed:
		if message == "" {
			message = "virtual cluster lifecycle mutation failed before convergence"
		}
		return ExecutionResult{State: StateFailed, RetryAllowed: true, Message: message}
	case OutcomePending:
		return ExecutionResult{State: BeginState(action), RetryAllowed: false, Message: message}
	case OutcomeApplied:
		if authoritativeConverged {
			return successFor(action, message)
		}
		if message == "" {
			message = "provider accepted mutation; authoritative readback has not converged"
		}
		return ExecutionResult{State: BeginState(action), RetryAllowed: false, Message: message}
	default:
		return ExecutionResult{State: StateFailed, RetryAllowed: false, Message: "unsupported lifecycle outcome"}
	}
}

func successFor(action Action, message string) ExecutionResult {
	switch action {
	case ActionProvision, ActionResume:
		return ExecutionResult{State: StateActive, RetryAllowed: false, Message: message}
	case ActionSuspend:
		return ExecutionResult{State: StateSuspended, RetryAllowed: false, Message: message}
	case ActionDelete:
		return ExecutionResult{State: StateDeleted, RetryAllowed: false, Message: message}
	default:
		return ExecutionResult{State: StateFailed, RetryAllowed: false, Message: "unsupported lifecycle action"}
	}
}
