package controlplane

var allowedTransitions = map[OperationState]map[OperationState]bool{
	OperationDraft:            {OperationPlanning: true, OperationCancelled: true},
	OperationPlanning:         {OperationPlanFailed: true, OperationAwaitingApproval: true, OperationQueued: true, OperationCancelled: true},
	OperationPlanFailed:       {OperationPlanning: true, OperationCancelled: true},
	OperationAwaitingApproval: {OperationApproved: true, OperationCancelled: true},
	OperationApproved:         {OperationQueued: true, OperationCancelled: true},
	OperationQueued:           {OperationRunning: true, OperationCancelled: true},
	OperationRunning:          {OperationVerifying: true, OperationRetryWait: true, OperationFailed: true, OperationRollingBack: true, OperationCancelRequested: true},
	OperationRetryWait:        {OperationQueued: true, OperationCancelled: true},
	OperationCancelRequested:  {OperationCancelled: true, OperationFailed: true, OperationRollingBack: true},
	OperationVerifying:        {OperationSucceeded: true, OperationRetryWait: true, OperationFailed: true, OperationRollingBack: true, OperationCancelRequested: true},
	OperationFailed:           {OperationQueued: true, OperationRollingBack: true, OperationCancelled: true},
	OperationRollingBack:      {OperationRolledBack: true, OperationRollbackFailed: true, OperationNeedsOperator: true, OperationCancelRequested: true},
	OperationRollbackFailed:   {OperationRollingBack: true, OperationNeedsOperator: true, OperationCancelled: true},
	OperationNeedsOperator:    {OperationRollingBack: true, OperationCancelled: true},
}

func CanTransition(from, to OperationState) bool { return allowedTransitions[from][to] }

// CanDirectOperationTransition defines the narrow orchestration-only surface
// exposed by the generic TransitionOperation method. Execution-plane state
// changes are authority-controlled by the lease/fence-aware attempt, failure,
// verification, completion, cancellation and compensation methods instead.
func CanDirectOperationTransition(from, to OperationState) bool {
	switch from {
	case OperationDraft:
		return to == OperationPlanning
	case OperationPlanning:
		return to == OperationPlanFailed || to == OperationAwaitingApproval || to == OperationQueued
	case OperationPlanFailed:
		return to == OperationPlanning
	case OperationApproved:
		return to == OperationQueued
	default:
		return false
	}
}

func IsTerminal(state OperationState) bool {
	switch state {
	case OperationSucceeded, OperationRolledBack, OperationCancelled:
		return true
	default:
		return false
	}
}
