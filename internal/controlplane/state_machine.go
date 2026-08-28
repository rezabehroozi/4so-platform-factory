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

func IsTerminal(state OperationState) bool {
	switch state {
	case OperationSucceeded, OperationRolledBack, OperationCancelled:
		return true
	default:
		return false
	}
}
