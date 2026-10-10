package controlplane

import "strings"

// TenantTaskResultActionMatchesState binds an agent result to the exact
// lifecycle action represented by the durable running state. This uses the
// running state rather than PendingAction so automatic runtime-contract
// reconciliation (ACTIVE -> PROVISIONING) remains valid.
func TenantTaskResultActionMatchesState(state TenantState, action string) bool {
	expected, _, runnable := tenantActionForState(state)
	return runnable && expected == strings.ToUpper(strings.TrimSpace(action))
}
