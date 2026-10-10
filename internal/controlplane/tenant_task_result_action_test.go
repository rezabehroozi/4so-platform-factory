package controlplane

import "testing"

func TestTenantTaskResultActionMatchesDurableRunningState(t *testing.T) {
	cases := []struct {
		state  TenantState
		action string
		want   bool
	}{
		{state: TenantProvisioning, action: "PROVISION", want: true},
		{state: TenantSuspending, action: "SUSPEND", want: true},
		{state: TenantResuming, action: "RESUME", want: true},
		{state: TenantResizing, action: "RESIZE", want: true},
		{state: TenantDeleting, action: "DELETE", want: true},
		{state: TenantSuspending, action: "PROVISION", want: false},
		{state: TenantResizing, action: "RESUME", want: false},
		{state: TenantActive, action: "PROVISION", want: false},
	}
	for _, tc := range cases {
		if got := TenantTaskResultActionMatchesState(tc.state, tc.action); got != tc.want {
			t.Fatalf("state=%s action=%s got=%v want=%v", tc.state, tc.action, got, tc.want)
		}
	}
}
