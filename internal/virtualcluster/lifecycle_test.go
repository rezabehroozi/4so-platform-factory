package virtualcluster

import "testing"

func executionFixture(t *testing.T, action Action, state State) ExecutionEnvelope {
	t.Helper()
	workspace, binding := fixture()
	plan, err := BuildPlan(workspace, binding, developerRequest())
	if err != nil { t.Fatal(err) }
	env, err := NewExecutionEnvelope(plan, "op-1", "idem-1", 7, action, state)
	if err != nil { t.Fatal(err) }
	return env
}

func TestLifecycleActionStateFences(t *testing.T) {
	cases := []struct{ action Action; state State }{
		{ActionProvision, StateRequested},
		{ActionSuspend, StateActive},
		{ActionResume, StateSuspended},
		{ActionDelete, StateActive},
	}
	for _, tc := range cases {
		if err := ValidateExecutionEnvelope(executionFixture(t, tc.action, tc.state)); err != nil {
			t.Fatalf("%s/%s rejected: %v", tc.action, tc.state, err)
		}
	}
	bad := executionFixture(t, ActionSuspend, StateActive)
	bad.CurrentState = StateRequested
	if err := ValidateExecutionEnvelope(bad); err == nil {
		t.Fatal("suspend from REQUESTED was admitted")
	}
}

func TestExecutionEnvelopeBindsWorkspacePlanAndFence(t *testing.T) {
	env := executionFixture(t, ActionProvision, StateRequested)
	if env.Authority != LifecycleAuthority || env.FenceToken != 7 || env.BindingRevision != 3 || env.WorkspaceID == "" || env.ProjectID == "" {
		t.Fatalf("execution envelope drift: %#v", env)
	}
	env.BindingRevision = 0
	if err := ValidateExecutionEnvelope(env); err == nil {
		t.Fatal("missing binding revision fence was admitted")
	}
}

func TestUnknownOutcomeNeverAllowsBlindRetry(t *testing.T) {
	got := ResolveOutcome(ActionProvision, OutcomeUnknown, false, "transport lost after submission")
	if got.State != StateRecoveryRequired || !got.RecoveryRequired || got.RetryAllowed {
		t.Fatalf("unknown outcome semantics drift: %#v", got)
	}
	resolved := ResolveOutcome(ActionProvision, OutcomeUnknown, true, "")
	if resolved.State != StateActive || resolved.RecoveryRequired || resolved.RetryAllowed {
		t.Fatalf("authoritative readback did not resolve ambiguity: %#v", resolved)
	}
}

func TestAppliedOutcomeRequiresAuthoritativeConvergence(t *testing.T) {
	pending := ResolveOutcome(ActionSuspend, OutcomeApplied, false, "")
	if pending.State != StateSuspending || pending.RetryAllowed || pending.RecoveryRequired {
		t.Fatalf("non-converged applied result drift: %#v", pending)
	}
	done := ResolveOutcome(ActionSuspend, OutcomeApplied, true, "")
	if done.State != StateSuspended {
		t.Fatalf("converged suspend result drift: %#v", done)
	}
}

func TestDeleteSuccessIsTerminal(t *testing.T) {
	got := ResolveOutcome(ActionDelete, OutcomeApplied, true, "")
	if got.State != StateDeleted || got.RetryAllowed || got.RecoveryRequired {
		t.Fatalf("delete terminal result drift: %#v", got)
	}
}
