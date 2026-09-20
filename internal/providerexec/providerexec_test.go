package providerexec

import (
	"context"
	"errors"
	"testing"
)

type fakeAdapter struct {
	provider    Provider
	plan        Plan
	planErr     error
	mutation    MutationResult
	applyErr    error
	observation Observation
	readErr     error
	plans       int
	applies     int
	readbacks   int
}

func (f *fakeAdapter) Provider() Provider { return f.provider }
func (f *fakeAdapter) Plan(context.Context, Request) (Plan, error) {
	f.plans++
	return f.plan, f.planErr
}
func (f *fakeAdapter) Apply(context.Context, MutationInput) (MutationResult, error) {
	f.applies++
	return f.mutation, f.applyErr
}
func (f *fakeAdapter) Readback(context.Context, Request) (Observation, error) {
	f.readbacks++
	return f.observation, f.readErr
}

func requestFor(t *testing.T, provider Provider, action Action) Request {
	t.Helper()
	r := Request{
		Provider: provider, OperationID: "op-1", FenceToken: 7, Action: action,
		ResourceID: "cluster-1", DesiredDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		CredentialRef: "external-secret://4so-provider-system/cloud-prod",
		Desired: map[string]any{"region": "eu-north-1", "workerCount": 3},
	}
	if action == ActionCreate {
		r.ResourceID = ""
	}
	if action == ActionDelete {
		r.DesiredDigest = ""
		r.Desired = nil
	}
	return r
}

func planFor(t *testing.T, r Request, mutation bool) Plan {
	t.Helper()
	digest, err := RequestDigest(r)
	if err != nil {
		t.Fatal(err)
	}
	return Plan{RequestDigest: digest, MutationRequired: mutation}
}

func TestUnknownOutcomeNeverReplaysAndRequiresRecoveryWithoutProof(t *testing.T) {
	r := requestFor(t, ProviderAWS, ActionUpdate)
	f := &fakeAdapter{
		provider: ProviderAWS, plan: planFor(t, r, true),
		mutation: MutationResult{Outcome: OutcomeUnknown, ProviderRequestID: "aws-request-1"},
		applyErr: errors.New("connection reset after request submission"),
		observation: Observation{Exists: true, ObservedDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
	}
	got := (Engine{}).Execute(context.Background(), f, r)
	if got.State != StateRecoveryRequired || !got.RecoveryRequired || f.applies != 1 || f.readbacks != 1 {
		t.Fatalf("got=%#v apply=%d readback=%d", got, f.applies, f.readbacks)
	}
}

func TestUnknownOutcomeMayCloseOnlyFromAuthoritativeReadback(t *testing.T) {
	r := requestFor(t, ProviderAzure, ActionCreate)
	f := &fakeAdapter{
		provider: ProviderAzure, plan: planFor(t, r, true),
		mutation: MutationResult{Outcome: OutcomeUnknown},
		applyErr: errors.New("timeout"),
		observation: Observation{Exists: true, Ready: true, ObservedDigest: r.DesiredDigest, ExternalID: "azure-1"},
	}
	got := (Engine{}).Execute(context.Background(), f, r)
	if got.State != StateSucceeded || got.RecoveryRequired || f.applies != 1 || f.readbacks != 1 {
		t.Fatalf("got=%#v apply=%d readback=%d", got, f.applies, f.readbacks)
	}
}

func TestAppliedMutationRequiresReadbackBeforeSuccess(t *testing.T) {
	r := requestFor(t, ProviderGCP, ActionUpdate)
	f := &fakeAdapter{
		provider: ProviderGCP, plan: planFor(t, r, true),
		mutation: MutationResult{Outcome: OutcomeApplied, ExternalID: "gcp-1"},
		observation: Observation{Exists: true, Ready: false, ObservedDigest: r.DesiredDigest, ExternalID: "gcp-1"},
	}
	got := (Engine{}).Execute(context.Background(), f, r)
	if got.State != StateSucceeded || f.applies != 1 || f.readbacks != 1 || got.IdempotencyKey == "" {
		t.Fatalf("got=%#v apply=%d readback=%d", got, f.applies, f.readbacks)
	}
}

func TestAppliedButNotConvergedIsReconcilingNotSuccess(t *testing.T) {
	r := requestFor(t, ProviderAWS, ActionUpdate)
	f := &fakeAdapter{
		provider: ProviderAWS, plan: planFor(t, r, true),
		mutation: MutationResult{Outcome: OutcomeApplied},
		observation: Observation{Exists: true, ObservedDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
	}
	got := (Engine{}).Execute(context.Background(), f, r)
	if got.State != StateReconciling || got.RecoveryRequired || f.applies != 1 || f.readbacks != 1 {
		t.Fatalf("got=%#v", got)
	}
}

func TestNoopStillRequiresReadback(t *testing.T) {
	r := requestFor(t, ProviderAWS, ActionCreate)
	f := &fakeAdapter{
		provider: ProviderAWS, plan: planFor(t, r, false),
		observation: Observation{Exists: true, ObservedDigest: r.DesiredDigest, ExternalID: "aws-1"},
	}
	got := (Engine{}).Execute(context.Background(), f, r)
	if got.State != StateSucceeded || got.Mutation.Outcome != OutcomeNoop || f.applies != 0 || f.readbacks != 1 {
		t.Fatalf("got=%#v apply=%d readback=%d", got, f.applies, f.readbacks)
	}
}

func TestDeleteConvergesOnlyWhenAuthoritativeReadbackIsAbsent(t *testing.T) {
	r := requestFor(t, ProviderAzure, ActionDelete)
	f := &fakeAdapter{
		provider: ProviderAzure, plan: planFor(t, r, true),
		mutation: MutationResult{Outcome: OutcomeApplied},
		observation: Observation{Exists: false},
	}
	got := (Engine{}).Execute(context.Background(), f, r)
	if got.State != StateSucceeded || f.applies != 1 || f.readbacks != 1 {
		t.Fatalf("got=%#v", got)
	}
}

func TestRawCredentialsAndUnsafeReferencesFailBeforeAdapter(t *testing.T) {
	cases := []Request{
		func() Request {
			r := requestFor(t, ProviderAWS, ActionCreate)
			r.Desired["accessKeyId"] = "AKIA..."
			return r
		}(),
		func() Request {
			r := requestFor(t, ProviderAzure, ActionCreate)
			r.CredentialRef = "client-secret-inline"
			return r
		}(),
		func() Request {
			r := requestFor(t, ProviderGCP, ActionCreate)
			r.CredentialRef = "external-secret://other/service-account"
			return r
		}(),
	}
	for _, r := range cases {
		f := &fakeAdapter{provider: r.Provider}
		got := (Engine{}).Execute(context.Background(), f, r)
		if got.State != StateFailed || f.plans != 0 || f.applies != 0 || f.readbacks != 0 {
			t.Fatalf("unsafe request was executed: %#v adapter=%#v", got, f)
		}
	}
}

func TestProviderMismatchFailsBeforePlan(t *testing.T) {
	r := requestFor(t, ProviderAWS, ActionCreate)
	f := &fakeAdapter{provider: ProviderAzure}
	got := (Engine{}).Execute(context.Background(), f, r)
	if got.State != StateFailed || f.plans != 0 {
		t.Fatalf("provider mismatch executed: %#v", got)
	}
}

func TestPlanMustBindExactRequestDigest(t *testing.T) {
	r := requestFor(t, ProviderGCP, ActionCreate)
	f := &fakeAdapter{provider: ProviderGCP, plan: Plan{RequestDigest: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", MutationRequired: true}}
	got := (Engine{}).Execute(context.Background(), f, r)
	if got.State != StateFailed || f.applies != 0 || f.readbacks != 0 {
		t.Fatalf("unfenced plan executed: %#v", got)
	}
}
