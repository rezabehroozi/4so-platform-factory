package bootmedia

import (
	"errors"
	"reflect"
	"testing"
)

type fakeProvider struct {
	calls []string
	fail  string
}

func (f *fakeProvider) Attach(Request) error {
	f.calls = append(f.calls, "attach")
	if f.fail == "attach" {
		return errors.New("attach failed")
	}
	return nil
}
func (f *fakeProvider) SetOneTimeBoot(Request) error {
	f.calls = append(f.calls, "boot")
	if f.fail == "boot" {
		return errors.New("boot failed")
	}
	return nil
}
func (f *fakeProvider) PowerCycle(Request) error {
	f.calls = append(f.calls, "power")
	if f.fail == "power" {
		return errors.New("power failed")
	}
	return nil
}
func (f *fakeProvider) Observe(Request) (Observation, error) {
	f.calls = append(f.calls, "observe")
	if f.fail == "observe" {
		return Observation{}, errors.New("observe failed")
	}
	return Observation{Attached: true, OneTimeBootSet: true, Powered: true, BootState: "INSTALLER_BOOTED"}, nil
}

func request() Request {
	return Request{OrganizationID: "org-1", ProjectID: "project-1", MachineID: "machine-1", Provider: "redfish", Endpoint: "https://bmc.example.test", CredentialRef: "secret:redfish-machine-1", MediaURL: "https://factory.example.test/agent.iso", MediaSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", SystemResource: "/redfish/v1/Systems/1", VirtualMediaResource: "/redfish/v1/Managers/1/VirtualMedia/CD", IdempotencyKey: "install-1"}
}

func TestRequestRejectsInlineCredentials(t *testing.T) {
	r := request()
	r.Endpoint = "https://root:password@bmc.example.test"
	if ValidateRequest(r) == nil {
		t.Fatal("expected inline endpoint credentials to be rejected")
	}
	r = request()
	r.CredentialRef = "username=root=password"
	if ValidateRequest(r) == nil {
		t.Fatal("expected inline credential material to be rejected")
	}
}

func TestAdvanceIsFencedAndRestartSafe(t *testing.T) {
	r := request()
	d, err := RequestDigest(r)
	if err != nil {
		t.Fatal(err)
	}
	op := Operation{ID: "boot-1", RequestDigest: d, State: StateRequested, NextStep: StepAttach}
	p := &fakeProvider{}
	for i := 0; i < 4; i++ {
		var err error
		op, _, err = Advance(p, r, op, 7)
		if err != nil {
			t.Fatal(err)
		}
	}
	if op.State != StateSucceeded || op.EvidenceDigest == "" {
		t.Fatalf("unexpected terminal operation: %#v", op)
	}
	if want := []string{"attach", "boot", "power", "observe"}; !reflect.DeepEqual(p.calls, want) {
		t.Fatalf("calls=%v want=%v", p.calls, want)
	}
	takeover, _, err := Advance(p, r, Operation{ID: "x", RequestDigest: d, Fence: 7, NextStep: StepAttach}, 8)
	if err != nil || takeover.Fence != 8 {
		t.Fatalf("higher fence takeover must succeed: %#v err=%v", takeover, err)
	}
	if _, _, err := Advance(p, r, Operation{ID: "x", RequestDigest: d, Fence: 8, NextStep: StepAttach}, 7); err == nil {
		t.Fatal("expected lower stale fence rejection")
	}
}

func TestFailedStepCanResumeWithoutRepeatingPriorSteps(t *testing.T) {
	r := request()
	d, _ := RequestDigest(r)
	op := Operation{ID: "boot-1", RequestDigest: d, NextStep: StepPowerCycle, Fence: 3}
	p := &fakeProvider{fail: "power"}
	failed, _, err := Advance(p, r, op, 3)
	if err == nil || failed.NextStep != StepPowerCycle {
		t.Fatalf("expected resumable power failure: %#v err=%v", failed, err)
	}
	p.fail = ""
	resumed, _, err := Advance(p, r, failed, 3)
	if err != nil || resumed.NextStep != StepObserve {
		t.Fatalf("resume failed: %#v err=%v", resumed, err)
	}
	if want := []string{"power", "power"}; !reflect.DeepEqual(p.calls, want) {
		t.Fatalf("calls=%v want=%v", p.calls, want)
	}
}
