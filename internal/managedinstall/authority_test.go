package managedinstall

import "testing"

func testRequest() Request {
	d := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	return Request{
		OrganizationID: "org-1", ProjectID: "project-1", TargetVersion: "4.19.0", ClusterName: "prod-a", BaseDomain: "example.test",
		APIVIP: "10.0.0.10", IngressVIP: "10.0.0.11",
		Machines: []Machine{
			{ID: "cp-1", Endpoint: "https://bmc-1.example.test", CredentialRef: "redfish-cp-1", SystemResource: "/redfish/v1/Systems/1", VirtualMediaResource: "/redfish/v1/Managers/1/VirtualMedia/CD"},
			{ID: "cp-2", Endpoint: "https://bmc-2.example.test", CredentialRef: "redfish-cp-2", SystemResource: "/redfish/v1/Systems/1", VirtualMediaResource: "/redfish/v1/Managers/1/VirtualMedia/CD"},
			{ID: "cp-3", Endpoint: "https://bmc-3.example.test", CredentialRef: "redfish-cp-3", SystemResource: "/redfish/v1/Systems/1", VirtualMediaResource: "/redfish/v1/Managers/1/VirtualMedia/CD"},
		},
		Artifacts: []Artifact{
			{Name: "release-payload", Version: "4.19.0", URL: "https://mirror.example.test/okd/release", SHA256: d},
			{Name: "fcos", Version: "42.20250818.3.0", URL: "https://mirror.example.test/fcos.raw.xz", SHA256: d},
			{Name: "agent-iso", Version: "4.19.0", URL: "https://mirror.example.test/agent.iso", SHA256: d},
		},
	}
}

func TestManagedInstallApprovalFenceAndResume(t *testing.T) {
	op, err := NewOperation("op-1", "alice", testRequest())
	if err != nil {
		t.Fatal(err)
	}
	if op.Status != StatusAwaitingApproval {
		t.Fatalf("unexpected status %s", op.Status)
	}
	if _, err := Approve(op, "alice"); err == nil {
		t.Fatal("self approval must fail")
	}
	op, err = Approve(op, "bob")
	if err != nil {
		t.Fatal(err)
	}
	op, err = Claim(op, 1)
	if err != nil {
		t.Fatal(err)
	}
	op, err = Advance(op, 1, "evidence-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Claim(op, 1); err == nil {
		t.Fatal("stale fence must fail")
	}
	op, err = Claim(op, 2)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		op, err = Advance(op, 2, "evidence-next")
		if err != nil {
			t.Fatal(err)
		}
	}
	if op.Status != StatusSucceeded || op.Step != StepComplete || op.Sequence != 7 {
		t.Fatalf("unexpected terminal state: %#v", op)
	}
}

func TestManagedInstallRequestDigestCanonicalOrder(t *testing.T) {
	req := testRequest()
	a, err := DigestRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	req.Machines[0], req.Machines[2] = req.Machines[2], req.Machines[0]
	req.Artifacts[0], req.Artifacts[2] = req.Artifacts[2], req.Artifacts[0]
	b, err := DigestRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("digest must be order-stable: %s != %s", a, b)
	}
	raw, digest, err := MarshalCanonicalRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	if digest != a {
		t.Fatalf("canonical marshal digest mismatch %s %s", digest, a)
	}
	if _, err := ParseCanonicalRequest(raw, a); err != nil {
		t.Fatal(err)
	}
}

func TestManagedInstallRejectsInvalidCompact3SecretAndArtifactVersion(t *testing.T) {
	req := testRequest()
	req.Machines = req.Machines[:2]
	if err := ValidateRequest(req); err == nil {
		t.Fatal("expected Compact-3 validation failure")
	}
	req = testRequest()
	req.Machines[0].CredentialRef = "password=plaintext"
	if err := ValidateRequest(req); err == nil {
		t.Fatal("expected secret-material rejection")
	}
	req = testRequest()
	req.Artifacts[2].Version = "4.18.0"
	if err := ValidateRequest(req); err == nil {
		t.Fatal("expected Agent ISO target-version mismatch")
	}
}
