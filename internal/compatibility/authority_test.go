package compatibility

import "testing"

func TestEvaluateAndSemanticValidation(t *testing.T) {
	constraints := []Constraint{
		{Name: "blueprint", KubernetesMinVersion: "1.34", KubernetesMaxVersion: "1.36", Architectures: []string{"amd64", "arm64"}, Distributions: []string{"rke2", "kubespray"}, Providers: []string{"imported", "cluster-api-topology-v1beta2"}},
		{Name: "component/gateway-api", KubernetesMinVersion: "1.34", KubernetesMaxVersion: "1.36", Architectures: []string{"amd64", "arm64"}, Distributions: []string{"rke2", "kubespray"}, Providers: []string{"*"}},
	}
	d := Evaluate(Target{KubernetesVersion: "v1.35.4+rke2r1", Architecture: "amd64", Distribution: "rke2", Provider: "imported"}, constraints)
	if d.Status != "PASS" || len(d.Checks) != 8 {
		t.Fatalf("unexpected decision: %+v", d)
	}
	if err := Validate(d, constraints); err != nil {
		t.Fatal(err)
	}
	tampered := d
	tampered.Checks[0].Message = "forged"
	tampered.Digest = Digest(tampered)
	if err := Validate(tampered, constraints); err == nil {
		t.Fatal("self-redigested tamper should fail semantic validation")
	}
}

func TestEvaluateRejectsEachDimension(t *testing.T) {
	c := []Constraint{{Name: "profile", KubernetesMinVersion: "1.34", KubernetesMaxVersion: "1.36", Architectures: []string{"amd64"}, Distributions: []string{"rke2"}, Providers: []string{"cluster-api-topology-v1beta2"}}}
	cases := []Target{
		{KubernetesVersion: "v1.33.9", Architecture: "amd64", Distribution: "rke2", Provider: "cluster-api-topology-v1beta2"},
		{KubernetesVersion: "v1.35.1", Architecture: "arm64", Distribution: "rke2", Provider: "cluster-api-topology-v1beta2"},
		{KubernetesVersion: "v1.35.1", Architecture: "amd64", Distribution: "kubespray", Provider: "cluster-api-topology-v1beta2"},
		{KubernetesVersion: "v1.35.1", Architecture: "amd64", Distribution: "rke2", Provider: "imported"},
	}
	for _, target := range cases {
		if got := Evaluate(target, c); got.Status != "FAIL" {
			t.Fatalf("expected failure for %+v: %+v", target, got)
		}
	}
}

func TestLegacyProvisionerNamesNormalizeToDistributionIdentity(t *testing.T) {
	constraints := []Constraint{{Name: "blueprint", KubernetesMinVersion: "1.34", KubernetesMaxVersion: "1.35", Architectures: []string{"amd64"}, Distributions: []string{"generic-imported", "kubespray", "rke2"}, Providers: []string{"imported"}}}
	for _, legacy := range []string{"generic-imported", "kubespray", "kubernetes"} {
		d := Evaluate(Target{KubernetesVersion: "1.34", Architecture: "amd64", Distribution: legacy, Provider: "imported"}, constraints)
		if d.Status != "PASS" || d.Target.Distribution != "kubernetes" {
			t.Fatalf("legacy %q decision=%#v", legacy, d)
		}
	}
}
