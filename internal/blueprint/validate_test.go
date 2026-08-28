package blueprint

import (
	"platform.4so.io/factory/catalog"
	"platform.4so.io/factory/internal/domain"
	"reflect"
	"testing"
)

func validBlueprint(cs map[string]catalog.Component) domain.Blueprint {
	var b domain.Blueprint
	b.APIVersion = "platform.4so.io/v1alpha1"
	b.Kind = "PlatformBlueprint"
	b.Metadata.Name = "test"
	b.Metadata.Version = "0.0.1"
	b.Spec.Description = "test blueprint"
	b.Spec.Compatibility.Kubernetes.MinVersion = "1.34"
	b.Spec.Compatibility.Kubernetes.MaxVersion = "1.35"
	b.Spec.Compatibility.Architectures = []string{"amd64", "arm64"}
	b.Spec.Compatibility.DistributionProfiles = []string{"generic-imported", "rke2", "kubespray"}
	b.Spec.Delivery.Mode = "gitops"
	b.Spec.Delivery.Repository = "https://git.example.invalid/platform.git"
	b.Spec.Delivery.OCIRegistry = "registry.example.invalid/platform"
	b.Spec.Delivery.Revision = "main"
	b.Spec.Delivery.RevisionType = "branch"
	b.Spec.Tenancy.Mode = "namespace"
	b.Spec.Tenancy.Plans = []string{"small"}
	b.Spec.Tenancy.DeletionPolicy = "approval-and-backup-required"
	b.Spec.Governance.ApprovalRequiredFor = []string{"high", "critical"}
	b.Spec.Governance.EnforceDigestImages = true
	b.Spec.Certification.RequiredLevel = "target-runtime"
	b.Spec.Certification.EvidenceRetentionDays = 365
	for n, c := range cs {
		if c.Spec.Mandatory {
			b.Spec.Components = append(b.Spec.Components, domain.ComponentSelection{Name: n, Enabled: true})
		}
	}
	return b
}

func TestValidateGoodPlanningBlueprintWithWarnings(t *testing.T) {
	cs, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	v := Validate(validBlueprint(cs), cs)
	if !v.Valid {
		t.Fatalf("unexpected findings: %#v", v.Findings)
	}
	if len(v.Findings) != 3 {
		t.Fatalf("expected endpoint and mutable-branch warnings, got %#v", v.Findings)
	}
}

func TestFindingsAreDeterministic(t *testing.T) {
	cs, _ := catalog.Load()
	b := validBlueprint(cs)
	one := Validate(b, cs)
	two := Validate(b, cs)
	if !reflect.DeepEqual(one, two) {
		t.Fatalf("validation is not deterministic\n%#v\n%#v", one, two)
	}
}

func TestRejectMissingMandatory(t *testing.T) {
	cs, _ := catalog.Load()
	b := validBlueprint(cs)
	b.Spec.Components = nil
	if Validate(b, cs).Valid {
		t.Fatal("expected invalid blueprint")
	}
}
func TestRejectPlaintextSecrets(t *testing.T) {
	cs, _ := catalog.Load()
	b := validBlueprint(cs)
	b.Spec.Governance.AllowPlaintextSecrets = true
	if Validate(b, cs).Valid {
		t.Fatal("expected invalid blueprint")
	}
}
func TestRejectSecretInSettings(t *testing.T) {
	cs, _ := catalog.Load()
	b := validBlueprint(cs)
	b.Spec.Components[0].Settings = map[string]any{"apiToken": "this-is-a-real-looking-secret"}
	if Validate(b, cs).Valid {
		t.Fatal("expected secret setting rejection")
	}
}
func TestAllowSecretReferenceInSettings(t *testing.T) {
	cs, _ := catalog.Load()
	b := validBlueprint(cs)
	b.Spec.Components[0].Settings = map[string]any{"apiTokenRef": "secret/path"}
	if !Validate(b, cs).Valid {
		t.Fatal("secret references must be allowed")
	}
}
func TestRejectInvertedVersionRange(t *testing.T) {
	cs, _ := catalog.Load()
	b := validBlueprint(cs)
	b.Spec.Compatibility.Kubernetes.MinVersion = "1.35"
	b.Spec.Compatibility.Kubernetes.MaxVersion = "1.34"
	if Validate(b, cs).Valid {
		t.Fatal("expected invalid version range")
	}
}
func TestRejectUnknownTenantPlan(t *testing.T) {
	cs, _ := catalog.Load()
	b := validBlueprint(cs)
	b.Spec.Tenancy.Plans = []string{"unlimited"}
	if Validate(b, cs).Valid {
		t.Fatal("expected unknown tenant plan rejection")
	}
}
func TestRejectMissingHighApproval(t *testing.T) {
	cs, _ := catalog.Load()
	b := validBlueprint(cs)
	b.Spec.Governance.ApprovalRequiredFor = []string{"critical"}
	if Validate(b, cs).Valid {
		t.Fatal("expected approval policy rejection")
	}
}
func TestRejectExclusiveCapabilityConflict(t *testing.T) {
	cs, _ := catalog.Load()
	b := validBlueprint(cs)
	other := cs["cilium"]
	other.Metadata.Name = "other-cni"
	other.Spec.Mandatory = false
	cs["other-cni"] = other
	b.Spec.Components = append(b.Spec.Components, domain.ComponentSelection{Name: "other-cni", Enabled: true})
	if Validate(b, cs).Valid {
		t.Fatal("expected exclusive capability conflict")
	}
}
