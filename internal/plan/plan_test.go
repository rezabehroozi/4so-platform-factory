package plan

import (
	"platform.4so.io/factory/catalog"
	"platform.4so.io/factory/internal/domain"
	"testing"
)

func planningBlueprint(cs map[string]catalog.Component) domain.Blueprint {
	var b domain.Blueprint
	b.Metadata.Name = "x"
	b.Metadata.Version = "0.0.1"
	b.Spec.Delivery.Repository = "https://git.example.invalid/x"
	b.Spec.Delivery.OCIRegistry = "registry.example.invalid/x"
	b.Spec.Delivery.Revision = "main"
	b.Spec.Delivery.RevisionType = "branch"
	b.Spec.Governance.ApprovalRequiredFor = []string{"critical", "high"}
	for n, c := range cs {
		if c.Spec.Mandatory {
			b.Spec.Components = append(b.Spec.Components, domain.ComponentSelection{Name: n, Enabled: true})
		}
	}
	return b
}

func TestPlanOrderingAndHonestExecutionStatus(t *testing.T) {
	cs, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	p, err := Build(planningBlueprint(cs), cs)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i < len(p.Steps); i++ {
		if p.Steps[i].Wave < p.Steps[i-1].Wave {
			t.Fatal("steps are not sorted")
		}
	}
	if !p.EvidenceRequired {
		t.Fatal("evidence must be required")
	}
	if p.Executable {
		t.Fatal("candidate catalog must not be executable")
	}
	if p.Status != "planning-only" {
		t.Fatalf("status=%s", p.Status)
	}
	blockerCounts := map[string]int{}
	for _, blocker := range p.Blockers {
		blockerCounts[blocker.Code]++
	}
	if blockerCounts["COMPONENT_VERSION_NOT_PINNED"] != 0 {
		t.Fatalf("exact review-candidate authority regressed to mutable component release identity: %+v", blockerCounts)
	}
	unresolved := 0
	for _, step := range p.Steps {
		if !step.SourceResolved {
			unresolved++
		}
	}
	if blockerCounts["COMPONENT_SOURCE_UNRESOLVED"] != unresolved || blockerCounts["SOURCE_LOCK_MISSING"] != unresolved {
		t.Fatalf("source blockers drifted from unresolved component truth: unresolved=%d blockers=%+v", unresolved, blockerCounts)
	}
	if blockerCounts["COMPONENT_NOT_RUNTIME_CERTIFIED"] != len(p.Steps) || blockerCounts["CERTIFICATION_EVIDENCE_MISSING"] != len(p.Steps) {
		t.Fatalf("certification blockers drifted from candidate catalog truth: steps=%d blockers=%+v", len(p.Steps), blockerCounts)
	}
	if p.BlueprintDigest == "" || p.CatalogDigest == "" {
		t.Fatal("plan digests are required")
	}
}

func TestPlanIdentityIsDeterministic(t *testing.T) {
	cs, _ := catalog.Load()
	b := planningBlueprint(cs)
	one, _ := Build(b, cs)
	two, _ := Build(b, cs)
	if one.ID != two.ID || one.BlueprintDigest != two.BlueprintDigest || one.CatalogDigest != two.CatalogDigest {
		t.Fatal("plan identity changed without input change")
	}
}

func TestUpgradeCertifiedIsExecutionEligibleCertification(t *testing.T) {
	cs, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	component := cs["secure-namespace-foundation"]
	component.Spec.Release = "1.0.0"
	component.Spec.Certification.Status = "upgrade-certified"
	component.Spec.Certification.EvidenceDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	cs = map[string]catalog.Component{component.Metadata.Name: component}
	b := planningBlueprint(cs)
	b.Spec.Delivery.Repository = "https://git.invalid.local/x"
	b.Spec.Delivery.OCIRegistry = "registry.invalid.local/x"
	b.Spec.Delivery.Revision = "0123456789abcdef0123456789abcdef01234567"
	b.Spec.Delivery.RevisionType = "commit"
	b.Spec.Components = []domain.ComponentSelection{{Name: component.Metadata.Name, Enabled: true}}
	p, err := Build(b, cs)
	if err != nil {
		t.Fatal(err)
	}
	foundAuthorityBlocker := false
	for _, blocker := range p.Blockers {
		if blocker.Code == "COMPONENT_NOT_RUNTIME_CERTIFIED" {
			t.Fatalf("upgrade-certified must satisfy runtime certification metadata gate: %+v", p.Blockers)
		}
		if blocker.Code == "CERTIFICATION_AUTHORITY_UNVERIFIED" {
			foundAuthorityBlocker = true
		}
	}
	if !foundAuthorityBlocker || p.Executable {
		t.Fatalf("source metadata alone must not create execution readiness: %+v", p.Blockers)
	}
	authorized, err := BuildWithCertificationAuthority(b, cs)
	if err != nil {
		t.Fatal(err)
	}
	if !authorized.Executable || authorized.Status != "execution-ready" || len(authorized.Blockers) != 0 {
		t.Fatalf("authority-validated plan should be execution-ready: %+v", authorized)
	}
}

func TestCertificationAuthorityStillBlocksWhenOnlyGitRevisionIsMutable(t *testing.T) {
	cs, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	component := cs["secure-namespace-foundation"]
	component.Spec.Release = "1.0.0"
	component.Spec.Certification.Status = "target-runtime-certified"
	component.Spec.Certification.EvidenceDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	cs = map[string]catalog.Component{component.Metadata.Name: component}
	b := planningBlueprint(cs)
	b.Spec.Delivery.Repository = "https://git.invalid.local/x"
	b.Spec.Delivery.OCIRegistry = "registry.invalid.local/x"
	b.Spec.Delivery.Revision = "main"
	b.Spec.Delivery.RevisionType = "branch"
	b.Spec.Components = []domain.ComponentSelection{{Name: component.Metadata.Name, Enabled: true}}

	p, err := Build(b, cs)
	if err != nil {
		t.Fatal(err)
	}
	codes := map[string]bool{}
	for _, blocker := range p.Blockers {
		codes[blocker.Code] = true
	}
	if !codes["GIT_REVISION_NOT_IMMUTABLE"] || !codes["CERTIFICATION_AUTHORITY_UNVERIFIED"] {
		t.Fatalf("Git deployment context suppressed certification authority: %+v", p.Blockers)
	}
	if p.Executable {
		t.Fatal("unverified certification authority became executable")
	}
}

func TestCertificationAuthorityCannotMakeInvalidCommitRevisionExecutable(t *testing.T) {
	cs, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	component := cs["secure-namespace-foundation"]
	component.Spec.Certification.Status = "target-runtime-certified"
	cs = map[string]catalog.Component{component.Metadata.Name: component}
	b := planningBlueprint(cs)
	b.Spec.Delivery.Repository = "https://git.invalid.local/x"
	b.Spec.Delivery.OCIRegistry = "registry.invalid.local/x"
	b.Spec.Delivery.Revision = "main"
	b.Spec.Delivery.RevisionType = "commit"
	b.Spec.Components = []domain.ComponentSelection{{Name: component.Metadata.Name, Enabled: true}}

	p, err := BuildWithCertificationAuthority(b, cs)
	if err != nil {
		t.Fatal(err)
	}
	if p.Executable || p.Status != "planning-only" {
		t.Fatalf("invalid commit revision became execution-ready: %+v", p)
	}
	found := false
	for _, blocker := range p.Blockers {
		if blocker.Code == "GIT_REVISION_NOT_IMMUTABLE" {
			found = true
		}
	}
	if !found {
		t.Fatalf("invalid commit revision missing immutable-revision blocker: %+v", p.Blockers)
	}
}

func TestCertificationAuthorityAcceptsFullSHA256GitObjectID(t *testing.T) {
	cs, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	component := cs["secure-namespace-foundation"]
	component.Spec.Certification.Status = "target-runtime-certified"
	cs = map[string]catalog.Component{component.Metadata.Name: component}
	b := planningBlueprint(cs)
	b.Spec.Delivery.Repository = "https://git.invalid.local/x"
	b.Spec.Delivery.OCIRegistry = "registry.invalid.local/x"
	b.Spec.Delivery.Revision = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	b.Spec.Delivery.RevisionType = "commit"
	b.Spec.Components = []domain.ComponentSelection{{Name: component.Metadata.Name, Enabled: true}}

	p, err := BuildWithCertificationAuthority(b, cs)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Executable || p.Status != "execution-ready" || len(p.Blockers) != 0 {
		t.Fatalf("valid SHA-256 Git object ID was rejected: %+v", p)
	}
}
