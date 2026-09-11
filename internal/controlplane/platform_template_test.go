package controlplane

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func createTemplateTestAuthorities(t *testing.T, store Store, actor string) (Project, BlueprintRelease, VariableSchema, PlatformPolicySet) {
	t.Helper()
	ctx := context.Background()
	org, err := store.CreateOrganization(ctx, Organization{Name: "template-org", DisplayName: "Template Org"}, actor)
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(ctx, Project{OrganizationID: org.ID, Name: "platform", DisplayName: "Platform"}, actor)
	if err != nil {
		t.Fatal(err)
	}
	revision, release, err := store.CreateBlueprintReleaseWithRevision(ctx, BlueprintRevision{ProjectID: project.ID, BlueprintName: "foundation", BlueprintVersion: "1.0.0", BlueprintDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", CatalogDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Payload: []byte(`{"kind":"PlatformBlueprint"}`)}, BlueprintRelease{ExecutionReady: true, PlanStatus: "READY"}, actor)
	if err != nil {
		t.Fatal(err)
	}
	_ = revision
	review, err := store.TransitionBlueprintRelease(ctx, release.ID, release.Revision, BlueprintReview, actor)
	if err != nil {
		t.Fatal(err)
	}
	published, err := store.TransitionBlueprintRelease(ctx, review.ID, review.Revision, BlueprintPublished, actor+"-approver")
	if err != nil {
		t.Fatal(err)
	}
	schema, err := store.CreateVariableSchema(ctx, VariableSchema{ProjectID: project.ID, Name: "production", Version: "1.0.0", Variables: []VariableDefinition{{Name: "replicas", Type: VariableTypeInteger, Required: true}}}, actor)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := store.CreatePlatformPolicySet(ctx, PlatformPolicySet{ProjectID: project.ID, Name: "production", Version: "1.0.0", Maintenance: PlatformMaintenancePolicy{RiskClass: "PRODUCTION", RequireApproval: true, MaxUnavailable: 1, RequireRecoveryCheckpoint: true}, Backup: PlatformBackupPolicy{Required: true, Provider: "s3", Schedule: "0 2 * * *", Retention: "30d"}, Security: PlatformSecurityPolicy{PodSecurityLevel: "restricted", DefaultDenyIngress: true, DefaultDenyEgress: true, AllowDNS: true}}, actor)
	if err != nil {
		t.Fatal(err)
	}
	return project, published, schema, policy
}

func TestPlatformTemplateAuthorityBindsImmutableSameProjectInputs(t *testing.T) {
	store := NewMemoryStore()
	project, blueprint, schema, policy := createTemplateTestAuthorities(t, store, "architect")
	created, err := store.CreatePlatformTemplate(context.Background(), PlatformTemplate{ProjectID: project.ID, Name: "private-cloud", Version: "1.0.0", BlueprintReleaseID: blueprint.ID, VariableSchemaID: schema.ID, PolicySetID: policy.ID, AllowedTargetClasses: []string{"RKE2", "existing-kubernetes"}, CertificationRequirements: []string{CertificationSourceSemantics, CertificationGeneratedRuntime, CertificationRuntimeRealism, CertificationExactSHAPhysical}}, "architect")
	if err != nil {
		t.Fatal(err)
	}
	if created.Digest == "" || created.BlueprintDigest != blueprint.CurrentBlueprintDigest || created.VariableSchemaDigest != schema.Digest || created.PolicySetDigest != policy.Digest {
		t.Fatalf("template binding=%#v", created)
	}
	if created.Impact.Status != TemplateImpactTargetPreviewRequired || len(created.Impact.Reasons) < 2 {
		t.Fatalf("impact=%#v", created.Impact)
	}
	if _, err := store.CreatePlatformTemplate(context.Background(), PlatformTemplate{ProjectID: project.ID, Name: "private-cloud", Version: "1.0.0", BlueprintReleaseID: blueprint.ID, VariableSchemaID: schema.ID, PolicySetID: policy.ID, AllowedTargetClasses: []string{"rke2"}, CertificationRequirements: []string{CertificationSourceSemantics}}, "architect"); !errors.Is(err, ErrDuplicateName) {
		t.Fatalf("duplicate identity err=%v", err)
	}
	admission := EvaluatePlatformTemplateAdmission(created, blueprint, schema, policy, "rke2")
	if !admission.BindingValid || !admission.TargetAllowed || admission.AdoptionReady || len(admission.Blockers) != 0 {
		t.Fatalf("admission=%#v", admission)
	}
}

func TestPlatformTemplateRejectsUnpublishedAndCrossProjectBindings(t *testing.T) {
	store := NewMemoryStore()
	project, blueprint, schema, policy := createTemplateTestAuthorities(t, store, "architect")
	ctx := context.Background()
	org2, _ := store.CreateOrganization(ctx, Organization{Name: "other-org", DisplayName: "Other Org"}, "other")
	project2, _ := store.CreateProject(ctx, Project{OrganizationID: org2.ID, Name: "other", DisplayName: "Other"}, "other")
	otherSchema, err := store.CreateVariableSchema(ctx, VariableSchema{ProjectID: project2.ID, Name: "other", Version: "1.0.0", Variables: []VariableDefinition{{Name: "x", Type: VariableTypeString}}}, "other")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreatePlatformTemplate(ctx, PlatformTemplate{ProjectID: project.ID, Name: "cross", Version: "1.0.0", BlueprintReleaseID: blueprint.ID, VariableSchemaID: otherSchema.ID, PolicySetID: policy.ID, AllowedTargetClasses: []string{"rke2"}, CertificationRequirements: []string{CertificationSourceSemantics}}, "architect"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-project schema err=%v", err)
	}

	revision, draft, err := store.CreateBlueprintReleaseWithRevision(ctx, BlueprintRevision{ProjectID: project.ID, BlueprintName: "draft", BlueprintVersion: "1.0.0", BlueprintDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", CatalogDigest: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", Payload: []byte(`{"kind":"PlatformBlueprint"}`)}, BlueprintRelease{ExecutionReady: true, PlanStatus: "READY"}, "architect")
	if err != nil {
		t.Fatal(err)
	}
	_ = revision
	if _, err := store.CreatePlatformTemplate(ctx, PlatformTemplate{ProjectID: project.ID, Name: "draft-template", Version: "1.0.0", BlueprintReleaseID: draft.ID, VariableSchemaID: schema.ID, PolicySetID: policy.ID, AllowedTargetClasses: []string{"rke2"}, CertificationRequirements: []string{CertificationSourceSemantics}}, "architect"); !errors.Is(err, ErrValidation) {
		t.Fatalf("unpublished blueprint err=%v", err)
	}
}

func TestPlatformTemplateAdmissionFailsClosedAfterBlueprintRevocation(t *testing.T) {
	store := NewMemoryStore()
	project, blueprint, schema, policy := createTemplateTestAuthorities(t, store, "architect")
	created, err := store.CreatePlatformTemplate(context.Background(), PlatformTemplate{ProjectID: project.ID, Name: "private-cloud", Version: "1.0.0", BlueprintReleaseID: blueprint.ID, VariableSchemaID: schema.ID, PolicySetID: policy.ID, AllowedTargetClasses: []string{"rke2"}, CertificationRequirements: []string{CertificationSourceSemantics}}, "architect")
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := store.TransitionBlueprintRelease(context.Background(), blueprint.ID, blueprint.Revision, BlueprintRevoked, "admin")
	if err != nil {
		t.Fatal(err)
	}
	admission := EvaluatePlatformTemplateAdmission(created, revoked, schema, policy, "rke2")
	if admission.AdoptionReady || len(admission.Blockers) == 0 || admission.Blockers[0] != "BLUEPRINT_RELEASE_NOT_PUBLISHED" {
		t.Fatalf("revoked admission=%#v", admission)
	}
}

func TestPlatformTemplateFileStoreSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "control-plane.json")
	store, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	project, blueprint, schema, policy := createTemplateTestAuthorities(t, store, "architect")
	created, err := store.CreatePlatformTemplate(context.Background(), PlatformTemplate{ProjectID: project.ID, Name: "private-cloud", Version: "1.0.0", BlueprintReleaseID: blueprint.ID, VariableSchemaID: schema.ID, PolicySetID: policy.ID, AllowedTargetClasses: []string{"rke2"}, CertificationRequirements: []string{CertificationSourceSemantics, CertificationExactSHAPhysical}}, "architect")
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reopened.GetPlatformTemplate(context.Background(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Digest != created.Digest || got.PolicySetDigest != policy.Digest {
		t.Fatalf("restored=%#v", got)
	}
	snap, err := reopened.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.PlatformPolicySets) != 1 || len(snap.PlatformTemplates) != 1 {
		t.Fatalf("snapshot policy/templates=%d/%d", len(snap.PlatformPolicySets), len(snap.PlatformTemplates))
	}
}
