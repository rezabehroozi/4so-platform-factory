package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"platform.4so.io/factory/internal/controlplane"
)

func TestPlatformTemplateHTTPAuthorityAdmissionAndProjectScope(t *testing.T) {
	store := controlplane.NewMemoryStore()
	ctx := context.Background()
	org, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "template-api", DisplayName: "Template API"}, "owner")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "platform", DisplayName: "Platform"}, "owner")
	if err != nil {
		t.Fatal(err)
	}
	_, release, err := store.CreateBlueprintReleaseWithRevision(ctx, controlplane.BlueprintRevision{ProjectID: project.ID, BlueprintName: "foundation", BlueprintVersion: "1.0.0", BlueprintDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", CatalogDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Payload: []byte(`{"kind":"PlatformBlueprint"}`)}, controlplane.BlueprintRelease{ExecutionReady: true, PlanStatus: "READY"}, "owner")
	if err != nil {
		t.Fatal(err)
	}
	review, err := store.TransitionBlueprintRelease(ctx, release.ID, release.Revision, controlplane.BlueprintReview, "owner")
	if err != nil {
		t.Fatal(err)
	}
	release, err = store.TransitionBlueprintRelease(ctx, review.ID, review.Revision, controlplane.BlueprintPublished, "approver")
	if err != nil {
		t.Fatal(err)
	}

	otherOrg, _ := store.CreateOrganization(ctx, controlplane.Organization{Name: "template-other", DisplayName: "Template Other"}, "outsider")
	_, _ = store.CreateProject(ctx, controlplane.Project{OrganizationID: otherOrg.ID, Name: "other", DisplayName: "Other"}, "outsider")
	srv := scopedServer(t, store)

	schemaBody := fmt.Sprintf(`{"projectId":%q,"name":"production","version":"1.0.0","variables":[{"name":"replicas","type":"INTEGER","required":true,"minimum":1,"maximum":9}]}`, project.ID)
	w := scopedRequest(t, srv, http.MethodPost, "/api/v1/variable-schemas", schemaBody, "owner", "platform-operator")
	if w.Code != http.StatusCreated {
		t.Fatalf("schema=%d body=%s", w.Code, w.Body.String())
	}
	schema := decodeBody[controlplane.VariableSchema](t, w)

	policyBody := fmt.Sprintf(`{"projectId":%q,"name":"production","version":"1.0.0","maintenance":{"riskClass":"PRODUCTION","requireApproval":true,"maxUnavailable":1,"requireRecoveryCheckpoint":true},"backup":{"required":true,"provider":"s3","schedule":"0 2 * * *","retention":"30d"},"security":{"podSecurityLevel":"restricted","defaultDenyIngress":true,"defaultDenyEgress":true,"allowDNS":true}}`, project.ID)
	w = scopedRequest(t, srv, http.MethodPost, "/api/v1/platform-policy-sets", policyBody, "owner", "platform-operator")
	if w.Code != http.StatusCreated {
		t.Fatalf("policy=%d body=%s", w.Code, w.Body.String())
	}
	policy := decodeBody[controlplane.PlatformPolicySet](t, w)

	templateBody := fmt.Sprintf(`{"projectId":%q,"name":"private-cloud","version":"1.0.0","blueprintReleaseId":%q,"variableSchemaId":%q,"policySetId":%q,"allowedTargetClasses":["rke2","existing-kubernetes"],"certificationRequirements":["source-semantics","generated-runtime","runtime-realism","exact-sha-physical"]}`, project.ID, release.ID, schema.ID, policy.ID)
	w = scopedRequest(t, srv, http.MethodPost, "/api/v1/platform-templates", templateBody, "owner", "platform-operator")
	if w.Code != http.StatusCreated {
		t.Fatalf("template=%d body=%s", w.Code, w.Body.String())
	}
	template := decodeBody[controlplane.PlatformTemplate](t, w)
	if template.Digest == "" || template.BlueprintDigest != release.CurrentBlueprintDigest {
		t.Fatalf("template=%#v", template)
	}

	w = scopedRequest(t, srv, http.MethodGet, "/api/v1/platform-templates/"+template.ID+"/admission?targetClass=rke2", "", "owner", "platform-operator")
	if w.Code != http.StatusOK {
		t.Fatalf("admission=%d body=%s", w.Code, w.Body.String())
	}
	admission := decodeBody[controlplane.PlatformTemplateAdmission](t, w)
	if !admission.BindingValid || !admission.TargetAllowed || admission.AdoptionReady || admission.ImpactStatus != controlplane.TemplateImpactTargetPreviewRequired {
		t.Fatalf("admission=%#v", admission)
	}

	w = scopedRequest(t, srv, http.MethodGet, "/api/v1/platform-templates?projectId="+project.ID, "", "owner", "platform-operator")
	if w.Code != http.StatusOK {
		t.Fatalf("list=%d body=%s", w.Code, w.Body.String())
	}
	var listed []controlplane.PlatformTemplate
	if err := json.Unmarshal(w.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].ID != template.ID {
		t.Fatalf("listed=%#v", listed)
	}

	w = scopedRequest(t, srv, http.MethodGet, "/api/v1/platform-templates/"+template.ID, "", "outsider", "platform-operator")
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-project get=%d body=%s", w.Code, w.Body.String())
	}
	w = scopedRequest(t, srv, http.MethodGet, "/api/v1/platform-templates?projectId="+project.ID, "", "outsider", "platform-operator")
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-project list=%d body=%s", w.Code, w.Body.String())
	}
}
