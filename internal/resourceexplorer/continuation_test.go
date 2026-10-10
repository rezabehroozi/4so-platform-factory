package resourceexplorer

import "testing"

func TestOwnerContinuationBindsExactResourceEvidenceAndTypedProductRoute(t *testing.T) {
	detail := ResourceDetail{
		Authority: BoundedResourceExplorerAuthority,
		OrganizationID: "org-a", ProjectID: "project-a", ClusterID: "cluster-a",
		Key: ResourceKey{APIVersion:"v1",Kind:"Node",Name:"worker-1",UID:"uid-worker-1"},
		State: TruthFresh, EvidenceDigest: continuationDigest('a'), ReadOnly: true,
	}
	binding, err := BuildProductOwnerBinding(detail, OwnerFamilyClusterNode, "worker-1", "", 9)
	if err != nil { t.Fatal(err) }
	continuation, err := BuildOwnerContinuation(detail, binding, OwnerActionMaintainNode)
	if err != nil { t.Fatal(err) }
	if continuation.Authority != ResourceExplorerOwnerContinuationAuthority || continuation.Method != "POST" || continuation.PathTemplate != "/api/v1/clusters/{id}/maintenance-runs" || continuation.PathParams["id"] != "cluster-a" || !continuation.MutationDelegated || !continuation.ImpactPreviewRequired || !continuation.ApprovalRequired || !continuation.ProgressOperation || !continuation.EvidenceRequired || continuation.RawKubernetesMutation {
		t.Fatalf("typed node continuation drift: %#v", continuation)
	}
	tampered := detail
	tampered.EvidenceDigest = continuationDigest('b')
	if _, err := BuildOwnerContinuation(tampered, binding, OwnerActionMaintainNode); err == nil { t.Fatal("owner binding must not replay across changed resource evidence") }
	if _, err := BuildOwnerContinuation(detail, binding, OwnerAction("kubectl-delete")); err == nil { t.Fatal("arbitrary kubernetes action must fail closed") }
}

func TestOwnerContinuationSupportsExistingVirtualClusterRoutesAndGatesUnclosedPromotion(t *testing.T) {
	detail := ResourceDetail{Authority:BoundedResourceExplorerAuthority,OrganizationID:"org-a",ProjectID:"project-a",ClusterID:"cluster-a",Key:ResourceKey{APIVersion:"v1",Kind:"Service",Namespace:"apps",Name:"vc-api"},State:TruthForbidden,EvidenceDigest:continuationDigest('c'),ReadOnly:true}
	vc, err := BuildProductOwnerBinding(detail, OwnerFamilyVirtualCluster, "vc-1", "ws-1", 4)
	if err != nil { t.Fatal(err) }
	resume, err := BuildOwnerContinuation(detail, vc, OwnerActionResumeVirtualCluster)
	if err != nil { t.Fatal(err) }
	if resume.PathTemplate != "/api/v1/workspaces/{id}/virtual-clusters/{virtualClusterId}/resume" || resume.PathParams["id"] != "ws-1" || resume.PathParams["virtualClusterId"] != "vc-1" || resume.ConfirmationRequired { t.Fatalf("virtual-cluster resume route drift: %#v", resume) }
	remove, err := BuildOwnerContinuation(detail, vc, OwnerActionDeleteVirtualCluster)
	if err != nil { t.Fatal(err) }
	if !remove.ConfirmationRequired || remove.ConfirmationHeader != "X-Confirm-Delete" { t.Fatalf("virtual-cluster delete must preserve explicit confirmation: %#v", remove) }

	promotionOwner, err := BuildProductOwnerBinding(detail, OwnerFamilyApplicationEnvironmentBinding, "envbind-1", "", 7)
	if err != nil { t.Fatal(err) }
	if _, err := BuildOwnerContinuation(detail, promotionOwner, OwnerActionPromoteApplication); err == nil {
		t.Fatal("application promotion continuation must stay gated until CP3 verified durable promotion owns the Product API path")
	}
}

func TestPersonaJourneysRemainTaskFirstAndNeverExposeRawKubernetesMutation(t *testing.T) {
	journeys := PersonaTaskJourneys()
	if len(journeys) != 3 { t.Fatalf("expected operator/platform-engineer/developer journeys: %#v", journeys) }
	seen := map[Persona]bool{}
	for _, journey := range journeys {
		seen[journey.Persona] = true
		if journey.Authority != PersonaTaskJourneyAuthority || !journey.TaskLanguageFirst || journey.AdvancedEvidenceByDefault || journey.RawKubernetesMutation || len(journey.Tasks) == 0 {
			t.Fatalf("persona journey safety/ux drift: %#v", journey)
		}
		for _, task := range journey.Tasks {
			if task == "kubectl" || task == "patch" || task == "delete" { t.Fatalf("raw kubernetes mutation leaked into persona tasks: %#v", journey) }
		}
	}
	for _, persona := range []Persona{PersonaOperator, PersonaPlatformEngineer, PersonaDeveloper} {
		if !seen[persona] { t.Fatalf("missing persona journey %q", persona) }
	}
}

func continuationDigest(ch byte) string { b:=make([]byte,64); for i:=range b { b[i]=ch }; return "sha256:"+string(b) }
