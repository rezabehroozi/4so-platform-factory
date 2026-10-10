package resourceexplorer

import (
	"testing"
	"time"
)

func TestBuildPageScopesBeforeLimitAndBindsCursorToQuery(t *testing.T) {
	now := time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC)
	items := []ResourceObservation{
		explorerObservation("org-a", "project-a", "cluster-a", "v1", "Pod", "apps", "pod-c", now.Add(-3*time.Minute), TruthFresh),
		explorerObservation("org-a", "project-b", "cluster-a", "v1", "Pod", "apps", "foreign-newest", now, TruthFresh),
		explorerObservation("org-a", "project-a", "cluster-a", "v1", "Pod", "apps", "pod-b", now.Add(-2*time.Minute), TruthFresh),
		explorerObservation("org-a", "project-a", "cluster-a", "v1", "Pod", "apps", "pod-a", now.Add(-time.Minute), TruthFresh),
		explorerObservation("org-a", "project-a", "cluster-b", "v1", "Pod", "apps", "other-cluster", now, TruthFresh),
	}
	query := ResourceQuery{OrganizationID: "org-a", ProjectID: "project-a", ClusterID: "cluster-a", APIVersion: "v1", Kind: "Pod", Namespace: "apps", Limit: 2}
	page, err := BuildPage(items, query, now, 10*time.Minute)
	if err != nil { t.Fatal(err) }
	if page.Authority != BoundedResourceExplorerAuthority || len(page.Items) != 2 || page.Items[0].Key.Name != "pod-a" || page.Items[1].Key.Name != "pod-b" || !page.HasMore || page.NextCursor == "" {
		t.Fatalf("bounded page drift: %#v", page)
	}
	query.Cursor = page.NextCursor
	next, err := BuildPage(items, query, now, 10*time.Minute)
	if err != nil { t.Fatal(err) }
	if len(next.Items) != 1 || next.Items[0].Key.Name != "pod-c" || next.HasMore { t.Fatalf("cursor continuation drift: %#v", next) }
	wrongScope := query
	wrongScope.ProjectID = "project-b"
	if _, err := BuildPage(items, wrongScope, now, 10*time.Minute); err == nil { t.Fatal("cursor from another scope/query must fail closed") }
}

func TestExplorerPreservesUnknownForbiddenStaleAndRejectsSecretPayloadFields(t *testing.T) {
	now := time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC)
	unknown := explorerObservation("org-a", "project-a", "cluster-a", "v1", "Service", "apps", "svc", now, TruthUnknown)
	unknown.Key.UID = ""
	forbidden := explorerObservation("org-a", "project-a", "cluster-a", "apps/v1", "Deployment", "apps", "web", now, TruthForbidden)
	forbidden.Key.UID = ""
	stale := explorerObservation("org-a", "project-a", "cluster-a", "v1", "Pod", "apps", "old", now.Add(-30*time.Minute), TruthFresh)
	page, err := BuildPage([]ResourceObservation{unknown, forbidden, stale}, ResourceQuery{OrganizationID:"org-a",ProjectID:"project-a",ClusterID:"cluster-a",Limit:10}, now, 5*time.Minute)
	if err != nil { t.Fatal(err) }
	states := map[string]TruthState{}
	for _, item := range page.Items { states[item.Key.Name] = item.State }
	if states["svc"] != TruthUnknown || states["web"] != TruthForbidden || states["old"] != TruthStale { t.Fatalf("truth-state preservation drift: %#v", states) }
	secret := explorerObservation("org-a", "project-a", "cluster-a", "v1", "Secret", "apps", "db", now, TruthFresh)
	secret.Summary = map[string]string{"password":"plaintext"}
	if _, err := BuildPage([]ResourceObservation{secret}, ResourceQuery{OrganizationID:"org-a",ProjectID:"project-a",ClusterID:"cluster-a",Limit:10}, now, 5*time.Minute); err == nil { t.Fatal("secret payload-like fields must never enter explorer output") }
}

func TestResourceDetailKeepsEvidenceOwnersEventsAndNoMutationSurface(t *testing.T) {
	now := time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC)
	item := explorerObservation("org-a", "project-a", "cluster-a", "apps/v1", "Deployment", "apps", "orders", now, TruthFresh)
	item.OwnerReferences = []ResourceReference{{APIVersion:"argoproj.io/v1alpha1",Kind:"Application",Namespace:"argocd",Name:"orders"}}
	item.RelatedEventDigests = []string{explorerDigest('e')}
	detail, err := BuildDetail(item, now, 5*time.Minute)
	if err != nil { t.Fatal(err) }
	if detail.Authority != BoundedResourceExplorerAuthority || detail.ReadOnly != true || detail.EvidenceDigest == "" || len(detail.OwnerReferences) != 1 || len(detail.RelatedEventDigests) != 1 {
		t.Fatalf("resource detail authority drift: %#v", detail)
	}
	if detail.AllowedVerbs != nil && len(detail.AllowedVerbs) != 0 { t.Fatalf("resource explorer must not expose raw mutation verbs: %#v", detail.AllowedVerbs) }
}

func explorerObservation(org, project, cluster, apiVersion, kind, namespace, name string, observedAt time.Time, state TruthState) ResourceObservation {
	return ResourceObservation{
		Authority: ResourceObservationAuthority,
		OrganizationID: org, ProjectID: project, ClusterID: cluster,
		Key: ResourceKey{APIVersion:apiVersion,Kind:kind,Namespace:namespace,Name:name,UID:"uid-"+name},
		State: state, ObservedAt: observedAt, SourceDigest: explorerDigest(name[0]),
		Summary: map[string]string{"status":"observed"},
	}
}

func explorerDigest(ch byte) string { b:=make([]byte,64); for i:=range b { b[i]=ch }; return "sha256:"+string(b) }
