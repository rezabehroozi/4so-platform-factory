package api

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/reliability"
)
func TestDeliveryInsightsPreservesUnknownDeploymentTruthAndDerivesResolvedIncidentRecovery(t *testing.T){
	store:=controlplane.NewMemoryStore();ctx:=context.Background();org,_:=store.CreateOrganization(ctx,controlplane.Organization{Name:"delivery-org",DisplayName:"Delivery Org"},"owner");project,_:=store.CreateProject(ctx,controlplane.Project{OrganizationID:org.ID,Name:"delivery",DisplayName:"Delivery"},"owner")
	incident,err:=store.CreateIncident(ctx,reliability.Incident{OrganizationID:org.ID,ProjectID:project.ID,Severity:"SEV2",State:reliability.IncidentOpen},"owner");if err!=nil{t.Fatal(err)}
	time.Sleep(time.Millisecond);if _,err=store.TransitionIncident(ctx,incident.ID,incident.Revision,reliability.IncidentActionResolve,"owner","recovered");err!=nil{t.Fatal(err)}
	srv:=scopedServer(t,store);from:=time.Now().Add(-time.Hour).UTC().Format(time.RFC3339);to:=time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	w:=scopedRequest(t,srv,http.MethodGet,"/api/v1/reliability/delivery-insights?projectId="+project.ID+"&from="+from+"&to="+to,"","owner","platform-operator");if w.Code!=http.StatusOK{t.Fatalf("delivery insights=%d %s",w.Code,w.Body.String())}
	body:=w.Body.String();for _,want:=range []string{reliability.DeliveryInsightsAuthority,"\"deploymentFrequency\":{\"status\":\"UNKNOWN\"","\"failedDeploymentRecovery\":{\"status\":\"OBSERVED\"","\"physicalCertificationInferred\":false"}{if !strings.Contains(body,want){t.Fatalf("missing %q in %s",want,body)}}
}
