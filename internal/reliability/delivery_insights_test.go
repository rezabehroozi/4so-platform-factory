package reliability

import (
	"testing"
	"time"
)

func TestDeliveryInsightsAreEvidenceBackedAndWindowScoped(t *testing.T){
	start:=time.Date(2026,9,1,0,0,0,0,time.UTC);end:=start.Add(24*time.Hour);commit:=start.Add(time.Hour)
	out,err:=BuildDeliveryInsights("prj-1",start,end,[]DeliveryEvidence{
		{EvidenceID:"d1",ProjectID:"prj-1",EventType:DeliveryEventDeploymentSucceeded,OccurredAt:start.Add(2*time.Hour),SourceCommittedAt:&commit,ReleaseDigest:"sha256:a"},
		{EvidenceID:"d2",ProjectID:"prj-1",EventType:DeliveryEventDeploymentFailed,OccurredAt:start.Add(4*time.Hour),SourceCommittedAt:&commit,ReleaseDigest:"sha256:b"},
		{EvidenceID:"i1-open",ProjectID:"prj-1",EventType:DeliveryEventIncidentOpened,OccurredAt:start.Add(5*time.Hour),IncidentID:"inc-1"},
		{EvidenceID:"i1-resolve",ProjectID:"prj-1",EventType:DeliveryEventIncidentResolved,OccurredAt:start.Add(7*time.Hour),IncidentID:"inc-1"},
		{EvidenceID:"foreign",ProjectID:"prj-2",EventType:DeliveryEventDeploymentSucceeded,OccurredAt:start.Add(3*time.Hour)},
		{EvidenceID:"outside",ProjectID:"prj-1",EventType:DeliveryEventDeploymentSucceeded,OccurredAt:end.Add(time.Minute)},
	})
	if err!=nil{t.Fatal(err)}
	if out.Authority!=DeliveryInsightsAuthority||out.EvidenceCount!=4{t.Fatalf("out=%#v",out)}
	if out.DeploymentFrequency.Status!=DeliveryMetricObserved||out.DeploymentFrequency.Value!=2_000_000{t.Fatalf("frequency=%#v",out.DeploymentFrequency)}
	if out.ChangeFailureRate.Value!=5000||out.ChangeFailureRate.SampleSize!=2{t.Fatalf("failure rate=%#v",out.ChangeFailureRate)}
	if out.LeadTimeForChanges.Value!=(3600+10800)/2{t.Fatalf("lead=%#v",out.LeadTimeForChanges)}
	if out.FailedDeploymentRecovery.Value!=7200||out.FailedDeploymentRecovery.SampleSize!=1{t.Fatalf("recovery=%#v",out.FailedDeploymentRecovery)}
}
func TestDeliveryInsightsNeverTurnsMissingEvidenceIntoZero(t *testing.T){
	start:=time.Date(2026,9,1,0,0,0,0,time.UTC);out,err:=BuildDeliveryInsights("prj-1",start,start.Add(7*24*time.Hour),nil);if err!=nil{t.Fatal(err)}
	for name,metric:=range map[string]DeliveryMetric{"frequency":out.DeploymentFrequency,"lead":out.LeadTimeForChanges,"failure":out.ChangeFailureRate,"recovery":out.FailedDeploymentRecovery}{if metric.Status!=DeliveryMetricUnknown||metric.SampleSize!=0{t.Fatalf("%s missing evidence became numeric truth: %#v",name,metric)}}
	if len(out.MissingEvidence)!=3{t.Fatalf("missing evidence=%#v",out.MissingEvidence)}
}
func TestDeliveryInsightsRejectDuplicateEvidenceIdentity(t *testing.T){
	start:=time.Date(2026,9,1,0,0,0,0,time.UTC);events:=[]DeliveryEvidence{{EvidenceID:"same",ProjectID:"p",EventType:DeliveryEventDeploymentSucceeded,OccurredAt:start.Add(time.Hour)},{EvidenceID:"same",ProjectID:"p",EventType:DeliveryEventDeploymentFailed,OccurredAt:start.Add(2*time.Hour)}}
	if _,err:=BuildDeliveryInsights("p",start,start.Add(24*time.Hour),events);err==nil{t.Fatal("duplicate evidence identity accepted")}
}
