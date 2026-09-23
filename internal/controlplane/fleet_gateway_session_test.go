package controlplane

import (
	"testing"
	"time"
)

func fleetSessionFixture(t *testing.T)(ManagedCluster,AgentCertificate,FleetGatewaySessionRequest,time.Time){
	t.Helper();now:=time.Date(2026,9,23,12,0,0,0,time.UTC)
	cluster:=ManagedCluster{ResourceMeta:ResourceMeta{ID:"clu-1",Revision:3},ProjectID:"prj-1",ExternalUID:"uid-1",ConnectionState:"CONNECTED"}
	cert:=AgentCertificate{ResourceMeta:ResourceMeta{ID:"cert-1",Revision:1},ClusterID:cluster.ID,Fingerprint:"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",State:AgentCertificateActive,NotBefore:now.Add(-time.Hour),NotAfter:now.Add(time.Hour)}
	req:=FleetGatewaySessionRequest{SessionID:"session-1",ClusterID:cluster.ID,ExternalUID:cluster.ExternalUID,CertificateID:cert.ID,CertificateFingerprint:cert.Fingerprint,Epoch:1,Transport:"wss",TargetInitiated:true,MutualTLS:true,GatewayInstanceID:"gateway-a"}
	return cluster,cert,req,now
}
func TestFleetGatewaySessionAdmissionUsesExactMTLSIdentityAndSingleLiveSession(t *testing.T){
	cluster,cert,req,now:=fleetSessionFixture(t)
	first,err:=AdmitFleetGatewaySession(cluster,cert,req,nil,now);if err!=nil{t.Fatal(err)}
	if first.Decision!=FleetGatewayAdmissionNew||first.Session==nil||!FleetGatewaySessionMayDispatch(*first.Session,now.Add(time.Minute)){t.Fatalf("first=%#v",first)}
	replay,err:=AdmitFleetGatewaySession(cluster,cert,req,first.Session,now.Add(time.Minute));if err!=nil{t.Fatal(err)}
	if replay.Decision!=FleetGatewayAdmissionReplay{t.Fatalf("replay=%#v",replay)}
	next:=req;next.SessionID="session-2";next.Epoch=2
	dup,err:=AdmitFleetGatewaySession(cluster,cert,next,first.Session,now.Add(time.Minute));if err!=nil{t.Fatal(err)}
	if dup.Decision!=FleetGatewayAdmissionReject{t.Fatalf("live duplicate session admitted: %#v",dup)}
}
func TestFleetGatewaySessionReplayCannotMoveAcrossGatewayOwners(t *testing.T){
	cluster,cert,req,now:=fleetSessionFixture(t)
	first,err:=AdmitFleetGatewaySession(cluster,cert,req,nil,now);if err!=nil{t.Fatal(err)}
	crossOwner:=req;crossOwner.GatewayInstanceID="gateway-b"
	admission,err:=AdmitFleetGatewaySession(cluster,cert,crossOwner,first.Session,now.Add(time.Minute));if err!=nil{t.Fatal(err)}
	if admission.Decision!=FleetGatewayAdmissionReject{t.Fatalf("cross-gateway replay bypassed HA ownership: %#v",admission)}
}

func TestFleetGatewaySessionStaleReplacementRequiresNewEpoch(t *testing.T){
	cluster,cert,req,now:=fleetSessionFixture(t);first,_:=AdmitFleetGatewaySession(cluster,cert,req,nil,now)
	next:=req;next.SessionID="session-2";next.GatewayInstanceID="gateway-b"
	sameEpoch,err:=AdmitFleetGatewaySession(cluster,cert,next,first.Session,now.Add(4*time.Minute));if err!=nil{t.Fatal(err)}
	if sameEpoch.Decision!=FleetGatewayAdmissionReject{t.Fatalf("same epoch replaced stale session: %#v",sameEpoch)}
	next.Epoch=2;replacement,err:=AdmitFleetGatewaySession(cluster,cert,next,first.Session,now.Add(4*time.Minute));if err!=nil{t.Fatal(err)}
	if replacement.Decision!=FleetGatewayAdmissionReplaceStale||replacement.Session==nil||replacement.Session.Epoch!=2{t.Fatalf("replacement=%#v",replacement)}
}
func TestFleetGatewayDrainBlocksTaskDispatchAndReplacement(t *testing.T){
	cluster,cert,req,now:=fleetSessionFixture(t);first,_:=AdmitFleetGatewaySession(cluster,cert,req,nil,now)
	draining,err:=DrainFleetGatewaySession(*first.Session,now.Add(time.Minute));if err!=nil{t.Fatal(err)}
	if FleetGatewaySessionMayDispatch(draining,now.Add(time.Minute)){t.Fatal("draining gateway session remained dispatch eligible")}
	next:=req;next.SessionID="session-2";next.Epoch=2
	admission,err:=AdmitFleetGatewaySession(cluster,cert,next,&draining,now.Add(2*time.Minute));if err!=nil{t.Fatal(err)}
	if admission.Decision!=FleetGatewayAdmissionReject{t.Fatalf("replacement bypassed gateway drain: %#v",admission)}
	closed,err:=CloseFleetGatewaySession(draining,now.Add(3*time.Minute));if err!=nil||closed.State!=FleetGatewaySessionClosed{t.Fatalf("close=%#v err=%v",closed,err)}
	admission,err=AdmitFleetGatewaySession(cluster,cert,next,&closed,now.Add(4*time.Minute));if err!=nil||admission.Decision!=FleetGatewayAdmissionReplaceStale{t.Fatalf("post-close replacement=%#v err=%v",admission,err)}
}
func TestFleetGatewaySessionRejectsRevokedCertificateOrCluster(t *testing.T){
	cluster,cert,req,now:=fleetSessionFixture(t);cert.State=AgentCertificateRevoked
	if _,err:=AdmitFleetGatewaySession(cluster,cert,req,nil,now);err==nil{t.Fatal("revoked certificate admitted")}
	cert.State=AgentCertificateActive;cluster.ConnectionState="REVOKED"
	if _,err:=AdmitFleetGatewaySession(cluster,cert,req,nil,now);err==nil{t.Fatal("revoked cluster admitted")}
}
