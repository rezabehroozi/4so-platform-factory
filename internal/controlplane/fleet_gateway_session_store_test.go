package controlplane

import (
	"context"
	"testing"
	"time"
)

func TestFleetGatewaySessionStorePersistsSingleLiveEpochAndDrain(t *testing.T) {
	now:=time.Date(2026,9,23,16,0,0,0,time.UTC)
	store:=NewMemoryStoreWith(func()time.Time{return now},func(prefix string)string{return prefix+"-1"})
	org,_:=store.CreateOrganization(context.Background(),Organization{Name:"fleet-sessions",DisplayName:"Fleet Sessions"},"admin")
	project,_:=store.CreateProject(context.Background(),Project{OrganizationID:org.ID,Name:"prod",DisplayName:"Prod"},"admin")
	cluster:=ManagedCluster{ResourceMeta:ResourceMeta{ID:"clu-1",Revision:1,CreatedAt:now,UpdatedAt:now},ProjectID:project.ID,ExternalUID:"uid-1",ConnectionState:"CONNECTED"}
	store.managedClusters[cluster.ID]=cluster
	cert:=AgentCertificate{ResourceMeta:ResourceMeta{ID:"cert-1",Revision:1,CreatedAt:now,UpdatedAt:now},ClusterID:cluster.ID,Fingerprint:"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",State:AgentCertificateActive,NotBefore:now.Add(-time.Hour),NotAfter:now.Add(time.Hour)}
	store.agentCertificates[cert.ID]=cert
	req:=FleetGatewaySessionRequest{SessionID:"session-1",ClusterID:cluster.ID,ExternalUID:cluster.ExternalUID,CertificateID:cert.ID,CertificateFingerprint:cert.Fingerprint,Epoch:1,Transport:"wss",TargetInitiated:true,MutualTLS:true,GatewayInstanceID:"gw-a"}
	admit,err:=store.AdmitFleetGatewaySession(context.Background(),req,now,"gateway")
	if err!=nil||admit.Decision!=FleetGatewayAdmissionNew||admit.Session==nil{t.Fatalf("admit=%#v err=%v",admit,err)}
	if _,err=store.HeartbeatFleetGatewaySession(context.Background(),cluster.ID,req.SessionID,1,cert.ID,now.Add(time.Minute));err!=nil{t.Fatal(err)}
	if _,err=store.DrainFleetGatewaySession(context.Background(),cluster.ID,1,"operator",now.Add(2*time.Minute));err!=nil{t.Fatal(err)}
	if _,err=store.HeartbeatFleetGatewaySession(context.Background(),cluster.ID,req.SessionID,1,cert.ID,now.Add(3*time.Minute));err==nil{t.Fatal("draining session accepted heartbeat")}
	closed,err:=store.CloseFleetGatewaySession(context.Background(),cluster.ID,req.SessionID,1,cert.ID,now.Add(3*time.Minute));if err!=nil||closed.State!=FleetGatewaySessionClosed{t.Fatalf("close=%#v err=%v",closed,err)}
}

func TestFleetGatewaySessionStoreReplacesOnlyStaleSessionWithNewerEpoch(t *testing.T){
	now:=time.Date(2026,9,23,16,0,0,0,time.UTC)
	store:=NewMemoryStoreWith(func()time.Time{return now},func(prefix string)string{return prefix+"-1"})
	cluster:=ManagedCluster{ResourceMeta:ResourceMeta{ID:"clu-1",Revision:1},ProjectID:"prj-1",ExternalUID:"uid-1",ConnectionState:"CONNECTED"};store.managedClusters[cluster.ID]=cluster
	cert:=AgentCertificate{ResourceMeta:ResourceMeta{ID:"cert-1",Revision:1},ClusterID:cluster.ID,Fingerprint:"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",State:AgentCertificateActive,NotBefore:now.Add(-time.Hour),NotAfter:now.Add(time.Hour)};store.agentCertificates[cert.ID]=cert
	req:=FleetGatewaySessionRequest{SessionID:"s1",ClusterID:cluster.ID,ExternalUID:cluster.ExternalUID,CertificateID:cert.ID,CertificateFingerprint:cert.Fingerprint,Epoch:1,Transport:"wss",TargetInitiated:true,MutualTLS:true,GatewayInstanceID:"gw-a"}
	if _,err:=store.AdmitFleetGatewaySession(context.Background(),req,now,"gw");err!=nil{t.Fatal(err)}
	req.SessionID="s2";req.GatewayInstanceID="gw-b"
	dup,err:=store.AdmitFleetGatewaySession(context.Background(),req,now.Add(time.Minute),"gw");if err!=nil||dup.Decision!=FleetGatewayAdmissionReject{t.Fatalf("dup=%#v err=%v",dup,err)}
	req.Epoch=2
	replaced,err:=store.AdmitFleetGatewaySession(context.Background(),req,now.Add(4*time.Minute),"gw");if err!=nil||replaced.Decision!=FleetGatewayAdmissionReplaceStale{t.Fatalf("replace=%#v err=%v",replaced,err)}
	old,_:=store.GetFleetGatewaySession(context.Background(),"s1");if old.State!=FleetGatewaySessionClosed{t.Fatalf("old session not closed: %#v",old)}
}

func TestFleetGatewaySessionStoreFencesClosedEpochReplay(t *testing.T){
	now:=time.Date(2026,9,23,18,0,0,0,time.UTC)
	store:=NewMemoryStoreWith(func()time.Time{return now},func(prefix string)string{return prefix+"-1"})
	cluster:=ManagedCluster{ResourceMeta:ResourceMeta{ID:"clu-history",Revision:1},ProjectID:"prj-1",ExternalUID:"uid-history",ConnectionState:"CONNECTED"};store.managedClusters[cluster.ID]=cluster
	cert:=AgentCertificate{ResourceMeta:ResourceMeta{ID:"cert-history",Revision:1},ClusterID:cluster.ID,Fingerprint:"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",State:AgentCertificateActive,NotBefore:now.Add(-time.Hour),NotAfter:now.Add(time.Hour)};store.agentCertificates[cert.ID]=cert
	req:=FleetGatewaySessionRequest{SessionID:"s5",ClusterID:cluster.ID,ExternalUID:cluster.ExternalUID,CertificateID:cert.ID,CertificateFingerprint:cert.Fingerprint,Epoch:5,Transport:"wss",TargetInitiated:true,MutualTLS:true,GatewayInstanceID:"gw-a"}
	first,err:=store.AdmitFleetGatewaySession(context.Background(),req,now,"gw");if err!=nil||first.Decision!=FleetGatewayAdmissionNew{t.Fatalf("first=%#v err=%v",first,err)}
	if _,err=store.CloseFleetGatewaySession(context.Background(),cluster.ID,req.SessionID,req.Epoch,cert.ID,now.Add(time.Minute));err!=nil{t.Fatal(err)}
	req.SessionID="s-replay";req.GatewayInstanceID="gw-b"
	replay,err:=store.AdmitFleetGatewaySession(context.Background(),req,now.Add(2*time.Minute),"gw");if err!=nil{t.Fatal(err)}
	if replay.Decision!=FleetGatewayAdmissionReject{t.Fatalf("closed epoch replay admitted: %#v",replay)}
	req.Epoch=6
	next,err:=store.AdmitFleetGatewaySession(context.Background(),req,now.Add(3*time.Minute),"gw");if err!=nil||next.Decision!=FleetGatewayAdmissionNew{t.Fatalf("next=%#v err=%v",next,err)}
	latest,err:=store.GetLatestFleetGatewaySession(context.Background(),cluster.ID);if err!=nil||latest.Epoch!=6||latest.SessionID!="s-replay"{t.Fatalf("latest=%#v err=%v",latest,err)}
}
