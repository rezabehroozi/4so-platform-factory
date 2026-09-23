package controlplane

import (
	"fmt"
	"strings"
	"time"
)

const FleetAgentGatewaySessionAuthority = "FLEET_AGENT_GATEWAY_SESSION_AUTHORITY_V1"

const (
	FleetGatewaySessionActive   = "ACTIVE"
	FleetGatewaySessionDraining = "DRAINING"
	FleetGatewaySessionClosed   = "CLOSED"

	FleetGatewayAdmissionNew          = "ADMIT_NEW"
	FleetGatewayAdmissionReplay       = "REPLAY_EXISTING"
	FleetGatewayAdmissionReplaceStale = "REPLACE_STALE"
	FleetGatewayAdmissionReject       = "REJECT"
)

type FleetGatewayTransportPolicy struct {
	Authority             string `json:"authority"`
	Transport             string `json:"transport"`
	TargetInitiated       bool   `json:"targetInitiated"`
	MutualTLSRequired     bool   `json:"mutualTlsRequired"`
	HeartbeatSeconds      int    `json:"heartbeatSeconds"`
	SessionStaleSeconds   int    `json:"sessionStaleSeconds"`
	ReconnectMinSeconds   int    `json:"reconnectMinSeconds"`
	ReconnectMaxSeconds   int    `json:"reconnectMaxSeconds"`
	MaxActivePerCluster   int    `json:"maxActivePerCluster"`
	TaskFenceBypassAllowed bool  `json:"taskFenceBypassAllowed"`
}

func FleetGatewayTransportPolicyModel() FleetGatewayTransportPolicy {
	return FleetGatewayTransportPolicy{
		Authority: FleetAgentGatewaySessionAuthority,
		Transport: "wss",
		TargetInitiated: true,
		MutualTLSRequired: true,
		HeartbeatSeconds: 30,
		SessionStaleSeconds: 180,
		ReconnectMinSeconds: 1,
		ReconnectMaxSeconds: 60,
		MaxActivePerCluster: 1,
		TaskFenceBypassAllowed: false,
	}
}

type FleetGatewaySessionRequest struct {
	SessionID              string `json:"sessionId"`
	ClusterID              string `json:"clusterId"`
	ExternalUID            string `json:"externalUid"`
	CertificateID          string `json:"certificateId"`
	CertificateFingerprint string `json:"certificateFingerprint"`
	Epoch                  int64  `json:"epoch"`
	Transport              string `json:"transport"`
	TargetInitiated        bool   `json:"targetInitiated"`
	MutualTLS              bool   `json:"mutualTls"`
	GatewayInstanceID      string `json:"gatewayInstanceId"`
}

type FleetGatewaySession struct {
	Authority              string    `json:"authority"`
	SessionID              string    `json:"sessionId"`
	ClusterID              string    `json:"clusterId"`
	ExternalUID            string    `json:"externalUid"`
	CertificateID          string    `json:"certificateId"`
	CertificateFingerprint string    `json:"certificateFingerprint"`
	Epoch                  int64     `json:"epoch"`
	State                  string    `json:"state"`
	GatewayInstanceID      string    `json:"gatewayInstanceId"`
	ConnectedAt            time.Time `json:"connectedAt"`
	LastHeartbeatAt        time.Time `json:"lastHeartbeatAt"`
	DrainRequestedAt       *time.Time `json:"drainRequestedAt,omitempty"`
	ClosedAt               *time.Time `json:"closedAt,omitempty"`
}

type FleetGatewaySessionAdmission struct {
	Authority string               `json:"authority"`
	Decision  string               `json:"decision"`
	Reason    string               `json:"reason"`
	Session   *FleetGatewaySession `json:"session,omitempty"`
}

func normalizeFleetGatewaySessionRequest(in FleetGatewaySessionRequest) (FleetGatewaySessionRequest,error) {
	out:=in
	out.SessionID=strings.TrimSpace(out.SessionID)
	out.ClusterID=strings.TrimSpace(out.ClusterID)
	out.ExternalUID=strings.TrimSpace(out.ExternalUID)
	out.CertificateID=strings.TrimSpace(out.CertificateID)
	out.CertificateFingerprint=strings.ToLower(strings.TrimSpace(out.CertificateFingerprint))
	out.Transport=strings.ToLower(strings.TrimSpace(out.Transport))
	out.GatewayInstanceID=strings.TrimSpace(out.GatewayInstanceID)
	if out.SessionID==""||out.ClusterID==""||out.ExternalUID==""||out.CertificateID==""||out.GatewayInstanceID==""||out.Epoch<=0 {
		return FleetGatewaySessionRequest{},fmt.Errorf("%w: fleet gateway session identity is incomplete",ErrValidation)
	}
	if out.Transport!="wss"||!out.TargetInitiated||!out.MutualTLS {
		return FleetGatewaySessionRequest{},fmt.Errorf("%w: fleet gateway transport must be target-initiated WSS with mutual TLS",ErrValidation)
	}
	if !strings.HasPrefix(out.CertificateFingerprint,"sha256:") {
		return FleetGatewaySessionRequest{},fmt.Errorf("%w: fleet gateway certificate fingerprint must be sha256",ErrValidation)
	}
	return out,nil
}

func AdmitFleetGatewaySession(cluster ManagedCluster, cert AgentCertificate, req FleetGatewaySessionRequest, current *FleetGatewaySession, now time.Time) (FleetGatewaySessionAdmission,error) {
	req,err:=normalizeFleetGatewaySessionRequest(req);if err!=nil{return FleetGatewaySessionAdmission{},err}
	now=now.UTC();if now.IsZero(){return FleetGatewaySessionAdmission{},fmt.Errorf("%w: session admission time is required",ErrValidation)}
	if cluster.ID!=req.ClusterID||strings.TrimSpace(cluster.ExternalUID)!=req.ExternalUID||cluster.ConnectionState=="REVOKED" {
		return FleetGatewaySessionAdmission{},fmt.Errorf("%w: cluster identity/revocation fence rejected gateway session",ErrValidation)
	}
	if cert.ID!=req.CertificateID||cert.ClusterID!=cluster.ID||cert.State!=AgentCertificateActive||!secureEqual(strings.ToLower(strings.TrimSpace(cert.Fingerprint)),req.CertificateFingerprint)||now.Before(cert.NotBefore.UTC())||!now.Before(cert.NotAfter.UTC()) {
		return FleetGatewaySessionAdmission{},fmt.Errorf("%w: active exact-cluster mTLS certificate is required",ErrValidation)
	}
	policy:=FleetGatewayTransportPolicyModel()
	if current!=nil {
		if current.ClusterID!=cluster.ID {return FleetGatewaySessionAdmission{},fmt.Errorf("%w: active session belongs to another cluster",ErrValidation)}
		if current.State==FleetGatewaySessionActive {
			if current.SessionID==req.SessionID&&current.Epoch==req.Epoch&&current.CertificateID==req.CertificateID&&current.GatewayInstanceID==req.GatewayInstanceID&&secureEqual(current.CertificateFingerprint,req.CertificateFingerprint) {
				copy:=*current
				return FleetGatewaySessionAdmission{Authority:FleetAgentGatewaySessionAuthority,Decision:FleetGatewayAdmissionReplay,Reason:"exact active session identity replay",Session:&copy},nil
			}
			stale:=now.Sub(current.LastHeartbeatAt.UTC())>time.Duration(policy.SessionStaleSeconds)*time.Second
			if !stale {
				return FleetGatewaySessionAdmission{Authority:FleetAgentGatewaySessionAuthority,Decision:FleetGatewayAdmissionReject,Reason:"another non-stale session is active for the cluster"},nil
			}
			if req.Epoch<=current.Epoch {
				return FleetGatewaySessionAdmission{Authority:FleetAgentGatewaySessionAuthority,Decision:FleetGatewayAdmissionReject,Reason:"stale-session replacement requires a strictly newer session epoch"},nil
			}
		} else if current.State==FleetGatewaySessionDraining {
			return FleetGatewaySessionAdmission{Authority:FleetAgentGatewaySessionAuthority,Decision:FleetGatewayAdmissionReject,Reason:"gateway session drain must close before replacement"},nil
		} else if req.Epoch<=current.Epoch {
			return FleetGatewaySessionAdmission{Authority:FleetAgentGatewaySessionAuthority,Decision:FleetGatewayAdmissionReject,Reason:"new session epoch must advance beyond the last closed session"},nil
		}
	}
	session:=FleetGatewaySession{Authority:FleetAgentGatewaySessionAuthority,SessionID:req.SessionID,ClusterID:req.ClusterID,ExternalUID:req.ExternalUID,CertificateID:req.CertificateID,CertificateFingerprint:req.CertificateFingerprint,Epoch:req.Epoch,State:FleetGatewaySessionActive,GatewayInstanceID:req.GatewayInstanceID,ConnectedAt:now,LastHeartbeatAt:now}
	decision:=FleetGatewayAdmissionNew;reason:="target-initiated mTLS session admitted"
	if current!=nil {decision=FleetGatewayAdmissionReplaceStale;reason="stale session replaced by a strictly newer epoch after certificate and cluster identity revalidation"}
	return FleetGatewaySessionAdmission{Authority:FleetAgentGatewaySessionAuthority,Decision:decision,Reason:reason,Session:&session},nil
}

func HeartbeatFleetGatewaySession(in FleetGatewaySession,sessionID string,epoch int64,at time.Time)(FleetGatewaySession,error){
	out:=in;at=at.UTC()
	if out.Authority!=FleetAgentGatewaySessionAuthority||out.State!=FleetGatewaySessionActive||strings.TrimSpace(sessionID)!=out.SessionID||epoch!=out.Epoch||at.IsZero()||at.Before(out.LastHeartbeatAt) {
		return FleetGatewaySession{},fmt.Errorf("%w: heartbeat does not match the active session epoch",ErrValidation)
	}
	out.LastHeartbeatAt=at
	return out,nil
}

func DrainFleetGatewaySession(in FleetGatewaySession,at time.Time)(FleetGatewaySession,error){
	out:=in;at=at.UTC()
	if out.Authority!=FleetAgentGatewaySessionAuthority||out.State!=FleetGatewaySessionActive||at.IsZero()||at.Before(out.ConnectedAt) {return FleetGatewaySession{},fmt.Errorf("%w: only an active session can enter gateway drain",ErrInvalidTransition)}
	out.State=FleetGatewaySessionDraining;out.DrainRequestedAt=&at
	return out,nil
}
func CloseFleetGatewaySession(in FleetGatewaySession,at time.Time)(FleetGatewaySession,error){
	out:=in;at=at.UTC()
	if out.Authority!=FleetAgentGatewaySessionAuthority||(out.State!=FleetGatewaySessionActive&&out.State!=FleetGatewaySessionDraining)||at.IsZero()||at.Before(out.ConnectedAt){return FleetGatewaySession{},fmt.Errorf("%w: session cannot close from current state",ErrInvalidTransition)}
	out.State=FleetGatewaySessionClosed;out.ClosedAt=&at
	return out,nil
}
func FleetGatewaySessionMayDispatch(in FleetGatewaySession,now time.Time) bool {
	p:=FleetGatewayTransportPolicyModel();return in.Authority==FleetAgentGatewaySessionAuthority&&in.State==FleetGatewaySessionActive&&!now.UTC().Before(in.LastHeartbeatAt.UTC())&&now.UTC().Sub(in.LastHeartbeatAt.UTC())<=time.Duration(p.SessionStaleSeconds)*time.Second
}
