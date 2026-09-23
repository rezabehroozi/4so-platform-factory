package api

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"platform.4so.io/factory/internal/controlplane"
)

type fleetGatewayAdmitInput struct {
	SessionID string `json:"sessionId"`
	Epoch     int64  `json:"epoch"`
}

func fleetGatewayInstanceIdentity() (string, error) {
	if configured := strings.TrimSpace(os.Getenv("PLATFORM_GATEWAY_INSTANCE_ID")); configured != "" {
		return configured, nil
	}
	host, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("resolve gateway instance hostname: %w", err)
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return "", fmt.Errorf("gateway instance identity is empty")
	}
	return host, nil
}
type fleetGatewayEpochInput struct { Epoch int64 `json:"epoch"` }

func (s *Server) fleetGatewaySessionStore() (controlplane.FleetGatewaySessionStore, bool) {
	v, ok := s.store.(controlplane.FleetGatewaySessionStore)
	return v, ok
}

func (s *Server) admitFleetGatewaySession(w http.ResponseWriter, r *http.Request) {
	clusterID := strings.TrimSpace(r.PathValue("id"))
	cert, err := s.mtlsAgentCertificate(r, clusterID)
	if err != nil { writeError(w,http.StatusUnauthorized,"AGENT_MTLS_REQUIRED",err.Error()); return }
	cluster, err := s.store.GetManagedCluster(r.Context(), clusterID)
	if err != nil { writeStoreError(w,err); return }
	var input fleetGatewayAdmitInput
	if err=decodeJSON(w,r,&input);err!=nil{return}
	store,ok:=s.fleetGatewaySessionStore();if !ok{writeError(w,http.StatusServiceUnavailable,"FLEET_GATEWAY_SESSION_STORE_UNAVAILABLE","fleet gateway session authority is unavailable");return}
	gatewayInstanceID,identityErr:=fleetGatewayInstanceIdentity();if identityErr!=nil{writeError(w,http.StatusServiceUnavailable,"FLEET_GATEWAY_INSTANCE_ID_UNAVAILABLE",identityErr.Error());return}
	admission,err:=store.AdmitFleetGatewaySession(r.Context(),controlplane.FleetGatewaySessionRequest{
		SessionID:strings.TrimSpace(input.SessionID),ClusterID:cluster.ID,ExternalUID:cluster.ExternalUID,
		CertificateID:cert.ID,CertificateFingerprint:cert.Fingerprint,Epoch:input.Epoch,
		Transport:"wss",TargetInitiated:true,MutualTLS:true,GatewayInstanceID:gatewayInstanceID,
	},time.Now().UTC(),"cluster-agent-gateway")
	if err!=nil{writeStoreError(w,err);return}
	if admission.Decision==controlplane.FleetGatewayAdmissionReject{writeJSON(w,http.StatusConflict,admission);return}
	writeJSON(w,http.StatusOK,admission)
}

func (s *Server) getAgentFleetGatewaySessionHead(w http.ResponseWriter,r *http.Request){
	clusterID:=strings.TrimSpace(r.PathValue("id"))
	if _,err:=s.mtlsAgentCertificate(r,clusterID);err!=nil{writeError(w,http.StatusUnauthorized,"AGENT_MTLS_REQUIRED",err.Error());return}
	cluster,err:=s.store.GetManagedCluster(r.Context(),clusterID);if err!=nil{writeStoreError(w,err);return}
	store,ok:=s.fleetGatewaySessionStore();if !ok{writeError(w,http.StatusServiceUnavailable,"FLEET_GATEWAY_SESSION_STORE_UNAVAILABLE","fleet gateway session authority is unavailable");return}
	v,err:=store.GetLatestFleetGatewaySession(r.Context(),cluster.ID)
	if errors.Is(err,controlplane.ErrNotFound){
		writeJSON(w,http.StatusOK,map[string]any{"authority":controlplane.FleetAgentGatewaySessionAuthority,"latestEpoch":int64(0),"session":nil})
		return
	}
	if err!=nil{writeStoreError(w,err);return}
	writeJSON(w,http.StatusOK,map[string]any{"authority":controlplane.FleetAgentGatewaySessionAuthority,"latestEpoch":v.Epoch,"session":v})
}

func (s *Server) heartbeatFleetGatewaySession(w http.ResponseWriter,r *http.Request){
	clusterID:=strings.TrimSpace(r.PathValue("id"));cert,err:=s.mtlsAgentCertificate(r,clusterID);if err!=nil{writeError(w,http.StatusUnauthorized,"AGENT_MTLS_REQUIRED",err.Error());return}
	var input fleetGatewayEpochInput;if err=decodeJSON(w,r,&input);err!=nil{return}
	store,ok:=s.fleetGatewaySessionStore();if !ok{writeError(w,http.StatusServiceUnavailable,"FLEET_GATEWAY_SESSION_STORE_UNAVAILABLE","fleet gateway session authority is unavailable");return}
	v,err:=store.HeartbeatFleetGatewaySession(r.Context(),clusterID,r.PathValue("sessionId"),input.Epoch,cert.ID,time.Now().UTC());if err!=nil{writeStoreError(w,err);return};writeJSON(w,http.StatusOK,v)
}
func (s *Server) closeFleetGatewaySession(w http.ResponseWriter,r *http.Request){
	clusterID:=strings.TrimSpace(r.PathValue("id"));cert,err:=s.mtlsAgentCertificate(r,clusterID);if err!=nil{writeError(w,http.StatusUnauthorized,"AGENT_MTLS_REQUIRED",err.Error());return}
	var input fleetGatewayEpochInput;if err=decodeJSON(w,r,&input);err!=nil{return}
	store,ok:=s.fleetGatewaySessionStore();if !ok{writeError(w,http.StatusServiceUnavailable,"FLEET_GATEWAY_SESSION_STORE_UNAVAILABLE","fleet gateway session authority is unavailable");return}
	v,err:=store.CloseFleetGatewaySession(r.Context(),clusterID,r.PathValue("sessionId"),input.Epoch,cert.ID,time.Now().UTC());if err!=nil{writeStoreError(w,err);return};writeJSON(w,http.StatusOK,v)
}
func (s *Server) getFleetGatewaySession(w http.ResponseWriter,r *http.Request){
	cluster,err:=s.store.GetManagedCluster(r.Context(),r.PathValue("id"));if err!=nil{writeStoreError(w,err);return}
	if _,err=s.requireProjectAccess(r,cluster.ProjectID,organizationRead);err!=nil{writeScopeError(w,err);return}
	store,ok:=s.fleetGatewaySessionStore();if !ok{writeError(w,http.StatusServiceUnavailable,"FLEET_GATEWAY_SESSION_STORE_UNAVAILABLE","fleet gateway session authority is unavailable");return}
	v,err:=store.GetCurrentFleetGatewaySession(r.Context(),cluster.ID);if err!=nil{writeStoreError(w,err);return}
	writeJSON(w,http.StatusOK,map[string]any{"authority":controlplane.FleetAgentGatewaySessionAuthority,"policy":controlplane.FleetGatewayTransportPolicyModel(),"session":v,"dispatchEligible":controlplane.FleetGatewaySessionMayDispatch(v,time.Now().UTC())})
}
func (s *Server) drainFleetGatewaySession(w http.ResponseWriter,r *http.Request){
	actor,err:=actorID(r);if err!=nil{writeError(w,http.StatusUnauthorized,"ACTOR_REQUIRED",err.Error());return}
	cluster,err:=s.store.GetManagedCluster(r.Context(),r.PathValue("id"));if err!=nil{writeStoreError(w,err);return}
	if _,err=s.requireProjectAccess(r,cluster.ProjectID,organizationWrite);err!=nil{writeScopeError(w,err);return}
	var input fleetGatewayEpochInput;if err=decodeJSON(w,r,&input);err!=nil{return}
	if input.Epoch<=0{writeError(w,http.StatusUnprocessableEntity,"EXPECTED_EPOCH_REQUIRED","positive epoch is required");return}
	store,ok:=s.fleetGatewaySessionStore();if !ok{writeError(w,http.StatusServiceUnavailable,"FLEET_GATEWAY_SESSION_STORE_UNAVAILABLE","fleet gateway session authority is unavailable");return}
	v,err:=store.DrainFleetGatewaySession(r.Context(),cluster.ID,input.Epoch,actor,time.Now().UTC());if err!=nil{writeStoreError(w,err);return};writeJSON(w,http.StatusOK,v)
}
