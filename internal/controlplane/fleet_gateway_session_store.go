package controlplane

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

type FleetGatewaySessionStore interface {
	AdmitFleetGatewaySession(context.Context, FleetGatewaySessionRequest, time.Time, string) (FleetGatewaySessionAdmission, error)
	GetFleetGatewaySession(context.Context, string) (FleetGatewaySession, error)
	GetCurrentFleetGatewaySession(context.Context, string) (FleetGatewaySession, error)
	GetLatestFleetGatewaySession(context.Context, string) (FleetGatewaySession, error)
	HeartbeatFleetGatewaySession(context.Context, string, string, int64, string, time.Time) (FleetGatewaySession, error)
	DrainFleetGatewaySession(context.Context, string, int64, string, time.Time) (FleetGatewaySession, error)
	CloseFleetGatewaySession(context.Context, string, string, int64, string, time.Time) (FleetGatewaySession, error)
}

func fleetGatewaySessionCurrent(values map[string]FleetGatewaySession, clusterID string) (*FleetGatewaySession, error) {
	var current *FleetGatewaySession
	for _, v := range values {
		if v.ClusterID != clusterID || (v.State != FleetGatewaySessionActive && v.State != FleetGatewaySessionDraining) {
			continue
		}
		if current != nil {
			return nil, fmt.Errorf("%w: multiple live gateway sessions exist for cluster", ErrConflict)
		}
		copy := v
		current = &copy
	}
	return current, nil
}

func fleetGatewaySessionLatest(values map[string]FleetGatewaySession, clusterID string) (*FleetGatewaySession, error) {
	var latest *FleetGatewaySession
	for _, v := range values {
		if v.ClusterID != clusterID { continue }
		if latest == nil || v.Epoch > latest.Epoch {
			copy := v
			latest = &copy
			continue
		}
		if v.Epoch == latest.Epoch && v.SessionID != latest.SessionID {
			return nil, fmt.Errorf("%w: duplicate fleet gateway epoch exists for cluster", ErrConflict)
		}
	}
	return latest, nil
}

func (s *MemoryStore) AdmitFleetGatewaySession(_ context.Context, req FleetGatewaySessionRequest, at time.Time, actor string) (FleetGatewaySessionAdmission, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cluster, ok := s.managedClusters[strings.TrimSpace(req.ClusterID)]
	if !ok {
		return FleetGatewaySessionAdmission{}, ErrNotFound
	}
	cert, ok := s.agentCertificates[strings.TrimSpace(req.CertificateID)]
	if !ok {
		return FleetGatewaySessionAdmission{}, ErrNotFound
	}
	current, err := fleetGatewaySessionCurrent(s.fleetGatewaySessions, cluster.ID)
	if err != nil {
		return FleetGatewaySessionAdmission{}, err
	}
	latest, err := fleetGatewaySessionLatest(s.fleetGatewaySessions, cluster.ID)
	if err != nil {
		return FleetGatewaySessionAdmission{}, err
	}
	latestEpoch := int64(0)
	if latest != nil { latestEpoch = latest.Epoch }
	admission, err := AdmitFleetGatewaySessionWithLatestEpoch(cluster, cert, req, current, latestEpoch, at)
	if err != nil {
		return FleetGatewaySessionAdmission{}, err
	}
	if admission.Decision == FleetGatewayAdmissionReject || admission.Decision == FleetGatewayAdmissionReplay {
		return admission, nil
	}
	if current != nil && admission.Decision == FleetGatewayAdmissionReplaceStale {
		closed, closeErr := CloseFleetGatewaySession(*current, at)
		if closeErr != nil {
			return FleetGatewaySessionAdmission{}, closeErr
		}
		s.fleetGatewaySessions[closed.SessionID] = closed
	}
	if admission.Session == nil {
		return FleetGatewaySessionAdmission{}, fmt.Errorf("%w: admitted fleet session is empty", ErrValidation)
	}
	s.fleetGatewaySessions[admission.Session.SessionID] = *admission.Session
	action := "fleet_gateway_session.admitted"
	if admission.Decision == FleetGatewayAdmissionReplaceStale {
		action = "fleet_gateway_session.replaced_stale"
	}
	s.appendAuditLocked(actor, action, "fleetGatewaySession", admission.Session.SessionID, admission.Session.Epoch, map[string]any{"projectId": cluster.ProjectID, "clusterId": cluster.ID, "certificateId": cert.ID, "epoch": admission.Session.Epoch, "gatewayInstanceId": admission.Session.GatewayInstanceID})
	s.appendOutboxLocked("fleetGatewaySession", admission.Session.SessionID, action, *admission.Session)
	return admission, nil
}

func (s *MemoryStore) GetFleetGatewaySession(_ context.Context, sessionID string) (FleetGatewaySession, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.fleetGatewaySessions[strings.TrimSpace(sessionID)]
	if !ok {
		return FleetGatewaySession{}, ErrNotFound
	}
	return v, nil
}

func (s *MemoryStore) GetCurrentFleetGatewaySession(_ context.Context, clusterID string) (FleetGatewaySession, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	current, err := fleetGatewaySessionCurrent(s.fleetGatewaySessions, strings.TrimSpace(clusterID))
	if err != nil {
		return FleetGatewaySession{}, err
	}
	if current == nil {
		return FleetGatewaySession{}, ErrNotFound
	}
	return *current, nil
}

func (s *MemoryStore) GetLatestFleetGatewaySession(_ context.Context, clusterID string) (FleetGatewaySession, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	latest, err := fleetGatewaySessionLatest(s.fleetGatewaySessions, strings.TrimSpace(clusterID))
	if err != nil {
		return FleetGatewaySession{}, err
	}
	if latest == nil {
		return FleetGatewaySession{}, ErrNotFound
	}
	return *latest, nil
}

func (s *MemoryStore) HeartbeatFleetGatewaySession(_ context.Context, clusterID, sessionID string, epoch int64, certificateID string, at time.Time) (FleetGatewaySession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.fleetGatewaySessions[strings.TrimSpace(sessionID)]
	if !ok || v.ClusterID != strings.TrimSpace(clusterID) || v.CertificateID != strings.TrimSpace(certificateID) {
		return FleetGatewaySession{}, ErrNotFound
	}
	cert, ok := s.agentCertificates[v.CertificateID]
	if !ok || cert.State != AgentCertificateActive || at.UTC().Before(cert.NotBefore.UTC()) || !at.UTC().Before(cert.NotAfter.UTC()) {
		return FleetGatewaySession{}, fmt.Errorf("%w: active exact session certificate is required", ErrValidation)
	}
	next, err := HeartbeatFleetGatewaySession(v, sessionID, epoch, at)
	if err != nil {
		return FleetGatewaySession{}, err
	}
	s.fleetGatewaySessions[next.SessionID] = next
	return next, nil
}

func (s *MemoryStore) DrainFleetGatewaySession(_ context.Context, clusterID string, expectedEpoch int64, actor string, at time.Time) (FleetGatewaySession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, err := fleetGatewaySessionCurrent(s.fleetGatewaySessions, strings.TrimSpace(clusterID))
	if err != nil {
		return FleetGatewaySession{}, err
	}
	if current == nil {
		return FleetGatewaySession{}, ErrNotFound
	}
	if current.Epoch != expectedEpoch {
		return FleetGatewaySession{}, ErrConflict
	}
	next, err := DrainFleetGatewaySession(*current, at)
	if err != nil {
		return FleetGatewaySession{}, err
	}
	s.fleetGatewaySessions[next.SessionID] = next
	cluster := s.managedClusters[next.ClusterID]
	s.appendAuditLocked(actor, "fleet_gateway_session.drain_requested", "fleetGatewaySession", next.SessionID, next.Epoch, map[string]any{"projectId": cluster.ProjectID, "clusterId": next.ClusterID, "epoch": next.Epoch})
	s.appendOutboxLocked("fleetGatewaySession", next.SessionID, "fleet_gateway_session.drain_requested", next)
	return next, nil
}

func (s *MemoryStore) CloseFleetGatewaySession(_ context.Context, clusterID, sessionID string, epoch int64, certificateID string, at time.Time) (FleetGatewaySession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.fleetGatewaySessions[strings.TrimSpace(sessionID)]
	if !ok || v.ClusterID != strings.TrimSpace(clusterID) || v.CertificateID != strings.TrimSpace(certificateID) || v.Epoch != epoch {
		return FleetGatewaySession{}, ErrNotFound
	}
	next, err := CloseFleetGatewaySession(v, at)
	if err != nil {
		return FleetGatewaySession{}, err
	}
	s.fleetGatewaySessions[next.SessionID] = next
	cluster := s.managedClusters[next.ClusterID]
	s.appendAuditLocked("cluster-agent-gateway", "fleet_gateway_session.closed", "fleetGatewaySession", next.SessionID, next.Epoch, map[string]any{"projectId": cluster.ProjectID, "clusterId": next.ClusterID, "epoch": next.Epoch})
	s.appendOutboxLocked("fleetGatewaySession", next.SessionID, "fleet_gateway_session.closed", next)
	return next, nil
}

func sortFleetGatewaySessions(out []FleetGatewaySession) {
	sort.Slice(out, func(i, j int) bool {
		if out[i].ClusterID != out[j].ClusterID { return out[i].ClusterID < out[j].ClusterID }
		if out[i].Epoch != out[j].Epoch { return out[i].Epoch < out[j].Epoch }
		return out[i].SessionID < out[j].SessionID
	})
}
