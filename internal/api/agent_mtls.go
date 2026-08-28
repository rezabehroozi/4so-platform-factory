package api

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"platform.4so.io/factory/internal/agentpki"
	"platform.4so.io/factory/internal/controlplane"
)

type agentCSRInput struct {
	CSRPEM string `json:"csrPem"`
}

func digestEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func (s *Server) legacyAgentDigest(r *http.Request, clusterID string) (string, error) {
	token, err := agentBearer(r)
	if err != nil {
		return "", err
	}
	cluster, err := s.store.GetManagedCluster(r.Context(), clusterID)
	if err != nil {
		return "", err
	}
	imp, err := s.store.GetClusterImport(r.Context(), cluster.ImportID)
	if err != nil {
		return "", err
	}
	got := credentialDigest(token)
	if imp.State != controlplane.ClusterImportClaimed || imp.AgentTokenDigest == "" || !digestEqual(imp.AgentTokenDigest, got) {
		return "", fmt.Errorf("agent credential is invalid")
	}
	return imp.AgentTokenDigest, nil
}

func (s *Server) mtlsAgentCertificate(r *http.Request, clusterID string) (controlplane.AgentCertificate, error) {
	if s.agentPKI == nil {
		return controlplane.AgentCertificate{}, fmt.Errorf("agent mTLS is not configured")
	}
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return controlplane.AgentCertificate{}, fmt.Errorf("agent client certificate is required")
	}
	cert := r.TLS.PeerCertificates[0]
	if err := s.agentPKI.VerifyClientCertificate(cert, r.TLS.PeerCertificates[1:], time.Now()); err != nil {
		return controlplane.AgentCertificate{}, fmt.Errorf("agent client certificate verification failed: %w", err)
	}
	certCluster, err := agentpki.ClusterIDFromCertificate(cert)
	if err != nil {
		return controlplane.AgentCertificate{}, err
	}
	if certCluster != clusterID {
		return controlplane.AgentCertificate{}, fmt.Errorf("agent certificate belongs to a different cluster")
	}
	serial := strings.ToLower(cert.SerialNumber.Text(16))
	stored, err := s.store.GetAgentCertificateBySerial(r.Context(), serial)
	if err != nil {
		return controlplane.AgentCertificate{}, fmt.Errorf("agent certificate is not registered")
	}
	if stored.ClusterID != clusterID || stored.State != controlplane.AgentCertificateActive || stored.NotAfter.Before(time.Now().UTC()) || stored.NotBefore.After(time.Now().UTC()) {
		return controlplane.AgentCertificate{}, fmt.Errorf("agent certificate is inactive or expired")
	}
	return stored, nil
}

func (s *Server) agentCredentialDigest(r *http.Request, clusterID string) (string, error) {
	if _, err := s.mtlsAgentCertificate(r, clusterID); err == nil {
		cluster, e := s.store.GetManagedCluster(r.Context(), clusterID)
		if e != nil {
			return "", e
		}
		imp, e := s.store.GetClusterImport(r.Context(), cluster.ImportID)
		if e != nil {
			return "", e
		}
		if imp.AgentTokenDigest == "" {
			return "", fmt.Errorf("cluster agent authority is revoked")
		}
		return imp.AgentTokenDigest, nil
	}
	if s.agentMTLSRequired {
		return "", fmt.Errorf("mTLS client certificate is required")
	}
	return s.legacyAgentDigest(r, clusterID)
}

func (s *Server) issueAgentCertificate(w http.ResponseWriter, r *http.Request) {
	if s.agentPKI == nil {
		writeError(w, http.StatusServiceUnavailable, "AGENT_MTLS_UNAVAILABLE", "agent certificate authority is not configured")
		return
	}
	clusterID := r.PathValue("id")
	if _, err := s.legacyAgentDigest(r, clusterID); err != nil {
		writeError(w, http.StatusUnauthorized, "AGENT_BOOTSTRAP_AUTH_REQUIRED", err.Error())
		return
	}
	existing, err := s.store.ListAgentCertificates(r.Context(), clusterID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if len(existing) != 0 {
		writeError(w, http.StatusConflict, "AGENT_REENROLLMENT_REQUIRED", "bootstrap bearer can issue only the first agent certificate; rotate with mTLS or explicitly re-enroll the cluster")
		return
	}
	var in agentCSRInput
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, 400, "INVALID_REQUEST", err.Error())
		return
	}
	issued, err := s.agentPKI.SignCSR([]byte(in.CSRPEM), clusterID, agentpki.DefaultLifetime)
	if err != nil {
		writeError(w, 422, "CSR_INVALID", err.Error())
		return
	}
	meta, err := s.store.CreateAgentCertificate(r.Context(), controlplane.AgentCertificate{ClusterID: clusterID, SerialNumber: issued.SerialNumber, Fingerprint: issued.Fingerprint, Subject: issued.Subject, NotBefore: issued.NotBefore, NotAfter: issued.NotAfter}, "cluster-agent-bootstrap")
	if err != nil {
		writeStoreError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, map[string]any{"certificate": meta, "certificatePem": issued.CertificatePEM, "caCertificatePem": issued.CACertificatePEM, "rotationRecommendedAt": issued.NotAfter.Add(-7 * 24 * time.Hour)})
}

func (s *Server) currentAgentCertificate(w http.ResponseWriter, r *http.Request) {
	current, err := s.mtlsAgentCertificate(r, r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusUnauthorized, "AGENT_MTLS_REQUIRED", err.Error())
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, current)
}

func (s *Server) rotateAgentCertificate(w http.ResponseWriter, r *http.Request) {
	if s.agentPKI == nil {
		writeError(w, http.StatusServiceUnavailable, "AGENT_MTLS_UNAVAILABLE", "agent certificate authority is not configured")
		return
	}
	clusterID := r.PathValue("id")
	current, err := s.mtlsAgentCertificate(r, clusterID)
	if err != nil {
		writeError(w, 401, "AGENT_MTLS_REQUIRED", err.Error())
		return
	}
	var in agentCSRInput
	if err = decodeJSON(w, r, &in); err != nil {
		writeError(w, 400, "INVALID_REQUEST", err.Error())
		return
	}
	issued, err := s.agentPKI.SignCSR([]byte(in.CSRPEM), clusterID, agentpki.DefaultLifetime)
	if err != nil {
		writeError(w, 422, "CSR_INVALID", err.Error())
		return
	}
	_, next, err := s.store.RotateAgentCertificate(r.Context(), current.ID, controlplane.AgentCertificate{ClusterID: clusterID, SerialNumber: issued.SerialNumber, Fingerprint: issued.Fingerprint, Subject: issued.Subject, NotBefore: issued.NotBefore, NotAfter: issued.NotAfter}, "cluster-agent")
	if err != nil {
		writeStoreError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"certificate": next, "certificatePem": issued.CertificatePEM, "caCertificatePem": issued.CACertificatePEM, "rotationRecommendedAt": issued.NotAfter.Add(-7 * 24 * time.Hour)})
}

func (s *Server) listAgentCertificates(w http.ResponseWriter, r *http.Request) {
	cluster, err := s.store.GetManagedCluster(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, cluster.ProjectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	rows, err := s.store.ListAgentCertificates(r.Context(), cluster.ID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, rows)
}
func (s *Server) revokeAgentCertificate(w http.ResponseWriter, r *http.Request) {
	if err := requirePlatformAdmin(r); err != nil {
		writeError(w, 403, "PLATFORM_ADMIN_REQUIRED", "agent certificate revocation requires platform-admin")
		return
	}
	if strings.TrimSpace(r.Header.Get("X-Confirm-Revoke")) != "revoke-agent-certificate" {
		writeError(w, 428, "REVOKE_CONFIRMATION_REQUIRED", "X-Confirm-Revoke: revoke-agent-certificate is required")
		return
	}
	cluster, err := s.store.GetManagedCluster(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	cert, err := s.store.GetAgentCertificate(r.Context(), r.PathValue("certId"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if cert.ClusterID != cluster.ID {
		writeError(w, 404, "NOT_FOUND", "certificate does not belong to cluster")
		return
	}
	rev, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, 428, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, 401, "ACTOR_REQUIRED", err.Error())
		return
	}
	cert, err = s.store.RevokeAgentCertificate(r.Context(), cert.ID, rev, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, cert.Revision)
	writeJSON(w, 200, cert)
}

var _ = json.Valid
