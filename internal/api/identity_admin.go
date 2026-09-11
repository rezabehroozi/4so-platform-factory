package api

import (
	"net/http"
	"strings"

	"platform.4so.io/factory/internal/controlplane"
)

type samlBrokerRequest struct {
	OrganizationID          string `json:"organizationId"`
	Alias                   string `json:"alias"`
	DisplayName             string `json:"displayName"`
	EntityID                string `json:"entityId"`
	SingleSignOnServiceURL  string `json:"singleSignOnServiceUrl"`
	SingleLogoutServiceURL  string `json:"singleLogoutServiceUrl,omitempty"`
	SigningCertificate      string `json:"signingCertificate"`
	NameIDPolicyFormat      string `json:"nameIdPolicyFormat,omitempty"`
	WantAuthnRequestsSigned bool   `json:"wantAuthnRequestsSigned,omitempty"`
	Enabled                 bool   `json:"enabled"`
	IdempotencyKey          string `json:"idempotencyKey"`
}

func (in samlBrokerRequest) broker() controlplane.SAMLBroker {
	return controlplane.SAMLBroker{
		OrganizationID:          strings.TrimSpace(in.OrganizationID),
		Alias:                   strings.TrimSpace(in.Alias),
		DisplayName:             strings.TrimSpace(in.DisplayName),
		EntityID:                strings.TrimSpace(in.EntityID),
		SingleSignOnServiceURL:  strings.TrimSpace(in.SingleSignOnServiceURL),
		SingleLogoutServiceURL:  strings.TrimSpace(in.SingleLogoutServiceURL),
		SigningCertificate:      strings.TrimSpace(in.SigningCertificate),
		NameIDPolicyFormat:      strings.TrimSpace(in.NameIDPolicyFormat),
		WantAuthnRequestsSigned: in.WantAuthnRequestsSigned,
		Enabled:                 in.Enabled,
	}
}

func (s *Server) createSAMLBroker(w http.ResponseWriter, r *http.Request) {
	var in samlBrokerRequest
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	if err := s.requireOrganizationAccess(r, in.OrganizationID, organizationAdminAccess); err != nil {
		writeScopeError(w, err)
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	requestDigest := complianceRequestDigest(map[string]any{"action": "upsert-saml", "expectedRevision": int64(0), "broker": in.broker()})
	broker, job, replay, err := s.store.RequestSAMLBrokerUpsert(r.Context(), in.broker(), 0, strings.TrimSpace(in.IdempotencyKey), requestDigest, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, broker.Revision)
	status := http.StatusAccepted
	if replay {
		status = http.StatusOK
	}
	writeJSON(w, status, map[string]any{"broker": broker, "job": job, "idempotentReplay": replay})
}

func (s *Server) updateSAMLBroker(w http.ResponseWriter, r *http.Request) {
	current, err := s.store.GetSAMLBroker(r.Context(), strings.TrimSpace(r.PathValue("id")))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if err = s.requireOrganizationAccess(r, current.OrganizationID, organizationAdminAccess); err != nil {
		writeScopeError(w, err)
		return
	}
	expected, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, http.StatusPreconditionRequired, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	var in samlBrokerRequest
	if err = decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	if strings.TrimSpace(in.OrganizationID) != "" && strings.TrimSpace(in.OrganizationID) != current.OrganizationID {
		writeError(w, http.StatusConflict, "ORGANIZATION_IMMUTABLE", "organizationId cannot be changed")
		return
	}
	in.OrganizationID = current.OrganizationID
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	brokerInput := in.broker()
	brokerInput.ID = current.ID
	requestDigest := complianceRequestDigest(map[string]any{"action": "upsert-saml", "expectedRevision": expected, "broker": brokerInput})
	broker, job, replay, err := s.store.RequestSAMLBrokerUpsert(r.Context(), brokerInput, expected, strings.TrimSpace(in.IdempotencyKey), requestDigest, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, broker.Revision)
	status := http.StatusAccepted
	if replay {
		status = http.StatusOK
	}
	writeJSON(w, status, map[string]any{"broker": broker, "job": job, "idempotentReplay": replay})
}

func (s *Server) deleteSAMLBroker(w http.ResponseWriter, r *http.Request) {
	current, err := s.store.GetSAMLBroker(r.Context(), strings.TrimSpace(r.PathValue("id")))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if err = s.requireOrganizationAccess(r, current.OrganizationID, organizationAdminAccess); err != nil {
		writeScopeError(w, err)
		return
	}
	expected, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, http.StatusPreconditionRequired, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	var in struct {
		IdempotencyKey string `json:"idempotencyKey"`
	}
	if err = decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	requestDigest := complianceRequestDigest(map[string]any{"action": "delete-saml", "brokerId": current.ID, "expectedRevision": expected, "desiredDigest": current.DesiredDigest})
	broker, job, replay, err := s.store.RequestSAMLBrokerDelete(r.Context(), current.ID, expected, strings.TrimSpace(in.IdempotencyKey), requestDigest, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, broker.Revision)
	status := http.StatusAccepted
	if replay {
		status = http.StatusOK
	}
	writeJSON(w, status, map[string]any{"broker": broker, "job": job, "idempotentReplay": replay})
}

func (s *Server) listSAMLBrokers(w http.ResponseWriter, r *http.Request) {
	organizationID := strings.TrimSpace(r.URL.Query().Get("organizationId"))
	if organizationID == "" {
		writeError(w, http.StatusBadRequest, "ORGANIZATION_ID_REQUIRED", "organizationId is required")
		return
	}
	if err := s.requireOrganizationAccess(r, organizationID, organizationAdminAccess); err != nil {
		writeScopeError(w, err)
		return
	}
	items, err := s.store.ListSAMLBrokers(r.Context(), organizationID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) listIdentityAdminJobs(w http.ResponseWriter, r *http.Request) {
	organizationID := strings.TrimSpace(r.URL.Query().Get("organizationId"))
	if organizationID == "" {
		writeError(w, http.StatusBadRequest, "ORGANIZATION_ID_REQUIRED", "organizationId is required")
		return
	}
	if err := s.requireOrganizationAccess(r, organizationID, organizationAdminAccess); err != nil {
		writeScopeError(w, err)
		return
	}
	items, err := s.store.ListIdentityAdminJobs(r.Context(), organizationID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) getIdentityAdminJob(w http.ResponseWriter, r *http.Request) {
	job, err := s.store.GetIdentityAdminJob(r.Context(), strings.TrimSpace(r.PathValue("id")))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if err = s.requireOrganizationAccess(r, job.OrganizationID, organizationAdminAccess); err != nil {
		writeScopeError(w, err)
		return
	}
	setRevisionETag(w, job.Revision)
	writeJSON(w, http.StatusOK, job)
}

func (s *Server) approveIdentityAdminJob(w http.ResponseWriter, r *http.Request) {
	job, err := s.store.GetIdentityAdminJob(r.Context(), strings.TrimSpace(r.PathValue("id")))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if err = s.requireOrganizationAccess(r, job.OrganizationID, organizationAdminAccess); err != nil {
		writeScopeError(w, err)
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	if strings.TrimSpace(job.RequestedBy) == actor {
		writeApprovalError(w, errSeparationOfDuties)
		return
	}
	expected, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, http.StatusPreconditionRequired, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	job, err = s.store.ApproveIdentityAdminJob(r.Context(), job.ID, expected, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, job.Revision)
	writeJSON(w, http.StatusOK, job)
}
