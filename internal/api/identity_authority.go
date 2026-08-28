package api

import (
	"net/http"
	"strconv"
	"strings"

	"platform.4so.io/factory/internal/controlplane"
)

func (s *Server) identityAuthority(w http.ResponseWriter, r *http.Request) {
	if err := requirePlatformAdmin(r); err != nil {
		writeApprovalError(w, err)
		return
	}
	mappings, err := s.store.ListOIDCGroupMappings(r.Context(), "")
	if err != nil {
		writeStoreError(w, err)
		return
	}
	active := 0
	for _, v := range mappings {
		if v.State == controlplane.OIDCGroupMappingActive {
			active++
		}
	}
	ttl := s.oidcGroupPropagationTTL
	if ttl <= 0 {
		ttl = 5 * 60 * 1000000000
	}
	writeJSON(w, http.StatusOK, map[string]any{"groupMappingMethod": controlplane.OIDCGroupMappingMethod, "securityAuditMethod": controlplane.SecurityAuditMethod, "groupPropagationSeconds": int64(ttl.Seconds()), "activeMappings": active, "totalMappings": len(mappings), "realmRolesAuthoritative": false, "securityAuditFailClosed": true})
}
func (s *Server) createOIDCGroupMapping(w http.ResponseWriter, r *http.Request) {
	if err := requirePlatformAdmin(r); err != nil {
		writeApprovalError(w, err)
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	var in controlplane.OIDCGroupMapping
	if err = decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	out, err := s.store.CreateOIDCGroupMapping(r.Context(), in, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, out.Revision)
	writeJSON(w, http.StatusCreated, out)
}
func (s *Server) listOIDCGroupMappings(w http.ResponseWriter, r *http.Request) {
	if err := requirePlatformAdmin(r); err != nil {
		writeApprovalError(w, err)
		return
	}
	state := controlplane.OIDCGroupMappingState(strings.TrimSpace(r.URL.Query().Get("state")))
	if state != "" && state != controlplane.OIDCGroupMappingActive && state != controlplane.OIDCGroupMappingRevoked {
		writeError(w, http.StatusBadRequest, "INVALID_STATE", "state must be ACTIVE or REVOKED")
		return
	}
	out, err := s.store.ListOIDCGroupMappings(r.Context(), state)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
func (s *Server) revokeOIDCGroupMapping(w http.ResponseWriter, r *http.Request) {
	if err := requirePlatformAdmin(r); err != nil {
		writeApprovalError(w, err)
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	rev, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, http.StatusPreconditionRequired, "REVISION_REQUIRED", err.Error())
		return
	}
	out, err := s.store.RevokeOIDCGroupMapping(r.Context(), r.PathValue("id"), rev, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, out.Revision)
	writeJSON(w, http.StatusOK, out)
}
func (s *Server) listSecurityAudit(w http.ResponseWriter, r *http.Request) {
	if err := requirePlatformAdmin(r); err != nil {
		writeApprovalError(w, err)
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	out, err := s.store.ListSecurityAudit(r.Context(), limit)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
