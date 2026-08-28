package api

import (
	"net/http"
	"strings"
	"time"

	"platform.4so.io/factory/internal/apitoken"
	"platform.4so.io/factory/internal/controlplane"
)

type createServiceAccountInput struct {
	OrganizationID string `json:"organizationId"`
	ProjectID      string `json:"projectId,omitempty"`
	Name           string `json:"name"`
	DisplayName    string `json:"displayName"`
	ProductRole    string `json:"productRole"`
}

type issueAPITokenInput struct {
	ExpiresAt   time.Time `json:"expiresAt"`
	Permissions []string  `json:"permissions,omitempty"`
}

type rotateAPITokenInput struct {
	ExpiresAt   time.Time `json:"expiresAt,omitempty"`
	Permissions []string  `json:"permissions,omitempty"`
}

type apiTokenSecretResponse struct {
	Token controlplane.APIToken `json:"token"`
	Value string                `json:"value"`
}

func redactedToken(v controlplane.APIToken) controlplane.APIToken {
	v.TokenDigest = ""
	v.IdempotencyKey = ""
	v.Permissions = append([]string(nil), v.Permissions...)
	return v
}

func (s *Server) createServiceAccount(w http.ResponseWriter, r *http.Request) {
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	var in createServiceAccountInput
	if err = decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	if err = s.requireOrganizationAccess(r, in.OrganizationID, organizationAdminAccess); err != nil {
		writeScopeError(w, err)
		return
	}
	if strings.TrimSpace(in.ProjectID) != "" {
		project, e := s.store.GetProject(r.Context(), strings.TrimSpace(in.ProjectID))
		if e != nil {
			writeStoreError(w, e)
			return
		}
		if project.OrganizationID != strings.TrimSpace(in.OrganizationID) {
			writeError(w, http.StatusUnprocessableEntity, "PROJECT_SCOPE_MISMATCH", "project must belong to the selected organization")
			return
		}
	}
	v, err := s.store.CreateServiceAccount(r.Context(), controlplane.ServiceAccount{OrganizationID: in.OrganizationID, ProjectID: in.ProjectID, Name: in.Name, DisplayName: in.DisplayName, ProductRole: in.ProductRole}, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusCreated, v)
}

func (s *Server) listServiceAccounts(w http.ResponseWriter, r *http.Request) {
	organizationID := strings.TrimSpace(r.URL.Query().Get("organizationId"))
	if organizationID != "" {
		if err := s.requireOrganizationAccess(r, organizationID, organizationAdminAccess); err != nil {
			writeScopeError(w, err)
			return
		}
	}
	values, err := s.store.ListServiceAccounts(r.Context(), organizationID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	allowed, all, err := s.accessibleOrganizationSet(r)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if !all {
		filtered := make([]controlplane.ServiceAccount, 0, len(values))
		for _, v := range values {
			level, e := s.organizationAccess(r, v.OrganizationID)
			if e == nil && level >= organizationAdminAccess && allowed[v.OrganizationID] {
				filtered = append(filtered, v)
			}
		}
		values = filtered
	}
	writeJSON(w, http.StatusOK, values)
}
func (s *Server) getServiceAccount(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.GetServiceAccount(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if err = s.requireOrganizationAccess(r, v.OrganizationID, organizationAdminAccess); err != nil {
		writeScopeError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusOK, v)
}
func (s *Server) revokeServiceAccount(w http.ResponseWriter, r *http.Request) {
	if strings.TrimSpace(r.Header.Get("X-Confirm-Revoke")) != "revoke-service-account" {
		writeError(w, http.StatusBadRequest, "REVOCATION_CONFIRMATION_REQUIRED", "X-Confirm-Revoke must be revoke-service-account")
		return
	}
	current, err := s.store.GetServiceAccount(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if err = s.requireOrganizationAccess(r, current.OrganizationID, organizationAdminAccess); err != nil {
		writeScopeError(w, err)
		return
	}
	rev, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, http.StatusPreconditionRequired, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	v, err := s.store.RevokeServiceAccount(r.Context(), current.ID, rev, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) issueAPIToken(w http.ResponseWriter, r *http.Request) {
	account, err := s.store.GetServiceAccount(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if err = s.requireOrganizationAccess(r, account.OrganizationID, organizationAdminAccess); err != nil {
		writeScopeError(w, err)
		return
	}
	var in issueAPITokenInput
	if err = decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	idempotencyKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if idempotencyKey == "" || len(idempotencyKey) > 200 {
		writeError(w, http.StatusBadRequest, "IDEMPOTENCY_KEY_REQUIRED", "Idempotency-Key is required and must be at most 200 characters")
		return
	}
	if committed, lookupErr := s.store.GetAPITokenByIdempotencyKey(r.Context(), account.ID, idempotencyKey); lookupErr == nil {
		writeError(w, http.StatusConflict, "TOKEN_ISSUANCE_ALREADY_COMMITTED", "this idempotent token action already committed; raw secret cannot be replayed; revoke the committed token and use a new Idempotency-Key if the secret was lost")
		_ = committed
		return
	} else if lookupErr != controlplane.ErrNotFound {
		writeStoreError(w, lookupErr)
		return
	}
	randomID, err := randomCredential(12)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "TOKEN_GENERATION_FAILED", "could not generate API token")
		return
	}
	tokenID := "tok_" + randomID
	raw, prefix, digest, err := apitoken.Generate(tokenID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "TOKEN_GENERATION_FAILED", "could not generate API token")
		return
	}
	created, err := s.store.CreateAPIToken(r.Context(), controlplane.APIToken{ResourceMeta: controlplane.ResourceMeta{ID: tokenID}, ServiceAccountID: account.ID, TokenPrefix: prefix, TokenDigest: digest, Permissions: in.Permissions, ExpiresAt: in.ExpiresAt, IdempotencyKey: idempotencyKey}, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	setRevisionETag(w, created.Revision)
	writeJSON(w, http.StatusCreated, apiTokenSecretResponse{Token: redactedToken(created), Value: raw})
}
func (s *Server) listAPITokens(w http.ResponseWriter, r *http.Request) {
	account, err := s.store.GetServiceAccount(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if err = s.requireOrganizationAccess(r, account.OrganizationID, organizationAdminAccess); err != nil {
		writeScopeError(w, err)
		return
	}
	values, err := s.store.ListAPITokens(r.Context(), account.ID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	out := make([]controlplane.APIToken, 0, len(values))
	for _, v := range values {
		out = append(out, redactedToken(v))
	}
	writeJSON(w, http.StatusOK, out)
}
func (s *Server) revokeAPIToken(w http.ResponseWriter, r *http.Request) {
	if strings.TrimSpace(r.Header.Get("X-Confirm-Revoke")) != "revoke-api-token" {
		writeError(w, http.StatusBadRequest, "REVOCATION_CONFIRMATION_REQUIRED", "X-Confirm-Revoke must be revoke-api-token")
		return
	}
	account, err := s.store.GetServiceAccount(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if err = s.requireOrganizationAccess(r, account.OrganizationID, organizationAdminAccess); err != nil {
		writeScopeError(w, err)
		return
	}
	token, err := s.store.GetAPIToken(r.Context(), r.PathValue("tokenId"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if token.ServiceAccountID != account.ID {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "API token not found")
		return
	}
	rev, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, http.StatusPreconditionRequired, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	v, err := s.store.RevokeAPIToken(r.Context(), token.ID, rev, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	v = redactedToken(v)
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusOK, v)
}
func (s *Server) rotateAPIToken(w http.ResponseWriter, r *http.Request) {
	if strings.TrimSpace(r.Header.Get("X-Confirm-Rotate")) != "rotate-api-token" {
		writeError(w, http.StatusBadRequest, "ROTATION_CONFIRMATION_REQUIRED", "X-Confirm-Rotate must be rotate-api-token")
		return
	}
	account, err := s.store.GetServiceAccount(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if err = s.requireOrganizationAccess(r, account.OrganizationID, organizationAdminAccess); err != nil {
		writeScopeError(w, err)
		return
	}
	old, err := s.store.GetAPIToken(r.Context(), r.PathValue("tokenId"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if old.ServiceAccountID != account.ID {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "API token not found")
		return
	}
	rev, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, http.StatusPreconditionRequired, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	var in rotateAPITokenInput
	if err = decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	idempotencyKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if idempotencyKey == "" || len(idempotencyKey) > 200 {
		writeError(w, http.StatusBadRequest, "IDEMPOTENCY_KEY_REQUIRED", "Idempotency-Key is required and must be at most 200 characters")
		return
	}
	if committed, lookupErr := s.store.GetAPITokenByIdempotencyKey(r.Context(), account.ID, idempotencyKey); lookupErr == nil {
		code := "TOKEN_ROTATION_ALREADY_COMMITTED"
		if committed.RotatedFromID != old.ID {
			code = "IDEMPOTENCY_KEY_REUSED"
		}
		writeError(w, http.StatusConflict, code, "this idempotent token action already committed; raw secret cannot be replayed; revoke the committed token and use a new Idempotency-Key if the secret was lost")
		return
	} else if lookupErr != controlplane.ErrNotFound {
		writeStoreError(w, lookupErr)
		return
	}
	randomID, err := randomCredential(12)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "TOKEN_GENERATION_FAILED", "could not generate API token")
		return
	}
	tokenID := "tok_" + randomID
	raw, prefix, digest, err := apitoken.Generate(tokenID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "TOKEN_GENERATION_FAILED", "could not generate API token")
		return
	}
	_, next, err := s.store.RotateAPIToken(r.Context(), old.ID, rev, controlplane.APIToken{ResourceMeta: controlplane.ResourceMeta{ID: tokenID}, TokenPrefix: prefix, TokenDigest: digest, Permissions: in.Permissions, ExpiresAt: in.ExpiresAt, IdempotencyKey: idempotencyKey}, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	setRevisionETag(w, next.Revision)
	writeJSON(w, http.StatusCreated, apiTokenSecretResponse{Token: redactedToken(next), Value: raw})
}
