package api

import (
	"net/http"

	"platform.4so.io/factory/internal/controlplane"
)

func requireGitAdmin(w http.ResponseWriter, r *http.Request) (string, bool) {
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return "", false
	}
	if err = requirePlatformAdmin(r); err != nil {
		writeError(w, http.StatusForbidden, "PLATFORM_ADMIN_REQUIRED", "Git credential and provider authority requires platform-admin")
		return "", false
	}
	return actor, true
}

func (s *Server) createGitCredential(w http.ResponseWriter, r *http.Request) {
	actor, ok := requireGitAdmin(w, r)
	if !ok {
		return
	}
	var in controlplane.GitCredential
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, 400, "INVALID_REQUEST", err.Error())
		return
	}
	v, err := s.store.CreateGitCredential(r.Context(), in, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusCreated, v)
}
func (s *Server) listGitCredentials(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireGitAdmin(w, r); !ok {
		return
	}
	v, err := s.store.ListGitCredentials(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, v)
}
func (s *Server) rotateGitCredential(w http.ResponseWriter, r *http.Request) {
	actor, ok := requireGitAdmin(w, r)
	if !ok {
		return
	}
	rev, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, 400, "REVISION_REQUIRED", err.Error())
		return
	}
	var in controlplane.GitCredential
	if err = decodeJSON(w, r, &in); err != nil {
		writeError(w, 400, "INVALID_REQUEST", err.Error())
		return
	}
	old, repl, err := s.store.RotateGitCredential(r.Context(), r.PathValue("id"), rev, in, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, repl.Revision)
	writeJSON(w, 200, map[string]any{"revoked": old, "replacement": repl, "providerBindingsRebound": true})
}
func (s *Server) revokeGitCredential(w http.ResponseWriter, r *http.Request) {
	actor, ok := requireGitAdmin(w, r)
	if !ok {
		return
	}
	rev, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, 400, "REVISION_REQUIRED", err.Error())
		return
	}
	v, err := s.store.RevokeGitCredential(r.Context(), r.PathValue("id"), rev, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, 200, v)
}
func (s *Server) createGitProvider(w http.ResponseWriter, r *http.Request) {
	actor, ok := requireGitAdmin(w, r)
	if !ok {
		return
	}
	var in controlplane.GitProvider
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, 400, "INVALID_REQUEST", err.Error())
		return
	}
	v, err := s.store.CreateGitProvider(r.Context(), in, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusCreated, v)
}
func (s *Server) listGitProviders(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireGitAdmin(w, r); !ok {
		return
	}
	v, err := s.store.ListGitProviders(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, v)
}
func (s *Server) rebindGitProviderCredential(w http.ResponseWriter, r *http.Request) {
	actor, ok := requireGitAdmin(w, r)
	if !ok {
		return
	}
	rev, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, 400, "REVISION_REQUIRED", err.Error())
		return
	}
	var in struct {
		CredentialID string `json:"credentialId"`
	}
	if err = decodeJSON(w, r, &in); err != nil {
		writeError(w, 400, "INVALID_REQUEST", err.Error())
		return
	}
	v, err := s.store.UpdateGitProviderCredential(r.Context(), r.PathValue("id"), rev, in.CredentialID, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, 200, v)
}
func (s *Server) gitAuthority(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireGitAdmin(w, r); !ok {
		return
	}
	providers, err := s.store.ListGitProviders(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	credentials, err := s.store.ListGitCredentials(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"method": "GIT_PROVIDER_CREDENTIAL_REFERENCE_V1", "providers": providers, "credentials": credentials, "secretMaterialPersisted": false})
}
