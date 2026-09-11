package api

import (
	"net/http"
	"strings"

	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/externalregistry"
)

type externalRegistryAdmissionInput struct {
	OrganizationID string `json:"organizationId"`
	ProjectID      string `json:"projectId,omitempty"`
	externalregistry.Request
}

func (s *Server) notificationProviderContracts(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, controlplane.NotificationProviderContracts())
}

func (s *Server) notificationRoutePolicyDigest(w http.ResponseWriter, r *http.Request) {
	route, err := s.store.GetNotificationRoute(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if err = s.requireNotificationResourceAccess(r, route.OrganizationID, route.ProjectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	digest, err := controlplane.NotificationPreferenceDigest(route)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"authority": controlplane.NotificationPreferenceDigestAuthority,
		"routeId":   route.ID,
		"revision":  route.Revision,
		"digest":    digest,
		"mutable":   false,
	})
}

func (s *Server) admitExternalRegistry(w http.ResponseWriter, r *http.Request) {
	var in externalRegistryAdmissionInput
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	in.OrganizationID = strings.TrimSpace(in.OrganizationID)
	in.ProjectID = strings.TrimSpace(in.ProjectID)
	if in.ProjectID != "" {
		project, err := s.requireProjectAccess(r, in.ProjectID, organizationRead)
		if err != nil {
			writeScopeError(w, err)
			return
		}
		if in.OrganizationID != "" && project.OrganizationID != in.OrganizationID {
			writeError(w, http.StatusUnprocessableEntity, "PROJECT_SCOPE_MISMATCH", "project must belong to selected organization")
			return
		}
		in.OrganizationID = project.OrganizationID
	} else {
		if in.OrganizationID == "" {
			writeError(w, http.StatusUnprocessableEntity, "ORGANIZATION_REQUIRED", "organizationId or projectId is required")
			return
		}
		if err := s.requireOrganizationAccess(r, in.OrganizationID, organizationRead); err != nil {
			writeScopeError(w, err)
			return
		}
	}
	result, err := externalregistry.Admit(in.Request)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "EXTERNAL_REGISTRY_NOT_ADMITTED", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}
