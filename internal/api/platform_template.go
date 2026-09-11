package api

import (
	"net/http"
	"strings"

	"platform.4so.io/factory/internal/controlplane"
)

type platformPolicySetInput struct {
	ProjectID   string                                 `json:"projectId"`
	Name        string                                 `json:"name"`
	Version     string                                 `json:"version"`
	Maintenance controlplane.PlatformMaintenancePolicy `json:"maintenance"`
	Backup      controlplane.PlatformBackupPolicy      `json:"backup"`
	Security    controlplane.PlatformSecurityPolicy    `json:"security"`
}

type platformTemplateInput struct {
	ProjectID                 string   `json:"projectId"`
	Name                      string   `json:"name"`
	Version                   string   `json:"version"`
	BlueprintReleaseID        string   `json:"blueprintReleaseId"`
	VariableSchemaID          string   `json:"variableSchemaId"`
	PolicySetID               string   `json:"policySetId"`
	AllowedTargetClasses      []string `json:"allowedTargetClasses"`
	CertificationRequirements []string `json:"certificationRequirements"`
}

func (s *Server) createPlatformPolicySet(w http.ResponseWriter, r *http.Request) {
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	var input platformPolicySetInput
	if err = decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	input.ProjectID = strings.TrimSpace(input.ProjectID)
	if _, err = s.requireProjectAccess(r, input.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	created, err := s.store.CreatePlatformPolicySet(r.Context(), controlplane.PlatformPolicySet{ProjectID: input.ProjectID, Name: input.Name, Version: input.Version, Maintenance: input.Maintenance, Backup: input.Backup, Security: input.Security}, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) getPlatformPolicySet(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.GetPlatformPolicySet(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, v.ProjectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) listPlatformPolicySets(w http.ResponseWriter, r *http.Request) {
	projectID := strings.TrimSpace(r.URL.Query().Get("projectId"))
	if projectID != "" {
		if _, err := s.requireProjectAccess(r, projectID, organizationRead); err != nil {
			writeScopeError(w, err)
			return
		}
	}
	items, err := s.store.ListPlatformPolicySets(r.Context(), projectID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	allowed, all, err := s.accessibleProjectSet(r)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	items = filterProjectScoped(items, allowed, all, func(v controlplane.PlatformPolicySet) string { return v.ProjectID })
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) createPlatformTemplate(w http.ResponseWriter, r *http.Request) {
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	var input platformTemplateInput
	if err = decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	input.ProjectID = strings.TrimSpace(input.ProjectID)
	if _, err = s.requireProjectAccess(r, input.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	created, err := s.store.CreatePlatformTemplate(r.Context(), controlplane.PlatformTemplate{ProjectID: input.ProjectID, Name: input.Name, Version: input.Version, BlueprintReleaseID: input.BlueprintReleaseID, VariableSchemaID: input.VariableSchemaID, PolicySetID: input.PolicySetID, AllowedTargetClasses: input.AllowedTargetClasses, CertificationRequirements: input.CertificationRequirements}, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) getPlatformTemplate(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.GetPlatformTemplate(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, v.ProjectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) listPlatformTemplates(w http.ResponseWriter, r *http.Request) {
	projectID := strings.TrimSpace(r.URL.Query().Get("projectId"))
	if projectID != "" {
		if _, err := s.requireProjectAccess(r, projectID, organizationRead); err != nil {
			writeScopeError(w, err)
			return
		}
	}
	var page func([]string, bool, *controlplane.CollectionCursor, int) ([]controlplane.PlatformTemplate, error)
	if pager, ok := s.store.(platformTemplatePageStore); ok {
		page = func(ids []string, all bool, cursor *controlplane.CollectionCursor, limit int) ([]controlplane.PlatformTemplate, error) {
			return pager.ListPlatformTemplatesPage(r.Context(), ids, all, cursor, limit)
		}
	}
	v, err := boundedProjectCollection(s, w, r, projectID, func() ([]controlplane.PlatformTemplate, error) {
		return s.store.ListPlatformTemplates(r.Context(), projectID)
	}, page, func(item controlplane.PlatformTemplate) string { return item.ProjectID })
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeOperatorCollectionJSON(w, r, http.StatusOK, v)
}

func (s *Server) getPlatformTemplateAdmission(w http.ResponseWriter, r *http.Request) {
	template, err := s.store.GetPlatformTemplate(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, template.ProjectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	blueprint, err := s.store.GetBlueprintRelease(r.Context(), template.BlueprintReleaseID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	schema, err := s.store.GetVariableSchema(r.Context(), template.VariableSchemaID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	policy, err := s.store.GetPlatformPolicySet(r.Context(), template.PolicySetID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	out := controlplane.EvaluatePlatformTemplateAdmission(template, blueprint, schema, policy, r.URL.Query().Get("targetClass"))
	writeJSON(w, http.StatusOK, out)
}
