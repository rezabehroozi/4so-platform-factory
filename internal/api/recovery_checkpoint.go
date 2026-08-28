package api

import (
	"net/http"
	"platform.4so.io/factory/internal/controlplane"
	"strings"
	"time"
)

type createRecoveryCheckpointInput struct {
	ProjectID      string    `json:"projectId"`
	ClusterID      string    `json:"clusterId"`
	Provider       string    `json:"provider"`
	Reference      string    `json:"reference"`
	EvidenceDigest string    `json:"evidenceDigest"`
	CompletedAt    time.Time `json:"completedAt"`
	ExpiresAt      time.Time `json:"expiresAt"`
}

func (s *Server) createRecoveryCheckpoint(w http.ResponseWriter, r *http.Request) {
	actor, err := actorID(r)
	if err != nil {
		writeError(w, 401, "ACTOR_REQUIRED", err.Error())
		return
	}
	var in createRecoveryCheckpointInput
	if err = decodeJSON(w, r, &in); err != nil {
		writeError(w, 400, "INVALID_JSON", err.Error())
		return
	}
	if _, err = s.requireProjectAccess(r, in.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	cluster, err := s.store.GetManagedCluster(r.Context(), strings.TrimSpace(in.ClusterID))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if cluster.ProjectID != in.ProjectID {
		writeError(w, 422, "CLUSTER_PROJECT_MISMATCH", "cluster does not belong to project")
		return
	}
	v, err := s.store.CreateRecoveryCheckpoint(r.Context(), controlplane.RecoveryCheckpoint{ProjectID: in.ProjectID, ClusterID: in.ClusterID, Provider: in.Provider, Reference: in.Reference, EvidenceDigest: in.EvidenceDigest, CompletedAt: in.CompletedAt, ExpiresAt: in.ExpiresAt}, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, 201, v)
}

func (s *Server) listRecoveryCheckpoints(w http.ResponseWriter, r *http.Request) {
	projectID := strings.TrimSpace(r.URL.Query().Get("projectId"))
	clusterID := strings.TrimSpace(r.URL.Query().Get("clusterId"))
	if projectID != "" {
		if _, err := s.requireProjectAccess(r, projectID, organizationRead); err != nil {
			writeScopeError(w, err)
			return
		}
	}
	v, err := s.store.ListRecoveryCheckpoints(r.Context(), projectID, clusterID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	allowed, all, err := s.accessibleProjectSet(r)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	v = filterProjectScoped(v, allowed, all, func(item controlplane.RecoveryCheckpoint) string { return item.ProjectID })
	writeJSON(w, 200, v)
}

func (s *Server) getRecoveryCheckpoint(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.GetRecoveryCheckpoint(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, v.ProjectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, 200, v)
}

func (s *Server) revokeRecoveryCheckpoint(w http.ResponseWriter, r *http.Request) {
	current, err := s.store.GetRecoveryCheckpoint(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, current.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, 401, "ACTOR_REQUIRED", err.Error())
		return
	}
	rev, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, 428, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	v, err := s.store.RevokeRecoveryCheckpoint(r.Context(), current.ID, rev, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, 200, v)
}
