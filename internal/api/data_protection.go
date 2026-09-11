package api

import (
	"errors"
	"net/http"
	"platform.4so.io/factory/internal/controlplane"
	"strings"
)

type backupPolicyInput struct {
	ProjectID             string   `json:"projectId"`
	ClusterID             string   `json:"clusterId"`
	Name                  string   `json:"name"`
	Provider              string   `json:"provider"`
	BackupStorageLocation string   `json:"backupStorageLocation"`
	CredentialRef         string   `json:"credentialRef"`
	Schedule              string   `json:"schedule"`
	Retention             string   `json:"retention"`
	IncludedNamespaces    []string `json:"includedNamespaces"`
}

type dataProtectionRunInput struct {
	ProjectID      string `json:"projectId"`
	ClusterID      string `json:"clusterId"`
	PolicyID       string `json:"policyId"`
	BackupRunID    string `json:"backupRunId,omitempty"`
	IdempotencyKey string `json:"idempotencyKey"`
}

func backupPolicyFromInput(in backupPolicyInput) controlplane.BackupPolicy {
	return controlplane.BackupPolicy{ProjectID: in.ProjectID, ClusterID: in.ClusterID, Name: in.Name, Provider: in.Provider, BackupStorageLocation: in.BackupStorageLocation, CredentialRef: in.CredentialRef, Schedule: in.Schedule, Retention: in.Retention, IncludedNamespaces: in.IncludedNamespaces}
}

func (s *Server) createBackupPolicy(w http.ResponseWriter, r *http.Request) {
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	var in backupPolicyInput
	if err = decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", err.Error())
		return
	}
	if _, err = s.requireProjectAccess(r, strings.TrimSpace(in.ProjectID), organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	v, err := s.store.UpsertBackupPolicy(r.Context(), backupPolicyFromInput(in), 0, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusCreated, v)
}

func (s *Server) updateBackupPolicy(w http.ResponseWriter, r *http.Request) {
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	current, err := s.store.GetBackupPolicy(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, current.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	expected, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, http.StatusPreconditionRequired, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	var in backupPolicyInput
	if err = decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", err.Error())
		return
	}
	if strings.TrimSpace(in.ProjectID) != current.ProjectID || strings.TrimSpace(in.ClusterID) != current.ClusterID {
		writeError(w, http.StatusUnprocessableEntity, "BACKUP_POLICY_SCOPE_IMMUTABLE", "projectId and clusterId cannot change")
		return
	}
	v := backupPolicyFromInput(in)
	v.ID = current.ID
	v, err = s.store.UpsertBackupPolicy(r.Context(), v, expected, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) listBackupPolicies(w http.ResponseWriter, r *http.Request) {
	projectID := strings.TrimSpace(r.URL.Query().Get("projectId"))
	clusterID := strings.TrimSpace(r.URL.Query().Get("clusterId"))
	if projectID == "" {
		writeError(w, http.StatusBadRequest, "PROJECT_REQUIRED", "projectId is required")
		return
	}
	if _, err := s.requireProjectAccess(r, projectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	v, err := s.store.ListBackupPolicies(r.Context(), projectID, clusterID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeOperatorCollectionJSON(w, r, http.StatusOK, v)
}

func (s *Server) getBackupPolicy(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.GetBackupPolicy(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, v.ProjectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) setBackupPolicyState(w http.ResponseWriter, r *http.Request, state controlplane.BackupPolicyState) {
	current, err := s.store.GetBackupPolicy(r.Context(), r.PathValue("id"))
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
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	expected, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, http.StatusPreconditionRequired, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	v, err := s.store.SetBackupPolicyState(r.Context(), current.ID, expected, state, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) enableBackupPolicy(w http.ResponseWriter, r *http.Request) {
	s.setBackupPolicyState(w, r, controlplane.BackupPolicyActive)
}

func (s *Server) disableBackupPolicy(w http.ResponseWriter, r *http.Request) {
	s.setBackupPolicyState(w, r, controlplane.BackupPolicyDisabled)
}

func (s *Server) createDataProtectionRun(w http.ResponseWriter, r *http.Request, kind controlplane.DataProtectionRunKind) {
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	var in dataProtectionRunInput
	if err = decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", err.Error())
		return
	}
	in.ProjectID, in.ClusterID, in.PolicyID, in.BackupRunID, in.IdempotencyKey = strings.TrimSpace(in.ProjectID), strings.TrimSpace(in.ClusterID), strings.TrimSpace(in.PolicyID), strings.TrimSpace(in.BackupRunID), strings.TrimSpace(in.IdempotencyKey)
	if _, err = s.requireProjectAccess(r, in.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	requestDigest := digestValue(map[string]any{"authority": "TARGET_DATA_PROTECTION_V1", "kind": kind, "projectId": in.ProjectID, "clusterId": in.ClusterID, "policyId": in.PolicyID, "backupRunId": in.BackupRunID, "idempotencyKey": in.IdempotencyKey})
	v, replay, err := s.store.CreateDataProtectionRun(r.Context(), controlplane.DataProtectionRun{Kind: kind, ProjectID: in.ProjectID, ClusterID: in.ClusterID, PolicyID: in.PolicyID, BackupRunID: in.BackupRunID, IdempotencyKey: in.IdempotencyKey, RequestDigest: requestDigest}, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	status := http.StatusAccepted
	if replay {
		status = http.StatusOK
	}
	writeJSON(w, status, v)
}

func (s *Server) createBackupRun(w http.ResponseWriter, r *http.Request) {
	s.createDataProtectionRun(w, r, controlplane.DataProtectionBackup)
}
func (s *Server) createRestoreRun(w http.ResponseWriter, r *http.Request) {
	s.createDataProtectionRun(w, r, controlplane.DataProtectionRestore)
}
func (s *Server) createRestoreDrill(w http.ResponseWriter, r *http.Request) {
	s.createDataProtectionRun(w, r, controlplane.DataProtectionRestoreDrill)
}

func (s *Server) listDataProtectionRuns(w http.ResponseWriter, r *http.Request) {
	projectID := strings.TrimSpace(r.URL.Query().Get("projectId"))
	clusterID := strings.TrimSpace(r.URL.Query().Get("clusterId"))
	kind := controlplane.DataProtectionRunKind(strings.TrimSpace(r.URL.Query().Get("kind")))
	if projectID == "" {
		writeError(w, http.StatusBadRequest, "PROJECT_REQUIRED", "projectId is required")
		return
	}
	if _, err := s.requireProjectAccess(r, projectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	if kind != "" && kind != controlplane.DataProtectionBackup && kind != controlplane.DataProtectionRestore && kind != controlplane.DataProtectionRestoreDrill {
		writeError(w, http.StatusBadRequest, "INVALID_KIND", "kind must be BACKUP, RESTORE, or RESTORE_DRILL")
		return
	}
	v, err := s.store.ListDataProtectionRuns(r.Context(), projectID, clusterID, kind)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeOperatorCollectionJSON(w, r, http.StatusOK, v)
}

func (s *Server) getDataProtectionRun(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.GetDataProtectionRun(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, v.ProjectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) approveRestoreRun(w http.ResponseWriter, r *http.Request) {
	current, err := s.store.GetDataProtectionRun(r.Context(), r.PathValue("id"))
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
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	expected, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, http.StatusPreconditionRequired, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	v, err := s.store.ApproveDataProtectionRun(r.Context(), current.ID, expected, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) nextDataProtectionTask(w http.ResponseWriter, r *http.Request) {
	clusterID := r.PathValue("id")
	agentDigest, err := s.agentCredentialDigest(r, clusterID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "AGENT_TOKEN_REQUIRED", err.Error())
		return
	}
	run, policy, err := s.store.NextDataProtectionTask(r.Context(), clusterID, agentDigest)
	if errors.Is(err, controlplane.ErrNotFound) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if run.State == controlplane.DataProtectionFailed || run.TaskLeaseExpiresAt == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	task := controlplane.DataProtectionTask{RunID: run.ID, RunRevision: run.Revision, Kind: run.Kind, TaskFenceToken: run.TaskFenceToken, LeaseExpiresAt: *run.TaskLeaseExpiresAt, ProjectID: run.ProjectID, ClusterID: run.ClusterID, PolicyID: run.PolicyID, BackupRunID: run.BackupRunID, InventoryDigest: run.InventoryDigest, PolicyDigest: run.PolicyDigest, Provider: policy.Provider, BackupStorageLocation: policy.BackupStorageLocation, CredentialRef: policy.CredentialRef, Retention: policy.Retention, IncludedNamespaces: append([]string(nil), policy.IncludedNamespaces...), VeleroName: run.VeleroName, SourceBackupName: run.SourceBackupName, TargetNamespace: run.TargetNamespace}
	setRevisionETag(w, run.Revision)
	writeJSON(w, http.StatusOK, task)
}

func (s *Server) reportDataProtectionTask(w http.ResponseWriter, r *http.Request) {
	clusterID := r.PathValue("id")
	agentDigest, err := s.agentCredentialDigest(r, clusterID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "AGENT_TOKEN_REQUIRED", err.Error())
		return
	}
	expected, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, http.StatusPreconditionRequired, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	var result controlplane.DataProtectionTaskResult
	if err = decodeJSON(w, r, &result); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	result.RunID = r.PathValue("runId")
	v, err := s.store.ReportDataProtectionTask(r.Context(), clusterID, agentDigest, expected, result)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusOK, v)
}
