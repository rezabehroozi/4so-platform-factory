package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"platform.4so.io/factory/internal/controlplane"
)

type maintenanceProfileInput struct {
	Environment                controlplane.ClusterEnvironment `json:"environment"`
	DefaultDrainTimeoutSeconds int                             `json:"defaultDrainTimeoutSeconds"`
}
type maintenanceWindowInput struct {
	Name                string    `json:"name"`
	StartsAt            time.Time `json:"startsAt"`
	EndsAt              time.Time `json:"endsAt"`
	MaxUnavailable      int       `json:"maxUnavailable"`
	DrainTimeoutSeconds int       `json:"drainTimeoutSeconds"`
}
type maintenanceRunInput struct {
	WindowID  string                                 `json:"windowId"`
	Action    controlplane.TargetNodeLifecycleAction `json:"action,omitempty"`
	NodeNames []string                               `json:"nodeNames"`
}

func optionalExpectedRevision(r *http.Request) (int64, error) {
	raw := strings.Trim(strings.TrimSpace(r.Header.Get("If-Match")), "\"")
	if raw == "" {
		return 0, nil
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || v <= 0 {
		return 0, errors.New("If-Match must contain a positive resource revision")
	}
	return v, nil
}

func (s *Server) upsertClusterMaintenanceProfile(w http.ResponseWriter, r *http.Request) {
	cluster, err := s.store.GetManagedCluster(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, cluster.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, 401, "ACTOR_REQUIRED", err.Error())
		return
	}
	expected, err := optionalExpectedRevision(r)
	if err != nil {
		writeError(w, 428, "EXPECTED_REVISION_INVALID", err.Error())
		return
	}
	var in maintenanceProfileInput
	if err = decodeJSON(w, r, &in); err != nil {
		writeError(w, 400, "INVALID_REQUEST", err.Error())
		return
	}
	v, err := s.store.UpsertClusterMaintenanceProfile(r.Context(), controlplane.ClusterMaintenanceProfile{ProjectID: cluster.ProjectID, ClusterID: cluster.ID, Environment: in.Environment, DefaultDrainTimeoutSeconds: in.DefaultDrainTimeoutSeconds}, expected, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, 200, map[string]any{"profile": v, "method": controlplane.ClusterMaintenanceAuthorityMethod})
}
func (s *Server) getClusterMaintenanceProfile(w http.ResponseWriter, r *http.Request) {
	cluster, err := s.store.GetManagedCluster(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, cluster.ProjectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	v, err := s.store.GetClusterMaintenanceProfile(r.Context(), cluster.ID)
	if err != nil {
		if errors.Is(err, controlplane.ErrNotFound) {
			writeJSON(w, 200, map[string]any{"profile": nil, "profileStatus": "NOT_CONFIGURED", "method": controlplane.ClusterMaintenanceAuthorityMethod})
			return
		}
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, 200, map[string]any{"profile": v, "profileStatus": "CONFIGURED", "method": controlplane.ClusterMaintenanceAuthorityMethod})
}
func (s *Server) createClusterMaintenanceWindow(w http.ResponseWriter, r *http.Request) {
	cluster, err := s.store.GetManagedCluster(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, cluster.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, 401, "ACTOR_REQUIRED", err.Error())
		return
	}
	var in maintenanceWindowInput
	if err = decodeJSON(w, r, &in); err != nil {
		writeError(w, 400, "INVALID_REQUEST", err.Error())
		return
	}
	profile, err := s.store.GetClusterMaintenanceProfile(r.Context(), cluster.ID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if in.DrainTimeoutSeconds == 0 {
		in.DrainTimeoutSeconds = profile.DefaultDrainTimeoutSeconds
	}
	v, err := s.store.CreateClusterMaintenanceWindow(r.Context(), controlplane.ClusterMaintenanceWindow{ProjectID: cluster.ProjectID, ClusterID: cluster.ID, Name: in.Name, StartsAt: in.StartsAt, EndsAt: in.EndsAt, MaxUnavailable: in.MaxUnavailable, DrainTimeoutSeconds: in.DrainTimeoutSeconds}, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, 201, v)
}
func (s *Server) listClusterMaintenanceWindows(w http.ResponseWriter, r *http.Request) {
	cluster, err := s.store.GetManagedCluster(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, cluster.ProjectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	v, err := s.store.ListClusterMaintenanceWindows(r.Context(), cluster.ID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"method": controlplane.ClusterMaintenanceAuthorityMethod, "windows": v})
}
func (s *Server) cancelClusterMaintenanceWindow(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.GetClusterMaintenanceWindow(r.Context(), r.PathValue("windowId"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, v.ProjectID, organizationWrite); err != nil {
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
	v, err = s.store.CancelClusterMaintenanceWindow(r.Context(), v.ID, rev, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, 200, v)
}

func (s *Server) createClusterMaintenanceRun(w http.ResponseWriter, r *http.Request) {
	cluster, err := s.store.GetManagedCluster(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, cluster.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, 401, "ACTOR_REQUIRED", err.Error())
		return
	}
	key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if key == "" || len(key) > 200 {
		writeError(w, 400, "IDEMPOTENCY_KEY_REQUIRED", "Idempotency-Key is required")
		return
	}
	var in maintenanceRunInput
	if err = decodeJSON(w, r, &in); err != nil {
		writeError(w, 400, "INVALID_REQUEST", err.Error())
		return
	}
	if strings.TrimSpace(in.WindowID) == "" || len(in.NodeNames) == 0 {
		writeError(w, 422, "VALIDATION_FAILED", "windowId and nodeNames are required")
		return
	}
	requestDigest := digestValue(in)
	opRequest := controlplane.OperationRequest{ProjectID: cluster.ProjectID, Kind: "CLUSTER_MAINTENANCE", TargetRef: "cluster/" + cluster.ID, DesiredRevision: requestDigest, Risk: "high", Class: controlplane.OperationClassMutating}
	v, op, replay, err := s.store.CreateClusterMaintenanceRunRequest(r.Context(), controlplane.ClusterMaintenanceRun{ProjectID: cluster.ProjectID, ClusterID: cluster.ID, WindowID: strings.TrimSpace(in.WindowID), Action: in.Action, NodeNames: in.NodeNames, IdempotencyKey: key, RequestDigest: requestDigest}, opRequest, "cluster-maintenance-operation:"+key, actor, r.Header.Get("X-Request-ID"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	status := 201
	if replay {
		status = 200
		w.Header().Set("Idempotent-Replay", "true")
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, status, map[string]any{"run": v, "operation": op, "method": controlplane.ClusterMaintenanceAuthorityMethod})
}
func (s *Server) getClusterMaintenanceRun(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.GetClusterMaintenanceRun(r.Context(), r.PathValue("runId"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, v.ProjectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	op, err := s.store.GetOperation(r.Context(), v.OperationID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, 200, map[string]any{"run": v, "operation": op, "method": controlplane.ClusterMaintenanceAuthorityMethod})
}
func (s *Server) listClusterMaintenanceRuns(w http.ResponseWriter, r *http.Request) {
	cluster, err := s.store.GetManagedCluster(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, cluster.ProjectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	v, err := s.store.ListClusterMaintenanceRuns(r.Context(), cluster.ID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"method": controlplane.ClusterMaintenanceAuthorityMethod, "runs": v})
}
func (s *Server) approveClusterMaintenanceRun(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.GetClusterMaintenanceRun(r.Context(), r.PathValue("runId"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, v.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	actor, err := approvalActor(r, v.RequestedBy)
	if err != nil {
		writeApprovalError(w, err)
		return
	}
	rev, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, 428, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	v, err = s.store.ApproveClusterMaintenanceRun(r.Context(), v.ID, rev, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	op, err := s.store.GetOperation(r.Context(), v.OperationID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, 200, map[string]any{"run": v, "operation": op})
}
func (s *Server) nextClusterMaintenanceTask(w http.ResponseWriter, r *http.Request) {
	agentDigest, err := s.agentCredentialDigest(r, r.PathValue("id"))
	if err != nil {
		writeError(w, 401, "AGENT_TOKEN_REQUIRED", err.Error())
		return
	}
	v, op, err := s.store.NextClusterMaintenanceTask(r.Context(), r.PathValue("id"), agentDigest)
	if err != nil {
		if errors.Is(err, controlplane.ErrNotFound) {
			w.WriteHeader(204)
			return
		}
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	if op.LeaseExpiresAt == nil {
		writeError(w, http.StatusConflict, "MAINTENANCE_LEASE_MISSING", "claimed maintenance operation has no execution lease")
		return
	}
	writeJSON(w, 200, controlplane.ClusterMaintenanceTask{RunID: v.ID, RunRevision: v.Revision, OperationID: op.ID, OperationRevision: op.Revision, OperationFenceToken: op.FenceToken, LeaseExpiresAt: *op.LeaseExpiresAt, ClusterID: v.ClusterID, Action: v.Action, NodeNames: v.NodeNames, NodeUIDs: v.NodeUIDs, InventoryDigest: v.InventoryDigest, DrainTimeoutSeconds: v.DrainTimeoutSeconds, HostActionTimeoutSeconds: v.HostActionTimeoutSeconds, Method: controlplane.ClusterMaintenanceAuthorityMethod})
}
func (s *Server) reportClusterMaintenanceTask(w http.ResponseWriter, r *http.Request) {
	if _, err := s.agentCredentialDigest(r, r.PathValue("id")); err != nil {
		writeError(w, 401, "AGENT_TOKEN_REQUIRED", err.Error())
		return
	}
	rev, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, 428, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	var result controlplane.ClusterMaintenanceTaskResult
	if err = decodeJSON(w, r, &result); err != nil {
		writeError(w, 400, "INVALID_REQUEST", err.Error())
		return
	}
	v, op, err := s.store.ReportClusterMaintenanceTask(r.Context(), r.PathValue("id"), r.PathValue("runId"), rev, result)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, 200, map[string]any{"run": v, "operation": op})
}
