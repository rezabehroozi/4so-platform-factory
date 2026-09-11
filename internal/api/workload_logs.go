package api

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"platform.4so.io/factory/internal/controlplane"
)

const (
	workloadLogOperationKind = "target.logs.query"
	workloadLogTargetPrefix  = "workload-log:"
	workloadLogLease         = 90 * time.Second
	workloadLogEvidenceKind  = "target-workload-logs"
)

type workloadLogRequest struct {
	ProjectID    string `json:"projectId"`
	ClusterID    string `json:"clusterId"`
	Namespace    string `json:"namespace"`
	WorkloadKind string `json:"workloadKind"`
	WorkloadName string `json:"workloadName"`
	Container    string `json:"container,omitempty"`
	Mode         string `json:"mode"`
	SinceSeconds int    `json:"sinceSeconds"`
	Limit        int    `json:"limit"`
}

type workloadLogLine struct {
	Timestamp time.Time `json:"timestamp"`
	Pod       string    `json:"pod"`
	Container string    `json:"container,omitempty"`
	Line      string    `json:"line"`
}

type workloadLogTask struct {
	OperationID       string             `json:"operationId"`
	OperationRevision int64              `json:"operationRevision"`
	TaskFenceToken    int64              `json:"taskFenceToken"`
	LeaseExpiresAt    time.Time          `json:"leaseExpiresAt"`
	InventoryDigest   string             `json:"inventoryDigest"`
	Request           workloadLogRequest `json:"request"`
}

type workloadLogResult struct {
	Success        bool              `json:"success"`
	TaskFenceToken int64             `json:"taskFenceToken"`
	Error          string            `json:"error,omitempty"`
	Lines          []workloadLogLine `json:"lines,omitempty"`
}

type workloadLogOperationPager interface {
	ListClaimableOperationsByKindTargetPrefix(context.Context, string, string, time.Time, int) ([]controlplane.Operation, error)
}

func normalizeWorkloadLogRequest(v workloadLogRequest) workloadLogRequest {
	v.ProjectID = strings.TrimSpace(v.ProjectID)
	v.ClusterID = strings.TrimSpace(v.ClusterID)
	v.Namespace = strings.TrimSpace(v.Namespace)
	v.WorkloadKind = strings.TrimSpace(v.WorkloadKind)
	v.WorkloadName = strings.TrimSpace(v.WorkloadName)
	v.Container = strings.TrimSpace(v.Container)
	v.Mode = strings.ToUpper(strings.TrimSpace(v.Mode))
	if v.Mode == "" {
		v.Mode = "QUERY"
	}
	if v.SinceSeconds == 0 {
		v.SinceSeconds = 900
	}
	if v.Limit == 0 {
		v.Limit = 200
	}
	return v
}

func validateWorkloadLogRequest(v workloadLogRequest) error {
	if v.ProjectID == "" || v.ClusterID == "" || v.Namespace == "" || v.WorkloadKind == "" || v.WorkloadName == "" {
		return fmt.Errorf("%w: projectId, clusterId, namespace, workloadKind and workloadName are required", controlplane.ErrValidation)
	}
	if v.Mode != "QUERY" && v.Mode != "TAIL" {
		return fmt.Errorf("%w: mode must be QUERY or TAIL", controlplane.ErrValidation)
	}
	if v.SinceSeconds < 60 || v.SinceSeconds > 3600 {
		return fmt.Errorf("%w: sinceSeconds must be between 60 and 3600", controlplane.ErrValidation)
	}
	if v.Limit < 1 || v.Limit > 500 {
		return fmt.Errorf("%w: limit must be between 1 and 500", controlplane.ErrValidation)
	}
	if len(v.Namespace) > 253 || len(v.WorkloadName) > 253 || len(v.WorkloadKind) > 32 || len(v.Container) > 253 {
		return fmt.Errorf("%w: workload log target exceeds bounded identifier length", controlplane.ErrValidation)
	}
	return nil
}

func workloadLogTarget(v workloadLogRequest) (string, error) {
	raw, err := json.Marshal(normalizeWorkloadLogRequest(v))
	if err != nil {
		return "", err
	}
	return workloadLogTargetPrefix + v.ClusterID + ":" + base64.RawURLEncoding.EncodeToString(raw), nil
}
func parseWorkloadLogTarget(target string) (workloadLogRequest, error) {
	if !strings.HasPrefix(target, workloadLogTargetPrefix) {
		return workloadLogRequest{}, fmt.Errorf("%w: invalid workload log target", controlplane.ErrValidation)
	}
	rest := strings.TrimPrefix(target, workloadLogTargetPrefix)
	idx := strings.IndexByte(rest, ':')
	if idx <= 0 {
		return workloadLogRequest{}, fmt.Errorf("%w: invalid workload log target", controlplane.ErrValidation)
	}
	raw, err := base64.RawURLEncoding.DecodeString(rest[idx+1:])
	if err != nil {
		return workloadLogRequest{}, fmt.Errorf("%w: invalid workload log target encoding", controlplane.ErrValidation)
	}
	var v workloadLogRequest
	if err = json.Unmarshal(raw, &v); err != nil {
		return workloadLogRequest{}, fmt.Errorf("%w: invalid workload log target payload", controlplane.ErrValidation)
	}
	v = normalizeWorkloadLogRequest(v)
	if v.ClusterID != rest[:idx] {
		return workloadLogRequest{}, fmt.Errorf("%w: workload log target cluster mismatch", controlplane.ErrValidation)
	}
	return v, validateWorkloadLogRequest(v)
}
func workloadLogRequestDigest(v workloadLogRequest) string {
	raw, _ := json.Marshal(normalizeWorkloadLogRequest(v))
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func hasString(values []string, wanted string) bool {
	for _, v := range values {
		if v == wanted {
			return true
		}
	}
	return false
}

func (s *Server) createWorkloadLogQuery(w http.ResponseWriter, r *http.Request) {
	var input workloadLogRequest
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	input = normalizeWorkloadLogRequest(input)
	if err := validateWorkloadLogRequest(input); err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err := s.requireProjectAccess(r, input.ProjectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	cluster, err := s.store.GetManagedCluster(r.Context(), input.ClusterID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if cluster.ProjectID != input.ProjectID {
		writeError(w, http.StatusForbidden, "SCOPE_FORBIDDEN", "cluster is outside requested project")
		return
	}
	inventory, err := s.store.GetLatestClusterInventory(r.Context(), cluster.ID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if !controlplane.ClusterInventoryAuthorityFreshAt(cluster, time.Now().UTC()) {
		writeError(w, http.StatusConflict, "INVENTORY_STALE", "fresh cluster inventory is required before querying target workload logs")
		return
	}
	if !inventory.WorkloadExplorer.Complete || inventory.WorkloadExplorer.Truncated {
		writeError(w, http.StatusConflict, "WORKLOAD_AUTHORITY_INCOMPLETE", "complete non-truncated workload inventory is required")
		return
	}
	if !hasString(inventory.Capabilities, "workload-explorer-read") || !hasString(inventory.Capabilities, "cert.logs") {
		writeError(w, http.StatusUnprocessableEntity, "LOG_CAPABILITY_UNAVAILABLE", "connected Agent must report workload-explorer-read and cert.logs capabilities")
		return
	}
	found := false
	for _, item := range inventory.WorkloadExplorer.Workloads {
		if strings.EqualFold(item.Kind, input.WorkloadKind) && item.Namespace == input.Namespace && item.Name == input.WorkloadName {
			found = true
			input.WorkloadKind = item.Kind
			break
		}
	}
	if !found {
		writeError(w, http.StatusNotFound, "WORKLOAD_NOT_FOUND", "workload is not present in current authoritative inventory")
		return
	}
	key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if key == "" {
		writeError(w, http.StatusBadRequest, "IDEMPOTENCY_KEY_REQUIRED", "Idempotency-Key is required")
		return
	}
	target, err := workloadLogTarget(input)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "ACTOR_REQUIRED", err.Error())
		return
	}
	op, replay, err := s.store.CreateOperation(r.Context(), controlplane.OperationRequest{ProjectID: input.ProjectID, Kind: workloadLogOperationKind, TargetRef: target, DesiredRevision: inventory.Digest, Risk: "low", Class: controlplane.OperationClassReadOnly}, key, actor, r.Header.Get("X-Request-ID"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if !replay && op.State == controlplane.OperationDraft {
		op, err = s.store.TransitionOperation(r.Context(), op.ID, op.Revision, controlplane.OperationPlanning, "", actor)
		if err == nil {
			op, err = s.store.TransitionOperation(r.Context(), op.ID, op.Revision, controlplane.OperationQueued, "", actor)
		}
		if err != nil {
			writeStoreError(w, err)
			return
		}
	}
	status := http.StatusAccepted
	if replay {
		status = http.StatusOK
	}
	writeJSON(w, status, map[string]any{"operation": op, "replay": replay, "requestDigest": workloadLogRequestDigest(input)})
}

func (s *Server) getWorkloadLogQuery(w http.ResponseWriter, r *http.Request) {
	op, err := s.store.GetOperation(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if op.Kind != workloadLogOperationKind {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "workload log query not found")
		return
	}
	if _, err = s.requireProjectAccess(r, op.ProjectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	evidence, err := s.store.ListEvidence(r.Context(), op.ID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	out := map[string]any{"operation": op, "ready": false}
	for _, item := range evidence {
		if item.Kind == workloadLogEvidenceKind && item.HasPayload {
			out["evidence"] = item
			out["ready"] = true
			_, payload, getErr := s.store.GetEvidencePayload(r.Context(), item.ID)
			if getErr == nil {
				var lines []workloadLogLine
				if json.Unmarshal(payload, &lines) == nil {
					out["lines"] = lines
				}
			}
			break
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) nextWorkloadLogTask(w http.ResponseWriter, r *http.Request) {
	clusterID := strings.TrimSpace(r.PathValue("id"))
	if _, err := s.agentCredentialDigest(r, clusterID); err != nil {
		writeError(w, http.StatusUnauthorized, "AGENT_TOKEN_REQUIRED", err.Error())
		return
	}
	pager, ok := s.store.(workloadLogOperationPager)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "WORKLOAD_LOG_QUEUE_UNAVAILABLE", "bounded workload log operation queue is unavailable")
		return
	}
	jobs, err := pager.ListClaimableOperationsByKindTargetPrefix(r.Context(), workloadLogOperationKind, workloadLogTargetPrefix+clusterID+":", time.Now().UTC(), 8)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if len(jobs) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	for _, candidate := range jobs {
		claim, claimErr := s.store.ClaimOperation(r.Context(), candidate.ID, "agent:"+clusterID, workloadLogLease, time.Now().UTC())
		if errors.Is(claimErr, controlplane.ErrLeaseHeld) || errors.Is(claimErr, controlplane.ErrNotClaimable) {
			continue
		}
		if claimErr != nil {
			writeStoreError(w, claimErr)
			return
		}
		op, err := s.store.GetOperation(r.Context(), candidate.ID)
		if err != nil {
			writeStoreError(w, err)
			return
		}
		input, parseErr := parseWorkloadLogTarget(op.TargetRef)
		if parseErr != nil {
			writeStoreError(w, parseErr)
			return
		}
		cluster, err := s.store.GetManagedCluster(r.Context(), clusterID)
		if err != nil {
			writeStoreError(w, err)
			return
		}
		if cluster.InventoryDigest != op.DesiredRevision {
			op, err = s.store.StartOperationAttempt(r.Context(), op.ID, op.Revision, "agent:"+clusterID, claim.FenceToken, "agent:"+clusterID)
			if err == nil {
				_, err = s.store.ReportOperationFailure(r.Context(), op.ID, op.Revision, "agent:"+clusterID, claim.FenceToken, controlplane.OperationFailureReport{Class: controlplane.OperationFailurePermanent, Code: "INVENTORY_CHANGED", Message: "cluster inventory changed after workload log query admission"}, "agent:"+clusterID)
			}
			if err != nil {
				writeStoreError(w, err)
				return
			}
			continue
		}
		op, err = s.store.StartOperationAttempt(r.Context(), op.ID, op.Revision, "agent:"+clusterID, claim.FenceToken, "agent:"+clusterID)
		if err != nil {
			writeStoreError(w, err)
			return
		}
		setRevisionETag(w, op.Revision)
		writeJSON(w, http.StatusOK, workloadLogTask{OperationID: op.ID, OperationRevision: op.Revision, TaskFenceToken: claim.FenceToken, LeaseExpiresAt: claim.LeaseExpiresAt, InventoryDigest: op.DesiredRevision, Request: input})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) reportWorkloadLogTask(w http.ResponseWriter, r *http.Request) {
	clusterID := strings.TrimSpace(r.PathValue("id"))
	if _, err := s.agentCredentialDigest(r, clusterID); err != nil {
		writeError(w, http.StatusUnauthorized, "AGENT_TOKEN_REQUIRED", err.Error())
		return
	}
	rev, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, http.StatusPreconditionRequired, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	var result workloadLogResult
	if err = decodeJSON(w, r, &result); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	if result.TaskFenceToken <= 0 {
		writeError(w, http.StatusUnprocessableEntity, "FENCE_REQUIRED", "taskFenceToken is required")
		return
	}
	op, err := s.store.GetOperation(r.Context(), r.PathValue("operationId"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if op.Kind != workloadLogOperationKind || op.Revision != rev {
		if op.Revision != rev {
			writeStoreError(w, controlplane.ErrConflict)
		} else {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "workload log query not found")
		}
		return
	}
	input, err := parseWorkloadLogTarget(op.TargetRef)
	if err != nil || input.ClusterID != clusterID {
		writeError(w, http.StatusForbidden, "AGENT_SCOPE_MISMATCH", "workload log task belongs to another cluster")
		return
	}
	worker := "agent:" + clusterID
	if !result.Success {
		message := strings.TrimSpace(result.Error)
		if message == "" {
			message = "target log query failed"
		}
		updated, reportErr := s.store.ReportOperationFailure(r.Context(), op.ID, op.Revision, worker, result.TaskFenceToken, controlplane.OperationFailureReport{Class: controlplane.OperationFailureDependencyUnavailable, Code: "TARGET_LOG_QUERY_FAILED", Message: message}, worker)
		if reportErr != nil {
			writeStoreError(w, reportErr)
			return
		}
		writeJSON(w, http.StatusOK, updated)
		return
	}
	if len(result.Lines) > input.Limit {
		writeError(w, http.StatusUnprocessableEntity, "LOG_RESULT_LIMIT_EXCEEDED", "agent returned more log lines than admitted")
		return
	}
	sort.SliceStable(result.Lines, func(i, j int) bool { return result.Lines[i].Timestamp.Before(result.Lines[j].Timestamp) })
	total := 0
	for i := range result.Lines {
		result.Lines[i].Pod = strings.TrimSpace(result.Lines[i].Pod)
		result.Lines[i].Container = strings.TrimSpace(result.Lines[i].Container)
		if result.Lines[i].Timestamp.IsZero() || result.Lines[i].Pod == "" || len(result.Lines[i].Line) > 16*1024 {
			writeError(w, http.StatusUnprocessableEntity, "LOG_RESULT_INVALID", "each log line requires timestamp/pod and max 16KiB line text")
			return
		}
		total += len(result.Lines[i].Line)
		if total > 4*1024*1024 {
			writeError(w, http.StatusUnprocessableEntity, "LOG_RESULT_TOO_LARGE", "log result exceeds 4MiB")
			return
		}
	}
	payload, _ := json.Marshal(result.Lines)
	sum := sha256.Sum256(payload)
	meta := controlplane.EvidenceMetadata{OperationID: op.ID, Kind: workloadLogEvidenceKind, Digest: "sha256:" + hex.EncodeToString(sum[:]), MediaType: "application/json", Size: int64(len(payload))}
	if _, err = s.store.AppendOperationEvidencePayload(r.Context(), meta, payload, worker, result.TaskFenceToken, worker); err != nil {
		writeStoreError(w, err)
		return
	}
	op, err = s.store.GetOperation(r.Context(), op.ID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	op, err = s.store.BeginOperationVerification(r.Context(), op.ID, op.Revision, worker, result.TaskFenceToken, worker)
	if err == nil {
		op, err = s.store.CompleteOperation(r.Context(), op.ID, op.Revision, worker, result.TaskFenceToken, worker)
	}
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"operation": op, "lineCount": len(result.Lines), "evidenceDigest": meta.Digest})
}
