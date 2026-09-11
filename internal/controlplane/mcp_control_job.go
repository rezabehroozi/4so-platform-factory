package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

const MCPDurableControlJobAuthority = "MCP_DURABLE_CONTROL_JOB_AUTHORITY_V1"
const MCPControlJobRecoveryAuthority = "MCP_CONTROL_JOB_RECOVERY_AUTHORITY_V1"

type MCPControlJobRecoveryResolution string

const (
	MCPControlJobRecoveryConfirmedSucceeded MCPControlJobRecoveryResolution = "CONFIRMED_SUCCEEDED"
	MCPControlJobRecoveryConfirmedFailed    MCPControlJobRecoveryResolution = "CONFIRMED_FAILED"
)

type MCPControlJobState string

const (
	MCPControlJobRunning          MCPControlJobState = "RUNNING"
	MCPControlJobSucceeded        MCPControlJobState = "SUCCEEDED"
	MCPControlJobFailed           MCPControlJobState = "FAILED"
	MCPControlJobRecoveryRequired MCPControlJobState = "RECOVERY_REQUIRED"
)

type MCPControlJob struct {
	ResourceMeta
	ToolName               string                          `json:"toolName"`
	Family                 string                          `json:"family"`
	Action                 string                          `json:"action"`
	Method                 string                          `json:"method"`
	Route                  string                          `json:"route"`
	State                  MCPControlJobState              `json:"state"`
	Risk                   string                          `json:"risk"`
	ActorID                string                          `json:"actorId"`
	Authentication         string                          `json:"authentication,omitempty"`
	OAuthClientID          string                          `json:"oauthClientId,omitempty"`
	DelegationProfile      string                          `json:"delegationProfile,omitempty"`
	OrganizationID         string                          `json:"organizationId,omitempty"`
	ProjectID              string                          `json:"projectId,omitempty"`
	RequestID              string                          `json:"requestId,omitempty"`
	IdempotencyKey         string                          `json:"idempotencyKey"`
	RequestDigest          string                          `json:"requestDigest"`
	Attempt                int                             `json:"attempt"`
	LeaseOwner             string                          `json:"leaseOwner"`
	LeaseExpiresAt         time.Time                       `json:"leaseExpiresAt"`
	FenceToken             int64                           `json:"fenceToken"`
	StatusCode             int                             `json:"statusCode,omitempty"`
	ResponseDigest         string                          `json:"responseDigest,omitempty"`
	Response               []byte                          `json:"response,omitempty"`
	ErrorCode              string                          `json:"errorCode,omitempty"`
	RecoveryResolution     MCPControlJobRecoveryResolution `json:"recoveryResolution,omitempty"`
	RecoveryReadbackDigest string                          `json:"recoveryReadbackDigest,omitempty"`
	RecoveryEvidenceDigest string                          `json:"recoveryEvidenceDigest,omitempty"`
	RecoveredBy            string                          `json:"recoveredBy,omitempty"`
	RecoveredAt            *time.Time                      `json:"recoveredAt,omitempty"`
}

type MCPControlJobStore interface {
	CreateMCPControlJob(context.Context, MCPControlJob, time.Duration, time.Time) (MCPControlJob, bool, error)
	CompleteMCPControlJob(context.Context, string, int64, int64, int, []byte, string) (MCPControlJob, error)
	MarkMCPControlJobRecoveryRequired(context.Context, string, int64, string) (MCPControlJob, error)
	ResolveMCPControlJobRecovery(context.Context, string, int64, MCPControlJobRecoveryResolution, string, string, string) (MCPControlJob, error)
	GetMCPControlJob(context.Context, string) (MCPControlJob, error)
	ListMCPControlJobs(context.Context, string, string, int) ([]MCPControlJob, error)
}

func MCPControlRequestDigest(tool string, arguments []byte) string {
	h := sha256.New()
	h.Write([]byte(strings.TrimSpace(tool)))
	h.Write([]byte{0})
	h.Write(arguments)
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

func NormalizeMCPControlJob(v MCPControlJob, lease time.Duration, now time.Time) (MCPControlJob, error) {
	v.ToolName = strings.TrimSpace(v.ToolName)
	v.Family = strings.TrimSpace(v.Family)
	v.Action = strings.TrimSpace(v.Action)
	v.Method = strings.ToUpper(strings.TrimSpace(v.Method))
	v.Route = strings.TrimSpace(v.Route)
	v.Risk = strings.ToLower(strings.TrimSpace(v.Risk))
	v.ActorID = strings.TrimSpace(v.ActorID)
	v.Authentication = strings.TrimSpace(v.Authentication)
	v.OAuthClientID = strings.TrimSpace(v.OAuthClientID)
	v.DelegationProfile = strings.ToUpper(strings.TrimSpace(v.DelegationProfile))
	v.OrganizationID = strings.TrimSpace(v.OrganizationID)
	v.ProjectID = strings.TrimSpace(v.ProjectID)
	v.RequestID = strings.TrimSpace(v.RequestID)
	v.IdempotencyKey = strings.TrimSpace(v.IdempotencyKey)
	v.RequestDigest = strings.TrimSpace(v.RequestDigest)
	v.LeaseOwner = strings.TrimSpace(v.LeaseOwner)
	if v.ToolName == "" || v.Family == "" || v.Action == "" || v.Method == "" || v.Route == "" || v.ActorID == "" || v.IdempotencyKey == "" || v.RequestDigest == "" || v.LeaseOwner == "" {
		return MCPControlJob{}, fmt.Errorf("%w: complete MCP control job identity is required", ErrValidation)
	}
	if len(v.IdempotencyKey) > 200 || len(v.ToolName) > 200 || len(v.Route) > 1000 || len(v.RequestDigest) > 96 {
		return MCPControlJob{}, fmt.Errorf("%w: MCP control job field exceeds bound", ErrValidation)
	}
	if v.Risk != "low" && v.Risk != "medium" && v.Risk != "high" && v.Risk != "critical" {
		return MCPControlJob{}, fmt.Errorf("%w: invalid MCP control risk", ErrValidation)
	}
	if lease <= 0 || lease > 10*time.Minute {
		lease = 2 * time.Minute
	}
	v.State = MCPControlJobRunning
	v.Attempt = 1
	v.FenceToken = 1
	v.LeaseExpiresAt = now.Add(lease)
	return v, nil
}

func mcpControlJobIdempotencyScope(v MCPControlJob) string {
	return strings.Join([]string{v.ActorID, v.OAuthClientID, v.DelegationProfile, v.OrganizationID, v.ProjectID, v.ToolName, v.IdempotencyKey}, "\x00")
}

func (s *MemoryStore) CreateMCPControlJob(_ context.Context, input MCPControlJob, lease time.Duration, now time.Time) (MCPControlJob, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, err := NormalizeMCPControlJob(input, lease, nowUTC(func() time.Time { return now }))
	if err != nil {
		return MCPControlJob{}, false, err
	}
	scope := mcpControlJobIdempotencyScope(v)
	if id, ok := s.mcpControlJobIdempotency[scope]; ok {
		existing := s.mcpControlJobs[id]
		if existing.RequestDigest != v.RequestDigest {
			return MCPControlJob{}, false, ErrIdempotencyConflict
		}
		if existing.State == MCPControlJobRunning && !existing.LeaseExpiresAt.After(now.UTC()) {
			existing.State = MCPControlJobRecoveryRequired
			existing.Revision++
			existing.UpdatedAt = nowUTC(s.now)
			existing.ErrorCode = "MCP_CONTROL_JOB_OUTCOME_INDETERMINATE"
			s.mcpControlJobs[id] = existing
			s.appendAuditLocked(v.ActorID, "mcp.control_job.recovery_required", "mcp-control-job", id, existing.Revision, map[string]any{"authority": MCPDurableControlJobAuthority, "requestDigest": existing.RequestDigest})
		}
		return s.mcpControlJobs[id], true, nil
	}
	stamp := nowUTC(s.now)
	v.ResourceMeta = ResourceMeta{ID: s.id("mcpjob"), Revision: 1, CreatedAt: stamp, UpdatedAt: stamp}
	s.mcpControlJobs[v.ID] = v
	s.mcpControlJobIdempotency[scope] = v.ID
	s.appendAuditLocked(v.ActorID, "mcp.control_job.created", "mcp-control-job", v.ID, v.Revision, map[string]any{"authority": MCPDurableControlJobAuthority, "tool": v.ToolName, "requestDigest": v.RequestDigest, "oauthClientId": v.OAuthClientID, "delegationProfile": v.DelegationProfile})
	return v, false, nil
}

func (s *MemoryStore) CompleteMCPControlJob(_ context.Context, id string, expectedRevision, fence int64, status int, response []byte, actor string) (MCPControlJob, error) {
	if len(response) > 65536 {
		return MCPControlJob{}, fmt.Errorf("%w: MCP control response exceeds 65536 bytes", ErrValidation)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.mcpControlJobs[strings.TrimSpace(id)]
	if !ok {
		return MCPControlJob{}, ErrNotFound
	}
	if v.Revision != expectedRevision || v.FenceToken != fence {
		return MCPControlJob{}, ErrConflict
	}
	if v.State != MCPControlJobRunning {
		return MCPControlJob{}, ErrPrerequisite
	}
	sum := sha256.Sum256(response)
	v.StatusCode = status
	v.Response = append([]byte(nil), response...)
	v.ResponseDigest = "sha256:" + hex.EncodeToString(sum[:])
	if status >= 200 && status < 400 {
		v.State = MCPControlJobSucceeded
	} else {
		v.State = MCPControlJobFailed
	}
	v.LeaseExpiresAt = time.Time{}
	v.Revision++
	v.UpdatedAt = nowUTC(s.now)
	s.mcpControlJobs[v.ID] = v
	s.appendAuditLocked(strings.TrimSpace(actor), "mcp.control_job.completed", "mcp-control-job", v.ID, v.Revision, map[string]any{"authority": MCPDurableControlJobAuthority, "state": v.State, "statusCode": status, "responseDigest": v.ResponseDigest})
	return cloneMCPControlJob(v), nil
}

func (s *MemoryStore) MarkMCPControlJobRecoveryRequired(_ context.Context, id string, expected int64, actor string) (MCPControlJob, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.mcpControlJobs[strings.TrimSpace(id)]
	if !ok {
		return MCPControlJob{}, ErrNotFound
	}
	if v.Revision != expected {
		return MCPControlJob{}, ErrConflict
	}
	if v.State != MCPControlJobRunning {
		return MCPControlJob{}, ErrPrerequisite
	}
	v.State = MCPControlJobRecoveryRequired
	v.ErrorCode = "MCP_CONTROL_JOB_OUTCOME_INDETERMINATE"
	v.LeaseExpiresAt = time.Time{}
	v.Revision++
	v.UpdatedAt = nowUTC(s.now)
	s.mcpControlJobs[v.ID] = v
	s.appendAuditLocked(strings.TrimSpace(actor), "mcp.control_job.recovery_required", "mcp-control-job", v.ID, v.Revision, map[string]any{"authority": MCPDurableControlJobAuthority})
	return cloneMCPControlJob(v), nil
}

func validMCPRecoveryDigest(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func mcpRecoverySummary(v MCPControlJob) []byte {
	raw, _ := json.Marshal(map[string]any{
		"authority":           MCPControlJobRecoveryAuthority,
		"automaticRedispatch": false,
		"evidenceDigest":      v.RecoveryEvidenceDigest,
		"readbackDigest":      v.RecoveryReadbackDigest,
		"recovered":           true,
		"resolution":          v.RecoveryResolution,
	})
	return raw
}

func ApplyMCPControlJobRecoveryResolution(v MCPControlJob, expected int64, resolution MCPControlJobRecoveryResolution, readbackDigest, evidenceDigest, actor string, now time.Time) (MCPControlJob, error) {
	readbackDigest = strings.TrimSpace(readbackDigest)
	evidenceDigest = strings.TrimSpace(evidenceDigest)
	actor = strings.TrimSpace(actor)
	if actor == "" || !validMCPRecoveryDigest(readbackDigest) || !validMCPRecoveryDigest(evidenceDigest) {
		return MCPControlJob{}, fmt.Errorf("%w: recovery requires actor plus sha256 readback/evidence digests", ErrValidation)
	}
	if resolution != MCPControlJobRecoveryConfirmedSucceeded && resolution != MCPControlJobRecoveryConfirmedFailed {
		return MCPControlJob{}, fmt.Errorf("%w: invalid MCP recovery resolution", ErrValidation)
	}
	if v.Revision != expected {
		return MCPControlJob{}, ErrConflict
	}
	if v.State != MCPControlJobRecoveryRequired {
		return MCPControlJob{}, ErrPrerequisite
	}
	now = now.UTC()
	v.RecoveryResolution = resolution
	v.RecoveryReadbackDigest = readbackDigest
	v.RecoveryEvidenceDigest = evidenceDigest
	v.RecoveredBy = actor
	v.RecoveredAt = &now
	v.LeaseExpiresAt = time.Time{}
	if resolution == MCPControlJobRecoveryConfirmedSucceeded {
		v.State = MCPControlJobSucceeded
		v.StatusCode = 200
		v.ErrorCode = ""
	} else {
		v.State = MCPControlJobFailed
		v.StatusCode = 500
		v.ErrorCode = "MCP_CONTROL_JOB_RECOVERY_CONFIRMED_FAILED"
	}
	v.Response = mcpRecoverySummary(v)
	sum := sha256.Sum256(v.Response)
	v.ResponseDigest = "sha256:" + hex.EncodeToString(sum[:])
	v.Revision++
	v.UpdatedAt = now
	return v, nil
}

func (s *MemoryStore) ResolveMCPControlJobRecovery(_ context.Context, id string, expected int64, resolution MCPControlJobRecoveryResolution, readbackDigest, evidenceDigest, actor string) (MCPControlJob, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.mcpControlJobs[strings.TrimSpace(id)]
	if !ok {
		return MCPControlJob{}, ErrNotFound
	}
	resolved, err := ApplyMCPControlJobRecoveryResolution(v, expected, resolution, readbackDigest, evidenceDigest, actor, nowUTC(s.now))
	if err != nil {
		return MCPControlJob{}, err
	}
	s.mcpControlJobs[resolved.ID] = resolved
	s.appendAuditLocked(strings.TrimSpace(actor), "mcp.control_job.recovery_resolved", "mcp-control-job", resolved.ID, resolved.Revision, map[string]any{"authority": MCPControlJobRecoveryAuthority, "resolution": resolution, "readbackDigest": resolved.RecoveryReadbackDigest, "evidenceDigest": resolved.RecoveryEvidenceDigest, "automaticRedispatch": false})
	return cloneMCPControlJob(resolved), nil
}

func cloneMCPControlJob(v MCPControlJob) MCPControlJob {
	v.Response = append([]byte(nil), v.Response...)
	if v.RecoveredAt != nil {
		stamp := *v.RecoveredAt
		v.RecoveredAt = &stamp
	}
	return v
}
func (s *MemoryStore) GetMCPControlJob(_ context.Context, id string) (MCPControlJob, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.mcpControlJobs[strings.TrimSpace(id)]
	if !ok {
		return MCPControlJob{}, ErrNotFound
	}
	return cloneMCPControlJob(v), nil
}
func (s *MemoryStore) ListMCPControlJobs(_ context.Context, organizationID, projectID string, limit int) ([]MCPControlJob, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	out := []MCPControlJob{}
	for _, v := range s.mcpControlJobs {
		if organizationID != "" && v.OrganizationID != organizationID {
			continue
		}
		if projectID != "" && v.ProjectID != projectID {
			continue
		}
		out = append(out, cloneMCPControlJob(v))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
