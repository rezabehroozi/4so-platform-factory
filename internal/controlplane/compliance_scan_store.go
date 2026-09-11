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

	"platform.4so.io/factory/internal/compliance"
)

const ComplianceScanCenterAuthority = "COMPLIANCE_SCAN_CENTER_AUTHORITY_V1"
const ComplianceAgentCapability = "assurance.compliance-scan"

type ComplianceProfileState string

const (
	ComplianceProfileActive   ComplianceProfileState = "ACTIVE"
	ComplianceProfileDisabled ComplianceProfileState = "DISABLED"
)

type ComplianceProfile struct {
	ResourceMeta
	ProjectID         string                 `json:"projectId"`
	Name              string                 `json:"name"`
	BaselineAuthority string                 `json:"baselineAuthority"`
	MinimumSeverity   compliance.Severity    `json:"minimumSeverity"`
	State             ComplianceProfileState `json:"state"`
	DesiredDigest     string                 `json:"desiredDigest"`
	CreatedBy         string                 `json:"createdBy"`
}

type ComplianceScanState string

const (
	ComplianceScanQueued    ComplianceScanState = "QUEUED"
	ComplianceScanRunning   ComplianceScanState = "RUNNING"
	ComplianceScanSucceeded ComplianceScanState = "SUCCEEDED"
	ComplianceScanFailed    ComplianceScanState = "FAILED"
)

type ComplianceScanRun struct {
	ResourceMeta
	ProjectID          string              `json:"projectId"`
	ClusterID          string              `json:"clusterId"`
	ProfileID          string              `json:"profileId"`
	BaselineAuthority  string              `json:"baselineAuthority"`
	InventoryDigest    string              `json:"inventoryDigest"`
	State              ComplianceScanState `json:"state"`
	IdempotencyKey     string              `json:"idempotencyKey"`
	RequestDigest      string              `json:"requestDigest"`
	Findings           int                 `json:"findings"`
	ResultDigest       string              `json:"resultDigest,omitempty"`
	EvidenceDigest     string              `json:"evidenceDigest,omitempty"`
	RequestedBy        string              `json:"requestedBy"`
	TaskAttempt        int                 `json:"taskAttempt"`
	TaskFenceToken     int64               `json:"taskFenceToken"`
	TaskLeaseOwner     string              `json:"taskLeaseOwner,omitempty"`
	TaskLeaseExpiresAt *time.Time          `json:"taskLeaseExpiresAt,omitempty"`
	StartedAt          *time.Time          `json:"startedAt,omitempty"`
	FinishedAt         *time.Time          `json:"finishedAt,omitempty"`
	LastError          string              `json:"lastError,omitempty"`
}

type ComplianceFindingRecord struct {
	ResourceMeta
	RunID          string              `json:"runId"`
	ProjectID      string              `json:"projectId"`
	ClusterID      string              `json:"clusterId"`
	Fingerprint    string              `json:"fingerprint"`
	RuleID         string              `json:"ruleId"`
	Severity       compliance.Severity `json:"severity"`
	Kind           string              `json:"kind"`
	Namespace      string              `json:"namespace,omitempty"`
	Name           string              `json:"name"`
	Summary        string              `json:"summary"`
	EvidenceDigest string              `json:"evidenceDigest"`
}

type ComplianceWaiverState string

const (
	ComplianceWaiverPending ComplianceWaiverState = "PENDING_APPROVAL"
	ComplianceWaiverActive  ComplianceWaiverState = "ACTIVE"
	ComplianceWaiverRevoked ComplianceWaiverState = "REVOKED"
)

type ComplianceWaiver struct {
	ResourceMeta
	ProjectID   string                `json:"projectId"`
	Fingerprint string                `json:"fingerprint"`
	Reason      string                `json:"reason"`
	State       ComplianceWaiverState `json:"state"`
	RequestedBy string                `json:"requestedBy"`
	ApprovedBy  string                `json:"approvedBy,omitempty"`
	ApprovedAt  *time.Time            `json:"approvedAt,omitempty"`
	RevokedBy   string                `json:"revokedBy,omitempty"`
	RevokedAt   *time.Time            `json:"revokedAt,omitempty"`
	ExpiresAt   *time.Time            `json:"expiresAt,omitempty"`
}

type ComplianceScanTask struct {
	RunID             string    `json:"runId"`
	RunRevision       int64     `json:"runRevision"`
	ProjectID         string    `json:"projectId"`
	ClusterID         string    `json:"clusterId"`
	BaselineAuthority string    `json:"baselineAuthority"`
	InventoryDigest   string    `json:"inventoryDigest"`
	Attempt           int       `json:"attempt"`
	FenceToken        int64     `json:"fenceToken"`
	LeaseExpiresAt    time.Time `json:"leaseExpiresAt"`
}

func complianceProfileDigest(v ComplianceProfile) string {
	raw, _ := json.Marshal(struct{ ProjectID, Name, Baseline, Minimum string }{v.ProjectID, normalizeName(v.Name), v.BaselineAuthority, string(v.MinimumSeverity)})
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func ComplianceFindingEvidenceDigest(f compliance.Finding) string {
	raw, _ := json.Marshal(struct{ Authority, RuleID, Severity, Kind, Namespace, Name, Fingerprint string }{compliance.BaselineAuthority, f.RuleID, string(f.Severity), f.Kind, f.Namespace, f.Name, f.Fingerprint})
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func ComplianceScanResultDigest(run ComplianceScanRun, findings []ComplianceFindingRecord) string {
	ids := make([]string, 0, len(findings))
	for _, f := range findings {
		ids = append(ids, f.Fingerprint+":"+f.EvidenceDigest)
	}
	sort.Strings(ids)
	raw, _ := json.Marshal(struct {
		Schema, RunID, InventoryDigest, ProfileID string
		Findings                                  []string
	}{"platform.4so.io/compliance-result/v1", run.ID, run.InventoryDigest, run.ProfileID, ids})
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func validComplianceSeverity(s compliance.Severity) bool {
	return s == compliance.SeverityMedium || s == compliance.SeverityHigh || s == compliance.SeverityCritical
}
func ComplianceSeverityRank(s compliance.Severity) int {
	switch s {
	case compliance.SeverityCritical:
		return 3
	case compliance.SeverityHigh:
		return 2
	case compliance.SeverityMedium:
		return 1
	default:
		return 0
	}
}

func (s *MemoryStore) CreateComplianceProfile(_ context.Context, v ComplianceProfile, actor string) (ComplianceProfile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.projects[v.ProjectID]; !ok {
		return ComplianceProfile{}, ErrNotFound
	}
	v.Name = normalizeName(v.Name)
	if v.Name == "" || !validComplianceSeverity(v.MinimumSeverity) {
		return ComplianceProfile{}, ErrValidation
	}
	if v.BaselineAuthority == "" {
		v.BaselineAuthority = compliance.BaselineAuthority
	}
	if v.BaselineAuthority != compliance.BaselineAuthority {
		return ComplianceProfile{}, ErrValidation
	}
	for _, x := range s.complianceProfiles {
		if x.ProjectID == v.ProjectID && x.Name == v.Name {
			return ComplianceProfile{}, ErrDuplicateName
		}
	}
	now := nowUTC(s.now)
	v.ResourceMeta = ResourceMeta{ID: s.id("cmp"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	v.State = ComplianceProfileActive
	v.CreatedBy = strings.TrimSpace(actor)
	v.DesiredDigest = complianceProfileDigest(v)
	s.complianceProfiles[v.ID] = v
	s.appendAuditLocked(actor, "compliance_profile.created", "complianceProfile", v.ID, v.Revision, map[string]any{"projectId": v.ProjectID, "digest": v.DesiredDigest})
	s.appendOutboxLocked("complianceProfile", v.ID, "compliance_profile.created", v)
	return v, nil
}
func (s *MemoryStore) GetComplianceProfile(_ context.Context, id string) (ComplianceProfile, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.complianceProfiles[id]
	if !ok {
		return v, ErrNotFound
	}
	return v, nil
}
func (s *MemoryStore) ListComplianceProfiles(_ context.Context, projectID string) ([]ComplianceProfile, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []ComplianceProfile{}
	for _, v := range s.complianceProfiles {
		if projectID == "" || v.ProjectID == projectID {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}
func (s *MemoryStore) CreateComplianceScanRun(_ context.Context, v ComplianceScanRun, actor string) (ComplianceScanRun, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.complianceProfiles[v.ProfileID]
	if !ok || p.State != ComplianceProfileActive || p.ProjectID != v.ProjectID {
		return ComplianceScanRun{}, false, ErrPrerequisite
	}
	c, ok := s.managedClusters[v.ClusterID]
	if !ok || c.ProjectID != v.ProjectID || !validSHA256(c.InventoryDigest) {
		return ComplianceScanRun{}, false, ErrPrerequisite
	}
	v.IdempotencyKey = strings.TrimSpace(v.IdempotencyKey)
	v.RequestDigest = strings.TrimSpace(v.RequestDigest)
	if v.IdempotencyKey == "" || !validSHA256(v.RequestDigest) {
		return ComplianceScanRun{}, false, ErrValidation
	}
	key := "complianceScan:" + v.ProjectID + ":" + v.IdempotencyKey
	if id := s.idempotency[key]; id != "" {
		cur := s.complianceScanRuns[id]
		if cur.RequestDigest != v.RequestDigest {
			return ComplianceScanRun{}, false, ErrConflict
		}
		return cur, true, nil
	}
	now := nowUTC(s.now)
	v.ResourceMeta = ResourceMeta{ID: s.id("cscan"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	v.State = ComplianceScanQueued
	v.BaselineAuthority = p.BaselineAuthority
	v.InventoryDigest = c.InventoryDigest
	v.RequestedBy = strings.TrimSpace(actor)
	s.complianceScanRuns[v.ID] = v
	s.idempotency[key] = v.ID
	s.appendAuditLocked(actor, "compliance_scan.requested", "complianceScan", v.ID, v.Revision, map[string]any{"clusterId": v.ClusterID, "inventoryDigest": v.InventoryDigest})
	s.appendOutboxLocked("complianceScan", v.ID, "compliance_scan.requested", v)
	return v, false, nil
}
func (s *MemoryStore) GetComplianceScanRun(_ context.Context, id string) (ComplianceScanRun, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.complianceScanRuns[id]
	if !ok {
		return v, ErrNotFound
	}
	return v, nil
}
func (s *MemoryStore) ListComplianceScanRuns(_ context.Context, projectID, clusterID string) ([]ComplianceScanRun, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []ComplianceScanRun{}
	for _, v := range s.complianceScanRuns {
		if (projectID == "" || v.ProjectID == projectID) && (clusterID == "" || v.ClusterID == clusterID) {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}
func (s *MemoryStore) ClaimComplianceScanTask(_ context.Context, clusterID, owner string, lease time.Duration, now time.Time) (ComplianceScanTask, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now = now.UTC()
	var selected *ComplianceScanRun
	for _, v := range s.complianceScanRuns {
		if v.ClusterID != clusterID || (v.State != ComplianceScanQueued && v.State != ComplianceScanRunning) {
			continue
		}
		if v.TaskLeaseExpiresAt != nil && v.TaskLeaseExpiresAt.After(now) && v.TaskLeaseOwner != owner {
			continue
		}
		vv := v
		if selected == nil || vv.CreatedAt.Before(selected.CreatedAt) {
			selected = &vv
		}
	}
	if selected == nil {
		return ComplianceScanTask{}, ErrNotFound
	}
	v := *selected
	v.State = ComplianceScanRunning
	v.TaskAttempt++
	v.TaskFenceToken++
	v.TaskLeaseOwner = owner
	until := now.Add(lease)
	v.TaskLeaseExpiresAt = &until
	if v.StartedAt == nil {
		t := now
		v.StartedAt = &t
	}
	v.Revision++
	v.UpdatedAt = now
	s.complianceScanRuns[v.ID] = v
	return ComplianceScanTask{RunID: v.ID, RunRevision: v.Revision, ProjectID: v.ProjectID, ClusterID: v.ClusterID, BaselineAuthority: v.BaselineAuthority, InventoryDigest: v.InventoryDigest, Attempt: v.TaskAttempt, FenceToken: v.TaskFenceToken, LeaseExpiresAt: until}, nil
}
func (s *MemoryStore) CompleteComplianceScan(_ context.Context, id, owner string, fence int64, findings []compliance.Finding, actor string) (ComplianceScanRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.complianceScanRuns[id]
	if !ok {
		return v, ErrNotFound
	}
	if v.State != ComplianceScanRunning || v.TaskLeaseOwner != owner || v.TaskFenceToken != fence {
		return v, ErrConflict
	}
	profile, ok := s.complianceProfiles[v.ProfileID]
	if !ok || profile.ProjectID != v.ProjectID || profile.BaselineAuthority != v.BaselineAuthority {
		return v, ErrPrerequisite
	}
	now := nowUTC(s.now)
	byFingerprint := make(map[string]ComplianceFindingRecord)
	for _, f := range findings {
		if !compliance.ValidateFindingIdentity(f) || !validComplianceSeverity(f.Severity) {
			return v, ErrValidation
		}
		if ComplianceSeverityRank(f.Severity) < ComplianceSeverityRank(profile.MinimumSeverity) {
			continue
		}
		if _, exists := byFingerprint[f.Fingerprint]; exists {
			continue
		}
		byFingerprint[f.Fingerprint] = ComplianceFindingRecord{ResourceMeta: ResourceMeta{ID: s.id("cfind"), Revision: 1, CreatedAt: now, UpdatedAt: now}, RunID: v.ID, ProjectID: v.ProjectID, ClusterID: v.ClusterID, Fingerprint: f.Fingerprint, RuleID: f.RuleID, Severity: f.Severity, Kind: f.Kind, Namespace: f.Namespace, Name: f.Name, Summary: f.Summary, EvidenceDigest: ComplianceFindingEvidenceDigest(f)}
	}
	records := make([]ComplianceFindingRecord, 0, len(byFingerprint))
	for _, rec := range byFingerprint {
		records = append(records, rec)
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Fingerprint < records[j].Fingerprint })
	for _, r := range records {
		s.complianceFindings[r.ID] = r
	}
	v.Findings = len(records)
	v.ResultDigest = ComplianceScanResultDigest(v, records)
	v.EvidenceDigest = v.ResultDigest
	v.State = ComplianceScanSucceeded
	v.TaskLeaseOwner = ""
	v.TaskLeaseExpiresAt = nil
	t := now
	v.FinishedAt = &t
	v.Revision++
	v.UpdatedAt = now
	s.complianceScanRuns[v.ID] = v
	s.appendAuditLocked(actor, "compliance_scan.completed", "complianceScan", v.ID, v.Revision, map[string]any{"findings": v.Findings, "resultDigest": v.ResultDigest})
	s.appendOutboxLocked("complianceScan", v.ID, "compliance_scan.completed", v)
	return v, nil
}
func (s *MemoryStore) FailComplianceScan(_ context.Context, id, owner string, fence int64, message, actor string) (ComplianceScanRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.complianceScanRuns[id]
	if !ok {
		return v, ErrNotFound
	}
	if v.State != ComplianceScanRunning || v.TaskLeaseOwner != owner || v.TaskFenceToken != fence {
		return v, ErrConflict
	}
	now := nowUTC(s.now)
	v.State = ComplianceScanFailed
	v.LastError = strings.TrimSpace(message)
	if len(v.LastError) > 1000 {
		v.LastError = v.LastError[:1000]
	}
	v.TaskLeaseOwner = ""
	v.TaskLeaseExpiresAt = nil
	t := now
	v.FinishedAt = &t
	v.Revision++
	v.UpdatedAt = now
	s.complianceScanRuns[v.ID] = v
	s.appendAuditLocked(actor, "compliance_scan.failed", "complianceScan", v.ID, v.Revision, map[string]any{"reason": v.LastError})
	return v, nil
}
func (s *MemoryStore) ListComplianceFindings(_ context.Context, projectID, runID string) ([]ComplianceFindingRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []ComplianceFindingRecord{}
	for _, v := range s.complianceFindings {
		if (projectID == "" || v.ProjectID == projectID) && (runID == "" || v.RunID == runID) {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return string(out[i].Severity) > string(out[j].Severity)
		}
		return out[i].Fingerprint < out[j].Fingerprint
	})
	return out, nil
}
func (s *MemoryStore) CreateComplianceWaiver(_ context.Context, v ComplianceWaiver, actor string) (ComplianceWaiver, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.projects[v.ProjectID]; !ok {
		return v, ErrNotFound
	}
	v.Fingerprint = strings.TrimSpace(v.Fingerprint)
	v.Reason = strings.TrimSpace(v.Reason)
	if len(v.Fingerprint) != 64 || v.Reason == "" || len(v.Reason) > 1000 {
		return v, ErrValidation
	}
	now := nowUTC(s.now)
	v.ResourceMeta = ResourceMeta{ID: s.id("cwv"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	v.State = ComplianceWaiverPending
	v.RequestedBy = strings.TrimSpace(actor)
	s.complianceWaivers[v.ID] = v
	s.appendAuditLocked(actor, "compliance_waiver.requested", "complianceWaiver", v.ID, v.Revision, map[string]any{"fingerprint": v.Fingerprint})
	return v, nil
}
func (s *MemoryStore) GetComplianceWaiver(_ context.Context, id string) (ComplianceWaiver, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.complianceWaivers[strings.TrimSpace(id)]
	if !ok {
		return v, ErrNotFound
	}
	return v, nil
}

func (s *MemoryStore) ApproveComplianceWaiver(_ context.Context, id string, expected int64, actor string) (ComplianceWaiver, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.complianceWaivers[id]
	if !ok {
		return v, ErrNotFound
	}
	actor = strings.TrimSpace(actor)
	if v.Revision != expected {
		return v, ErrConflict
	}
	if v.State != ComplianceWaiverPending {
		return v, ErrPrerequisite
	}
	if actor == "" || actor == v.RequestedBy {
		return v, ErrPrerequisite
	}
	now := nowUTC(s.now)
	v.State = ComplianceWaiverActive
	v.ApprovedBy = actor
	t := now
	v.ApprovedAt = &t
	v.Revision++
	v.UpdatedAt = now
	s.complianceWaivers[v.ID] = v
	s.appendAuditLocked(actor, "compliance_waiver.approved", "complianceWaiver", v.ID, v.Revision, nil)
	s.appendOutboxLocked("complianceWaiver", v.ID, "compliance_waiver.approved", v)
	return v, nil
}
func (s *MemoryStore) RevokeComplianceWaiver(_ context.Context, id string, expected int64, actor string) (ComplianceWaiver, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.complianceWaivers[id]
	if !ok {
		return v, ErrNotFound
	}
	if v.Revision != expected {
		return v, ErrConflict
	}
	if v.State == ComplianceWaiverRevoked {
		return v, nil
	}
	now := nowUTC(s.now)
	v.State = ComplianceWaiverRevoked
	v.RevokedBy = strings.TrimSpace(actor)
	t := now
	v.RevokedAt = &t
	v.Revision++
	v.UpdatedAt = now
	s.complianceWaivers[v.ID] = v
	s.appendAuditLocked(actor, "compliance_waiver.revoked", "complianceWaiver", v.ID, v.Revision, nil)
	return v, nil
}
func (s *MemoryStore) ListComplianceWaivers(_ context.Context, projectID string) ([]ComplianceWaiver, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []ComplianceWaiver{}
	for _, v := range s.complianceWaivers {
		if projectID == "" || v.ProjectID == projectID {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func ValidateComplianceSnapshot(profiles []ComplianceProfile, runs []ComplianceScanRun, findings []ComplianceFindingRecord, waivers []ComplianceWaiver, projects map[string]Project, clusters map[string]ManagedCluster) error {
	ps := map[string]ComplianceProfile{}
	for _, p := range profiles {
		if _, ok := projects[p.ProjectID]; !ok || p.BaselineAuthority != compliance.BaselineAuthority || !validComplianceSeverity(p.MinimumSeverity) || p.DesiredDigest != complianceProfileDigest(p) {
			return fmt.Errorf("%w: invalid compliance profile %q", ErrValidation, p.ID)
		}
		ps[p.ID] = p
	}
	rs := map[string]ComplianceScanRun{}
	for _, r := range runs {
		p, ok := ps[r.ProfileID]
		c, cok := clusters[r.ClusterID]
		if !ok || !cok || p.ProjectID != r.ProjectID || c.ProjectID != r.ProjectID || !validSHA256(r.InventoryDigest) {
			return fmt.Errorf("%w: invalid compliance scan %q", ErrValidation, r.ID)
		}
		rs[r.ID] = r
	}
	for _, f := range findings {
		r, ok := rs[f.RunID]
		if !ok || r.ProjectID != f.ProjectID || r.ClusterID != f.ClusterID || !validSHA256(f.EvidenceDigest) {
			return fmt.Errorf("%w: invalid compliance finding %q", ErrValidation, f.ID)
		}
	}
	for _, w := range waivers {
		if _, ok := projects[w.ProjectID]; !ok || len(w.Fingerprint) != 64 {
			return fmt.Errorf("%w: invalid compliance waiver %q", ErrValidation, w.ID)
		}
		if w.State == ComplianceWaiverActive && (w.ApprovedBy == "" || w.ApprovedBy == w.RequestedBy) {
			return fmt.Errorf("%w: invalid compliance waiver approval %q", ErrValidation, w.ID)
		}
	}
	return nil
}

type ComplianceScanTaskResult struct {
	TaskFenceToken int64                `json:"taskFenceToken"`
	Findings       []compliance.Finding `json:"findings,omitempty"`
	Error          string               `json:"error,omitempty"`
}
