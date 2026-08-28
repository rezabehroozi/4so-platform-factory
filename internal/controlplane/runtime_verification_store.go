package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

func cloneRuntimeVerification(v RuntimeVerification) RuntimeVerification {
	v.Checks = append([]RuntimeCheck(nil), v.Checks...)
	return v
}

func verificationReportDigest(v RuntimeVerification) string {
	raw, _ := json.Marshal(struct {
		ID       string         `json:"id"`
		Cluster  string         `json:"clusterId"`
		Baseline string         `json:"baselineDeploymentId"`
		Desired  string         `json:"desiredDigest"`
		Observed string         `json:"observedDigest"`
		Checks   []RuntimeCheck `json:"checks"`
	}{v.ID, v.ClusterID, v.BaselineDeploymentID, v.DesiredDigest, v.ObservedDigest, v.Checks})
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (s *MemoryStore) CreateRuntimeVerification(_ context.Context, v RuntimeVerification, actor string) (RuntimeVerification, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	baseline, ok := s.baselineDeployments[v.BaselineDeploymentID]
	if !ok || baseline.ProjectID != v.ProjectID || baseline.ClusterID != v.ClusterID {
		return RuntimeVerification{}, false, ErrNotFound
	}
	if !BaselineCompletionEvidenceReady(baseline, nowUTC(s.now)) {
		return RuntimeVerification{}, false, fmt.Errorf("%w: baseline deployment must have sealed, unexpired completion evidence", ErrInvalidTransition)
	}
	if !strings.HasPrefix(v.ProbeImage, "sha256:") && !strings.Contains(v.ProbeImage, "@sha256:") {
		return RuntimeVerification{}, false, fmt.Errorf("%w: digest-pinned probe image is required", ErrValidation)
	}
	if !strings.HasPrefix(v.RequestDigest, "sha256:") || strings.TrimSpace(v.IdempotencyKey) == "" {
		return RuntimeVerification{}, false, fmt.Errorf("%w: request digest and idempotency key are required", ErrValidation)
	}
	for _, existing := range s.runtimeVerifications {
		if existing.ProjectID == v.ProjectID && existing.IdempotencyKey == v.IdempotencyKey {
			if existing.RequestDigest != v.RequestDigest {
				return RuntimeVerification{}, false, ErrIdempotencyConflict
			}
			return cloneRuntimeVerification(existing), true, nil
		}
		if existing.BaselineDeploymentID == v.BaselineDeploymentID && (existing.State == RuntimeVerificationQueued || existing.State == RuntimeVerificationRunning) {
			return RuntimeVerification{}, false, ErrDuplicateName
		}
	}
	now := nowUTC(s.now)
	v.ResourceMeta = ResourceMeta{ID: s.id("rtv"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	v.State = RuntimeVerificationQueued
	v.DesiredDigest = baseline.DesiredDigest
	v.RequestedBy = actor
	v.Checks = nil
	s.runtimeVerifications[v.ID] = cloneRuntimeVerification(v)
	s.appendAuditLocked(actor, "runtime_verification.queued", "runtimeVerification", v.ID, v.Revision, map[string]any{"clusterId": v.ClusterID, "baselineDeploymentId": v.BaselineDeploymentID})
	s.appendOutboxLocked("runtimeVerification", v.ID, "runtime_verification.queued", v)
	return cloneRuntimeVerification(v), false, nil
}

func (s *MemoryStore) GetRuntimeVerification(_ context.Context, id string) (RuntimeVerification, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.runtimeVerifications[id]
	if !ok {
		return RuntimeVerification{}, ErrNotFound
	}
	return cloneRuntimeVerification(v), nil
}

func (s *MemoryStore) ListRuntimeVerifications(_ context.Context, projectID, clusterID, baselineDeploymentID string) ([]RuntimeVerification, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []RuntimeVerification{}
	for _, v := range s.runtimeVerifications {
		if (projectID == "" || v.ProjectID == projectID) && (clusterID == "" || v.ClusterID == clusterID) && (baselineDeploymentID == "" || v.BaselineDeploymentID == baselineDeploymentID) {
			out = append(out, cloneRuntimeVerification(v))
		}
	}
	sort.Slice(out, func(i, j int) bool { return resourceCreatedBefore(out[i].ResourceMeta, out[j].ResourceMeta) })
	return out, nil
}

func (s *MemoryStore) RetryRuntimeVerification(_ context.Context, id string, expected int64, actor string) (RuntimeVerification, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.runtimeVerifications[id]
	if !ok {
		return RuntimeVerification{}, ErrNotFound
	}
	if v.Revision != expected {
		return RuntimeVerification{}, ErrConflict
	}
	if v.State != RuntimeVerificationFailed {
		return RuntimeVerification{}, ErrInvalidTransition
	}
	baseline, ok := s.baselineDeployments[v.BaselineDeploymentID]
	if !ok || !BaselineCompletionEvidenceReady(baseline, nowUTC(s.now)) || baseline.DesiredDigest != v.DesiredDigest {
		return RuntimeVerification{}, fmt.Errorf("%w: baseline deployment no longer has valid completion evidence", ErrInvalidTransition)
	}
	now := nowUTC(s.now)
	v.State = RuntimeVerificationQueued
	v.ObservedDigest = ""
	v.Checks = nil
	v.ReportDigest = ""
	v.LastError = ""
	v.StartedAt = nil
	v.FinishedAt = nil
	v.Revision++
	v.UpdatedAt = now
	s.runtimeVerifications[v.ID] = cloneRuntimeVerification(v)
	s.appendAuditLocked(actor, "runtime_verification.retried", "runtimeVerification", v.ID, v.Revision, map[string]any{"attempt": v.TaskAttempt + 1})
	s.appendOutboxLocked("runtimeVerification", v.ID, "runtime_verification.retried", v)
	return cloneRuntimeVerification(v), nil
}

func (s *MemoryStore) NextRuntimeVerificationTask(_ context.Context, clusterID, tokenDigest string) (RuntimeVerification, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.requireFreshClusterTaskAdmissionLocked(clusterID, tokenDigest)
	if err != nil {
		return RuntimeVerification{}, err
	}
	now := nowUTC(s.now)
	ids := []string{}
	for id, v := range s.runtimeVerifications {
		if v.ClusterID != clusterID {
			continue
		}
		if v.State == RuntimeVerificationQueued || (v.State == RuntimeVerificationRunning && !AgentTaskLeaseActive(v.TaskLeaseExpiresAt, now)) {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return RuntimeVerification{}, ErrNotFound
	}
	sort.Slice(ids, func(i, j int) bool {
		return resourceCreatedBefore(s.runtimeVerifications[ids[i]].ResourceMeta, s.runtimeVerifications[ids[j]].ResourceMeta)
	})
	v := s.runtimeVerifications[ids[0]]
	if v.State == RuntimeVerificationQueued {
		v.State = RuntimeVerificationRunning
		v.StartedAt = &now
	}
	lease := now.Add(AgentTaskLeaseDuration)
	v.TaskAttempt++
	v.TaskFenceToken++
	v.TaskLeaseExpiresAt = &lease
	v.Revision++
	v.UpdatedAt = now
	s.runtimeVerifications[v.ID] = cloneRuntimeVerification(v)
	s.appendAuditLocked("cluster-agent", "runtime_verification.claimed", "runtimeVerification", v.ID, v.Revision, map[string]any{"attempt": v.TaskAttempt, "taskFenceToken": v.TaskFenceToken, "leaseExpiresAt": lease})
	return cloneRuntimeVerification(v), nil
}

func (s *MemoryStore) ReportRuntimeVerificationTask(_ context.Context, clusterID, tokenDigest string, expected int64, result RuntimeVerificationResult) (RuntimeVerification, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.requireClusterTaskAdmissionLocked(clusterID, tokenDigest)
	if err != nil {
		return RuntimeVerification{}, err
	}
	v, ok := s.runtimeVerifications[result.VerificationID]
	if !ok || v.ClusterID != clusterID {
		return RuntimeVerification{}, ErrNotFound
	}
	now := nowUTC(s.now)
	if v.Revision != expected || result.TaskFenceToken <= 0 || v.TaskFenceToken != result.TaskFenceToken || !AgentTaskLeaseActive(v.TaskLeaseExpiresAt, now) {
		return RuntimeVerification{}, ErrConflict
	}
	if v.State != RuntimeVerificationRunning {
		return RuntimeVerification{}, ErrInvalidTransition
	}
	allPass := len(result.Checks) > 0
	for _, check := range result.Checks {
		if check.Status != "PASS" {
			allPass = false
		}
	}
	v.Checks = append([]RuntimeCheck(nil), result.Checks...)
	v.ObservedDigest = result.ObservedDigest
	if result.Success && allPass && result.ObservedDigest == v.DesiredDigest {
		v.State = RuntimeVerificationSucceeded
		v.LastError = ""
	} else {
		v.State = RuntimeVerificationFailed
		v.LastError = strings.TrimSpace(result.Error)
		if v.LastError == "" {
			v.LastError = "runtime verification checks or digest equality failed"
		}
	}
	v.FinishedAt = &now
	v.TaskLeaseExpiresAt = nil
	v.Revision++
	v.UpdatedAt = now
	v.ReportDigest = verificationReportDigest(v)
	s.runtimeVerifications[v.ID] = cloneRuntimeVerification(v)
	action := "runtime_verification." + strings.ToLower(string(v.State))
	s.appendAuditLocked("cluster-agent", action, "runtimeVerification", v.ID, v.Revision, map[string]any{"reportDigest": v.ReportDigest, "taskFenceToken": result.TaskFenceToken})
	s.appendOutboxLocked("runtimeVerification", v.ID, action, v)
	return cloneRuntimeVerification(v), nil
}
