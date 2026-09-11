package api

import (
	"context"
	"errors"
	"fmt"
	"platform.4so.io/factory/internal/controlplane"
	"strings"
	"time"
)

const dataProtectionSchedulerActor = "system-data-protection-scheduler"

func scheduledBackupBucket(at time.Time) string {
	return at.UTC().Truncate(time.Minute).Format("20060102T1504Z")
}

func (s *Server) enqueueScheduledBackupsAt(ctx context.Context, at time.Time) (int, error) {
	policies, err := s.store.ListBackupPolicies(ctx, "", "")
	if err != nil {
		return 0, err
	}
	created := 0
	var failures []error
	bucket := scheduledBackupBucket(at)
	for _, policy := range policies {
		if policy.State != controlplane.BackupPolicyActive {
			continue
		}
		due, matchErr := controlplane.BackupScheduleMatchesUTC(policy.Schedule, at)
		if matchErr != nil {
			failures = append(failures, fmt.Errorf("policy %s schedule: %w", policy.ID, matchErr))
			continue
		}
		if !due {
			continue
		}
		key := "schedule:" + policy.ID + ":" + bucket
		requestDigest := digestValue(map[string]any{"authority": "TARGET_DATA_PROTECTION_SCHEDULER_V1", "kind": controlplane.DataProtectionBackup, "projectId": policy.ProjectID, "clusterId": policy.ClusterID, "policyId": policy.ID, "schedule": policy.Schedule, "policyDigest": policy.DesiredDigest, "bucket": bucket, "idempotencyKey": key})
		_, replay, createErr := s.store.CreateDataProtectionRun(ctx, controlplane.DataProtectionRun{Kind: controlplane.DataProtectionBackup, ProjectID: policy.ProjectID, ClusterID: policy.ClusterID, PolicyID: policy.ID, IdempotencyKey: key, RequestDigest: requestDigest}, dataProtectionSchedulerActor)
		if createErr != nil {
			failures = append(failures, fmt.Errorf("policy %s scheduled backup: %w", policy.ID, createErr))
			continue
		}
		if !replay {
			created++
		}
	}
	if len(failures) > 0 {
		return created, errors.Join(failures...)
	}
	return created, nil
}

// RunDataProtectionScheduler materializes each due BackupPolicy into a durable
// BackupRun. Minute-bucket idempotency makes the loop safe across HA replicas.
func (s *Server) RunDataProtectionScheduler(ctx context.Context, poll time.Duration) {
	if poll <= 0 {
		poll = 20 * time.Second
	}
	run := func() {
		created, err := s.enqueueScheduledBackupsAt(ctx, time.Now().UTC())
		if err != nil && ctx.Err() == nil {
			s.logger.Warn("data protection scheduler cycle incomplete", "error", err)
		}
		if created > 0 {
			s.logger.Info("data protection scheduled backups queued", "count", created)
		}
	}
	run()
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}

func normalizeDataProtectionPollEnv(raw string) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 20 * time.Second, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d < time.Second || d > time.Minute {
		return 0, fmt.Errorf("data protection scheduler poll interval must be between 1s and 1m")
	}
	return d, nil
}

// DataProtectionSchedulerPollInterval validates the operator-configurable scheduler cadence.
func DataProtectionSchedulerPollInterval(raw string) (time.Duration, error) {
	return normalizeDataProtectionPollEnv(raw)
}
