-- Complete execution ownership for every agent task family that can create,
-- mutate, verify or roll back target-cluster state. Active leases prevent a
-- second claim; monotonic fence tokens reject stale reports after recovery.
ALTER TABLE baseline_deployments
    ADD COLUMN task_fence_token bigint NOT NULL DEFAULT 0 CHECK (task_fence_token >= 0),
    ADD COLUMN task_lease_expires_at timestamptz;

ALTER TABLE runtime_verifications
    ADD COLUMN task_fence_token bigint NOT NULL DEFAULT 0 CHECK (task_fence_token >= 0),
    ADD COLUMN task_lease_expires_at timestamptz;

ALTER TABLE runtime_certification_runs
    ADD COLUMN task_fence_token bigint NOT NULL DEFAULT 0 CHECK (task_fence_token >= 0),
    ADD COLUMN task_lease_expires_at timestamptz;

CREATE INDEX baseline_agent_task_lease_idx ON baseline_deployments(cluster_id, task_lease_expires_at, id)
    WHERE state IN ('PLANNING','QUEUED','APPLYING','ROLLBACK_QUEUED','ROLLING_BACK');
CREATE INDEX runtime_verification_agent_task_lease_idx ON runtime_verifications(cluster_id, task_lease_expires_at, id)
    WHERE state IN ('QUEUED','RUNNING');
CREATE INDEX runtime_certification_agent_task_lease_idx ON runtime_certification_runs(cluster_id, task_lease_expires_at, id)
    WHERE state IN ('QUEUED','INSTALLING','VERIFYING');
