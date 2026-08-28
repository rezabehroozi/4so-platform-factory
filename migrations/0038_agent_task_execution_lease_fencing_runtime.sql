-- Generic execution ownership for agent-driven side effects. A revision fences
-- stale reports; these fields additionally prevent concurrent task execution.
ALTER TABLE tenant_environments
    ADD COLUMN task_fence_token bigint NOT NULL DEFAULT 0 CHECK (task_fence_token >= 0),
    ADD COLUMN task_lease_expires_at timestamptz;

ALTER TABLE provider_profiles
    ADD COLUMN task_fence_token bigint NOT NULL DEFAULT 0 CHECK (task_fence_token >= 0),
    ADD COLUMN task_lease_expires_at timestamptz;

ALTER TABLE provider_clusters
    ADD COLUMN task_fence_token bigint NOT NULL DEFAULT 0 CHECK (task_fence_token >= 0),
    ADD COLUMN task_lease_expires_at timestamptz;

CREATE INDEX tenant_agent_task_lease_idx ON tenant_environments(cluster_id, task_lease_expires_at, id)
    WHERE state IN ('QUEUED','PROVISIONING','SUSPEND_QUEUED','SUSPENDING','RESUME_QUEUED','RESUMING','RESIZE_QUEUED','RESIZING','DELETE_QUEUED','DELETING');
CREATE INDEX provider_profile_agent_task_lease_idx ON provider_profiles(management_cluster_id, task_lease_expires_at, id)
    WHERE state IN ('VERIFY_QUEUED','VERIFYING');
CREATE INDEX provider_cluster_agent_task_lease_idx ON provider_clusters(management_cluster_id, task_lease_expires_at, id)
    WHERE state IN ('QUEUED','APPLYING','RECONCILING','DELETE_QUEUED','DELETING');
