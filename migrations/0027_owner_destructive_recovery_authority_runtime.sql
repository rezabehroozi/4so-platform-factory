-- 4SO Platform Factory 0.0.59
-- Bind owner-specific destructive workflows to the generic durable Operation
-- recovery authority. Existing rows remain readable; every new destructive
-- request must persist a linked DESTRUCTIVE operation before mutation.

ALTER TABLE baseline_deployments
    ADD COLUMN IF NOT EXISTS destructive_operation_id text REFERENCES operations(id) ON DELETE RESTRICT;
ALTER TABLE tenant_environments
    ADD COLUMN IF NOT EXISTS destructive_operation_id text REFERENCES operations(id) ON DELETE RESTRICT;
ALTER TABLE provider_clusters
    ADD COLUMN IF NOT EXISTS destructive_operation_id text REFERENCES operations(id) ON DELETE RESTRICT;

CREATE INDEX IF NOT EXISTS idx_baseline_deployments_destructive_operation
    ON baseline_deployments(destructive_operation_id)
    WHERE destructive_operation_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_tenant_environments_destructive_operation
    ON tenant_environments(destructive_operation_id)
    WHERE destructive_operation_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_provider_clusters_destructive_operation
    ON provider_clusters(destructive_operation_id)
    WHERE destructive_operation_id IS NOT NULL;

-- NOT VALID preserves upgrade compatibility for historical rows while making
-- the contract explicit for newly-written/updated destructive states.
ALTER TABLE baseline_deployments
    ADD CONSTRAINT baseline_destructive_operation_required
    CHECK (state NOT IN ('ROLLBACK_QUEUED','ROLLING_BACK') OR destructive_operation_id IS NOT NULL) NOT VALID;
ALTER TABLE tenant_environments
    ADD CONSTRAINT tenant_destructive_operation_required
    CHECK (state NOT IN ('DELETE_QUEUED','DELETING') OR destructive_operation_id IS NOT NULL) NOT VALID;
ALTER TABLE provider_clusters
    ADD CONSTRAINT provider_cluster_destructive_operation_required
    CHECK (state NOT IN ('DELETE_AWAITING_APPROVAL','DELETE_QUEUED','DELETING') OR destructive_operation_id IS NOT NULL) NOT VALID;
