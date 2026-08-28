-- Mark tenant runtime resources with a durable contract version so upgrades can
-- reconcile existing ACTIVE tenants through the normal fenced Agent task path.
ALTER TABLE tenant_environments
  ADD COLUMN IF NOT EXISTS runtime_contract_version INTEGER NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_tenant_runtime_contract_reconcile
  ON tenant_environments(cluster_id, state, runtime_contract_version, created_at)
  WHERE state = 'ACTIVE';
