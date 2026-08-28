ALTER TABLE baseline_deployments
  ADD COLUMN plan_created_at timestamptz,
  ADD COLUMN plan_expires_at timestamptz,
  ADD COLUMN plan_inventory_digest text NOT NULL DEFAULT '',
  ADD COLUMN plan_context_digest text NOT NULL DEFAULT '',
  ADD COLUMN plan_revalidation_count integer NOT NULL DEFAULT 0 CHECK(plan_revalidation_count >= 0);

ALTER TABLE baseline_deployments
  ADD CONSTRAINT baseline_plan_inventory_digest_format CHECK(plan_inventory_digest = '' OR plan_inventory_digest LIKE 'sha256:%'),
  ADD CONSTRAINT baseline_plan_context_digest_format CHECK(plan_context_digest = '' OR plan_context_digest LIKE 'sha256:%'),
  ADD CONSTRAINT baseline_plan_time_order CHECK(plan_expires_at IS NULL OR (plan_created_at IS NOT NULL AND plan_expires_at > plan_created_at));

CREATE INDEX baseline_deployments_plan_expiry_idx
  ON baseline_deployments(plan_expires_at)
  WHERE state IN ('AWAITING_APPROVAL','QUEUED');

CREATE TYPE recovery_checkpoint_state AS ENUM ('VERIFIED','REVOKED');

CREATE TABLE recovery_checkpoints (
  id text PRIMARY KEY,
  project_id text NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  cluster_id text NOT NULL REFERENCES managed_clusters(id) ON DELETE CASCADE,
  revision bigint NOT NULL CHECK(revision > 0),
  provider text NOT NULL CHECK(length(trim(provider)) > 0),
  reference text NOT NULL CHECK(length(trim(reference)) > 0),
  evidence_digest text NOT NULL CHECK(evidence_digest LIKE 'sha256:%'),
  inventory_digest text NOT NULL CHECK(inventory_digest LIKE 'sha256:%'),
  completed_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  state recovery_checkpoint_state NOT NULL,
  requested_by text NOT NULL,
  revoked_by text NOT NULL DEFAULT '',
  revoked_at timestamptz,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  CHECK(expires_at > completed_at),
  CHECK((state = 'VERIFIED' AND revoked_at IS NULL) OR state = 'REVOKED')
);

CREATE UNIQUE INDEX recovery_checkpoints_active_evidence_idx
  ON recovery_checkpoints(project_id,cluster_id,evidence_digest)
  WHERE state='VERIFIED';
CREATE INDEX recovery_checkpoints_cluster_expiry_idx
  ON recovery_checkpoints(project_id,cluster_id,expires_at,state);

ALTER TABLE upgrade_campaigns
  ADD COLUMN maintenance_window_start timestamptz,
  ADD COLUMN maintenance_window_end timestamptz,
  ADD COLUMN recovery_checkpoint_ids jsonb NOT NULL DEFAULT '[]'::jsonb,
  ADD COLUMN target_inventory_digests jsonb NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN plan_context_digest text NOT NULL DEFAULT '',
  ADD COLUMN plan_created_at timestamptz,
  ADD COLUMN plan_expires_at timestamptz,
  ADD COLUMN plan_revalidation_count integer NOT NULL DEFAULT 0 CHECK(plan_revalidation_count >= 0);

ALTER TABLE upgrade_campaigns
  ADD CONSTRAINT upgrade_campaign_window_order CHECK(maintenance_window_end IS NULL OR (maintenance_window_start IS NOT NULL AND maintenance_window_end > maintenance_window_start)),
  ADD CONSTRAINT upgrade_campaign_plan_digest_format CHECK(plan_context_digest = '' OR plan_context_digest LIKE 'sha256:%'),
  ADD CONSTRAINT upgrade_campaign_plan_time_order CHECK(plan_expires_at IS NULL OR (plan_created_at IS NOT NULL AND plan_expires_at > plan_created_at)),
  ADD CONSTRAINT upgrade_campaign_recovery_ids_array CHECK(jsonb_typeof(recovery_checkpoint_ids)='array'),
  ADD CONSTRAINT upgrade_campaign_inventory_map CHECK(jsonb_typeof(target_inventory_digests)='object');

CREATE INDEX upgrade_campaigns_plan_expiry_idx
  ON upgrade_campaigns(plan_expires_at)
  WHERE state IN ('AWAITING_APPROVAL','QUEUED');
CREATE INDEX upgrade_campaigns_maintenance_window_idx
  ON upgrade_campaigns(maintenance_window_start,maintenance_window_end)
  WHERE state IN ('AWAITING_APPROVAL','QUEUED','RUNNING');
