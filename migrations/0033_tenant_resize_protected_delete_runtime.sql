BEGIN;

ALTER TABLE tenant_environments
  ADD COLUMN IF NOT EXISTS pending_plan_name text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS pending_quota jsonb NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN IF NOT EXISTS pending_desired_digest text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS recovery_checkpoint_id text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS approved_by text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS approved_at timestamptz;

ALTER TABLE tenant_environments DROP CONSTRAINT IF EXISTS tenant_environments_state_check;
ALTER TABLE tenant_environments
  ADD CONSTRAINT tenant_environments_state_check CHECK (state IN (
    'QUEUED','PROVISIONING','ACTIVE','SUSPEND_QUEUED','SUSPENDING','SUSPENDED',
    'RESUME_QUEUED','RESUMING','RESIZE_AWAITING_APPROVAL','RESIZE_QUEUED','RESIZING',
    'DELETE_AWAITING_APPROVAL','DELETE_QUEUED','DELETING','DELETED','FAILED'
  ));

ALTER TABLE tenant_environments DROP CONSTRAINT IF EXISTS tenant_environments_pending_action_check;
ALTER TABLE tenant_environments
  ADD CONSTRAINT tenant_environments_pending_action_check CHECK (pending_action IN ('','PROVISION','SUSPEND','RESUME','RESIZE','DELETE'));

CREATE INDEX IF NOT EXISTS idx_tenant_environments_approval_state
  ON tenant_environments(project_id,state,updated_at)
  WHERE state IN ('RESIZE_AWAITING_APPROVAL','DELETE_AWAITING_APPROVAL');

COMMIT;
