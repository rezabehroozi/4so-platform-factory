BEGIN;
ALTER TABLE tenant_environments
  ADD COLUMN IF NOT EXISTS storage_policy jsonb NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN IF NOT EXISTS backup_policy jsonb NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN IF NOT EXISTS security_policy jsonb NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN IF NOT EXISTS evidence jsonb NOT NULL DEFAULT '[]'::jsonb,
  ADD COLUMN IF NOT EXISTS evidence_digest text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS evidence_sealed_at timestamptz;
CREATE INDEX IF NOT EXISTS idx_tenant_environments_evidence_digest ON tenant_environments(evidence_digest) WHERE evidence_digest <> '';
COMMIT;
