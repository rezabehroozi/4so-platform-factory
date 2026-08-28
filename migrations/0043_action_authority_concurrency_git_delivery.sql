-- 0.0.116: close action-authority concurrency and Git pull-request crash/reconciliation gaps.
ALTER TABLE git_pull_requests
  ADD COLUMN IF NOT EXISTS base_commit_sha text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS candidate_commit_sha text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS approved_head_commit_sha text NOT NULL DEFAULT '';

ALTER TABLE git_pull_requests DROP CONSTRAINT IF EXISTS git_pull_requests_state_check;
ALTER TABLE git_pull_requests ADD CONSTRAINT git_pull_requests_state_check
  CHECK (state IN ('REQUESTED','OPEN','APPROVED','MERGED','CLOSED'));

ALTER TABLE git_pull_requests DROP CONSTRAINT IF EXISTS git_pull_requests_external_number_check;
ALTER TABLE git_pull_requests ADD CONSTRAINT git_pull_requests_external_number_check
  CHECK (external_number >= 0);

ALTER TABLE git_pull_requests ALTER COLUMN external_number SET DEFAULT 0;

-- Bind one-time API-token issuance/rotation to a durable request identity without persisting raw secret material.
ALTER TABLE api_tokens ADD COLUMN IF NOT EXISTS idempotency_key text NOT NULL DEFAULT '';
CREATE UNIQUE INDEX IF NOT EXISTS api_tokens_service_account_idempotency_unique
  ON api_tokens(service_account_id,idempotency_key) WHERE idempotency_key <> '';
