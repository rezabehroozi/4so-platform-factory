-- Durable pre-provider dispatch claims ensure one Idempotency-Key cannot issue
-- concurrent or automatic post-crash duplicate model calls. A DISPATCHED claim
-- is intentionally fail-closed: if process outcome is unknown, operators must
-- use a new key to explicitly authorize another provider call.
CREATE TABLE IF NOT EXISTS ai_execution_claims (
  id text PRIMARY KEY,
  project_id text NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  revision bigint NOT NULL CHECK (revision >= 1),
  purpose text NOT NULL,
  idempotency_key text NOT NULL,
  request_digest text NOT NULL,
  state text NOT NULL CHECK (state IN ('DISPATCHED','COMPLETED','FAILED')),
  ai_run_id text NOT NULL DEFAULT '',
  failure_code text NOT NULL DEFAULT '',
  requested_by text NOT NULL,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  CONSTRAINT ai_execution_claim_terminal_shape CHECK (
    (state='DISPATCHED' AND ai_run_id='' AND failure_code='') OR
    (state='COMPLETED' AND ai_run_id<>'' AND failure_code='') OR
    (state='FAILED' AND ai_run_id='' AND failure_code<>'')
  ),
  CONSTRAINT ai_execution_claim_project_idempotency UNIQUE(project_id,idempotency_key)
);
CREATE INDEX IF NOT EXISTS ai_execution_claims_project_created_idx ON ai_execution_claims(project_id,created_at,id);
