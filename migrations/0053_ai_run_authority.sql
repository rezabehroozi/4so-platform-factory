-- Durable, redacted AI advisory run metadata. Raw prompts/secrets are forbidden;
-- only structured redacted output and content digests become authority.
CREATE TABLE IF NOT EXISTS ai_runs (
  id text PRIMARY KEY,
  project_id text NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  revision bigint NOT NULL CHECK (revision = 1),
  purpose text NOT NULL,
  provider text NOT NULL,
  model text NOT NULL DEFAULT '',
  prompt_id text NOT NULL,
  prompt_digest text NOT NULL,
  context_digest text NOT NULL,
  output_digest text NOT NULL,
  redaction_count integer NOT NULL DEFAULT 0 CHECK (redaction_count >= 0),
  input_bytes integer NOT NULL CHECK (input_bytes >= 0),
  input_tokens integer NOT NULL DEFAULT 0 CHECK (input_tokens >= 0),
  cached_tokens integer NOT NULL DEFAULT 0 CHECK (cached_tokens >= 0),
  output_tokens integer NOT NULL DEFAULT 0 CHECK (output_tokens >= 0),
  output jsonb NOT NULL,
  linked_resource_type text NOT NULL DEFAULT '',
  linked_resource_id text NOT NULL DEFAULT '',
  requested_by text NOT NULL,
  idempotency_key text NOT NULL,
  request_digest text NOT NULL,
  advisory_only boolean NOT NULL DEFAULT true CHECK (advisory_only = true),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  CONSTRAINT ai_runs_link_shape CHECK ((linked_resource_type = '') = (linked_resource_id = '')),
  CONSTRAINT ai_runs_project_idempotency UNIQUE(project_id,idempotency_key)
);
CREATE INDEX IF NOT EXISTS ai_runs_project_created_idx ON ai_runs(project_id,created_at,id);
