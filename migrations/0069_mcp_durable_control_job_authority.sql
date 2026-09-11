-- Durable AI/MCP mutation envelope. This table records bounded, sanitized
-- execution metadata before canonical REST mutation dispatch. It never stores
-- raw credentials and terminal response payloads are capped by application code.
CREATE TABLE mcp_control_jobs (
  id text PRIMARY KEY,
  revision bigint NOT NULL CHECK (revision > 0),
  tool_name text NOT NULL CHECK (char_length(tool_name) BETWEEN 1 AND 200),
  family text NOT NULL CHECK (char_length(family) BETWEEN 1 AND 200),
  action text NOT NULL CHECK (char_length(action) BETWEEN 1 AND 200),
  method text NOT NULL CHECK (method IN ('POST','PUT','DELETE','PATCH')),
  route text NOT NULL CHECK (char_length(route) BETWEEN 1 AND 1000),
  state text NOT NULL CHECK (state IN ('RUNNING','SUCCEEDED','FAILED','RECOVERY_REQUIRED')),
  risk text NOT NULL CHECK (risk IN ('low','medium','high','critical')),
  actor_id text NOT NULL,
  authentication text NOT NULL DEFAULT '',
  oauth_client_id text NOT NULL DEFAULT '',
  delegation_profile text NOT NULL DEFAULT '',
  organization_id text NOT NULL DEFAULT '',
  project_id text NOT NULL DEFAULT '',
  request_id text NOT NULL DEFAULT '',
  idempotency_key text NOT NULL CHECK (char_length(idempotency_key) BETWEEN 1 AND 200),
  request_digest text NOT NULL CHECK (request_digest ~ '^sha256:[0-9a-f]{64}$'),
  attempt integer NOT NULL DEFAULT 1 CHECK (attempt > 0),
  lease_owner text NOT NULL,
  lease_expires_at timestamptz,
  fence_token bigint NOT NULL DEFAULT 1 CHECK (fence_token > 0),
  status_code integer,
  response_digest text CHECK (response_digest IS NULL OR response_digest ~ '^sha256:[0-9a-f]{64}$'),
  response bytea NOT NULL DEFAULT ''::bytea CHECK (octet_length(response) <= 65536),
  error_code text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL
);
CREATE UNIQUE INDEX mcp_control_jobs_idempotency_idx ON mcp_control_jobs(actor_id,oauth_client_id,delegation_profile,organization_id,project_id,tool_name,idempotency_key);
CREATE INDEX mcp_control_jobs_scope_created_idx ON mcp_control_jobs(organization_id,project_id,created_at DESC,id);
