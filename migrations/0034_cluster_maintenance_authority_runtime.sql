BEGIN;

CREATE TABLE IF NOT EXISTS cluster_maintenance_profiles (
  id text PRIMARY KEY,
  project_id text NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  cluster_id text NOT NULL UNIQUE REFERENCES managed_clusters(id) ON DELETE CASCADE,
  revision bigint NOT NULL,
  environment text NOT NULL CHECK (environment IN ('DEVELOPMENT','STAGING','PRODUCTION')),
  default_drain_timeout_seconds integer NOT NULL CHECK (default_drain_timeout_seconds BETWEEN 30 AND 3600),
  updated_by text NOT NULL,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS cluster_maintenance_windows (
  id text PRIMARY KEY,
  project_id text NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  cluster_id text NOT NULL REFERENCES managed_clusters(id) ON DELETE CASCADE,
  revision bigint NOT NULL,
  name text NOT NULL,
  starts_at timestamptz NOT NULL,
  ends_at timestamptz NOT NULL,
  max_unavailable integer NOT NULL CHECK (max_unavailable = 1),
  drain_timeout_seconds integer NOT NULL CHECK (drain_timeout_seconds BETWEEN 30 AND 3600),
  state text NOT NULL CHECK (state IN ('ACTIVE','CANCELLED')),
  created_by text NOT NULL,
  cancelled_by text NOT NULL DEFAULT '',
  cancelled_at timestamptz,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  CHECK (ends_at > starts_at)
);
CREATE INDEX IF NOT EXISTS idx_cluster_maintenance_windows_cluster_time
  ON cluster_maintenance_windows(cluster_id,starts_at,ends_at)
  WHERE state='ACTIVE';

CREATE TABLE IF NOT EXISTS cluster_maintenance_runs (
  id text PRIMARY KEY,
  project_id text NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  cluster_id text NOT NULL REFERENCES managed_clusters(id) ON DELETE CASCADE,
  window_id text NOT NULL REFERENCES cluster_maintenance_windows(id),
  operation_id text NOT NULL UNIQUE REFERENCES operations(id) ON DELETE CASCADE,
  revision bigint NOT NULL,
  state text NOT NULL CHECK (state IN ('AWAITING_APPROVAL','QUEUED','RUNNING','RESTORING','SUCCEEDED','FAILED','NEEDS_OPERATOR','CANCELLED')),
  node_names jsonb NOT NULL,
  inventory_digest text NOT NULL,
  max_unavailable integer NOT NULL CHECK (max_unavailable = 1),
  drain_timeout_seconds integer NOT NULL CHECK (drain_timeout_seconds BETWEEN 30 AND 3600),
  requested_by text NOT NULL,
  approved_by text NOT NULL DEFAULT '',
  approved_at timestamptz,
  started_at timestamptz,
  finished_at timestamptz,
  results jsonb NOT NULL DEFAULT '[]'::jsonb,
  last_error text NOT NULL DEFAULT '',
  idempotency_key text NOT NULL,
  request_digest text NOT NULL,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  UNIQUE(project_id,idempotency_key)
);
CREATE INDEX IF NOT EXISTS idx_cluster_maintenance_runs_claim
  ON cluster_maintenance_runs(cluster_id,state,created_at,id)
  WHERE state='QUEUED';
CREATE INDEX IF NOT EXISTS idx_cluster_maintenance_runs_window
  ON cluster_maintenance_runs(window_id,state);

COMMIT;
