-- First-class target data-protection authorities.
-- Policies contain only scoped references; raw backup credentials are never persisted.
CREATE TABLE backup_policies (
  id text PRIMARY KEY,
  revision bigint NOT NULL CHECK (revision > 0),
  project_id text NOT NULL REFERENCES projects(id),
  cluster_id text NOT NULL REFERENCES managed_clusters(id),
  name text NOT NULL,
  provider text NOT NULL CHECK (provider = 'velero'),
  backup_storage_location text NOT NULL,
  credential_ref text NOT NULL,
  schedule text NOT NULL,
  retention text NOT NULL,
  included_namespaces jsonb NOT NULL CHECK (jsonb_typeof(included_namespaces) = 'array'),
  desired_digest text NOT NULL,
  state text NOT NULL CHECK (state IN ('ACTIVE','DISABLED')),
  requested_by text NOT NULL,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  UNIQUE(project_id, cluster_id, name)
);
CREATE INDEX backup_policies_project_cluster_idx ON backup_policies(project_id, cluster_id, created_at, id);

CREATE TABLE data_protection_runs (
  id text PRIMARY KEY,
  revision bigint NOT NULL CHECK (revision > 0),
  kind text NOT NULL CHECK (kind IN ('BACKUP','RESTORE','RESTORE_DRILL')),
  state text NOT NULL CHECK (state IN ('REQUESTED','AWAITING_APPROVAL','QUEUED','RUNNING','SUCCEEDED','FAILED')),
  project_id text NOT NULL REFERENCES projects(id),
  cluster_id text NOT NULL REFERENCES managed_clusters(id),
  policy_id text NOT NULL REFERENCES backup_policies(id),
  backup_run_id text REFERENCES data_protection_runs(id),
  recovery_checkpoint_id text REFERENCES recovery_checkpoints(id),
  inventory_digest text NOT NULL,
  policy_digest text NOT NULL,
  source_backup_name text NOT NULL DEFAULT '',
  target_namespace text NOT NULL DEFAULT '',
  velero_name text NOT NULL,
  reference text NOT NULL DEFAULT '',
  evidence_digest text NOT NULL DEFAULT '',
  checks jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(checks) = 'array'),
  rpo_seconds bigint NOT NULL DEFAULT 0 CHECK (rpo_seconds >= 0),
  rto_seconds bigint NOT NULL DEFAULT 0 CHECK (rto_seconds >= 0),
  idempotency_key text NOT NULL,
  request_digest text NOT NULL,
  requested_by text NOT NULL,
  approved_by text NOT NULL DEFAULT '',
  approved_at timestamptz,
  task_attempt integer NOT NULL DEFAULT 0 CHECK (task_attempt >= 0),
  task_fence_token bigint NOT NULL DEFAULT 0 CHECK (task_fence_token >= 0),
  task_lease_expires_at timestamptz,
  started_at timestamptz,
  finished_at timestamptz,
  last_error text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  UNIQUE(project_id, idempotency_key)
);
CREATE INDEX data_protection_runs_cluster_queue_idx ON data_protection_runs(cluster_id, state, task_lease_expires_at, created_at, id);
CREATE INDEX data_protection_runs_project_cluster_idx ON data_protection_runs(project_id, cluster_id, kind, created_at, id);
