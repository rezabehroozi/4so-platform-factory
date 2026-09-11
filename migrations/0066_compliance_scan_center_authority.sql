-- Durable compliance Scan Center authority. Raw Kubernetes objects are not persisted here;
-- only normalized finding identity, bounded summaries and evidence digests cross the control-plane boundary.
CREATE TABLE compliance_profiles (
  id text PRIMARY KEY,
  revision bigint NOT NULL CHECK (revision > 0),
  project_id text NOT NULL REFERENCES projects(id),
  name text NOT NULL,
  baseline_authority text NOT NULL,
  minimum_severity text NOT NULL CHECK (minimum_severity IN ('MEDIUM','HIGH','CRITICAL')),
  state text NOT NULL CHECK (state IN ('ACTIVE','DISABLED')),
  desired_digest text NOT NULL,
  created_by text NOT NULL,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  UNIQUE(project_id,name)
);
CREATE INDEX compliance_profiles_project_idx ON compliance_profiles(project_id,created_at,id);

CREATE TABLE compliance_scan_runs (
  id text PRIMARY KEY,
  revision bigint NOT NULL CHECK (revision > 0),
  project_id text NOT NULL REFERENCES projects(id),
  cluster_id text NOT NULL REFERENCES managed_clusters(id),
  profile_id text NOT NULL REFERENCES compliance_profiles(id),
  baseline_authority text NOT NULL,
  inventory_digest text NOT NULL,
  state text NOT NULL CHECK (state IN ('QUEUED','RUNNING','SUCCEEDED','FAILED')),
  idempotency_key text NOT NULL,
  request_digest text NOT NULL,
  findings integer NOT NULL DEFAULT 0 CHECK (findings >= 0),
  result_digest text NOT NULL DEFAULT '',
  evidence_digest text NOT NULL DEFAULT '',
  requested_by text NOT NULL,
  task_attempt integer NOT NULL DEFAULT 0 CHECK (task_attempt >= 0),
  task_fence_token bigint NOT NULL DEFAULT 0 CHECK (task_fence_token >= 0),
  task_lease_owner text NOT NULL DEFAULT '',
  task_lease_expires_at timestamptz,
  started_at timestamptz,
  finished_at timestamptz,
  last_error text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  UNIQUE(project_id,idempotency_key)
);
CREATE INDEX compliance_scan_queue_idx ON compliance_scan_runs(cluster_id,state,task_lease_expires_at,created_at,id);
CREATE INDEX compliance_scan_project_cluster_idx ON compliance_scan_runs(project_id,cluster_id,created_at,id);

CREATE TABLE compliance_findings (
  id text PRIMARY KEY,
  revision bigint NOT NULL CHECK (revision > 0),
  run_id text NOT NULL REFERENCES compliance_scan_runs(id) ON DELETE CASCADE,
  project_id text NOT NULL REFERENCES projects(id),
  cluster_id text NOT NULL REFERENCES managed_clusters(id),
  fingerprint text NOT NULL,
  rule_id text NOT NULL,
  severity text NOT NULL CHECK (severity IN ('MEDIUM','HIGH','CRITICAL')),
  kind text NOT NULL,
  namespace text NOT NULL DEFAULT '',
  name text NOT NULL,
  summary text NOT NULL,
  evidence_digest text NOT NULL,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  UNIQUE(run_id,fingerprint)
);
CREATE INDEX compliance_findings_project_run_idx ON compliance_findings(project_id,run_id,severity,rule_id,id);

CREATE TABLE compliance_waivers (
  id text PRIMARY KEY,
  revision bigint NOT NULL CHECK (revision > 0),
  project_id text NOT NULL REFERENCES projects(id),
  fingerprint text NOT NULL,
  reason text NOT NULL,
  state text NOT NULL CHECK (state IN ('PENDING_APPROVAL','ACTIVE','REVOKED')),
  requested_by text NOT NULL,
  approved_by text NOT NULL DEFAULT '',
  approved_at timestamptz,
  revoked_by text NOT NULL DEFAULT '',
  revoked_at timestamptz,
  expires_at timestamptz,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL
);
CREATE INDEX compliance_waivers_project_fingerprint_idx ON compliance_waivers(project_id,fingerprint,state,created_at,id);
