BEGIN;

CREATE TABLE IF NOT EXISTS provider_profiles (
  id text PRIMARY KEY,
  project_id text NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  management_cluster_id text NOT NULL REFERENCES managed_clusters(id) ON DELETE RESTRICT,
  revision bigint NOT NULL CHECK (revision > 0),
  name text NOT NULL,
  display_name text NOT NULL,
  adapter text NOT NULL CHECK (adapter = 'cluster-api-topology-v1beta2'),
  namespace text NOT NULL CHECK (namespace = '4so-provider-system'),
  cluster_class_name text NOT NULL,
  worker_class_name text NOT NULL,
  default_kubernetes_version text NOT NULL,
  kubernetes_series jsonb NOT NULL,
  max_worker_replicas integer NOT NULL CHECK (max_worker_replicas BETWEEN 1 AND 500),
  state text NOT NULL CHECK (state IN ('VERIFY_QUEUED','VERIFYING','READY','FAILED')),
  desired_digest text NOT NULL CHECK (desired_digest LIKE 'sha256:%'),
  observed_digest text NOT NULL DEFAULT '',
  requested_by text NOT NULL,
  idempotency_key text NOT NULL,
  request_digest text NOT NULL CHECK (request_digest LIKE 'sha256:%'),
  task_attempt integer NOT NULL DEFAULT 0 CHECK (task_attempt >= 0),
  last_error text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  UNIQUE(project_id,name),
  UNIQUE(project_id,idempotency_key)
);
CREATE INDEX IF NOT EXISTS provider_profiles_management_state_idx ON provider_profiles(management_cluster_id,state,created_at);

CREATE TABLE IF NOT EXISTS provider_clusters (
  id text PRIMARY KEY,
  project_id text NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  provider_profile_id text NOT NULL REFERENCES provider_profiles(id) ON DELETE RESTRICT,
  management_cluster_id text NOT NULL REFERENCES managed_clusters(id) ON DELETE RESTRICT,
  revision bigint NOT NULL CHECK (revision > 0),
  name text NOT NULL,
  display_name text NOT NULL,
  resource_name text NOT NULL,
  namespace text NOT NULL CHECK (namespace = '4so-provider-system'),
  state text NOT NULL CHECK (state IN ('AWAITING_APPROVAL','QUEUED','APPLYING','RECONCILING','ACTIVE','DELETE_AWAITING_APPROVAL','DELETE_QUEUED','DELETING','DELETED','FAILED')),
  desired jsonb NOT NULL,
  applied jsonb NOT NULL DEFAULT '{}'::jsonb,
  desired_digest text NOT NULL CHECK (desired_digest LIKE 'sha256:%'),
  observed_digest text NOT NULL DEFAULT '',
  pending_action text NOT NULL CHECK (pending_action IN ('','PROVISION','SCALE','UPGRADE','DELETE')),
  requested_by text NOT NULL,
  approved_by text NOT NULL DEFAULT '',
  approved_at timestamptz,
  idempotency_key text NOT NULL,
  request_digest text NOT NULL CHECK (request_digest LIKE 'sha256:%'),
  task_attempt integer NOT NULL DEFAULT 0 CHECK (task_attempt >= 0),
  phase text NOT NULL DEFAULT '',
  last_error text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  UNIQUE(project_id,idempotency_key),
  UNIQUE(management_cluster_id,namespace,resource_name)
);
CREATE UNIQUE INDEX IF NOT EXISTS provider_clusters_live_name_uq ON provider_clusters(project_id,name) WHERE state <> 'DELETED';
CREATE INDEX IF NOT EXISTS provider_clusters_management_state_idx ON provider_clusters(management_cluster_id,state,updated_at);

COMMIT;
