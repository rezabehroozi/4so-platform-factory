BEGIN;

CREATE TABLE virtual_clusters (
  id text PRIMARY KEY,
  project_id text NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  workspace_id text NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
  workspace_binding_id text NOT NULL REFERENCES workspace_bindings(id) ON DELETE RESTRICT,
  host_cluster_id text NOT NULL REFERENCES managed_clusters(id) ON DELETE RESTRICT,
  host_namespace text NOT NULL,
  revision bigint NOT NULL CHECK (revision > 0),
  name text NOT NULL,
  profile text NOT NULL CHECK (profile IN ('developer','team')),
  developer_mode boolean NOT NULL,
  kubernetes_version text NOT NULL,
  cpu_milli integer NOT NULL CHECK (cpu_milli >= 250),
  memory_mib integer NOT NULL CHECK (memory_mib >= 512),
  storage_gib integer NOT NULL CHECK (storage_gib >= 1),
  max_namespaces integer NOT NULL CHECK (max_namespaces >= 1),
  sleep_after_minutes integer NOT NULL DEFAULT 0 CHECK (sleep_after_minutes >= 0),
  desired_digest text NOT NULL CHECK (desired_digest ~ '^sha256:[0-9a-f]{64}$'),
  state text NOT NULL CHECK (state IN ('REQUESTED','PROVISIONING','ACTIVE','SUSPENDING','SUSPENDED','RESUMING','DELETING','DELETED','RECOVERY_REQUIRED','FAILED')),
  pending_action text NOT NULL DEFAULT '' CHECK (pending_action IN ('','PROVISION','SUSPEND','RESUME','DELETE')),
  requested_by text NOT NULL,
  idempotency_key text NOT NULL,
  request_digest text NOT NULL CHECK (request_digest ~ '^sha256:[0-9a-f]{64}$'),
  last_error text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  UNIQUE(project_id,idempotency_key)
);

CREATE UNIQUE INDEX virtual_clusters_live_workspace_name_uq
  ON virtual_clusters(workspace_id,name)
  WHERE state <> 'DELETED';
CREATE INDEX virtual_clusters_project_state_idx ON virtual_clusters(project_id,state,updated_at);
CREATE INDEX virtual_clusters_host_state_idx ON virtual_clusters(host_cluster_id,state,updated_at);

COMMIT;
