BEGIN;

CREATE TABLE IF NOT EXISTS entitlements (
  id text PRIMARY KEY,
  organization_id text NOT NULL UNIQUE REFERENCES organizations(id) ON DELETE CASCADE,
  revision bigint NOT NULL CHECK (revision > 0),
  edition text NOT NULL CHECK (edition IN ('pilot','enterprise','service-provider')),
  max_tenants integer NOT NULL CHECK (max_tenants > 0),
  oem_enabled boolean NOT NULL,
  features jsonb NOT NULL DEFAULT '[]'::jsonb,
  expires_at timestamptz,
  issued_by text NOT NULL,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS oem_profiles (
  id text PRIMARY KEY,
  organization_id text NOT NULL UNIQUE REFERENCES organizations(id) ON DELETE CASCADE,
  revision bigint NOT NULL CHECK (revision > 0),
  brand_name text NOT NULL,
  product_title text NOT NULL,
  support_url text NOT NULL DEFAULT '',
  logo_object_ref text NOT NULL DEFAULT '',
  accent_color text NOT NULL DEFAULT '',
  custom_domain text NOT NULL DEFAULT '',
  default_locale text NOT NULL CHECK (default_locale IN ('fa','en')),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS tenant_environments (
  id text PRIMARY KEY,
  organization_id text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  project_id text NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  cluster_id text NOT NULL REFERENCES managed_clusters(id) ON DELETE RESTRICT,
  revision bigint NOT NULL CHECK (revision > 0),
  name text NOT NULL,
  display_name text NOT NULL,
  plan_name text NOT NULL CHECK (plan_name IN ('small','medium','large')),
  namespace text NOT NULL UNIQUE,
  state text NOT NULL CHECK (state IN ('QUEUED','PROVISIONING','ACTIVE','SUSPEND_QUEUED','SUSPENDING','SUSPENDED','RESUME_QUEUED','RESUMING','DELETE_QUEUED','DELETING','DELETED','FAILED')),
  quota jsonb NOT NULL,
  desired_digest text NOT NULL CHECK (desired_digest LIKE 'sha256:%'),
  observed_digest text NOT NULL DEFAULT '',
  requested_by text NOT NULL,
  idempotency_key text NOT NULL,
  request_digest text NOT NULL CHECK (request_digest LIKE 'sha256:%'),
  task_attempt integer NOT NULL DEFAULT 0 CHECK (task_attempt >= 0),
  pending_action text NOT NULL DEFAULT 'PROVISION' CHECK (pending_action IN ('','PROVISION','SUSPEND','RESUME','DELETE')),
  last_error text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  UNIQUE(project_id,idempotency_key)
);
CREATE UNIQUE INDEX IF NOT EXISTS tenant_environments_live_name_uq ON tenant_environments(project_id,name) WHERE state <> 'DELETED';
CREATE INDEX IF NOT EXISTS tenant_environments_cluster_state_idx ON tenant_environments(cluster_id,state,created_at);

COMMIT;
