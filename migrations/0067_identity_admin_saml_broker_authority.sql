-- Enterprise SAML remains brokered by managed Keycloak. Platform persists only
-- product-owned desired state, durable job coordination, public trust material
-- and evidence digests. Keycloak admin credentials are never stored here.
CREATE TABLE saml_brokers (
  id text PRIMARY KEY,
  revision bigint NOT NULL CHECK (revision > 0),
  organization_id text NOT NULL REFERENCES organizations(id),
  alias text NOT NULL,
  keycloak_alias text NOT NULL UNIQUE,
  display_name text NOT NULL,
  entity_id text NOT NULL,
  single_sign_on_service_url text NOT NULL,
  single_logout_service_url text NOT NULL DEFAULT '',
  signing_certificate text NOT NULL,
  name_id_policy_format text NOT NULL,
  want_authn_requests_signed boolean NOT NULL DEFAULT true,
  enabled boolean NOT NULL DEFAULT true,
  state text NOT NULL CHECK (state IN ('PENDING_APPROVAL','QUEUED','RECONCILING','READY','ERROR','DELETING','DELETED')),
  desired_digest text NOT NULL,
  observed_digest text NOT NULL DEFAULT '',
  requested_by text NOT NULL,
  last_error text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  UNIQUE(organization_id,alias)
);
CREATE INDEX saml_brokers_organization_state_idx ON saml_brokers(organization_id,state,created_at,id);

CREATE TABLE identity_admin_jobs (
  id text PRIMARY KEY,
  revision bigint NOT NULL CHECK (revision > 0),
  organization_id text NOT NULL REFERENCES organizations(id),
  broker_id text NOT NULL REFERENCES saml_brokers(id),
  broker_revision bigint NOT NULL CHECK (broker_revision > 0),
  kind text NOT NULL CHECK (kind IN ('UPSERT_SAML_BROKER','DELETE_SAML_BROKER')),
  state text NOT NULL CHECK (state IN ('AWAITING_APPROVAL','QUEUED','RUNNING','SUCCEEDED','FAILED')),
  idempotency_key text NOT NULL,
  request_digest text NOT NULL,
  desired_digest text NOT NULL,
  requested_by text NOT NULL,
  approved_by text NOT NULL DEFAULT '',
  approved_at timestamptz,
  task_attempt integer NOT NULL DEFAULT 0 CHECK (task_attempt >= 0),
  task_fence_token bigint NOT NULL DEFAULT 0 CHECK (task_fence_token >= 0),
  task_lease_owner text NOT NULL DEFAULT '',
  task_lease_expires_at timestamptz,
  started_at timestamptz,
  finished_at timestamptz,
  evidence_digest text NOT NULL DEFAULT '',
  last_error text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  UNIQUE(organization_id,idempotency_key)
);
CREATE INDEX identity_admin_jobs_queue_idx ON identity_admin_jobs(state,task_lease_expires_at,created_at,id);
CREATE INDEX identity_admin_jobs_organization_idx ON identity_admin_jobs(organization_id,created_at,id);
