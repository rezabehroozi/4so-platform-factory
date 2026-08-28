CREATE TABLE IF NOT EXISTS schema_migrations (
    version bigint PRIMARY KEY,
    applied_at timestamptz NOT NULL DEFAULT now(),
    checksum text NOT NULL
);

CREATE TABLE organizations (
    id text PRIMARY KEY,
    revision bigint NOT NULL CHECK (revision > 0),
    name text NOT NULL,
    display_name text NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT organizations_name_key UNIQUE (lower(name))
);

CREATE TABLE projects (
    id text PRIMARY KEY,
    organization_id text NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK (revision > 0),
    name text NOT NULL,
    display_name text NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);
CREATE UNIQUE INDEX projects_org_name_key ON projects(organization_id, lower(name));

CREATE TABLE blueprint_revisions (
    id text PRIMARY KEY,
    project_id text NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision = 1),
    blueprint_name text NOT NULL,
    blueprint_version text NOT NULL,
    blueprint_digest text NOT NULL CHECK (blueprint_digest LIKE 'sha256:%'),
    catalog_digest text NOT NULL CHECK (catalog_digest LIKE 'sha256:%'),
    payload jsonb NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT blueprint_revision_immutable_unique UNIQUE(project_id, blueprint_digest, catalog_digest)
);

CREATE TABLE assignments (
    id text PRIMARY KEY,
    project_id text NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK (revision > 0),
    target_ref text NOT NULL,
    blueprint_revision_id text NOT NULL REFERENCES blueprint_revisions(id) ON DELETE RESTRICT,
    desired_generation bigint NOT NULL CHECK (desired_generation > 0),
    observed_generation bigint NOT NULL DEFAULT 0 CHECK (observed_generation >= 0 AND observed_generation <= desired_generation),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT assignments_project_target_key UNIQUE(project_id, target_ref)
);

CREATE TYPE operation_state AS ENUM (
    'DRAFT','PLANNING','PLAN_FAILED','AWAITING_APPROVAL','APPROVED','QUEUED',
    'RUNNING','VERIFYING','SUCCEEDED','FAILED','ROLLING_BACK','ROLLED_BACK','CANCELLED'
);

CREATE TABLE operations (
    id text PRIMARY KEY,
    project_id text NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK (revision > 0),
    kind text NOT NULL,
    target_ref text NOT NULL,
    desired_revision text NOT NULL,
    state operation_state NOT NULL,
    risk text NOT NULL CHECK (risk IN ('low','medium','high','critical')),
    idempotency_key text NOT NULL,
    request_digest text NOT NULL CHECK (request_digest LIKE 'sha256:%'),
    actor_id text NOT NULL,
    lease_owner text,
    lease_expires_at timestamptz,
    fence_token bigint NOT NULL DEFAULT 0 CHECK (fence_token >= 0),
    last_error text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT operations_idempotency_key UNIQUE(project_id, idempotency_key),
    CONSTRAINT operation_lease_shape CHECK ((lease_owner IS NULL) = (lease_expires_at IS NULL))
);
CREATE INDEX operations_project_created_idx ON operations(project_id, created_at, id);
CREATE INDEX operations_runnable_idx ON operations(state, lease_expires_at) WHERE state IN ('QUEUED','RUNNING','VERIFYING','ROLLING_BACK');

CREATE TABLE operation_steps (
    id text PRIMARY KEY,
    operation_id text NOT NULL REFERENCES operations(id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK (revision > 0),
    step_key text NOT NULL,
    state operation_state NOT NULL,
    attempt integer NOT NULL CHECK (attempt > 0),
    fence_token bigint NOT NULL CHECK (fence_token > 0),
    started_at timestamptz,
    finished_at timestamptz,
    last_error text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT operation_steps_operation_key UNIQUE(operation_id, step_key),
    CONSTRAINT operation_step_time_order CHECK (finished_at IS NULL OR started_at IS NULL OR finished_at >= started_at)
);

CREATE TABLE outbox_events (
    id text PRIMARY KEY,
    revision bigint NOT NULL CHECK (revision > 0),
    aggregate_type text NOT NULL,
    aggregate_id text NOT NULL,
    event_type text NOT NULL,
    payload jsonb NOT NULL,
    available_at timestamptz NOT NULL,
    claimed_by text,
    claimed_until timestamptz,
    attempt integer NOT NULL DEFAULT 0 CHECK (attempt >= 0),
    published_at timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT outbox_claim_shape CHECK ((claimed_by IS NULL) = (claimed_until IS NULL))
);
CREATE INDEX outbox_available_idx ON outbox_events(available_at, id) WHERE published_at IS NULL;

CREATE TABLE audit_events (
    id text PRIMARY KEY,
    occurred_at timestamptz NOT NULL,
    actor_id text NOT NULL,
    action text NOT NULL,
    resource_type text NOT NULL,
    resource_id text NOT NULL,
    resource_revision bigint NOT NULL CHECK (resource_revision > 0),
    request_id text,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX audit_resource_idx ON audit_events(resource_type, resource_id, occurred_at, id);
CREATE INDEX audit_actor_idx ON audit_events(actor_id, occurred_at, id);

CREATE OR REPLACE FUNCTION reject_audit_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER audit_events_no_update BEFORE UPDATE OR DELETE ON audit_events
FOR EACH ROW EXECUTE FUNCTION reject_audit_mutation();

CREATE TABLE evidence_metadata (
    id text PRIMARY KEY,
    operation_id text NOT NULL REFERENCES operations(id) ON DELETE RESTRICT,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision = 1),
    kind text NOT NULL,
    digest text NOT NULL CHECK (digest LIKE 'sha256:%'),
    media_type text NOT NULL,
    location text NOT NULL,
    size_bytes bigint NOT NULL CHECK (size_bytes >= 0),
    sealed boolean NOT NULL DEFAULT true CHECK (sealed),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT evidence_operation_digest_key UNIQUE(operation_id, digest)
);

CREATE OR REPLACE FUNCTION reject_immutable_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'immutable control-plane resource cannot be updated or deleted';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER blueprint_revisions_immutable BEFORE UPDATE OR DELETE ON blueprint_revisions
FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();
CREATE TRIGGER evidence_metadata_immutable BEFORE UPDATE OR DELETE ON evidence_metadata
FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();
