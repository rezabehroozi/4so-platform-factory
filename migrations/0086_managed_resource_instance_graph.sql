BEGIN;
-- MANAGED_RESOURCE_INSTANCE_AUTHORITY_V1
-- ROLLING_SAFE: introduces new PostgreSQL authorities only. Existing
-- ManagedResourceType/ApplicationRelease/EnvironmentBinding writers are
-- unchanged. Target CRDs/providers remain executors/observed state, not SoT.

CREATE TABLE IF NOT EXISTS application_managed_resource_instances (
  id text PRIMARY KEY,
  project_id text NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  revision bigint NOT NULL CHECK (revision > 0),
  type_id text NOT NULL REFERENCES application_platform_authorities(id) ON DELETE RESTRICT,
  type_digest text NOT NULL CHECK (type_digest ~ '^sha256:[0-9a-f]{64}$'),
  name text NOT NULL CHECK (name ~ '^[a-z][a-z0-9]*([._-][a-z0-9]+)*$'),
  input_digest text NOT NULL CHECK (input_digest ~ '^sha256:[0-9a-f]{64}$'),
  plan_digest text NOT NULL CHECK (plan_digest ~ '^sha256:[0-9a-f]{64}$'),
  dependency_instance_ids jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(dependency_instance_ids)='array'),
  state text NOT NULL CHECK (state IN ('REQUESTED','PROVISIONING','READY','DELETING','RETAINED','DELETED','RECOVERY_REQUIRED','FAILED')),
  outputs jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(outputs)='array'),
  outputs_digest text NOT NULL DEFAULT '' CHECK (outputs_digest='' OR outputs_digest ~ '^sha256:[0-9a-f]{64}$'),
  observed_digest text NOT NULL DEFAULT '' CHECK (observed_digest='' OR observed_digest ~ '^sha256:[0-9a-f]{64}$'),
  last_evidence_digest text NOT NULL DEFAULT '' CHECK (last_evidence_digest='' OR last_evidence_digest ~ '^sha256:[0-9a-f]{64}$'),
  last_error text NOT NULL DEFAULT '' CHECK (octet_length(last_error) <= 8192),
  created_by text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS application_managed_resource_instances_live_name_uq
  ON application_managed_resource_instances(project_id, lower(name))
  WHERE state <> 'DELETED';
CREATE INDEX IF NOT EXISTS application_managed_resource_instances_project_state_idx
  ON application_managed_resource_instances(project_id, state, updated_at DESC, id);
CREATE INDEX IF NOT EXISTS application_managed_resource_instances_type_idx
  ON application_managed_resource_instances(project_id, type_id, state, id);

CREATE TABLE IF NOT EXISTS application_managed_resource_bindings (
  id text PRIMARY KEY,
  project_id text NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  instance_id text NOT NULL REFERENCES application_managed_resource_instances(id) ON DELETE RESTRICT,
  instance_revision bigint NOT NULL CHECK (instance_revision > 0),
  environment_binding_id text NOT NULL REFERENCES application_environment_bindings(id) ON DELETE CASCADE,
  environment_digest text NOT NULL CHECK (environment_digest ~ '^sha256:[0-9a-f]{64}$'),
  output_names jsonb NOT NULL CHECK (jsonb_typeof(output_names)='array'),
  outputs_digest text NOT NULL CHECK (outputs_digest ~ '^sha256:[0-9a-f]{64}$'),
  digest text NOT NULL CHECK (digest ~ '^sha256:[0-9a-f]{64}$'),
  created_by text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS application_managed_resource_bindings_scope_uq
  ON application_managed_resource_bindings(instance_id, environment_binding_id, digest);
CREATE INDEX IF NOT EXISTS application_managed_resource_bindings_environment_idx
  ON application_managed_resource_bindings(project_id, environment_binding_id, created_at DESC, id);

COMMIT;
