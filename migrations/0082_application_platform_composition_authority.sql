BEGIN;
-- APPLICATION_PLATFORM_COMPOSITION_AUTHORITY_V1
-- ROLLING_SAFE: all tables are independent additive authorities. Existing
-- binaries ignore them; new writers bind environment promotion to the exact
-- active WorkspaceBinding revision and immutable release digest.

CREATE TABLE IF NOT EXISTS application_platform_authorities (
    id text PRIMARY KEY,
    project_id text NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision = 1),
    kind text NOT NULL CHECK (kind IN ('WORKLOAD_TYPE','CAPABILITY_TRAIT','MANAGED_RESOURCE_TYPE','WORKSPACE_PROFILE','APPLICATION_RELEASE')),
    name text NOT NULL,
    version text NOT NULL,
    digest text NOT NULL CHECK (digest ~ '^sha256:[0-9a-f]{64}$'),
    payload jsonb NOT NULL,
    created_by text NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

CREATE UNIQUE INDEX application_platform_authority_identity_unique
    ON application_platform_authorities(project_id,kind,lower(name),version);
CREATE INDEX application_platform_authority_project_kind_idx
    ON application_platform_authorities(project_id,kind,lower(name),version,id);

CREATE OR REPLACE FUNCTION reject_application_platform_authority_mutation() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'application platform authorities are immutable';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS application_platform_authorities_immutable ON application_platform_authorities;
CREATE TRIGGER application_platform_authorities_immutable
  BEFORE UPDATE OR DELETE ON application_platform_authorities
  FOR EACH ROW EXECUTE FUNCTION reject_application_platform_authority_mutation();

CREATE TABLE IF NOT EXISTS application_environment_bindings (
    id text PRIMARY KEY,
    project_id text NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK (revision >= 1),
    release_id text NOT NULL REFERENCES application_platform_authorities(id) ON DELETE RESTRICT,
    release_digest text NOT NULL CHECK (release_digest ~ '^sha256:[0-9a-f]{64}$'),
    workspace_id text NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
    workspace_binding_id text NOT NULL REFERENCES workspace_bindings(id) ON DELETE RESTRICT,
    workspace_binding_revision bigint NOT NULL CHECK (workspace_binding_revision >= 1),
    cluster_id text NOT NULL REFERENCES managed_clusters(id) ON DELETE RESTRICT,
    namespace text NOT NULL,
    environment text NOT NULL CHECK (environment IN ('development','staging','production')),
    capability_resolution_digest text NOT NULL CHECK (capability_resolution_digest ~ '^sha256:[0-9a-f]{64}$'),
    digest text NOT NULL CHECK (digest ~ '^sha256:[0-9a-f]{64}$'),
    created_by text NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

CREATE UNIQUE INDEX application_environment_binding_scope_unique
    ON application_environment_bindings(project_id,workspace_binding_id,environment);
CREATE INDEX application_environment_binding_project_idx
    ON application_environment_bindings(project_id,environment,updated_at DESC,id);

CREATE OR REPLACE FUNCTION validate_application_environment_binding() RETURNS trigger AS $$
DECLARE
  rel_project text; rel_digest text; rel_kind text;
  wsb_project text; wsb_workspace text; wsb_cluster text; wsb_namespace text; wsb_state text; wsb_revision bigint;
BEGIN
  SELECT project_id,digest,kind INTO rel_project,rel_digest,rel_kind
    FROM application_platform_authorities WHERE id=NEW.release_id;
  IF rel_project IS NULL OR rel_kind <> 'APPLICATION_RELEASE' OR rel_project <> NEW.project_id OR rel_digest <> NEW.release_digest THEN
    RAISE EXCEPTION 'environment binding release authority mismatch';
  END IF;

  SELECT project_id,workspace_id,cluster_id,namespace,state,revision
    INTO wsb_project,wsb_workspace,wsb_cluster,wsb_namespace,wsb_state,wsb_revision
    FROM workspace_bindings WHERE id=NEW.workspace_binding_id;
  IF wsb_project IS NULL OR wsb_state <> 'ACTIVE'
     OR wsb_project <> NEW.project_id OR wsb_workspace <> NEW.workspace_id
     OR wsb_cluster <> NEW.cluster_id OR wsb_namespace <> NEW.namespace
     OR wsb_revision <> NEW.workspace_binding_revision THEN
    RAISE EXCEPTION 'environment binding WorkspaceBinding authority mismatch';
  END IF;

  IF TG_OP='UPDATE' THEN
    IF NEW.project_id <> OLD.project_id OR NEW.workspace_id <> OLD.workspace_id
       OR NEW.workspace_binding_id <> OLD.workspace_binding_id
       OR NEW.workspace_binding_revision <> OLD.workspace_binding_revision
       OR NEW.cluster_id <> OLD.cluster_id OR NEW.namespace <> OLD.namespace
       OR NEW.environment <> OLD.environment OR NEW.created_at <> OLD.created_at
       OR NEW.revision <> OLD.revision + 1 THEN
      RAISE EXCEPTION 'environment binding promotion may only advance release/resolution with revision +1';
    END IF;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS application_environment_bindings_guard ON application_environment_bindings;
CREATE TRIGGER application_environment_bindings_guard
  BEFORE INSERT OR UPDATE ON application_environment_bindings
  FOR EACH ROW EXECUTE FUNCTION validate_application_environment_binding();

COMMIT;
