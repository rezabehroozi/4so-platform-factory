CREATE TABLE IF NOT EXISTS workspaces (
    id text PRIMARY KEY,
    project_id text NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision = 1),
    name text NOT NULL,
    display_name text NOT NULL,
    description text NOT NULL DEFAULT '',
    digest text NOT NULL CHECK (digest ~ '^sha256:[0-9a-f]{64}$'),
    created_by text NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT workspace_identity_unique UNIQUE(project_id, lower(name))
);

CREATE INDEX IF NOT EXISTS workspaces_project_name_idx
    ON workspaces(project_id, lower(name), id);

CREATE TRIGGER workspaces_immutable BEFORE UPDATE OR DELETE ON workspaces
FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();
CREATE TRIGGER workspaces_no_truncate BEFORE TRUNCATE ON workspaces
FOR EACH STATEMENT EXECUTE FUNCTION reject_append_only_truncate();

CREATE TABLE IF NOT EXISTS workspace_bindings (
    id text PRIMARY KEY,
    workspace_id text NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
    project_id text NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    cluster_id text NOT NULL REFERENCES managed_clusters(id) ON DELETE RESTRICT,
    namespace text NOT NULL,
    state text NOT NULL CHECK (state IN ('ACTIVE','REVOKED')),
    revision bigint NOT NULL CHECK (revision >= 1),
    created_by text NOT NULL,
    revoked_by text,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CHECK ((state='ACTIVE' AND revoked_by IS NULL AND revoked_at IS NULL) OR
           (state='REVOKED' AND revoked_by IS NOT NULL AND revoked_at IS NOT NULL)),
    CHECK (namespace ~ '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$')
);

CREATE UNIQUE INDEX IF NOT EXISTS workspace_bindings_active_scope_unique
    ON workspace_bindings(project_id, cluster_id, lower(namespace)) WHERE state='ACTIVE';
CREATE INDEX IF NOT EXISTS workspace_bindings_workspace_idx
    ON workspace_bindings(workspace_id, state, cluster_id, lower(namespace), id);

CREATE OR REPLACE FUNCTION validate_workspace_binding_authority() RETURNS trigger AS $$
DECLARE
    workspace_project text;
    cluster_project text;
BEGIN
    SELECT project_id INTO workspace_project FROM workspaces WHERE id=NEW.workspace_id;
    SELECT project_id INTO cluster_project FROM managed_clusters WHERE id=NEW.cluster_id;
    IF workspace_project IS NULL OR cluster_project IS NULL THEN
        RAISE EXCEPTION 'workspace binding authority reference does not exist';
    END IF;
    IF workspace_project <> NEW.project_id OR cluster_project <> NEW.project_id THEN
        RAISE EXCEPTION 'workspace binding cross-project authority is forbidden';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER workspace_bindings_authority_guard BEFORE INSERT OR UPDATE ON workspace_bindings
FOR EACH ROW EXECUTE FUNCTION validate_workspace_binding_authority();
CREATE TRIGGER workspace_bindings_no_truncate BEFORE TRUNCATE ON workspace_bindings
FOR EACH STATEMENT EXECUTE FUNCTION reject_append_only_truncate();
