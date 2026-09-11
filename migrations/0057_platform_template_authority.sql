CREATE TABLE IF NOT EXISTS platform_policy_sets (
    id text PRIMARY KEY,
    project_id text NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision = 1),
    name text NOT NULL,
    version text NOT NULL,
    digest text NOT NULL CHECK (digest ~ '^sha256:[0-9a-f]{64}$'),
    maintenance jsonb NOT NULL CHECK (jsonb_typeof(maintenance) = 'object'),
    backup jsonb NOT NULL CHECK (jsonb_typeof(backup) = 'object'),
    security jsonb NOT NULL CHECK (jsonb_typeof(security) = 'object'),
    created_by text NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);
CREATE UNIQUE INDEX platform_policy_set_identity_unique ON platform_policy_sets(project_id, lower(name), version);

CREATE INDEX IF NOT EXISTS platform_policy_sets_project_name_idx
    ON platform_policy_sets(project_id, lower(name), version, id);

CREATE TRIGGER platform_policy_sets_immutable BEFORE UPDATE OR DELETE ON platform_policy_sets
FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();
CREATE TRIGGER platform_policy_sets_no_truncate BEFORE TRUNCATE ON platform_policy_sets
FOR EACH STATEMENT EXECUTE FUNCTION reject_append_only_truncate();

CREATE TABLE IF NOT EXISTS platform_templates (
    id text PRIMARY KEY,
    project_id text NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision = 1),
    name text NOT NULL,
    version text NOT NULL,
    digest text NOT NULL CHECK (digest ~ '^sha256:[0-9a-f]{64}$'),
    blueprint_release_id text NOT NULL REFERENCES blueprint_releases(id) ON DELETE RESTRICT,
    blueprint_digest text NOT NULL CHECK (blueprint_digest ~ '^sha256:[0-9a-f]{64}$'),
    variable_schema_id text NOT NULL REFERENCES variable_schemas(id) ON DELETE RESTRICT,
    variable_schema_digest text NOT NULL CHECK (variable_schema_digest ~ '^sha256:[0-9a-f]{64}$'),
    policy_set_id text NOT NULL REFERENCES platform_policy_sets(id) ON DELETE RESTRICT,
    policy_set_digest text NOT NULL CHECK (policy_set_digest ~ '^sha256:[0-9a-f]{64}$'),
    allowed_target_classes jsonb NOT NULL CHECK (jsonb_typeof(allowed_target_classes) = 'array' AND jsonb_array_length(allowed_target_classes) BETWEEN 1 AND 16),
    certification_requirements jsonb NOT NULL CHECK (jsonb_typeof(certification_requirements) = 'array' AND jsonb_array_length(certification_requirements) BETWEEN 1 AND 16),
    impact jsonb NOT NULL CHECK (jsonb_typeof(impact) = 'object'),
    created_by text NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);
CREATE UNIQUE INDEX platform_template_identity_unique ON platform_templates(project_id, lower(name), version);

CREATE INDEX IF NOT EXISTS platform_templates_project_name_idx
    ON platform_templates(project_id, lower(name), version, id);

CREATE OR REPLACE FUNCTION validate_platform_template_binding() RETURNS trigger AS $$
DECLARE
    blueprint_project text;
    blueprint_state text;
    blueprint_execution_ready boolean;
    current_blueprint_digest text;
    schema_project text;
    current_schema_digest text;
    policy_project text;
    current_policy_digest text;
BEGIN
    SELECT project_id, state, execution_ready, current_blueprint_digest
      INTO blueprint_project, blueprint_state, blueprint_execution_ready, current_blueprint_digest
      FROM blueprint_releases WHERE id = NEW.blueprint_release_id;
    SELECT project_id, digest INTO schema_project, current_schema_digest
      FROM variable_schemas WHERE id = NEW.variable_schema_id;
    SELECT project_id, digest INTO policy_project, current_policy_digest
      FROM platform_policy_sets WHERE id = NEW.policy_set_id;

    IF blueprint_project IS NULL OR schema_project IS NULL OR policy_project IS NULL THEN
        RAISE EXCEPTION 'platform template authority reference does not exist';
    END IF;
    IF blueprint_project <> NEW.project_id OR schema_project <> NEW.project_id OR policy_project <> NEW.project_id THEN
        RAISE EXCEPTION 'platform template cross-project authority binding is forbidden';
    END IF;
    IF blueprint_state <> 'PUBLISHED' OR blueprint_execution_ready IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'platform template requires published execution-ready blueprint release';
    END IF;
    IF current_blueprint_digest <> NEW.blueprint_digest OR current_schema_digest <> NEW.variable_schema_digest OR current_policy_digest <> NEW.policy_set_digest THEN
        RAISE EXCEPTION 'platform template authority digest mismatch';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER platform_templates_binding_guard BEFORE INSERT ON platform_templates
FOR EACH ROW EXECUTE FUNCTION validate_platform_template_binding();
CREATE TRIGGER platform_templates_immutable BEFORE UPDATE OR DELETE ON platform_templates
FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();
CREATE TRIGGER platform_templates_no_truncate BEFORE TRUNCATE ON platform_templates
FOR EACH STATEMENT EXECUTE FUNCTION reject_append_only_truncate();
