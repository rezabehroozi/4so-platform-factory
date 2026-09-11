CREATE TABLE IF NOT EXISTS variable_schemas (
    id text PRIMARY KEY,
    project_id text NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision = 1),
    name text NOT NULL,
    version text NOT NULL,
    digest text NOT NULL CHECK (digest ~ '^sha256:[0-9a-f]{64}$'),
    variables jsonb NOT NULL,
    created_by text NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT variable_schema_identity_unique UNIQUE(project_id, lower(name), version),
    CONSTRAINT variable_schema_variables_array CHECK (jsonb_typeof(variables) = 'array' AND jsonb_array_length(variables) BETWEEN 1 AND 128)
);

CREATE INDEX IF NOT EXISTS variable_schemas_project_name_idx
    ON variable_schemas(project_id, lower(name), version, id);

CREATE TRIGGER variable_schemas_immutable BEFORE UPDATE OR DELETE ON variable_schemas
FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();
CREATE TRIGGER variable_schemas_no_truncate BEFORE TRUNCATE ON variable_schemas
FOR EACH STATEMENT EXECUTE FUNCTION reject_append_only_truncate();
