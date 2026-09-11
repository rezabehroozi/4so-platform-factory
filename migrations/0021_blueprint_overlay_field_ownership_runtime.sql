CREATE TYPE blueprint_overlay_scope AS ENUM ('PROVIDER','ENVIRONMENT');

CREATE TABLE blueprint_overlays (
    id text PRIMARY KEY,
    project_id text NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision = 1),
    name text NOT NULL,
    version text NOT NULL,
    scope blueprint_overlay_scope NOT NULL,
    scope_key text NOT NULL,
    digest text NOT NULL CHECK (digest LIKE 'sha256:%'),
    changes jsonb NOT NULL,
    created_by text NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT blueprint_overlay_changes_array CHECK (jsonb_typeof(changes) = 'array' AND jsonb_array_length(changes) > 0)
);
CREATE UNIQUE INDEX blueprint_overlay_identity_unique ON blueprint_overlays(project_id, lower(name), version);

CREATE INDEX blueprint_overlays_project_scope_idx ON blueprint_overlays(project_id, scope, scope_key, name, version);
CREATE TRIGGER blueprint_overlays_immutable BEFORE UPDATE OR DELETE ON blueprint_overlays
FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();
CREATE TRIGGER blueprint_overlays_no_truncate BEFORE TRUNCATE ON blueprint_overlays
FOR EACH STATEMENT EXECUTE FUNCTION reject_append_only_truncate();

ALTER TABLE blueprint_revisions
    ADD COLUMN base_blueprint_digest text,
    ADD COLUMN overlay_digest text,
    ADD COLUMN ownership_digest text,
    ADD COLUMN provider_overlay_id text REFERENCES blueprint_overlays(id) ON DELETE RESTRICT,
    ADD COLUMN environment_overlay_id text REFERENCES blueprint_overlays(id) ON DELETE RESTRICT,
    ADD COLUMN base_payload jsonb,
    ADD COLUMN resolution_payload jsonb;

UPDATE blueprint_revisions
SET base_blueprint_digest = blueprint_digest,
    overlay_digest = 'sha256:0000000000000000000000000000000000000000000000000000000000000000',
    ownership_digest = 'sha256:0000000000000000000000000000000000000000000000000000000000000000',
    base_payload = payload,
    resolution_payload = '{"fields":[],"migration":"historical-pre-overlay"}'::jsonb
WHERE base_blueprint_digest IS NULL;

ALTER TABLE blueprint_revisions
    ALTER COLUMN base_blueprint_digest SET NOT NULL,
    ALTER COLUMN overlay_digest SET NOT NULL,
    ALTER COLUMN ownership_digest SET NOT NULL,
    ALTER COLUMN base_payload SET NOT NULL,
    ALTER COLUMN resolution_payload SET NOT NULL,
    ADD CONSTRAINT blueprint_revision_base_digest_shape CHECK (base_blueprint_digest LIKE 'sha256:%'),
    ADD CONSTRAINT blueprint_revision_overlay_digest_shape CHECK (overlay_digest LIKE 'sha256:%'),
    ADD CONSTRAINT blueprint_revision_ownership_digest_shape CHECK (ownership_digest LIKE 'sha256:%');

CREATE INDEX blueprint_revisions_overlay_idx ON blueprint_revisions(provider_overlay_id, environment_overlay_id);

ALTER TABLE blueprint_revisions DROP CONSTRAINT blueprint_revision_immutable_unique;
ALTER TABLE blueprint_revisions ADD CONSTRAINT blueprint_revision_resolution_unique
    UNIQUE(project_id, blueprint_digest, catalog_digest, base_blueprint_digest, overlay_digest, ownership_digest);

-- Defense in depth: a direct SQL writer cannot attach an overlay from another
-- project or swap PROVIDER/ENVIRONMENT scopes on an immutable revision.
CREATE FUNCTION validate_blueprint_revision_overlay_scope() RETURNS trigger AS $$
DECLARE
    overlay_project text;
    overlay_scope text;
BEGIN
    IF NEW.provider_overlay_id IS NOT NULL THEN
        SELECT project_id, scope::text INTO overlay_project, overlay_scope
          FROM blueprint_overlays WHERE id = NEW.provider_overlay_id;
        IF overlay_project IS NULL OR overlay_project <> NEW.project_id OR overlay_scope <> 'PROVIDER' THEN
            RAISE EXCEPTION 'provider overlay must belong to the same project and have PROVIDER scope';
        END IF;
    END IF;
    IF NEW.environment_overlay_id IS NOT NULL THEN
        SELECT project_id, scope::text INTO overlay_project, overlay_scope
          FROM blueprint_overlays WHERE id = NEW.environment_overlay_id;
        IF overlay_project IS NULL OR overlay_project <> NEW.project_id OR overlay_scope <> 'ENVIRONMENT' THEN
            RAISE EXCEPTION 'environment overlay must belong to the same project and have ENVIRONMENT scope';
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER blueprint_revisions_overlay_scope_guard
BEFORE INSERT ON blueprint_revisions
FOR EACH ROW EXECUTE FUNCTION validate_blueprint_revision_overlay_scope();
