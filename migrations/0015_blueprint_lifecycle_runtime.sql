CREATE TABLE blueprint_releases (
    id text PRIMARY KEY,
    project_id text NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK (revision > 0),
    blueprint_name text NOT NULL,
    blueprint_version text NOT NULL,
    state text NOT NULL CHECK (state IN ('DRAFT','REVIEW','PUBLISHED','DEPRECATED','REVOKED')),
    current_revision_id text NOT NULL REFERENCES blueprint_revisions(id) ON DELETE RESTRICT,
    current_blueprint_digest text NOT NULL CHECK (current_blueprint_digest LIKE 'sha256:%'),
    catalog_digest text NOT NULL CHECK (catalog_digest LIKE 'sha256:%'),
    source_release_id text REFERENCES blueprint_releases(id) ON DELETE RESTRICT,
    upgrade_from_ids jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(upgrade_from_ids) = 'array'),
    execution_ready boolean NOT NULL DEFAULT false,
    plan_status text NOT NULL DEFAULT 'planning-only',
    requested_by text NOT NULL,
    review_requested_at timestamptz,
    published_by text,
    published_at timestamptz,
    deprecated_by text,
    deprecated_at timestamptz,
    revoked_by text,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT blueprint_release_source_not_self CHECK (source_release_id IS NULL OR source_release_id <> id),
    CONSTRAINT blueprint_release_publish_shape CHECK ((published_by IS NULL) = (published_at IS NULL)),
    CONSTRAINT blueprint_release_deprecate_shape CHECK ((deprecated_by IS NULL) = (deprecated_at IS NULL)),
    CONSTRAINT blueprint_release_revoke_shape CHECK ((revoked_by IS NULL) = (revoked_at IS NULL))
);

CREATE UNIQUE INDEX blueprint_releases_project_name_version_unique
    ON blueprint_releases(project_id, lower(blueprint_name), blueprint_version);
CREATE INDEX blueprint_releases_project_state_idx ON blueprint_releases(project_id, state, blueprint_name, blueprint_version);
CREATE INDEX blueprint_releases_current_revision_idx ON blueprint_releases(current_revision_id);

CREATE OR REPLACE FUNCTION validate_blueprint_release_update() RETURNS trigger AS $$
BEGIN
    IF NEW.revision <> OLD.revision + 1 THEN
        RAISE EXCEPTION 'blueprint release revision must increment by exactly one';
    END IF;
    IF NEW.project_id <> OLD.project_id OR lower(NEW.blueprint_name) <> lower(OLD.blueprint_name) OR NEW.blueprint_version <> OLD.blueprint_version OR NEW.created_at <> OLD.created_at THEN
        RAISE EXCEPTION 'blueprint release identity is immutable';
    END IF;
    IF OLD.state IN ('PUBLISHED','DEPRECATED','REVOKED') AND (
        NEW.current_revision_id <> OLD.current_revision_id OR
        NEW.current_blueprint_digest <> OLD.current_blueprint_digest OR
        NEW.catalog_digest <> OLD.catalog_digest OR
        NEW.upgrade_from_ids <> OLD.upgrade_from_ids OR
        NEW.execution_ready <> OLD.execution_ready OR
        NEW.plan_status <> OLD.plan_status
    ) THEN
        RAISE EXCEPTION 'published blueprint release content is immutable';
    END IF;
    IF NOT (
        (OLD.state = 'DRAFT' AND NEW.state IN ('DRAFT','REVIEW')) OR
        (OLD.state = 'REVIEW' AND NEW.state IN ('DRAFT','PUBLISHED')) OR
        (OLD.state = 'PUBLISHED' AND NEW.state IN ('DEPRECATED','REVOKED')) OR
        (OLD.state = 'DEPRECATED' AND NEW.state = 'REVOKED')
    ) THEN
        RAISE EXCEPTION 'invalid blueprint release lifecycle transition % -> %', OLD.state, NEW.state;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER blueprint_releases_validate_update
BEFORE UPDATE ON blueprint_releases
FOR EACH ROW EXECUTE FUNCTION validate_blueprint_release_update();
