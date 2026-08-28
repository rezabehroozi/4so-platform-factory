CREATE TABLE catalog_trust_keys (
    id text PRIMARY KEY,
    organization_id text REFERENCES organizations(id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK (revision > 0),
    name text NOT NULL,
    algorithm text NOT NULL CHECK (algorithm = 'Ed25519'),
    public_key text NOT NULL,
    fingerprint text NOT NULL CHECK (fingerprint LIKE 'sha256:%'),
    state text NOT NULL CHECK (state IN ('ACTIVE','REVOKED')),
    created_by text NOT NULL,
    revoked_by text,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT catalog_trust_key_revoke_shape CHECK ((revoked_by IS NULL) = (revoked_at IS NULL))
);

CREATE UNIQUE INDEX catalog_trust_keys_scope_name_unique
    ON catalog_trust_keys(COALESCE(organization_id,''), lower(name));
CREATE UNIQUE INDEX catalog_trust_keys_scope_fingerprint_unique
    ON catalog_trust_keys(COALESCE(organization_id,''), fingerprint);
CREATE INDEX catalog_trust_keys_scope_state_idx ON catalog_trust_keys(organization_id, state);

CREATE TABLE catalog_revisions (
    id text PRIMARY KEY,
    organization_id text REFERENCES organizations(id) ON DELETE RESTRICT,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision = 1),
    catalog_name text NOT NULL,
    catalog_version text NOT NULL,
    manifest_digest text NOT NULL CHECK (manifest_digest LIKE 'sha256:%'),
    payload jsonb NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT catalog_revision_immutable_time CHECK (created_at = updated_at)
);

CREATE UNIQUE INDEX catalog_revisions_scope_identity_digest_unique
    ON catalog_revisions(COALESCE(organization_id,''), lower(catalog_name), catalog_version, manifest_digest);

CREATE OR REPLACE FUNCTION reject_catalog_revision_update() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'catalog revisions are immutable';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER catalog_revisions_reject_update
BEFORE UPDATE OR DELETE ON catalog_revisions
FOR EACH ROW EXECUTE FUNCTION reject_catalog_revision_update();

CREATE TABLE catalog_releases (
    id text PRIMARY KEY,
    organization_id text REFERENCES organizations(id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK (revision > 0),
    catalog_name text NOT NULL,
    catalog_version text NOT NULL,
    visibility text NOT NULL CHECK (visibility IN ('PLATFORM','PRIVATE')),
    channel text NOT NULL CHECK (channel IN ('CANDIDATE','RENDER','RUNTIME','PRODUCTION')),
    state text NOT NULL CHECK (state IN ('DRAFT','REVIEW','PUBLISHED','DEPRECATED','REVOKED')),
    current_revision_id text NOT NULL REFERENCES catalog_revisions(id) ON DELETE RESTRICT,
    manifest_digest text NOT NULL CHECK (manifest_digest LIKE 'sha256:%'),
    source_release_id text REFERENCES catalog_releases(id) ON DELETE RESTRICT,
    signing_key_id text REFERENCES catalog_trust_keys(id) ON DELETE RESTRICT,
    signing_key_fingerprint text,
    signature text,
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
    CONSTRAINT catalog_release_scope_shape CHECK ((visibility='PLATFORM' AND organization_id IS NULL) OR (visibility='PRIVATE' AND organization_id IS NOT NULL)),
    CONSTRAINT catalog_release_source_not_self CHECK (source_release_id IS NULL OR source_release_id <> id),
    CONSTRAINT catalog_release_signature_shape CHECK ((signing_key_id IS NULL AND signing_key_fingerprint IS NULL AND signature IS NULL) OR (signing_key_id IS NOT NULL AND signing_key_fingerprint IS NOT NULL AND signature IS NOT NULL)),
    CONSTRAINT catalog_release_publish_shape CHECK ((published_by IS NULL) = (published_at IS NULL)),
    CONSTRAINT catalog_release_deprecate_shape CHECK ((deprecated_by IS NULL) = (deprecated_at IS NULL)),
    CONSTRAINT catalog_release_revoke_shape CHECK ((revoked_by IS NULL) = (revoked_at IS NULL))
);

CREATE UNIQUE INDEX catalog_releases_scope_name_version_channel_unique
    ON catalog_releases(COALESCE(organization_id,''), lower(catalog_name), catalog_version, channel);
CREATE INDEX catalog_releases_scope_state_channel_idx ON catalog_releases(organization_id, state, channel);
CREATE INDEX catalog_releases_signing_key_idx ON catalog_releases(signing_key_id);

CREATE OR REPLACE FUNCTION validate_catalog_release_update() RETURNS trigger AS $$
BEGIN
    IF NEW.revision <> OLD.revision + 1 THEN
        RAISE EXCEPTION 'catalog release revision must increment by exactly one';
    END IF;
    IF COALESCE(NEW.organization_id,'') <> COALESCE(OLD.organization_id,'') OR lower(NEW.catalog_name) <> lower(OLD.catalog_name) OR NEW.catalog_version <> OLD.catalog_version OR NEW.visibility <> OLD.visibility OR NEW.channel <> OLD.channel OR COALESCE(NEW.source_release_id,'') <> COALESCE(OLD.source_release_id,'') OR NEW.created_at <> OLD.created_at THEN
        RAISE EXCEPTION 'catalog release identity and promotion source are immutable';
    END IF;
    IF OLD.state IN ('PUBLISHED','DEPRECATED','REVOKED') AND (
        NEW.current_revision_id <> OLD.current_revision_id OR
        NEW.manifest_digest <> OLD.manifest_digest OR
        COALESCE(NEW.signing_key_id,'') <> COALESCE(OLD.signing_key_id,'') OR
        COALESCE(NEW.signing_key_fingerprint,'') <> COALESCE(OLD.signing_key_fingerprint,'') OR
        COALESCE(NEW.signature,'') <> COALESCE(OLD.signature,'')
    ) THEN
        RAISE EXCEPTION 'published catalog release content and signature are immutable';
    END IF;
    IF NOT (
        (OLD.state='DRAFT' AND NEW.state IN ('DRAFT','REVIEW')) OR
        (OLD.state='REVIEW' AND NEW.state IN ('DRAFT','PUBLISHED')) OR
        (OLD.state='PUBLISHED' AND NEW.state IN ('DEPRECATED','REVOKED')) OR
        (OLD.state='DEPRECATED' AND NEW.state='REVOKED')
    ) THEN
        RAISE EXCEPTION 'invalid catalog release lifecycle transition % -> %', OLD.state, NEW.state;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER catalog_releases_validate_update
BEFORE UPDATE ON catalog_releases
FOR EACH ROW EXECUTE FUNCTION validate_catalog_release_update();

ALTER TABLE blueprint_releases
    ADD COLUMN catalog_release_id text REFERENCES catalog_releases(id) ON DELETE RESTRICT;
CREATE INDEX blueprint_releases_catalog_release_idx ON blueprint_releases(catalog_release_id);

-- The catalog binding is part of the immutable Blueprint release identity.
-- Replacing the function also updates the trigger created by migration 0015.
CREATE OR REPLACE FUNCTION validate_blueprint_release_update() RETURNS trigger AS $$
BEGIN
    IF NEW.revision <> OLD.revision + 1 THEN
        RAISE EXCEPTION 'blueprint release revision must increment by exactly one';
    END IF;
    IF NEW.project_id <> OLD.project_id OR lower(NEW.blueprint_name) <> lower(OLD.blueprint_name) OR NEW.blueprint_version <> OLD.blueprint_version OR COALESCE(NEW.catalog_release_id,'') <> COALESCE(OLD.catalog_release_id,'') OR NEW.created_at <> OLD.created_at THEN
        RAISE EXCEPTION 'blueprint release identity and catalog binding are immutable';
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
