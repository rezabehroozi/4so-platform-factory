CREATE TABLE organization_memberships (
    id text PRIMARY KEY,
    organization_id text NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK (revision > 0),
    subject text NOT NULL,
    role text NOT NULL CHECK (role IN ('organization-admin','organization-operator','organization-viewer')),
    state text NOT NULL CHECK (state IN ('ACTIVE','REVOKED')),
    granted_by text NOT NULL,
    revoked_by text NOT NULL DEFAULT '',
    revoked_at timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT organization_membership_subject_unique UNIQUE (organization_id, subject)
);
CREATE INDEX organization_memberships_subject_state_idx ON organization_memberships(subject, state, organization_id);
