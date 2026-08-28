CREATE TABLE service_accounts (
    id text PRIMARY KEY,
    organization_id text NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    project_id text REFERENCES projects(id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK (revision > 0),
    name text NOT NULL,
    display_name text NOT NULL,
    product_role text NOT NULL CHECK (product_role IN ('platform-viewer','platform-operator')),
    state text NOT NULL CHECK (state IN ('ACTIVE','REVOKED')),
    created_by text NOT NULL,
    revoked_by text NOT NULL DEFAULT '',
    revoked_at timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);
CREATE UNIQUE INDEX service_accounts_scope_name_unique
    ON service_accounts(organization_id, COALESCE(project_id,''), name);
CREATE INDEX service_accounts_org_state_idx ON service_accounts(organization_id,state,id);
CREATE INDEX service_accounts_project_state_idx ON service_accounts(project_id,state,id) WHERE project_id IS NOT NULL;

CREATE TABLE api_tokens (
    id text PRIMARY KEY,
    service_account_id text NOT NULL REFERENCES service_accounts(id) ON DELETE RESTRICT,
    organization_id text NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    project_id text REFERENCES projects(id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK (revision > 0),
    token_prefix text NOT NULL UNIQUE,
    token_digest text NOT NULL UNIQUE CHECK (token_digest LIKE 'sha256:%'),
    permissions jsonb NOT NULL,
    state text NOT NULL CHECK (state IN ('ACTIVE','REVOKED')),
    expires_at timestamptz NOT NULL,
    created_by text NOT NULL,
    rotated_from_id text,
    revoked_by text NOT NULL DEFAULT '',
    revoked_at timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);
CREATE INDEX api_tokens_service_account_state_idx ON api_tokens(service_account_id,state,expires_at,id);
CREATE INDEX api_tokens_expiry_idx ON api_tokens(state,expires_at,id);
