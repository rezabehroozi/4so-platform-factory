-- 0.0.318: human MCP OAuth client trust and revocable delegation grant authority.
CREATE TABLE mcp_trusted_clients (
  id text PRIMARY KEY,
  revision bigint NOT NULL CHECK (revision > 0),
  client_id text NOT NULL UNIQUE,
  display_name text NOT NULL,
  provider text NOT NULL CHECK (provider IN ('chatgpt','claude','gemini','grok','other')),
  redirect_uris jsonb NOT NULL DEFAULT '[]'::jsonb,
  state text NOT NULL CHECK (state IN ('ACTIVE','REVOKED')),
  created_by text NOT NULL,
  revoked_by text NOT NULL DEFAULT '',
  revoked_at timestamptz,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL
);
CREATE INDEX mcp_trusted_clients_state_idx ON mcp_trusted_clients(state,client_id);

CREATE TABLE mcp_delegation_grants (
  id text PRIMARY KEY,
  revision bigint NOT NULL CHECK (revision > 0),
  issuer text NOT NULL,
  subject text NOT NULL,
  client_id text NOT NULL REFERENCES mcp_trusted_clients(client_id) ON UPDATE CASCADE ON DELETE RESTRICT,
  organization_id text REFERENCES organizations(id) ON DELETE RESTRICT,
  project_id text REFERENCES projects(id) ON DELETE RESTRICT,
  access_profile text NOT NULL CHECK (access_profile IN ('VIEW','OPERATE','ADMINISTRATION')),
  consent_digest text NOT NULL,
  expires_at timestamptz NOT NULL,
  state text NOT NULL CHECK (state IN ('ACTIVE','REVOKED')),
  created_by text NOT NULL,
  revoked_by text NOT NULL DEFAULT '',
  revoked_at timestamptz,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  CHECK (project_id IS NULL OR organization_id IS NOT NULL)
);
CREATE INDEX mcp_delegation_grants_lookup_idx ON mcp_delegation_grants(issuer,subject,client_id,state,expires_at);
CREATE INDEX mcp_delegation_grants_scope_idx ON mcp_delegation_grants(organization_id,project_id,state,expires_at);
COMMENT ON TABLE mcp_delegation_grants IS 'Product-owned, revocable human MCP delegation grants; OAuth identity alone never grants product authority.';
