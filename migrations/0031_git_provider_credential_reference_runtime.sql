-- 0.0.64: Git provider and credential-reference authority. Secret material is
-- never persisted; only env:// or file:// references are stored.
CREATE TABLE IF NOT EXISTS git_credentials (
  id text PRIMARY KEY,
  revision bigint NOT NULL CHECK (revision > 0),
  name text NOT NULL,
  username text NOT NULL,
  secret_ref text NOT NULL CHECK (secret_ref LIKE 'env://%' OR secret_ref LIKE 'file:///%'),
  state text NOT NULL CHECK (state IN ('ACTIVE','REVOKED')),
  created_by text NOT NULL,
  rotated_from_id text REFERENCES git_credentials(id),
  revoked_by text NOT NULL DEFAULT '',
  revoked_at timestamptz,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS git_credentials_active_name_idx ON git_credentials(name) WHERE state='ACTIVE';

CREATE TABLE IF NOT EXISTS git_providers (
  id text PRIMARY KEY,
  revision bigint NOT NULL CHECK (revision > 0),
  name text NOT NULL UNIQUE,
  kind text NOT NULL CHECK (kind='FORGEJO'),
  base_url text NOT NULL,
  credential_id text NOT NULL REFERENCES git_credentials(id),
  is_default boolean NOT NULL DEFAULT false,
  state text NOT NULL CHECK (state IN ('ACTIVE','DISABLED')),
  created_by text NOT NULL,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS git_providers_single_default_idx ON git_providers(is_default) WHERE is_default=true AND state='ACTIVE';
CREATE INDEX IF NOT EXISTS git_providers_credential_idx ON git_providers(credential_id);
