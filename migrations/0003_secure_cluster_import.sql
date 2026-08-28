CREATE TYPE cluster_import_state AS ENUM ('PENDING_APPROVAL','APPROVED','CLAIMED','EXPIRED','REVOKED');
CREATE TABLE cluster_imports (
 id text PRIMARY KEY, project_id text NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
 revision bigint NOT NULL CHECK(revision>0), name text NOT NULL, display_name text NOT NULL,
 state cluster_import_state NOT NULL, token_digest text NOT NULL CHECK(token_digest LIKE 'sha256:%'),
 agent_token_digest text NOT NULL DEFAULT '', expires_at timestamptz NOT NULL, approved_at timestamptz,
 claimed_at timestamptz, cluster_id text, requested_by text NOT NULL, approved_by text NOT NULL DEFAULT '',
 created_at timestamptz NOT NULL, updated_at timestamptz NOT NULL
);
CREATE UNIQUE INDEX cluster_imports_active_name_key ON cluster_imports(project_id,lower(name)) WHERE state NOT IN ('EXPIRED','REVOKED');
CREATE TABLE managed_clusters (
 id text PRIMARY KEY, project_id text NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
 import_id text NOT NULL UNIQUE REFERENCES cluster_imports(id) ON DELETE RESTRICT,
 revision bigint NOT NULL CHECK(revision>0), name text NOT NULL, display_name text NOT NULL,
 external_uid text NOT NULL UNIQUE, connection_state text NOT NULL CHECK(connection_state IN ('CONNECTED','DISCONNECTED','REVOKED')),
 distribution text NOT NULL DEFAULT '', kubernetes_version text NOT NULL DEFAULT '', agent_version text NOT NULL DEFAULT '',
 last_seen_at timestamptz, labels jsonb NOT NULL DEFAULT '{}'::jsonb, capabilities jsonb NOT NULL DEFAULT '[]'::jsonb,
 inventory_digest text NOT NULL DEFAULT '', created_at timestamptz NOT NULL, updated_at timestamptz NOT NULL
);
ALTER TABLE cluster_imports ADD CONSTRAINT cluster_imports_cluster_fk FOREIGN KEY(cluster_id) REFERENCES managed_clusters(id) DEFERRABLE INITIALLY DEFERRED;
CREATE TABLE cluster_inventory_snapshots (
 id text PRIMARY KEY, cluster_id text NOT NULL REFERENCES managed_clusters(id) ON DELETE RESTRICT,
 revision bigint NOT NULL DEFAULT 1 CHECK(revision=1), observed_at timestamptz NOT NULL,
 distribution text NOT NULL, kubernetes_version text NOT NULL, nodes jsonb NOT NULL, addons jsonb NOT NULL,
 capabilities jsonb NOT NULL, digest text NOT NULL CHECK(digest LIKE 'sha256:%'), created_at timestamptz NOT NULL, updated_at timestamptz NOT NULL,
 CONSTRAINT cluster_inventory_digest_key UNIQUE(cluster_id,digest)
);
CREATE INDEX cluster_inventory_latest_idx ON cluster_inventory_snapshots(cluster_id,observed_at DESC,id DESC);
