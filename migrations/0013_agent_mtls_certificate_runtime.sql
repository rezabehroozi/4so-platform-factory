CREATE TABLE agent_certificates (
    id text PRIMARY KEY,
    cluster_id text NOT NULL REFERENCES managed_clusters(id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK (revision > 0),
    serial_number text NOT NULL UNIQUE,
    fingerprint text NOT NULL UNIQUE CHECK (fingerprint LIKE 'sha256:%'),
    subject text NOT NULL,
    state text NOT NULL CHECK (state IN ('ACTIVE','REVOKED')),
    not_before timestamptz NOT NULL,
    not_after timestamptz NOT NULL,
    issued_by text NOT NULL,
    revoked_by text NOT NULL DEFAULT '',
    revoked_at timestamptz,
    replaced_by_id text,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CHECK (not_after > not_before)
);
CREATE INDEX agent_certificates_cluster_state_idx ON agent_certificates(cluster_id,state,not_after,id);
CREATE INDEX agent_certificates_serial_state_idx ON agent_certificates(serial_number,state);
