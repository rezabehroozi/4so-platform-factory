-- 0.0.63: append-only per-step trace/log authority with sealed evidence payload linkage.
ALTER TABLE evidence_metadata
    ADD COLUMN IF NOT EXISTS step_phase text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS step_key text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS attempt integer NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS trace_id text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS has_payload boolean NOT NULL DEFAULT false;

ALTER TABLE evidence_metadata DROP CONSTRAINT IF EXISTS evidence_operation_digest_key;
DROP INDEX IF EXISTS evidence_legacy_operation_digest_key;
DROP INDEX IF EXISTS evidence_step_operation_digest_key;
CREATE UNIQUE INDEX evidence_legacy_operation_digest_key
    ON evidence_metadata(operation_id,digest) WHERE step_phase='';
CREATE UNIQUE INDEX evidence_step_operation_digest_key
    ON evidence_metadata(operation_id,step_phase,step_key,attempt,digest) WHERE step_phase<>'';

ALTER TABLE evidence_metadata DROP CONSTRAINT IF EXISTS evidence_step_link_check;
ALTER TABLE evidence_metadata ADD CONSTRAINT evidence_step_link_check CHECK (
    (step_phase='' AND step_key='' AND attempt=0 AND trace_id='') OR
    (step_phase IN ('FORWARD','COMPENSATION') AND step_key<>'' AND attempt>0 AND trace_id<>'')
);

CREATE TABLE IF NOT EXISTS operation_evidence_payloads (
    evidence_id text PRIMARY KEY REFERENCES evidence_metadata(id) ON DELETE RESTRICT,
    payload bytea NOT NULL,
    digest text NOT NULL CHECK (digest LIKE 'sha256:%'),
    size_bytes bigint NOT NULL CHECK (size_bytes >= 0),
    created_at timestamptz NOT NULL
);

CREATE OR REPLACE FUNCTION reject_operation_evidence_payload_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'operation evidence payloads are append-only';
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS operation_evidence_payloads_immutable ON operation_evidence_payloads;
CREATE TRIGGER operation_evidence_payloads_immutable BEFORE UPDATE OR DELETE ON operation_evidence_payloads
FOR EACH ROW EXECUTE FUNCTION reject_operation_evidence_payload_mutation();

CREATE TABLE IF NOT EXISTS operation_step_traces (
    id text PRIMARY KEY,
    operation_id text NOT NULL REFERENCES operations(id) ON DELETE RESTRICT,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision=1),
    step_phase text NOT NULL CHECK (step_phase IN ('FORWARD','COMPENSATION')),
    step_key text NOT NULL,
    attempt integer NOT NULL CHECK (attempt>0),
    sequence bigint NOT NULL CHECK (sequence>0),
    trace_key text NOT NULL,
    level text NOT NULL CHECK (level IN ('DEBUG','INFO','WARN','ERROR')),
    event_type text NOT NULL,
    message text NOT NULL,
    evidence_id text NOT NULL REFERENCES evidence_metadata(id) ON DELETE RESTRICT,
    evidence_digest text NOT NULL CHECK (evidence_digest LIKE 'sha256:%'),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT operation_step_trace_idempotency UNIQUE(operation_id,step_phase,step_key,attempt,trace_key),
    CONSTRAINT operation_step_trace_sequence UNIQUE(operation_id,step_phase,step_key,attempt,sequence)
);
CREATE INDEX IF NOT EXISTS operation_step_traces_operation_idx
    ON operation_step_traces(operation_id,attempt,step_phase,step_key,sequence);

CREATE OR REPLACE FUNCTION reject_operation_step_trace_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'operation step traces are append-only';
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS operation_step_traces_immutable ON operation_step_traces;
CREATE TRIGGER operation_step_traces_immutable BEFORE UPDATE OR DELETE ON operation_step_traces
FOR EACH ROW EXECUTE FUNCTION reject_operation_step_trace_mutation();
