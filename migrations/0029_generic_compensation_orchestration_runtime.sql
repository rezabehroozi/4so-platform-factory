-- 0.0.62: generic reverse-order compensation orchestration with durable per-step state.
ALTER TYPE operation_state ADD VALUE IF NOT EXISTS 'ROLLBACK_FAILED';
ALTER TYPE operation_state ADD VALUE IF NOT EXISTS 'NEEDS_OPERATOR';

ALTER TABLE operations
    ADD COLUMN IF NOT EXISTS compensation_plan_digest text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS compensation_step_count integer NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS compensation_cursor integer NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS compensation_started_at timestamptz,
    ADD COLUMN IF NOT EXISTS compensation_finished_at timestamptz,
    ADD COLUMN IF NOT EXISTS compensation_failure_step text NOT NULL DEFAULT '';

ALTER TABLE operations DROP CONSTRAINT IF EXISTS operations_compensation_digest_check;
ALTER TABLE operations ADD CONSTRAINT operations_compensation_digest_check CHECK (
    compensation_plan_digest = '' OR compensation_plan_digest LIKE 'sha256:%'
);
ALTER TABLE operations DROP CONSTRAINT IF EXISTS operations_compensation_counts_check;
ALTER TABLE operations ADD CONSTRAINT operations_compensation_counts_check CHECK (
    compensation_step_count >= 0 AND compensation_cursor >= 0
);

CREATE TABLE IF NOT EXISTS operation_compensation_steps (
    id text PRIMARY KEY,
    operation_id text NOT NULL REFERENCES operations(id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK (revision > 0),
    step_key text NOT NULL,
    forward_order integer NOT NULL CHECK (forward_order > 0),
    strategy text NOT NULL CHECK (strategy IN ('NONE','AUTOMATIC_ROLLBACK','RESTORE_PREVIOUS_REVISION','PRESERVE_DATA_RESTORE_CONTROLLER','PROVIDER_RECOVERY','MANUAL_RECOVERY','IRREVERSIBLE')),
    action text NOT NULL DEFAULT '',
    input_digest text NOT NULL CHECK (input_digest LIKE 'sha256:%'),
    max_attempts integer NOT NULL DEFAULT 3 CHECK (max_attempts BETWEEN 1 AND 10),
    forward_completed boolean NOT NULL DEFAULT false,
    forward_completed_at timestamptz,
    state text NOT NULL DEFAULT 'PENDING' CHECK (state IN ('PENDING','RUNNING','SUCCEEDED','FAILED','SKIPPED','MANUAL_REQUIRED')),
    attempt integer NOT NULL DEFAULT 0 CHECK (attempt >= 0),
    fence_token bigint NOT NULL DEFAULT 0 CHECK (fence_token >= 0),
    started_at timestamptz,
    finished_at timestamptz,
    evidence_digest text NOT NULL DEFAULT '',
    last_error text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT operation_compensation_step_key UNIQUE(operation_id, step_key),
    CONSTRAINT operation_compensation_forward_order UNIQUE(operation_id, forward_order),
    CONSTRAINT operation_compensation_forward_time CHECK ((forward_completed = false AND forward_completed_at IS NULL) OR forward_completed = true),
    CONSTRAINT operation_compensation_evidence_check CHECK (evidence_digest = '' OR evidence_digest LIKE 'sha256:%')
);
CREATE INDEX IF NOT EXISTS operation_compensation_steps_next_idx ON operation_compensation_steps(operation_id, forward_completed, state, forward_order DESC);
