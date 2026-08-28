-- 0.0.48: generic bounded retry classes, destructive recovery binding and safe cancellation.
ALTER TYPE operation_state ADD VALUE IF NOT EXISTS 'RETRY_WAIT';
ALTER TYPE operation_state ADD VALUE IF NOT EXISTS 'CANCEL_REQUESTED';

ALTER TABLE operations
    ADD COLUMN IF NOT EXISTS operation_class text NOT NULL DEFAULT 'MUTATING',
    ADD COLUMN IF NOT EXISTS retry_policy jsonb NOT NULL DEFAULT '{"maxAttempts":3,"initialBackoffSeconds":5,"maxBackoffSeconds":60,"retryableClasses":["TRANSIENT_NETWORK","RATE_LIMITED","DEPENDENCY_UNAVAILABLE"]}'::jsonb,
    ADD COLUMN IF NOT EXISTS attempt integer NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS next_attempt_at timestamptz,
    ADD COLUMN IF NOT EXISTS last_failure_class text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS retry_exhausted boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS recovery_checkpoint_id text REFERENCES recovery_checkpoints(id) ON DELETE RESTRICT,
    ADD COLUMN IF NOT EXISTS recovery_evidence_digest text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS recovery_inventory_digest text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS cancel_requested_by text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS cancel_requested_at timestamptz,
    ADD COLUMN IF NOT EXISTS cancel_reason text NOT NULL DEFAULT '';

ALTER TABLE operations
    DROP CONSTRAINT IF EXISTS operations_operation_class_check;
ALTER TABLE operations
    ADD CONSTRAINT operations_operation_class_check CHECK (operation_class IN ('READ_ONLY','MUTATING','DESTRUCTIVE'));

ALTER TABLE operations
    DROP CONSTRAINT IF EXISTS operations_attempt_check;
ALTER TABLE operations
    ADD CONSTRAINT operations_attempt_check CHECK (attempt >= 0);

ALTER TABLE operations
    DROP CONSTRAINT IF EXISTS operations_recovery_shape_check;
ALTER TABLE operations
    ADD CONSTRAINT operations_recovery_shape_check CHECK (
        operation_class <> 'DESTRUCTIVE' OR (
            recovery_checkpoint_id IS NOT NULL AND
            recovery_evidence_digest LIKE 'sha256:%' AND
            recovery_inventory_digest LIKE 'sha256:%'
        )
    );

CREATE INDEX IF NOT EXISTS operations_next_attempt_idx ON operations(next_attempt_at, id);

ALTER TABLE operation_steps DROP CONSTRAINT IF EXISTS operation_steps_operation_key;
ALTER TABLE operation_steps ADD CONSTRAINT operation_steps_operation_attempt_key UNIQUE(operation_id, attempt, step_key);
