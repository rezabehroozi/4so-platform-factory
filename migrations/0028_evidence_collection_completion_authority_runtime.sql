ALTER TABLE baseline_deployments
    ADD COLUMN IF NOT EXISTS evidence jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS evidence_digest text NOT NULL DEFAULT '';

ALTER TABLE baseline_deployments
    DROP CONSTRAINT IF EXISTS baseline_deployments_evidence_digest_check;
ALTER TABLE baseline_deployments
    ADD CONSTRAINT baseline_deployments_evidence_digest_check
    CHECK (evidence_digest = '' OR evidence_digest ~ '^sha256:[0-9a-f]{64}$');

CREATE INDEX IF NOT EXISTS idx_baseline_deployments_evidence_digest
    ON baseline_deployments(evidence_digest)
    WHERE evidence_digest <> '';
