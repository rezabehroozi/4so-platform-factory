-- MCP_CONTROL_JOB_RECOVERY_AUTHORITY_V1
-- Additive, ROLLING_SAFE operator reconciliation fields for MCP control jobs.
-- Old writers leave these fields empty. New writers populate them only when a
-- human platform-admin resolves a RECOVERY_REQUIRED job from authoritative
-- readback plus sealed evidence. No automatic redispatch is authorized here.
ALTER TABLE mcp_control_jobs
  ADD COLUMN recovery_resolution text NOT NULL DEFAULT '',
  ADD COLUMN recovery_readback_digest text NOT NULL DEFAULT '',
  ADD COLUMN recovery_evidence_digest text NOT NULL DEFAULT '',
  ADD COLUMN recovered_by text NOT NULL DEFAULT '',
  ADD COLUMN recovered_at timestamptz;

ALTER TABLE mcp_control_jobs
  ADD CONSTRAINT mcp_control_jobs_recovery_resolution_shape CHECK (
    (
      recovery_resolution = ''
      AND recovery_readback_digest = ''
      AND recovery_evidence_digest = ''
      AND recovered_by = ''
      AND recovered_at IS NULL
    )
    OR
    (
      recovery_resolution IN ('CONFIRMED_SUCCEEDED', 'CONFIRMED_FAILED')
      AND recovery_readback_digest ~ '^sha256:[0-9a-f]{64}$'
      AND recovery_evidence_digest ~ '^sha256:[0-9a-f]{64}$'
      AND recovered_by <> ''
      AND recovered_at IS NOT NULL
      AND state IN ('SUCCEEDED', 'FAILED')
      AND lease_expires_at IS NULL
    )
  );
