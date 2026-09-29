BEGIN;
-- SECURITY_AUDIT_MCP_INTEROP_BINDING_V1
-- ROLLING_SAFE: this widens an existing CHECK constraint and adds a
-- default-empty column. Older writers remain valid; newer writers may bind
-- named-client MCP campaign requests into the immutable audit chain.

ALTER TABLE security_audit_events
  DROP CONSTRAINT IF EXISTS security_audit_events_category_check;

ALTER TABLE security_audit_events
  ADD CONSTRAINT security_audit_events_category_check
  CHECK (category IN (
    'AUTHENTICATION',
    'AUTHORIZATION',
    'SCOPE_AUTHORIZATION',
    'CAPABILITY_AUTHORIZATION',
    'DELEGATION_AUTHORIZATION',
    'APPROVAL_AUTHORIZATION'
  ));

ALTER TABLE security_audit_events
  ADD COLUMN IF NOT EXISTS mcp_interop_binding_digest text NOT NULL DEFAULT '';

ALTER TABLE security_audit_events
  DROP CONSTRAINT IF EXISTS security_audit_events_mcp_interop_binding_digest_check;

ALTER TABLE security_audit_events
  ADD CONSTRAINT security_audit_events_mcp_interop_binding_digest_check
  CHECK (
    mcp_interop_binding_digest = ''
    OR mcp_interop_binding_digest ~ '^sha256:[0-9a-f]{64}$'
  );

COMMIT;
