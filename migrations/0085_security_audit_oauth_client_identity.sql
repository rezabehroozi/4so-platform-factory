BEGIN;
-- SECURITY_AUDIT_OAUTH_CLIENT_IDENTITY_V1
-- ROLLING_SAFE: widens the authorization category CHECK for the executor
-- category already emitted by current API code and adds a default-empty OAuth
-- client identity column. Older writers remain valid; newer writers bind the
-- authorized OIDC/OAuth client into immutable audit digests.

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
    'APPROVAL_AUTHORIZATION',
    'OPERATION_EXECUTOR_AUTHORIZATION'
  ));

ALTER TABLE security_audit_events
  ADD COLUMN IF NOT EXISTS oauth_client_id text NOT NULL DEFAULT '';

ALTER TABLE security_audit_events
  DROP CONSTRAINT IF EXISTS security_audit_events_oauth_client_id_check;

ALTER TABLE security_audit_events
  ADD CONSTRAINT security_audit_events_oauth_client_id_check
  CHECK (
    octet_length(oauth_client_id) <= 512
    AND oauth_client_id !~ E'[\\r\\n\\t]'
  );

COMMIT;
