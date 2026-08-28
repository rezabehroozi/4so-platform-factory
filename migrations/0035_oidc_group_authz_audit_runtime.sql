CREATE TABLE IF NOT EXISTS oidc_group_mappings (
    id text PRIMARY KEY,
    revision bigint NOT NULL CHECK (revision > 0),
    group_name text NOT NULL CHECK (btrim(group_name) <> ''),
    product_role text NOT NULL CHECK (product_role IN ('platform-admin','platform-operator','platform-viewer')),
    organization_id text REFERENCES organizations(id) ON DELETE RESTRICT,
    organization_role text,
    project_id text REFERENCES projects(id) ON DELETE RESTRICT,
    project_role text,
    state text NOT NULL CHECK (state IN ('ACTIVE','REVOKED')),
    created_by text NOT NULL,
    revoked_by text NOT NULL DEFAULT '',
    revoked_at timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT oidc_group_mapping_org_shape CHECK (
      (organization_id IS NULL AND organization_role IS NULL) OR
      (organization_id IS NOT NULL AND organization_role IN ('organization-admin','organization-operator','organization-viewer'))
    ),
    CONSTRAINT oidc_group_mapping_project_shape CHECK (
      (project_id IS NULL AND project_role IS NULL) OR
      (project_id IS NOT NULL AND project_role IN ('project-admin','project-operator','project-viewer'))
    ),
    CONSTRAINT oidc_group_mapping_revoke_shape CHECK (
      (state='ACTIVE' AND revoked_by='' AND revoked_at IS NULL) OR
      (state='REVOKED' AND revoked_by<>'' AND revoked_at IS NOT NULL)
    )
);
CREATE UNIQUE INDEX IF NOT EXISTS oidc_group_mappings_active_identity_idx
ON oidc_group_mappings(group_name,product_role,COALESCE(organization_id,''),COALESCE(organization_role,''),COALESCE(project_id,''),COALESCE(project_role,''))
WHERE state='ACTIVE';
CREATE INDEX IF NOT EXISTS oidc_group_mappings_group_state_idx ON oidc_group_mappings(group_name,state,id);

CREATE TABLE IF NOT EXISTS security_audit_events (
    sequence bigint PRIMARY KEY CHECK (sequence > 0),
    id text NOT NULL UNIQUE,
    occurred_at timestamptz NOT NULL,
    method_version text NOT NULL CHECK (method_version='IMMUTABLE_AUTHN_AUTHZ_AUDIT_V1'),
    category text NOT NULL CHECK (category IN ('AUTHENTICATION','AUTHORIZATION','SCOPE_AUTHORIZATION')),
    decision text NOT NULL CHECK (decision IN ('ALLOW','DENY')),
    actor_id text NOT NULL,
    authentication text NOT NULL DEFAULT '',
    request_method text NOT NULL DEFAULT '',
    request_path text NOT NULL DEFAULT '',
    status_code integer NOT NULL DEFAULT 0 CHECK (status_code >= 0 AND status_code <= 599),
    reason_code text NOT NULL DEFAULT '',
    request_id text NOT NULL DEFAULT '',
    scope_type text NOT NULL DEFAULT '',
    scope_id text NOT NULL DEFAULT '',
    effective_role text NOT NULL DEFAULT '',
    mapping_digest text NOT NULL DEFAULT '',
    previous_digest text NOT NULL DEFAULT '',
    event_digest text NOT NULL UNIQUE CHECK (event_digest LIKE 'sha256:%')
);
CREATE INDEX IF NOT EXISTS security_audit_events_actor_idx ON security_audit_events(actor_id,sequence DESC);
CREATE INDEX IF NOT EXISTS security_audit_events_decision_idx ON security_audit_events(category,decision,sequence DESC);
CREATE INDEX IF NOT EXISTS security_audit_events_request_idx ON security_audit_events(request_id,sequence DESC) WHERE request_id<>'';
CREATE TRIGGER security_audit_events_no_update BEFORE UPDATE OR DELETE ON security_audit_events
FOR EACH ROW EXECUTE FUNCTION reject_audit_mutation();
CREATE TRIGGER security_audit_events_no_truncate BEFORE TRUNCATE ON security_audit_events
FOR EACH STATEMENT EXECUTE FUNCTION reject_append_only_truncate();
