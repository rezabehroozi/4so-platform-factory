-- PostgreSQL authority invariants that must remain true even if an application
-- defect attempts an unsafe direct update.

ALTER TABLE outbox_events
    ADD CONSTRAINT outbox_published_not_claimed
    CHECK (published_at IS NULL OR (claimed_by IS NULL AND claimed_until IS NULL));

CREATE OR REPLACE FUNCTION validate_revision_increment() RETURNS trigger AS $$
BEGIN
    IF NEW.id <> OLD.id OR NEW.created_at <> OLD.created_at THEN
        RAISE EXCEPTION 'resource identity and created_at are immutable';
    END IF;
    IF NEW.revision <> OLD.revision + 1 THEN
        RAISE EXCEPTION 'resource revision must increase by exactly one';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER organizations_revision_guard BEFORE UPDATE ON organizations
FOR EACH ROW EXECUTE FUNCTION validate_revision_increment();
CREATE TRIGGER projects_revision_guard BEFORE UPDATE ON projects
FOR EACH ROW EXECUTE FUNCTION validate_revision_increment();
CREATE TRIGGER assignments_revision_guard BEFORE UPDATE ON assignments
FOR EACH ROW EXECUTE FUNCTION validate_revision_increment();
CREATE TRIGGER operation_steps_revision_guard BEFORE UPDATE ON operation_steps
FOR EACH ROW EXECUTE FUNCTION validate_revision_increment();
CREATE TRIGGER outbox_events_revision_guard BEFORE UPDATE ON outbox_events
FOR EACH ROW EXECUTE FUNCTION validate_revision_increment();

CREATE OR REPLACE FUNCTION validate_operation_update() RETURNS trigger AS $$
DECLARE
    allowed boolean := false;
BEGIN
    IF NEW.id <> OLD.id OR NEW.project_id <> OLD.project_id OR
       NEW.idempotency_key <> OLD.idempotency_key OR
       NEW.request_digest <> OLD.request_digest OR
       NEW.actor_id <> OLD.actor_id OR NEW.created_at <> OLD.created_at THEN
        RAISE EXCEPTION 'operation identity and request fields are immutable';
    END IF;
    IF NEW.revision <> OLD.revision + 1 THEN
        RAISE EXCEPTION 'operation revision must increase by exactly one';
    END IF;
    IF NEW.fence_token < OLD.fence_token OR NEW.fence_token > OLD.fence_token + 1 THEN
        RAISE EXCEPTION 'operation fence token must be monotonic and increase by at most one';
    END IF;
    IF NEW.state = OLD.state THEN
        allowed := true;
    ELSIF OLD.state = 'DRAFT' AND NEW.state IN ('PLANNING','CANCELLED') THEN allowed := true;
    ELSIF OLD.state = 'PLANNING' AND NEW.state IN ('PLAN_FAILED','AWAITING_APPROVAL','QUEUED','CANCELLED') THEN allowed := true;
    ELSIF OLD.state = 'PLAN_FAILED' AND NEW.state IN ('PLANNING','CANCELLED') THEN allowed := true;
    ELSIF OLD.state = 'AWAITING_APPROVAL' AND NEW.state IN ('APPROVED','CANCELLED') THEN allowed := true;
    ELSIF OLD.state = 'APPROVED' AND NEW.state IN ('QUEUED','CANCELLED') THEN allowed := true;
    ELSIF OLD.state = 'QUEUED' AND NEW.state IN ('RUNNING','CANCELLED') THEN allowed := true;
    ELSIF OLD.state = 'RUNNING' AND NEW.state IN ('VERIFYING','FAILED','ROLLING_BACK') THEN allowed := true;
    ELSIF OLD.state = 'VERIFYING' AND NEW.state IN ('SUCCEEDED','FAILED','ROLLING_BACK') THEN allowed := true;
    ELSIF OLD.state = 'FAILED' AND NEW.state IN ('QUEUED','ROLLING_BACK','CANCELLED') THEN allowed := true;
    ELSIF OLD.state = 'ROLLING_BACK' AND NEW.state IN ('ROLLED_BACK','FAILED') THEN allowed := true;
    END IF;
    IF NOT allowed THEN
        RAISE EXCEPTION 'invalid operation state transition from % to %', OLD.state, NEW.state;
    END IF;
    IF NEW.state IN ('SUCCEEDED','ROLLED_BACK','CANCELLED') AND
       (NEW.lease_owner IS NOT NULL OR NEW.lease_expires_at IS NOT NULL) THEN
        RAISE EXCEPTION 'terminal operation cannot retain a lease';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER operations_update_guard BEFORE UPDATE ON operations
FOR EACH ROW EXECUTE FUNCTION validate_operation_update();

CREATE OR REPLACE FUNCTION reject_append_only_truncate() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'append-only or immutable table cannot be truncated';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_events_no_truncate BEFORE TRUNCATE ON audit_events
FOR EACH STATEMENT EXECUTE FUNCTION reject_append_only_truncate();
CREATE TRIGGER blueprint_revisions_no_truncate BEFORE TRUNCATE ON blueprint_revisions
FOR EACH STATEMENT EXECUTE FUNCTION reject_append_only_truncate();
CREATE TRIGGER evidence_metadata_no_truncate BEFORE TRUNCATE ON evidence_metadata
FOR EACH STATEMENT EXECUTE FUNCTION reject_append_only_truncate();

CREATE INDEX IF NOT EXISTS operations_lease_expiry_idx
ON operations(lease_expires_at, id)
WHERE lease_expires_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS assignments_blueprint_revision_idx
ON assignments(blueprint_revision_id, id);
