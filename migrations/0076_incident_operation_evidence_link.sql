-- Link reliability incidents to the canonical durable operation/evidence authority.
-- The nullable column keeps old writers schema-compatible during rolling upgrades.
ALTER TABLE incidents
    ADD COLUMN operation_id text NULL REFERENCES operations(id) ON DELETE RESTRICT;

CREATE INDEX incidents_operation_idx
    ON incidents(operation_id)
    WHERE operation_id IS NOT NULL;

CREATE FUNCTION validate_incident_operation_scope() RETURNS trigger AS $$
DECLARE
    operation_project text;
BEGIN
    IF NEW.operation_id IS NULL OR btrim(NEW.operation_id) = '' THEN
        RETURN NEW;
    END IF;
    SELECT project_id INTO operation_project FROM operations WHERE id=NEW.operation_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'incident operation does not exist';
    END IF;
    IF operation_project <> NEW.project_id THEN
        RAISE EXCEPTION 'incident operation is outside project authority';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER incidents_operation_scope_guard
    BEFORE INSERT ON incidents
    FOR EACH ROW EXECUTE FUNCTION validate_incident_operation_scope();

CREATE OR REPLACE FUNCTION validate_incident_update() RETURNS trigger AS $$
BEGIN
    IF NEW.id <> OLD.id OR NEW.organization_id <> OLD.organization_id OR NEW.project_id <> OLD.project_id OR
       NEW.operation_id IS DISTINCT FROM OLD.operation_id OR NEW.cluster_id <> OLD.cluster_id OR
       NEW.service <> OLD.service OR NEW.severity <> OLD.severity OR NEW.authority <> OLD.authority OR
       NEW.created_at <> OLD.created_at THEN
        RAISE EXCEPTION 'incident identity, operation link and scope are immutable';
    END IF;
    IF NEW.revision <> OLD.revision + 1 THEN
        RAISE EXCEPTION 'incident revision must increase by exactly one';
    END IF;
    IF NOT ((OLD.state = 'OPEN' AND NEW.state IN ('ACKNOWLEDGED','RESOLVED')) OR
            (OLD.state = 'ACKNOWLEDGED' AND NEW.state = 'RESOLVED')) THEN
        RAISE EXCEPTION 'invalid incident state transition';
    END IF;
    IF NEW.state = 'ACKNOWLEDGED' AND btrim(NEW.acknowledged_by) = '' THEN
        RAISE EXCEPTION 'incident acknowledgement actor is required';
    END IF;
    IF NEW.state = 'RESOLVED' AND (btrim(NEW.resolved_by) = '' OR btrim(NEW.resolution_summary) = '') THEN
        RAISE EXCEPTION 'incident resolution actor and summary are required';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
