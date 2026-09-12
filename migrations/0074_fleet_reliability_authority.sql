-- Product-owned fleet reliability authority. Raw telemetry remains owned by the
-- existing monitoring/runtime stacks; these tables persist bounded product
-- observations, incident lifecycle state, and immutable SLO policy revisions.

CREATE TABLE health_observations (
    id text PRIMARY KEY,
    organization_id text NOT NULL,
    project_id text NOT NULL,
    cluster_id text NOT NULL,
    health text NOT NULL CHECK (health IN ('HEALTHY','WARNING','DEGRADED','STALE','CRITICAL')),
    observed_at timestamptz NOT NULL,
    source_digest text NOT NULL,
    authority text NOT NULL DEFAULT 'HEALTH_OBSERVATION_AUTHORITY_V1'
        CHECK (authority = 'HEALTH_OBSERVATION_AUTHORITY_V1'),
    created_at timestamptz NOT NULL
);
CREATE INDEX health_observations_project_cluster_time_idx
    ON health_observations(project_id, cluster_id, observed_at DESC, id DESC);

CREATE FUNCTION reject_health_observation_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'health observations are immutable';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER health_observations_immutable
    BEFORE UPDATE OR DELETE ON health_observations
    FOR EACH ROW EXECUTE FUNCTION reject_health_observation_mutation();
CREATE TRIGGER health_observations_no_truncate
    BEFORE TRUNCATE ON health_observations
    FOR EACH STATEMENT EXECUTE FUNCTION reject_append_only_truncate();

CREATE TABLE incidents (
    id text PRIMARY KEY,
    organization_id text NOT NULL,
    project_id text NOT NULL,
    cluster_id text NOT NULL DEFAULT '',
    service text NOT NULL DEFAULT '',
    severity text NOT NULL CHECK (length(btrim(severity)) > 0),
    state text NOT NULL CHECK (state IN ('OPEN','ACKNOWLEDGED','RESOLVED')),
    revision bigint NOT NULL CHECK (revision > 0),
    acknowledged_by text NOT NULL DEFAULT '',
    resolved_by text NOT NULL DEFAULT '',
    resolution_summary text NOT NULL DEFAULT '',
    authority text NOT NULL DEFAULT 'INCIDENT_AUTHORITY_V1'
        CHECK (authority = 'INCIDENT_AUTHORITY_V1'),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);
CREATE INDEX incidents_project_state_idx ON incidents(project_id, state, updated_at DESC, id DESC);

CREATE FUNCTION validate_incident_update() RETURNS trigger AS $$
BEGIN
    IF NEW.id <> OLD.id OR NEW.organization_id <> OLD.organization_id OR NEW.project_id <> OLD.project_id OR
       NEW.cluster_id <> OLD.cluster_id OR NEW.service <> OLD.service OR NEW.severity <> OLD.severity OR
       NEW.authority <> OLD.authority OR NEW.created_at <> OLD.created_at THEN
        RAISE EXCEPTION 'incident identity and scope are immutable';
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
CREATE TRIGGER incidents_update_guard BEFORE UPDATE ON incidents
    FOR EACH ROW EXECUTE FUNCTION validate_incident_update();

CREATE TABLE slo_policies (
    id text PRIMARY KEY,
    organization_id text NOT NULL,
    project_id text NOT NULL,
    name text NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    objective_basis_points integer NOT NULL CHECK (objective_basis_points BETWEEN 1 AND 10000),
    window_seconds bigint NOT NULL CHECK (window_seconds > 0),
    observation_interval_seconds bigint NOT NULL CHECK (observation_interval_seconds > 0 AND observation_interval_seconds <= window_seconds),
    authority text NOT NULL DEFAULT 'SLO_ERROR_BUDGET_AUTHORITY_V1'
        CHECK (authority = 'SLO_ERROR_BUDGET_AUTHORITY_V1'),
    created_at timestamptz NOT NULL
);
CREATE UNIQUE INDEX slo_policies_project_name_revision_unique
    ON slo_policies(project_id, lower(name), revision);
CREATE INDEX slo_policies_project_name_idx ON slo_policies(project_id, lower(name), revision DESC);

CREATE FUNCTION reject_slo_policy_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'SLO policy revisions are immutable';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER slo_policies_immutable BEFORE UPDATE OR DELETE ON slo_policies
    FOR EACH ROW EXECUTE FUNCTION reject_slo_policy_mutation();
CREATE TRIGGER slo_policies_no_truncate BEFORE TRUNCATE ON slo_policies
    FOR EACH STATEMENT EXECUTE FUNCTION reject_append_only_truncate();
