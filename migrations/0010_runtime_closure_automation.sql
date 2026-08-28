CREATE TYPE runtime_closure_campaign_state AS ENUM (
    'WAITING_BASELINE','WAITING_APPROVAL','WAITING_VERIFICATION','SUCCEEDED','FAILED'
);

CREATE TABLE runtime_closure_campaigns (
    id text PRIMARY KEY,
    project_id text NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    cluster_id text NOT NULL REFERENCES managed_clusters(id) ON DELETE RESTRICT,
    baseline_deployment_id text NOT NULL REFERENCES baseline_deployments(id) ON DELETE RESTRICT,
    runtime_verification_id text REFERENCES runtime_verifications(id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK (revision > 0),
    state runtime_closure_campaign_state NOT NULL,
    desired_digest text NOT NULL CHECK (desired_digest LIKE 'sha256:%'),
    observed_digest text NOT NULL DEFAULT '',
    evidence_digest text NOT NULL DEFAULT '',
    next_action text NOT NULL,
    summary text NOT NULL DEFAULT '',
    last_error text NOT NULL DEFAULT '',
    requested_by text NOT NULL,
    idempotency_key text NOT NULL,
    request_digest text NOT NULL CHECK (request_digest LIKE 'sha256:%'),
    started_at timestamptz,
    finished_at timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT runtime_closure_project_idempotency UNIQUE(project_id,idempotency_key),
    CONSTRAINT runtime_closure_one_per_baseline UNIQUE(baseline_deployment_id),
    CONSTRAINT runtime_closure_terminal_shape CHECK (
        (state IN ('SUCCEEDED','FAILED') AND finished_at IS NOT NULL) OR
        (state NOT IN ('SUCCEEDED','FAILED') AND finished_at IS NULL)
    ),
    CONSTRAINT runtime_closure_success_evidence CHECK (
        state <> 'SUCCEEDED' OR (
            runtime_verification_id IS NOT NULL AND
            desired_digest = observed_digest AND
            evidence_digest LIKE 'sha256:%'
        )
    ),
    CONSTRAINT runtime_closure_failure_error CHECK (state <> 'FAILED' OR length(last_error) > 0)
);
CREATE INDEX runtime_closure_campaigns_project_state_idx
    ON runtime_closure_campaigns(project_id,state,created_at,id);
CREATE INDEX runtime_closure_campaigns_cluster_state_idx
    ON runtime_closure_campaigns(cluster_id,state,created_at,id);

CREATE OR REPLACE FUNCTION validate_runtime_closure_campaign_update() RETURNS trigger AS $$
DECLARE
    allowed boolean := false;
BEGIN
    IF NEW.id <> OLD.id OR NEW.project_id <> OLD.project_id OR NEW.cluster_id <> OLD.cluster_id OR
       NEW.baseline_deployment_id <> OLD.baseline_deployment_id OR NEW.desired_digest <> OLD.desired_digest OR
       NEW.requested_by <> OLD.requested_by OR NEW.idempotency_key <> OLD.idempotency_key OR
       NEW.request_digest <> OLD.request_digest OR NEW.created_at <> OLD.created_at THEN
        RAISE EXCEPTION 'runtime closure identity and request fields are immutable';
    END IF;
    IF OLD.runtime_verification_id IS NOT NULL AND NEW.runtime_verification_id <> OLD.runtime_verification_id THEN
        RAISE EXCEPTION 'runtime verification binding is immutable';
    END IF;
    IF NEW.revision <> OLD.revision + 1 THEN
        RAISE EXCEPTION 'resource revision must increase by exactly one';
    END IF;
    IF NEW.state = OLD.state THEN allowed := true;
    ELSIF OLD.state = 'WAITING_BASELINE' AND NEW.state IN ('WAITING_APPROVAL','WAITING_VERIFICATION','FAILED') THEN allowed := true;
    ELSIF OLD.state = 'WAITING_APPROVAL' AND NEW.state IN ('WAITING_BASELINE','WAITING_VERIFICATION','FAILED') THEN allowed := true;
    ELSIF OLD.state = 'WAITING_VERIFICATION' AND NEW.state IN ('SUCCEEDED','FAILED') THEN allowed := true;
    ELSIF OLD.state = 'FAILED' AND NEW.state IN ('WAITING_BASELINE','WAITING_APPROVAL','WAITING_VERIFICATION') THEN allowed := true;
    END IF;
    IF NOT allowed THEN
        RAISE EXCEPTION 'invalid runtime closure state transition % -> %', OLD.state, NEW.state;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER runtime_closure_campaigns_update_guard
BEFORE UPDATE ON runtime_closure_campaigns
FOR EACH ROW EXECUTE FUNCTION validate_runtime_closure_campaign_update();
