ALTER TABLE runtime_closure_campaigns
  ADD COLUMN evidence_schema_version integer NOT NULL DEFAULT 0,
  ADD COLUMN release_artifact_digest text NOT NULL DEFAULT '',
  ADD COLUMN producer_binary_digest text NOT NULL DEFAULT '';

ALTER TABLE runtime_closure_campaigns
  ADD CONSTRAINT runtime_closure_exact_release_identity_shape CHECK (
    (evidence_schema_version = 0 AND release_artifact_digest = '' AND producer_binary_digest = '') OR
    (evidence_schema_version = 2 AND release_artifact_digest LIKE 'sha256:%' AND producer_binary_digest LIKE 'sha256:%')
  );

CREATE OR REPLACE FUNCTION validate_runtime_closure_campaign_update() RETURNS trigger AS $$
DECLARE
    allowed boolean := false;
BEGIN
    IF NEW.id <> OLD.id OR NEW.project_id <> OLD.project_id OR NEW.cluster_id <> OLD.cluster_id OR
       NEW.baseline_deployment_id <> OLD.baseline_deployment_id OR NEW.desired_digest <> OLD.desired_digest OR
       NEW.requested_by <> OLD.requested_by OR NEW.idempotency_key <> OLD.idempotency_key OR
       NEW.request_digest <> OLD.request_digest OR NEW.created_at <> OLD.created_at OR
       NEW.evidence_schema_version <> OLD.evidence_schema_version OR
       NEW.release_artifact_digest <> OLD.release_artifact_digest OR
       NEW.producer_binary_digest <> OLD.producer_binary_digest THEN
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
