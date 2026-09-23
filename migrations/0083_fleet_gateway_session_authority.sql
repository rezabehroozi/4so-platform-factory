BEGIN;
-- FLEET_AGENT_GATEWAY_SESSION_AUTHORITY_V1
-- ROLLING_SAFE: independent session journal. Existing agents ignore it; new
-- gateways use it to prevent two live sessions from owning one cluster.

CREATE TABLE IF NOT EXISTS fleet_gateway_sessions (
    session_id text PRIMARY KEY,
    cluster_id text NOT NULL REFERENCES managed_clusters(id) ON DELETE RESTRICT,
    external_uid text NOT NULL,
    certificate_id text NOT NULL REFERENCES agent_certificates(id) ON DELETE RESTRICT,
    certificate_fingerprint text NOT NULL CHECK (certificate_fingerprint LIKE 'sha256:%'),
    epoch bigint NOT NULL CHECK (epoch > 0),
    state text NOT NULL CHECK (state IN ('ACTIVE','DRAINING','CLOSED')),
    gateway_instance_id text NOT NULL,
    connected_at timestamptz NOT NULL,
    last_heartbeat_at timestamptz NOT NULL,
    drain_requested_at timestamptz,
    closed_at timestamptz,
    CHECK (last_heartbeat_at >= connected_at),
    CHECK ((state='ACTIVE' AND drain_requested_at IS NULL AND closed_at IS NULL)
        OR (state='DRAINING' AND drain_requested_at IS NOT NULL AND closed_at IS NULL)
        OR (state='CLOSED' AND closed_at IS NOT NULL))
);
CREATE UNIQUE INDEX fleet_gateway_sessions_cluster_epoch_unique ON fleet_gateway_sessions(cluster_id,epoch);
CREATE UNIQUE INDEX fleet_gateway_sessions_one_live_per_cluster ON fleet_gateway_sessions(cluster_id) WHERE state IN ('ACTIVE','DRAINING');
CREATE INDEX fleet_gateway_sessions_cluster_history_idx ON fleet_gateway_sessions(cluster_id,epoch DESC,session_id);

CREATE OR REPLACE FUNCTION validate_fleet_gateway_session_authority() RETURNS trigger AS $$
DECLARE
  cluster_uid text; cluster_state text;
  cert_cluster text; cert_fingerprint text; cert_state text; cert_not_before timestamptz; cert_not_after timestamptz;
BEGIN
  SELECT external_uid,connection_state INTO cluster_uid,cluster_state FROM managed_clusters WHERE id=NEW.cluster_id;
  IF cluster_uid IS NULL OR cluster_state='REVOKED' OR cluster_uid<>NEW.external_uid THEN
    RAISE EXCEPTION 'fleet gateway cluster identity/revocation mismatch';
  END IF;
  SELECT cluster_id,fingerprint,state::text,not_before,not_after
    INTO cert_cluster,cert_fingerprint,cert_state,cert_not_before,cert_not_after
    FROM agent_certificates WHERE id=NEW.certificate_id;
  IF cert_cluster IS NULL OR cert_cluster<>NEW.cluster_id OR cert_fingerprint<>NEW.certificate_fingerprint
     OR cert_state<>'ACTIVE' OR NEW.connected_at<cert_not_before OR NEW.connected_at>=cert_not_after THEN
    RAISE EXCEPTION 'fleet gateway certificate authority mismatch';
  END IF;
  IF TG_OP='UPDATE' THEN
    IF NEW.session_id<>OLD.session_id OR NEW.cluster_id<>OLD.cluster_id OR NEW.external_uid<>OLD.external_uid
       OR NEW.certificate_id<>OLD.certificate_id OR NEW.certificate_fingerprint<>OLD.certificate_fingerprint
       OR NEW.epoch<>OLD.epoch OR NEW.gateway_instance_id<>OLD.gateway_instance_id OR NEW.connected_at<>OLD.connected_at THEN
      RAISE EXCEPTION 'fleet gateway session identity is immutable';
    END IF;
    IF OLD.state='CLOSED' THEN RAISE EXCEPTION 'closed fleet gateway session is immutable'; END IF;
    IF OLD.state='DRAINING' AND NEW.state<>'CLOSED' THEN RAISE EXCEPTION 'draining session may only close'; END IF;
    IF OLD.state='ACTIVE' AND NEW.state NOT IN ('ACTIVE','DRAINING','CLOSED') THEN RAISE EXCEPTION 'invalid fleet gateway session transition'; END IF;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS fleet_gateway_sessions_authority_guard ON fleet_gateway_sessions;
CREATE TRIGGER fleet_gateway_sessions_authority_guard
  BEFORE INSERT OR UPDATE ON fleet_gateway_sessions
  FOR EACH ROW EXECUTE FUNCTION validate_fleet_gateway_session_authority();
COMMIT;
