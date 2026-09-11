-- Durable operation input authority. Critical product workflows can atomically
-- bind a bounded sealed request payload to the operation that carries approval,
-- lease/fence, audit and evidence lifecycle. Payloads are product request data,
-- never raw credentials; domain validators must reject inline secret material.
CREATE TABLE operation_request_payloads (
  operation_id text PRIMARY KEY REFERENCES operations(id) ON DELETE CASCADE,
  payload_digest text NOT NULL CHECK (payload_digest ~ '^sha256:[0-9a-f]{64}$'),
  media_type text NOT NULL CHECK (char_length(media_type) BETWEEN 1 AND 160),
  payload bytea NOT NULL CHECK (octet_length(payload) BETWEEN 1 AND 1048576),
  created_at timestamptz NOT NULL
);
CREATE INDEX operation_request_payloads_created_idx ON operation_request_payloads(created_at,operation_id);

CREATE FUNCTION operation_request_payloads_reject_update() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'operation request payloads are immutable';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER operation_request_payloads_no_update
BEFORE UPDATE ON operation_request_payloads
FOR EACH ROW EXECUTE FUNCTION operation_request_payloads_reject_update();
