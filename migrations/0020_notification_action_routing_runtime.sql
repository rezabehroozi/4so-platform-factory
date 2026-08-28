CREATE TABLE notification_destinations (
  id text PRIMARY KEY,
  organization_id text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  revision bigint NOT NULL CHECK(revision > 0),
  name text NOT NULL,
  kind text NOT NULL CHECK(kind IN ('CONSOLE','WEBHOOK')),
  endpoint text NOT NULL DEFAULT '',
  authorization_env text NOT NULL DEFAULT '',
  hmac_secret_env text NOT NULL DEFAULT '',
  allow_http boolean NOT NULL DEFAULT false,
  timeout_seconds integer NOT NULL DEFAULT 10 CHECK(timeout_seconds BETWEEN 1 AND 60),
  state text NOT NULL CHECK(state IN ('ACTIVE','DISABLED')),
  created_by text NOT NULL,
  disabled_by text NOT NULL DEFAULT '',
  disabled_at timestamptz,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  CONSTRAINT notification_destination_shape CHECK(
    (kind='CONSOLE' AND endpoint='' AND authorization_env='' AND hmac_secret_env='') OR
    (kind='WEBHOOK' AND length(trim(endpoint)) > 0)
  ),
  CONSTRAINT notification_destination_disable_shape CHECK(
    (state='DISABLED' AND disabled_at IS NOT NULL AND disabled_by<>'') OR
    (state='ACTIVE' AND disabled_at IS NULL)
  )
);
CREATE UNIQUE INDEX notification_destination_org_name_uq ON notification_destinations(organization_id,lower(name));
CREATE INDEX notification_destination_state_idx ON notification_destinations(organization_id,state,name);

CREATE TABLE notification_routes (
  id text PRIMARY KEY,
  organization_id text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  project_id text REFERENCES projects(id) ON DELETE CASCADE,
  revision bigint NOT NULL CHECK(revision > 0),
  name text NOT NULL,
  enabled boolean NOT NULL DEFAULT true,
  event_patterns jsonb NOT NULL CHECK(jsonb_typeof(event_patterns)='array' AND jsonb_array_length(event_patterns)>0),
  minimum_severity text NOT NULL CHECK(minimum_severity IN ('INFO','WARNING','CRITICAL')),
  destination_ids jsonb NOT NULL CHECK(jsonb_typeof(destination_ids)='array' AND jsonb_array_length(destination_ids)>0),
  created_by text NOT NULL,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL
);
CREATE UNIQUE INDEX notification_route_org_name_uq ON notification_routes(organization_id,lower(name));
CREATE INDEX notification_route_scope_idx ON notification_routes(organization_id,project_id,enabled);

CREATE TABLE notification_events (
  id text PRIMARY KEY,
  organization_id text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  project_id text REFERENCES projects(id) ON DELETE CASCADE,
  revision bigint NOT NULL CHECK(revision > 0),
  source_event_id text NOT NULL,
  aggregate_type text NOT NULL,
  aggregate_id text NOT NULL,
  event_type text NOT NULL,
  severity text NOT NULL CHECK(severity IN ('INFO','WARNING','CRITICAL')),
  title text NOT NULL,
  summary text NOT NULL DEFAULT '',
  payload jsonb NOT NULL DEFAULT '{}'::jsonb,
  occurred_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL
);
CREATE UNIQUE INDEX notification_event_source_uq ON notification_events(source_event_id);
CREATE INDEX notification_event_scope_time_idx ON notification_events(organization_id,project_id,occurred_at DESC);
CREATE INDEX notification_event_type_idx ON notification_events(event_type,occurred_at DESC);

CREATE TABLE notification_deliveries (
  id text PRIMARY KEY,
  event_id text NOT NULL REFERENCES notification_events(id) ON DELETE CASCADE,
  route_id text NOT NULL REFERENCES notification_routes(id) ON DELETE RESTRICT,
  destination_id text NOT NULL REFERENCES notification_destinations(id) ON DELETE RESTRICT,
  revision bigint NOT NULL CHECK(revision > 0),
  state text NOT NULL CHECK(state IN ('PENDING','DELIVERING','RETRY_WAIT','SUCCEEDED','DEAD_LETTER')),
  attempt integer NOT NULL DEFAULT 0 CHECK(attempt >= 0),
  max_attempts integer NOT NULL DEFAULT 5 CHECK(max_attempts BETWEEN 1 AND 20),
  next_attempt_at timestamptz NOT NULL,
  claimed_by text NOT NULL DEFAULT '',
  claimed_until timestamptz,
  last_status_code integer NOT NULL DEFAULT 0 CHECK(last_status_code BETWEEN 0 AND 599),
  last_error text NOT NULL DEFAULT '',
  delivered_at timestamptz,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  CONSTRAINT notification_delivery_success_shape CHECK(state<>'SUCCEEDED' OR delivered_at IS NOT NULL),
  CONSTRAINT notification_delivery_claim_shape CHECK((claimed_by='' AND claimed_until IS NULL) OR (claimed_by<>'' AND claimed_until IS NOT NULL))
);
CREATE UNIQUE INDEX notification_delivery_route_destination_uq ON notification_deliveries(event_id,route_id,destination_id);
CREATE INDEX notification_delivery_claim_idx ON notification_deliveries(state,next_attempt_at,claimed_until,created_at);

CREATE TABLE notification_delivery_attempts (
  id text PRIMARY KEY,
  delivery_id text NOT NULL REFERENCES notification_deliveries(id) ON DELETE CASCADE,
  revision bigint NOT NULL CHECK(revision > 0),
  attempt integer NOT NULL CHECK(attempt > 0),
  started_at timestamptz NOT NULL,
  finished_at timestamptz NOT NULL,
  success boolean NOT NULL,
  retryable boolean NOT NULL,
  status_code integer NOT NULL DEFAULT 0 CHECK(status_code BETWEEN 0 AND 599),
  error text NOT NULL DEFAULT '',
  response_digest text NOT NULL DEFAULT '' CHECK(response_digest='' OR response_digest LIKE 'sha256:%'),
  duration_millis bigint NOT NULL DEFAULT 0 CHECK(duration_millis >= 0),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  CONSTRAINT notification_attempt_time_order CHECK(finished_at >= started_at)
);
CREATE UNIQUE INDEX notification_delivery_attempt_uq ON notification_delivery_attempts(delivery_id,attempt);
