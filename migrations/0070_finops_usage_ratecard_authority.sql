-- Product-owned FinOps authority. All monetary values and quantities use
-- integer micro-units; missing telemetry remains explicit in the JSON metric
-- samples and is never coerced to zero by schema defaults.
CREATE TABLE finops_rate_cards (
  id text PRIMARY KEY,
  organization_id text NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
  revision bigint NOT NULL CHECK (revision > 0),
  authority text NOT NULL CHECK (authority='FINOPS_RATE_CARD_AUTHORITY_V1'),
  name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 120),
  version text NOT NULL CHECK (char_length(version) BETWEEN 1 AND 64),
  currency text NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
  effective_from timestamptz NOT NULL,
  effective_until timestamptz CHECK (effective_until IS NULL OR effective_until > effective_from),
  rates jsonb NOT NULL CHECK (jsonb_typeof(rates)='object' AND rates <> '{}'::jsonb),
  digest text NOT NULL CHECK (digest ~ '^sha256:[0-9a-f]{64}$'),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  CONSTRAINT finops_rate_card_identity_unique UNIQUE(organization_id,name,version)
);
CREATE INDEX finops_rate_cards_scope_time_idx ON finops_rate_cards(organization_id,currency,effective_from,id);

CREATE TABLE finops_usage_measurements (
  id text PRIMARY KEY,
  organization_id text NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
  project_id text NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
  cluster_id text NOT NULL DEFAULT '',
  workspace_id text NOT NULL DEFAULT '',
  namespace text NOT NULL DEFAULT '',
  revision bigint NOT NULL CHECK (revision > 0),
  authority text NOT NULL CHECK (authority='FINOPS_USAGE_MEASUREMENT_AUTHORITY_V1'),
  source text NOT NULL CHECK (char_length(source) BETWEEN 1 AND 128),
  source_event_id text NOT NULL CHECK (char_length(source_event_id) BETWEEN 1 AND 200),
  window_start timestamptz NOT NULL,
  window_end timestamptz NOT NULL CHECK (window_end > window_start),
  metrics jsonb NOT NULL CHECK (jsonb_typeof(metrics)='object'),
  digest text NOT NULL CHECK (digest ~ '^sha256:[0-9a-f]{64}$'),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  CONSTRAINT finops_usage_source_event_unique UNIQUE(project_id,source,source_event_id)
);
CREATE INDEX finops_usage_scope_window_idx ON finops_usage_measurements(organization_id,project_id,window_start DESC,id);

CREATE TABLE finops_capacity_observations (
  id text PRIMARY KEY,
  organization_id text NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
  project_id text NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
  cluster_id text NOT NULL DEFAULT '',
  revision bigint NOT NULL CHECK (revision > 0),
  authority text NOT NULL CHECK (authority='FINOPS_CAPACITY_OBSERVATION_AUTHORITY_V1'),
  source text NOT NULL CHECK (char_length(source) BETWEEN 1 AND 128),
  source_event_id text NOT NULL CHECK (char_length(source_event_id) BETWEEN 1 AND 200),
  observed_at timestamptz NOT NULL,
  metrics jsonb NOT NULL CHECK (jsonb_typeof(metrics)='object'),
  digest text NOT NULL CHECK (digest ~ '^sha256:[0-9a-f]{64}$'),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  CONSTRAINT finops_capacity_source_event_unique UNIQUE(project_id,source,source_event_id)
);
CREATE INDEX finops_capacity_scope_time_idx ON finops_capacity_observations(organization_id,project_id,observed_at DESC,id);

CREATE FUNCTION validate_finops_scope() RETURNS trigger AS $$
DECLARE project_org text; cluster_project text; workspace_project text;
BEGIN
  SELECT organization_id INTO project_org FROM projects WHERE id=NEW.project_id;
  IF project_org IS NULL OR project_org <> NEW.organization_id THEN RAISE EXCEPTION 'FinOps project crosses organization authority'; END IF;
  IF NEW.cluster_id <> '' THEN
    SELECT project_id INTO cluster_project FROM managed_clusters WHERE id=NEW.cluster_id;
    IF cluster_project IS NULL OR cluster_project <> NEW.project_id THEN RAISE EXCEPTION 'FinOps cluster crosses project authority'; END IF;
  END IF;
  IF TG_TABLE_NAME='finops_usage_measurements' AND NEW.workspace_id <> '' THEN
    SELECT project_id INTO workspace_project FROM workspaces WHERE id=NEW.workspace_id;
    IF workspace_project IS NULL OR workspace_project <> NEW.project_id THEN RAISE EXCEPTION 'FinOps workspace crosses project authority'; END IF;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER finops_usage_scope_guard BEFORE INSERT ON finops_usage_measurements FOR EACH ROW EXECUTE FUNCTION validate_finops_scope();
CREATE TRIGGER finops_capacity_scope_guard BEFORE INSERT ON finops_capacity_observations FOR EACH ROW EXECUTE FUNCTION validate_finops_scope();

CREATE FUNCTION finops_immutable_reject_update() RETURNS trigger AS $$
BEGIN RAISE EXCEPTION 'FinOps evidence authority is immutable'; END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER finops_rate_cards_immutable BEFORE UPDATE OR DELETE ON finops_rate_cards FOR EACH ROW EXECUTE FUNCTION finops_immutable_reject_update();
CREATE TRIGGER finops_usage_measurements_immutable BEFORE UPDATE OR DELETE ON finops_usage_measurements FOR EACH ROW EXECUTE FUNCTION finops_immutable_reject_update();
CREATE TRIGGER finops_capacity_observations_immutable BEFORE UPDATE OR DELETE ON finops_capacity_observations FOR EACH ROW EXECUTE FUNCTION finops_immutable_reject_update();
