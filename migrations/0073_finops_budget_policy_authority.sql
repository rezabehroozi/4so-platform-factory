-- Immutable product-owned FinOps budget policy authority. Forecast/anomaly and
-- rightsizing are derived read models over measured FinOps evidence and are not
-- persisted as billing truth.
CREATE TABLE finops_budget_policies (
  id text PRIMARY KEY,
  organization_id text NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
  project_id text REFERENCES projects(id) ON DELETE RESTRICT,
  revision bigint NOT NULL CHECK (revision > 0),
  authority text NOT NULL CHECK (authority='FINOPS_BUDGET_POLICY_AUTHORITY_V1'),
  name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 120),
  version text NOT NULL CHECK (char_length(version) BETWEEN 1 AND 64),
  currency text NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
  effective_from timestamptz NOT NULL,
  effective_until timestamptz CHECK (effective_until IS NULL OR effective_until > effective_from),
  limit_micros bigint NOT NULL CHECK (limit_micros > 0),
  warning_basis_points bigint NOT NULL CHECK (warning_basis_points > 0),
  critical_basis_points bigint NOT NULL CHECK (critical_basis_points > warning_basis_points AND critical_basis_points <= 100000),
  digest text NOT NULL CHECK (digest ~ '^sha256:[0-9a-f]{64}$'),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  CONSTRAINT finops_budget_identity_unique UNIQUE(organization_id, project_id, name, version)
);
CREATE UNIQUE INDEX finops_budget_identity_scope_unique
  ON finops_budget_policies(organization_id, COALESCE(project_id,''), lower(name), version);
CREATE INDEX finops_budget_scope_time_idx ON finops_budget_policies(organization_id, project_id, currency, effective_from, id);

CREATE FUNCTION validate_finops_budget_scope() RETURNS trigger AS $$
DECLARE project_org text;
BEGIN
  IF NEW.project_id IS NOT NULL THEN
    SELECT organization_id INTO project_org FROM projects WHERE id=NEW.project_id;
    IF project_org IS NULL OR project_org <> NEW.organization_id THEN
      RAISE EXCEPTION 'FinOps budget project crosses organization authority';
    END IF;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER finops_budget_scope_guard BEFORE INSERT ON finops_budget_policies FOR EACH ROW EXECUTE FUNCTION validate_finops_budget_scope();
CREATE TRIGGER finops_budget_policies_immutable BEFORE UPDATE OR DELETE ON finops_budget_policies FOR EACH ROW EXECUTE FUNCTION finops_immutable_reject_update();
