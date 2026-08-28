ALTER TABLE cluster_inventory_snapshots
  ADD COLUMN api_resources jsonb NOT NULL DEFAULT '[]'::jsonb,
  ADD COLUMN crds jsonb NOT NULL DEFAULT '[]'::jsonb,
  ADD COLUMN api_discovery_complete boolean NOT NULL DEFAULT false,
  ADD COLUMN crd_discovery_complete boolean NOT NULL DEFAULT false;

ALTER TABLE baseline_deployments
  ADD COLUMN plan_impact jsonb NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN plan_impact_digest text NOT NULL DEFAULT '';

ALTER TABLE baseline_deployments
  ADD CONSTRAINT baseline_deployments_plan_impact_digest_check
  CHECK (plan_impact_digest = '' OR plan_impact_digest ~ '^sha256:[0-9a-f]{64}$');

CREATE INDEX baseline_deployments_plan_impact_idx
  ON baseline_deployments(plan_impact_digest)
  WHERE plan_impact_digest <> '';
