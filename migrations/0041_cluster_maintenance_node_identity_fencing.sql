BEGIN;

ALTER TABLE cluster_maintenance_runs
  ADD COLUMN IF NOT EXISTS node_uids jsonb NOT NULL DEFAULT '{}'::jsonb;

COMMENT ON COLUMN cluster_maintenance_runs.node_uids IS
  'Immutable node-name to Kubernetes UID identity captured from the approved cluster inventory. Empty maps on pre-migration unfinished runs are intentionally not backfilled and must fail closed/re-request.';

COMMIT;
