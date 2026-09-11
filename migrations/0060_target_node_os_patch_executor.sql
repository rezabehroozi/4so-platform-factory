BEGIN;

ALTER TABLE cluster_maintenance_runs
  ADD COLUMN IF NOT EXISTS action text NOT NULL DEFAULT 'DRAIN',
  ADD COLUMN IF NOT EXISTS host_action_timeout_seconds integer NOT NULL DEFAULT 0;

ALTER TABLE cluster_maintenance_runs
  DROP CONSTRAINT IF EXISTS cluster_maintenance_runs_action_check;
ALTER TABLE cluster_maintenance_runs
  ADD CONSTRAINT cluster_maintenance_runs_action_check CHECK (action IN ('DRAIN','OS_PATCH'));

ALTER TABLE cluster_maintenance_runs
  DROP CONSTRAINT IF EXISTS cluster_maintenance_runs_host_action_timeout_check;
ALTER TABLE cluster_maintenance_runs
  ADD CONSTRAINT cluster_maintenance_runs_host_action_timeout_check
  CHECK ((action='DRAIN' AND host_action_timeout_seconds=0) OR
         (action='OS_PATCH' AND host_action_timeout_seconds BETWEEN 60 AND 7200));

COMMENT ON COLUMN cluster_maintenance_runs.action IS
  'Fenced target-node lifecycle action executed by the cluster maintenance authority. DRAIN remains the backward-compatible default.';
COMMENT ON COLUMN cluster_maintenance_runs.host_action_timeout_seconds IS
  'Bounded host-maintenance execution timeout for OS_PATCH. Zero for DRAIN.';

COMMIT;
