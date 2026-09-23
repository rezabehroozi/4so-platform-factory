BEGIN;
-- VIRTUAL_CLUSTER_LIFECYCLE_JOURNAL_V1
-- QUIESCED_REQUIRED: new lifecycle task actions and durable dispatch ACK semantics
-- are not understood by pre-v80 agents. Old agents must be stopped before any
-- SUSPEND/RESUME/DELETE lifecycle mutation is admitted.

ALTER TABLE virtual_clusters
  DROP CONSTRAINT virtual_clusters_task_action_known;

ALTER TABLE virtual_clusters
  ADD COLUMN task_dispatched_at timestamptz,
  ADD COLUMN lifecycle_action text NOT NULL DEFAULT '',
  ADD COLUMN lifecycle_idempotency_key text NOT NULL DEFAULT '',
  ADD COLUMN lifecycle_request_digest text NOT NULL DEFAULT '';

ALTER TABLE virtual_clusters
  ADD CONSTRAINT virtual_clusters_task_action_known CHECK (task_action IN ('','APPLY','INSPECT','SUSPEND','RESUME','DELETE','LIFECYCLE_INSPECT')),
  ADD CONSTRAINT virtual_clusters_lifecycle_action_known CHECK (lifecycle_action IN ('','SUSPEND','RESUME','DELETE')),
  ADD CONSTRAINT virtual_clusters_lifecycle_request_digest_shape CHECK (lifecycle_request_digest = '' OR lifecycle_request_digest ~ '^sha256:[0-9a-f]{64}$'),
  ADD CONSTRAINT virtual_clusters_lifecycle_journal_complete CHECK (
    (lifecycle_action = '' AND lifecycle_idempotency_key = '' AND lifecycle_request_digest = '')
    OR
    (lifecycle_action IN ('SUSPEND','RESUME','DELETE') AND lifecycle_idempotency_key <> '' AND lifecycle_request_digest ~ '^sha256:[0-9a-f]{64}$')
  ),
  ADD CONSTRAINT virtual_clusters_dispatch_action_consistent CHECK (
    task_dispatched_at IS NULL OR task_action IN ('SUSPEND','RESUME','DELETE')
  );

COMMIT;
