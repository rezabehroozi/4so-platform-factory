BEGIN;

ALTER TABLE virtual_clusters
  ADD COLUMN workspace_binding_revision bigint NOT NULL DEFAULT 0,
  ADD COLUMN observed_digest text NOT NULL DEFAULT '',
  ADD COLUMN phase text NOT NULL DEFAULT '',
  ADD COLUMN runtime_source_digest text NOT NULL DEFAULT '',
  ADD COLUMN task_attempt integer NOT NULL DEFAULT 0,
  ADD COLUMN task_fence_token bigint NOT NULL DEFAULT 0,
  ADD COLUMN task_action text NOT NULL DEFAULT '',
  ADD COLUMN task_lease_expires_at timestamptz;

UPDATE virtual_clusters vc
SET workspace_binding_revision = wb.revision
FROM workspace_bindings wb
WHERE wb.id = vc.workspace_binding_id
  AND vc.workspace_binding_revision = 0;

ALTER TABLE virtual_clusters
  ADD CONSTRAINT virtual_clusters_binding_revision_positive CHECK (workspace_binding_revision > 0),
  ADD CONSTRAINT virtual_clusters_observed_digest_shape CHECK (observed_digest = '' OR observed_digest ~ '^sha256:[0-9a-f]{64}$'),
  ADD CONSTRAINT virtual_clusters_runtime_source_digest_shape CHECK (runtime_source_digest = '' OR runtime_source_digest ~ '^sha256:[0-9a-f]{64}$'),
  ADD CONSTRAINT virtual_clusters_task_attempt_nonnegative CHECK (task_attempt >= 0),
  ADD CONSTRAINT virtual_clusters_task_fence_nonnegative CHECK (task_fence_token >= 0),
  ADD CONSTRAINT virtual_clusters_task_action_known CHECK (task_action IN ('','APPLY','INSPECT'));

ALTER TABLE virtual_clusters
  ALTER COLUMN workspace_binding_revision DROP DEFAULT;

CREATE INDEX virtual_clusters_task_claim_idx
  ON virtual_clusters(host_cluster_id,state,task_lease_expires_at,updated_at);

COMMIT;
