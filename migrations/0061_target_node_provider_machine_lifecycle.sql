-- 0.0.313: durable exact target-node provider mutation envelope.
ALTER TABLE provider_clusters
  ADD COLUMN IF NOT EXISTS target_node_mutation jsonb NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE provider_clusters DROP CONSTRAINT IF EXISTS provider_clusters_pending_action_check;
ALTER TABLE provider_clusters ADD CONSTRAINT provider_clusters_pending_action_check
  CHECK (pending_action IN ('','PROVISION','SCALE','UPGRADE','DELETE','TARGET_NODE_REMOVE','TARGET_NODE_REPLACE'));

COMMENT ON COLUMN provider_clusters.target_node_mutation IS
  'Inventory/window/node-bound provider mutation envelope for exact CAPI worker remove/replace; empty for ordinary provider lifecycle.';
