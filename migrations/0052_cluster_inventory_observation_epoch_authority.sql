-- Inventory authority freshness must be bound to the target observation epoch,
-- not only to the Hub receipt time. Existing rows remain NULL and therefore
-- fail closed for mutation admission until a fresh inventory report arrives.
ALTER TABLE managed_clusters
  ADD COLUMN IF NOT EXISTS inventory_observed_at timestamptz;
