-- WORKLOAD_EXPLORER_READ_AUTHORITY_V1
-- Bounded live workload/event/storage/ingress observations remain part of the
-- authenticated cluster inventory snapshot. They are observational only and
-- never become desired-state or mutation authority.
ALTER TABLE cluster_inventory_snapshots
  ADD COLUMN IF NOT EXISTS workload_explorer JSONB NOT NULL DEFAULT '{}'::jsonb;
