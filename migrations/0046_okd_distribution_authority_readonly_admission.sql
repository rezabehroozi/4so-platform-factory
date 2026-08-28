ALTER TABLE managed_clusters
  ADD COLUMN inventory_updated_at timestamptz;

ALTER TABLE cluster_inventory_snapshots
  ADD COLUMN distribution_evidence_method text NOT NULL DEFAULT '',
  ADD COLUMN distribution_evidence_uid text NOT NULL DEFAULT '',
  ADD COLUMN distribution_evidence_version text NOT NULL DEFAULT '';
