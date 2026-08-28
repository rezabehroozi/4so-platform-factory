BEGIN;
ALTER TABLE cluster_inventory_snapshots
  ADD COLUMN storage_classes jsonb NOT NULL DEFAULT '[]'::jsonb,
  ADD COLUMN capacity jsonb NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN certificates jsonb NOT NULL DEFAULT '[]'::jsonb,
  ADD COLUMN networking jsonb NOT NULL DEFAULT '{}'::jsonb;
COMMIT;
