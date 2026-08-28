ALTER TABLE cluster_inventory_snapshots
  ADD COLUMN schema_discovery_version text NOT NULL DEFAULT '',
  ADD COLUMN schema_discovery_digest text NOT NULL DEFAULT '',
  ADD COLUMN schema_discovery_complete boolean NOT NULL DEFAULT false;

ALTER TABLE cluster_inventory_snapshots
  ADD CONSTRAINT cluster_inventory_schema_discovery_consistency_check CHECK (
    (schema_discovery_complete = false AND schema_discovery_version = '' AND schema_discovery_digest = '') OR
    (schema_discovery_complete = true AND schema_discovery_version IN ('OPENAPI_V3','OPENAPI_V2') AND schema_discovery_digest ~ '^sha256:[0-9a-f]{64}$')
  );
