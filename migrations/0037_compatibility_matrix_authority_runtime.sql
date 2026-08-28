BEGIN;
ALTER TABLE provider_profiles
  ADD COLUMN IF NOT EXISTS architectures jsonb NOT NULL DEFAULT '["amd64"]'::jsonb,
  ADD COLUMN IF NOT EXISTS distribution_profiles jsonb NOT NULL DEFAULT '["generic-imported"]'::jsonb;
ALTER TABLE provider_clusters
  ADD COLUMN IF NOT EXISTS compatibility_decision jsonb NOT NULL DEFAULT '{}'::jsonb;
CREATE INDEX IF NOT EXISTS idx_provider_profiles_compatibility ON provider_profiles USING gin (architectures, distribution_profiles);
CREATE INDEX IF NOT EXISTS idx_provider_clusters_compatibility_status ON provider_clusters ((compatibility_decision->>'status'));
COMMIT;
