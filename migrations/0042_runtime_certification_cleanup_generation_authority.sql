-- Persist attempt-scoped cleanup ownership before agent execution so a later
-- lease holder can safely remove crash-orphaned TARGET_RUNTIME resources.
ALTER TABLE runtime_certification_runs
    ADD COLUMN cleanup_generations jsonb NOT NULL DEFAULT '[]'::jsonb
    CHECK (jsonb_typeof(cleanup_generations) = 'array');
