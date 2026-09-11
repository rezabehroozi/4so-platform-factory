ALTER TABLE runtime_certification_runs
  ADD COLUMN IF NOT EXISTS component_name text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS component_release text NOT NULL DEFAULT '';

ALTER TABLE runtime_certification_runs
  DROP CONSTRAINT IF EXISTS runtime_certification_runs_profile_check;

ALTER TABLE runtime_certification_runs
  ADD CONSTRAINT runtime_certification_runs_profile_check
  CHECK(profile IN ('FOUNDATION_V1','OBSERVABILITY_V1','TARGET_RUNTIME_V1','COMPONENT_RUNTIME_V1'));

ALTER TABLE runtime_certification_runs
  ADD CONSTRAINT runtime_certification_component_identity_check
  CHECK(
    (profile='COMPONENT_RUNTIME_V1' AND length(trim(component_name)) > 0 AND length(trim(component_release)) > 0)
    OR
    (profile<>'COMPONENT_RUNTIME_V1' AND component_name='' AND component_release='')
  );

CREATE INDEX IF NOT EXISTS runtime_certification_component_idx
  ON runtime_certification_runs(component_name,component_release,state,created_at)
  WHERE component_name<>'';
