ALTER TABLE runtime_certification_runs
  DROP CONSTRAINT IF EXISTS runtime_certification_runs_profile_check;

ALTER TABLE runtime_certification_runs
  ADD CONSTRAINT runtime_certification_runs_profile_check
  CHECK(profile IN ('FOUNDATION_V1','OBSERVABILITY_V1','TARGET_RUNTIME_V1'));
