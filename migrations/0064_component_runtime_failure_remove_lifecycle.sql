-- Extend runtime certification phases only for the component lifecycle executor.
-- Existing FOUNDATION/OBSERVABILITY/TARGET runs remain INSTALL -> VERIFY.
ALTER TABLE runtime_certification_runs
  DROP CONSTRAINT IF EXISTS runtime_certification_runs_phase_check;

ALTER TABLE runtime_certification_runs
  ADD CONSTRAINT runtime_certification_runs_phase_check
  CHECK(phase IN ('INSTALL','VERIFY','FAILURE_RECOVERY','REMOVE'));

ALTER TABLE runtime_certification_runs
  ADD CONSTRAINT runtime_certification_component_extended_phase_check
  CHECK(
    phase IN ('INSTALL','VERIFY')
    OR profile='COMPONENT_RUNTIME_V1'
  );
