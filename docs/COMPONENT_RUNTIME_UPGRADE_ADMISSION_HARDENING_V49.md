# Component Runtime Upgrade Admission Hardening — V49

Release `0.0.343` advances the upgrade-pair authority to `COMPONENT_RUNTIME_UPGRADE_MATRIX_V2`.

The prior matrix correctly required two distinct source-lock digests, but directory presence could still stand in for semantic source-lock identity and version direction. V49 makes those properties explicit admission requirements. `source-lock.json` must bind its own `component` and `version` to the directory being evaluated. Upgrade edges require exact three-part numeric versions and `fromRelease < toRelease`; wildcard/alias releases and reverse edges are not admitted.

This is deliberately a source-level hardening change. The shipped catalog still has zero admitted historical source pairs, so no component upgrade runtime PASS is claimed and S2 remains blocked on `COMPONENT_RUNTIME_UPGRADE_MATRIX_PENDING`.
