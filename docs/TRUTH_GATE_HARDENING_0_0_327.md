# Truth Gate Hardening — 0.0.327

`0.0.327` keeps `PROGRAM_PHASE_MODEL_V37` as the canonical roadmap authority. This release is a corrective source-level hardening checkpoint and does not claim Generated Runtime, Integration, Exact-SHA Physical, Chaos, Soak, or production certification.

## Closed defects

### Data Protection evidence determinism

Canonical Data Protection evidence identity no longer depends on local timing telemetry. `RuntimeCheck.DurationMillis`, `RPOSeconds`, and `RTOSeconds` remain recorded on the durable run, but retrying or resuming observation of the same completed Velero object cannot change the evidence digest merely because the local observer measured a different elapsed duration. A regression test covers this invariant.

### Compliance evaluator correctness

Severity ordering is now explicit (`CRITICAL > HIGH > MEDIUM`), all workload container classes include `ephemeralContainers`, and hardened-image evaluation requires an exact SHA-256 digest pin. Tagged-but-not-digest-pinned images receive `IMAGE_NOT_DIGEST_PINNED`; mutable or implicit latest remains `IMAGE_MUTABLE_LATEST_TAG`.

### Release provenance truth

The deterministic release builder records the exact Go compiler string used to produce binaries. This is provenance evidence, not a declaration that the compiler version is inside the supported production security window. Toolchain support/upgrade remains a release-engineering closure item before production certification.

## Roadmap truth

No V37 phase is promoted by this patch. G4 remains source-implemented after its deterministic-evidence defect is repaired, while its higher certification levels remain independently open. G5 remains blocked on durable ScanRun/Finding/Waiver/Recheck authority and SAML lifecycle. S1/S2 remain the primary Core critical path; C7W, H1, and I1 remain mandatory independent Core closures. Physical certification remains deferred until the exact C9-frozen artifact exists.
