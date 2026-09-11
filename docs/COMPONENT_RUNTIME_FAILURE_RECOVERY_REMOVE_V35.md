# Component Runtime Failure-Recovery and Safe Remove — V35

`PROGRAM_PHASE_MODEL_V35` advances S2 without declaring it complete. Gateway API 1.5.1 and Snapshot Controller 8.5.0 now execute five of the six mandatory component lifecycle stages through `COMPONENT_RUNTIME_V1`: install, readiness, dependency, failure/recovery and remove. Upgrade remains independently blocked until an exact, admitted two-version source matrix exists. Full six-stage certification therefore remains **0/20**.

## Failure-recovery authority

The Agent injects a bounded ownership drift on one exact component-owned object and tags that mutation with the run's fenced cleanup token. Recovery must preserve the Kubernetes UID, restore exact desired ownership/read-back and readiness, and remove the failure token before the phase can PASS. After a crash, a new attempt may resume a drifted object only when its failure token matches a prior `FAILURE_RECOVERY` cleanup generation for the same durable run. Foreign or unproven drift remains fail-closed.

## Remove authority

Removal runs in reverse resource order. The Agent revalidates exact component/catalog/profile ownership and deletes with UID plus resourceVersion preconditions. CRDs are removable only after listing the served Custom Resource endpoint and proving **zero live instances**. A resource already absent is accepted only on a retry that carries a prior fenced `REMOVE` cleanup generation; disappearance before the first remove attempt is treated as lifecycle drift and fails certification. Successful runs leave zero certification-created resources behind.

## Upgrade compatibility

Migration `0064_component_runtime_failure_remove_lifecycle.sql` adds the component-only `FAILURE_RECOVERY` and `REMOVE` phases. It is classified `QUIESCED_REQUIRED`, because an older Agent cannot safely execute those phases. V35 intentionally does not claim rolling compatibility across this migration. TARGET_RUNTIME and the other pre-existing profiles keep their INSTALL/VERIFY lifecycle.

## Operator Console

The Runtime Certification workflow exposes `COMPONENT_RUNTIME_V1` and derives selectable components from `/api/v1/catalog/runtime-certification-authority`. Only source-ready entries with an admitted component executor are offered. The UI reports the current **5/6** lifecycle truth and does not represent the component as fully certified while upgrade remains open.

## Non-claims

V35 does not claim component upgrade certification, S2 closure, S1 source-byte acquisition closure, Exact-SHA Physical PASS or production readiness. Those gates remain independent and fail-closed.
