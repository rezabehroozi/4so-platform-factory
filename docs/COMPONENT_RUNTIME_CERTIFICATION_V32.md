# Component Runtime Certification Authority — V32

`PROGRAM_PHASE_MODEL_V32` keeps S1 Supply Chain and S2 Component Runtime Certification separate and fail-closed. Source acquisition proves exact bytes; runtime certification proves that the exact component lifecycle works. Neither can substitute for the other.

## Machine-readable authority

`catalog/component-runtime-certification.json` is `COMPONENT_RUNTIME_CERTIFICATION_REGISTRY_V1`. Every catalog component must have exactly one contract bound to its current catalog release and source-lock state. The required lifecycle stages are:

`install -> readiness -> dependency -> upgrade -> remove -> failure`

Each stage has an evidence contract and an execution authority. A missing source lock is represented as `blocked-source-lock`; it is never inferred from an upstream admission row or a rendered manifest. `secure-namespace-foundation` may use the existing `TARGET_RUNTIME_V1` foundation harness for install/readiness/dependency evidence, but this is explicitly partial and does not certify upgrade/remove/failure or any other catalog component.

The API exposes the derived authority through `GET /api/v1/catalog/runtime-certification-authority`. `productionReady` and `physicalCertified` remain false because V32 establishes authority and binding, not lifecycle completion or Exact-SHA Physical PASS.

## Source acquisition transaction

External bundle import changes three product authorities together: the resolved component contract, its runtime-certification source binding, and the unresolved Helm upstream-admission queue. `COMPONENT_RUNTIME_SOURCE_REBIND_TRANSACTION_V1` serializes these changes under the existing catalog install lock and writes a durable recovery journal before authority mutation. An interrupted transaction is restored on retry before a new import is admitted. A previously resolved source cannot be silently replaced with a different source lock.

Runtime payload directories remain immutable. A fully installed payload can safely remain as an unreferenced cache after rollback, but it does not become product authority until the component and certification bindings commit.

## Current truthful state

At V32 there are 20 component contracts. Three components are source-ready and 17 remain source-blocked. One component (`secure-namespace-foundation`) has partial foundation-harness execution. Zero components have all six lifecycle stages certified.

Therefore S2 remains blocked on two explicit items:

- `COMPONENT_RUNTIME_EXECUTOR_PARITY_PENDING`
- `COMPONENT_RUNTIME_LIFECYCLE_NEGATIVE_CONTROLS_PENDING`

S1 remains independently blocked on exact upstream and management-workload acquisition. V32 must not be reported as component runtime certification completion.

## Negative controls

V32 requires a stale/wrong task fence token to be rejected before a runtime-certification result can mutate a run. Future lifecycle executors must additionally prove missing readiness, dependency failure, failed upgrade, partial remove, cleanup failure and recovery/retry semantics before their stage can become certified.
