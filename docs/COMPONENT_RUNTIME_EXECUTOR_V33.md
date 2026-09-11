# Component Runtime Install/Readiness Executor — V33

`PROGRAM_PHASE_MODEL_V33` advances S2 from registry-only ownership to the first source-bound component execution path. This is a **partial lifecycle closure**, not S2 completion and not Physical PASS.

## Authority boundary

`COMPONENT_RUNTIME_V1` is a durable/fenced Runtime Certification profile. Every run persists and validates:

- catalog release ID and revision,
- exact component name and admitted component release,
- exact component `sourceLockDigest`,
- rendered-resource digest after mutation-boundary normalization,
- target inventory digest, lease and fence token,
- install checkpoint plus readiness evidence.

The API admits this profile only when the target explicitly reports `cert.component-runtime`. Generic `TARGET_RUNTIME_V1` evidence cannot be promoted into component lifecycle certification.

## Executable components in V33

| Component | Release | Install | Readiness | Dependency | Upgrade | Remove | Failure | Full lifecycle |
|---|---:|---|---|---|---|---|---|---|
| Gateway API | 1.5.1 | executable | executable | pending | pending | pending | pending | **No** |
| Snapshot Controller | 8.5.0 | executable | executable | pending | pending | pending | pending | **No** |

`secure-namespace-foundation` remains a separate `TARGET_RUNTIME_V1` foundation-harness partial. It is not counted as a component-owned full lifecycle executor.

Current registry truth remains 20 contracts, 3 source-ready, 17 source-blocked, 2 component install/readiness partial executors, 17 pending component executors and **0/20 full six-stage lifecycle certified**.

## Mutation safety

The Agent does not execute arbitrary YAML. Component runtime tasks are limited to an explicit Kubernetes resource allowlist required by the current executable components. The executor:

1. validates the component/release/profile ownership labels;
2. preflights every desired resource as absent before the first mutation;
3. refuses adoption of an existing or foreign-owned resource;
4. creates only explicitly supported API resource kinds;
5. performs exact ownership/read-back checks;
6. requires component-specific readiness evidence before VERIFY succeeds.

Both API and Agent reject tasks larger than **256 resources** or **4 MiB** serialized payload.

Upstream manifest `status` is observed state, not desired mutation authority. It is stripped before the operational payload is hashed and dispatched. This prevents stale/defaulted status from contaminating desired-state evidence or causing invalid Kubernetes writes.

## Durability

Migration `0063_component_runtime_certification_identity.sql` persists `component_name` and `component_release` and expands the profile constraint for `COMPONENT_RUNTIME_V1`. The durable Store requires component identity only for this profile and evidence/checkpoint digests include that identity.

## Readiness semantics

For V33:

- CRD readiness requires an `Established=True` condition.
- Deployment readiness requires observed generation and ready replicas to satisfy the desired state.
- Other supported persisted resources require exact ownership/read-back.
- The generic cluster node/DNS/API-TLS checks remain required.

The report exposes `lifecycleStagesCertified=["install","readiness"]` and `fullLifecycleCertified=false`.

## S2 remains blocked

`S2-component-runtime-certification-authorities` remains blocked by:

- `COMPONENT_RUNTIME_EXECUTOR_PARITY_PENDING`
- `COMPONENT_RUNTIME_LIFECYCLE_NEGATIVE_CONTROLS_PENDING`

The next S2 work is owner-specific dependency/upgrade/remove/failure execution and negative controls, followed by executor coverage for the remaining source-ready and eventually source-acquired mandatory components. No source-level partial executor may be represented as Exact-SHA Physical or production certification.
