# Component Runtime Dependency + Negative-Control Authority — V34

`PROGRAM_PHASE_MODEL_V34` advances S2 without closing it. `COMPONENT_RUNTIME_V1` remains a durable, source-bound, fenced component executor; V34 adds explicit dependency evidence and a non-destructive failure negative control for the two component-owned executors already admitted in V33.

## Executable lifecycle truth

| Component | Release | Install | Readiness | Dependency | Upgrade | Remove | Failure/Recovery | Full lifecycle |
|---|---:|---|---|---|---|---|---|---|
| Gateway API | 1.5.1 | executable | executable | executable | pending | pending | pending | **No** |
| Snapshot Controller | 8.5.0 | executable | executable | executable | pending | pending | pending | **No** |

The registry still contains 20 component contracts, only 3 source-ready components, 17 source-blocked components, 2 component install/readiness/dependency partial executors and **0/20 full six-stage lifecycle certifications**.

## Dependency evidence

Component VERIFY must carry the normal cluster prerequisites and the component-owned aliases below so component certification cannot inherit dependency truth implicitly from a generic target harness:

- `component-dependency/nodes-ready`
- `component-dependency/cluster-dns-service`
- `component-dependency/kubernetes-api-tls`

These checks certify only the dependency stage currently modeled for Gateway API and Snapshot Controller. They do not certify application traffic, upgrade compatibility, removal safety or recovery behavior.

## Duplicate-create negative control

After a successful fresh create and exact read-back, the Agent submits the first owned desired resource a second time and requires the Kubernetes API to return **HTTP 409 Conflict**. The evidence key is:

`component-failure-control/duplicate-create-conflict`

This proves the executor's create-only boundary does not silently replace or adopt an object after the initial mutation. It is a negative control inside the install execution path and **does not** promote the lifecycle `failure` stage to certified. Full failure/recovery remains pending until failure injection, rollback/recovery checkpoints and post-recovery verification are implemented per component owner.

## Existing safety boundaries retained

- exact component name/release/source-lock identity is durable;
- target capability `cert.component-runtime` is mandatory;
- foreign/existing resource adoption remains forbidden;
- upstream `status` is stripped before desired-state hashing and mutation;
- task limits remain 256 resources / 4 MiB;
- lease/fence-token and stale/wrong-token checks remain fail-closed;
- generic `TARGET_RUNTIME_V1` evidence cannot be promoted into per-component lifecycle closure.

## S2 remains blocked

The blockers remain:

- `COMPONENT_RUNTIME_EXECUTOR_PARITY_PENDING`
- `COMPONENT_RUNTIME_LIFECYCLE_NEGATIVE_CONTROLS_PENDING`

The next meaningful S2 closure is upgrade/remove/failure-recovery semantics for the partial executors plus executor coverage for source-ready/source-acquired mandatory components. No V34 source-level evidence is Physical PASS.
