# Current Phase Status — PROGRAM_PHASE_MODEL_V48

> Snapshot for release `0.0.342`. The executable roadmap in `internal/targetmodel` is canonical. `source-implemented` is source-level only and never implies Generated Runtime, Integration, Exact-SHA Physical or production PASS.

- Total phases: **34**
- Core Freeze phases: **25**
- Core source-implemented: **19/25 = 76%**
- All source-implemented phases: **19**
- Blocked phases: **11**
- Deferred certification phases: **2**
- Not-evaluated optional phases: **2**

## Open Core Freeze phases

| Phase | Status | Current blockers |
|---|---|---|
| `C7W-mcp-user-admin-write-parity` | blocked | `MCP_EXTERNAL_CLIENT_INTEROP_MATRIX_PENDING` |
| `S1-exact-supply-chain-acquisition-closure` | blocked | `UPSTREAM_ADMISSION_REVIEWS_PENDING`, `COMPONENT_SOURCE_ACQUISITION_PENDING`, `SOURCE_LOCKS_PENDING`, `MANAGEMENT_WORKLOAD_OCI_ARCHIVE_PENDING`, `MANAGEMENT_IMAGE_DIGEST_LOCKS_PENDING`, `RELEASE_BUILD_TOOLCHAIN_LOCK_PENDING` |
| `S2-component-runtime-certification-authorities` | blocked | `COMPONENT_RUNTIME_UPGRADE_MATRIX_PENDING` |
| `H1-baremetal-connected-managed-okd` | blocked | `OKD_CONNECTED_MANAGED_INSTALL_PENDING` |
| `I1-disconnected-okd-core` | blocked | `OKD_OC_MIRROR_V2_ACQUISITION_PENDING` |
| `C9-pre-certification-feature-freeze-exact-bundle` | blocked | `PRE_CERTIFICATION_REQUIRED_FEATURES_OPEN`, `LAB_CANONICAL_BUNDLE_SOURCE_LOCKS_PENDING` |

## V48 feature-certification contract closure

`FEATURE_CERTIFICATION_REGISTRY_V2` replaces the broad V1 list with explicit owner-phase contracts. The registry now declares for every mandatory Core phase before C9:

- the owning roadmap phase;
- required certification levels;
- physical/chaos rows when one is required;
- at least one explicit negative-control contract.

`FEATURE_CERTIFICATION_CONTRACT_COVERAGE_V1` reports **24/24 required owner phases covered, 0 missing, complete=true**. `ValidateFeatureCertificationRegistry` fails closed on unknown/missing owners, duplicate features, unknown levels, missing physical scenarios and missing negative controls. Owner tests remove an MCP owner and a negative-control set and prove both defects are rejected.

This closes the source-governance blocker `FEATURE_CERTIFICATION_CONTRACTS_INCOMPLETE`. It does **not** execute any physical scenario and does not close C7W/S1/S2/H1/I1. C9 therefore remains blocked on the actual mandatory feature branches and exact appliance bundle source locks.

## AI / MCP truth preserved

- `MCP_ROUTE_PARITY_AUTHORITY_V1` covers **318/318 stable API routes**.
- **281** routes are AI-callable: **147 read + 63 operate + 71 administration**.
- **37** routes remain intentionally security-excluded.
- `MCP_DURABLE_CONTROL_JOB_AUTHORITY_V1` covers **134/134 AI-callable mutations** with idempotency, durable job state, actor/delegation scope, lease/fence and terminal replay.
- `persian-writing` 1.3.5 remains pinned offline and `PERSIAN_WRITING_GATE_V1` remains part of repository/UI validation.
- C7W is still blocked only on **real named-client execution** for ChatGPT, Claude, Gemini and Grok. Local black-box conformance is not substituted for that evidence.

## Remaining critical path

1. **S1** — finish exact upstream/source/image/build-toolchain acquisition.
2. **S2** — admit and physically execute real two-version component upgrade pairs.
3. **H1** — execute connected Managed OKD Compact-3 on exact acquired artifacts.
4. **I1** — acquire exact `oc-mirror v2` and execute disconnected certification.
5. **C7W** — run the named-client OAuth/delegation/read/write/approval/revocation matrix.
6. **C9** — closes only after all required branches above are ready and the exact appliance bundle source lock is complete.

## Required current markers

- `PROGRAM_PHASE_MODEL_V48`
- release `0.0.342`
- `FEATURE_CERTIFICATION_REGISTRY_V2`
- `FEATURE_CERTIFICATION_CONTRACT_COVERAGE_V1`
- `MCP_EXTERNAL_CLIENT_INTEROP_MATRIX_PENDING`
- `OKD_CONNECTED_MANAGED_INSTALL_PENDING`
- `OKD_OC_MIRROR_V2_ACQUISITION_PENDING`
- `RELEASE_BUILD_TOOLCHAIN_LOCK_PENDING`
- `COMPONENT_RUNTIME_UPGRADE_MATRIX_PENDING`
