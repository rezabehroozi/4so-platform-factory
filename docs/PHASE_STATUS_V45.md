# Current Phase Status — PROGRAM_PHASE_MODEL_V45

> Snapshot for release `0.0.339`. The executable roadmap in `internal/targetmodel` is canonical. `source-implemented` is source-level only and never implies Generated Runtime, Integration, Exact-SHA Physical or production PASS.

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
| `C7W-mcp-user-admin-write-parity` | blocked | `MCP_WRITE_JOB_COVERAGE_PENDING`, `MCP_EXTERNAL_CLIENT_INTEROP_MATRIX_PENDING` |
| `S1-exact-supply-chain-acquisition-closure` | blocked | `UPSTREAM_ADMISSION_REVIEWS_PENDING`, `COMPONENT_SOURCE_ACQUISITION_PENDING`, `SOURCE_LOCKS_PENDING`, `MANAGEMENT_WORKLOAD_OCI_ARCHIVE_PENDING`, `MANAGEMENT_IMAGE_DIGEST_LOCKS_PENDING`, `RELEASE_BUILD_TOOLCHAIN_LOCK_PENDING` |
| `S2-component-runtime-certification-authorities` | blocked | `COMPONENT_RUNTIME_UPGRADE_MATRIX_PENDING` |
| `H1-baremetal-connected-managed-okd` | blocked | `OKD_CONNECTED_MANAGED_INSTALL_PENDING` |
| `I1-disconnected-okd-core` | blocked | `OKD_OC_MIRROR_V2_ACQUISITION_PENDING` |
| `C9-pre-certification-feature-freeze-exact-bundle` | blocked | `PRE_CERTIFICATION_REQUIRED_FEATURES_OPEN`, `LAB_CANONICAL_BUNDLE_SOURCE_LOCKS_PENDING`, `FEATURE_CERTIFICATION_CONTRACTS_INCOMPLETE` |

## V45 delta

### C7W — typed MCP parity advanced without generic mutation authority

- `workspaces` is now `typed-tool-complete` across all six stable REST routes: list/get/create plus binding list/create/revoke.
- `projects` is now `typed-tool-complete` across both stable REST routes: visible-project listing and administration-only create.
- Five low-risk read-only families are also `typed-tool-complete`: `version`, `baselines`, `tenancy`, `day2-campaign-engine`, and `catalog-governance` signing identity.
- The canonical registry now contains 70 route families: **16 typed-tool-complete, 10 typed-tool-partial, 42 pending-parity, 2 security-excluded**.
- Project/org scope, delegated administration, cross-project denial and binding authority are regression-tested.
- `tools/list`/`tools/call` still use the effective RBAC + delegation filter; raw shell/SSH/SQL/secret authority remains forbidden.
- C7W remains blocked because other route families and named external-client interoperability are still incomplete.

### I1 — disconnected install workflow source boundary implemented

- Managed OKD now has distinct `connected` and `disconnected` durable step sequences.
- Disconnected mode requires exact SHA-256 locks for ImageSetConfiguration and mirror inventory, validates every sealed archive file and rejects symlinks, special files and unsealed extras.
- Only an exact-SHA `oc-mirror v2` binary may perform disk-to-mirror into the product-configured internal registry; inherited proxy authority is stripped from the child process.
- A secure operation marker gates disconnected install so install cannot run before the exact mirror preparation step completes.
- The Operator Console exposes Connected/Disconnected mode and fail-closes submission against mode-specific runtime readiness.
- `OKD_DISCONNECTED_INSTALL_WORKFLOW_PENDING` is removed. I1 remains blocked only by `OKD_OC_MIRROR_V2_ACQUISITION_PENDING`; the release does not contain or claim acquisition/certification of that upstream binary.

### Truth preserved

- H1 remains blocked on real connected Managed OKD execution evidence.
- S1 remains blocked on exact upstream/source/image/toolchain acquisition truth; current upstream admission still has unresolved review items.
- S2 remains blocked until real exact two-version component upgrade edges and runtime evidence are admitted.
- C9 remains blocked by the mandatory open branches above.
- Core source closure therefore remains **19/25 = 76%**. No Physical PASS is inferred.

## Required current markers

- `PROGRAM_PHASE_MODEL_V45`
- release `0.0.339`
- `OKD_CONNECTED_MANAGED_INSTALL_PENDING`
- `OKD_OC_MIRROR_V2_ACQUISITION_PENDING`
- `RELEASE_BUILD_TOOLCHAIN_LOCK_PENDING`
- `COMPONENT_RUNTIME_UPGRADE_MATRIX_PENDING`
