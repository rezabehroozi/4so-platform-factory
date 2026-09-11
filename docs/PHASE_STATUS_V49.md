# Current Phase Status — PROGRAM_PHASE_MODEL_V49

> Snapshot for release `0.0.343`. The executable roadmap in `internal/targetmodel` remains canonical. `source-implemented` never implies Generated Runtime, Integration, Exact-SHA Physical or production PASS.

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

## V49 component-upgrade admission hardening

`COMPONENT_RUNTIME_UPGRADE_MATRIX_V2` closes a source-admission correctness gap without pretending to close S2. A sibling directory is no longer enough to create an upgrade edge. Every source lock must self-identify the same component and exact release represented by its path, and an admitted edge must be a strict numeric `from < to` exact-version transition. Wildcard releases (`x`), aliases, malformed identities and newer siblings stay fail-closed.

New negative controls prove that:

- a foreign component lock under the correct directory is not admitted;
- a newer sibling cannot be reversed into an upgrade edge;
- wildcard target releases do not produce exact-version upgrade claims;
- a valid older exact release is admitted only in the correct direction;
- validation rejects a forged reverse edge even when the source-lock digests differ.

The current catalog still reports **20 components, 0 admitted upgrade pairs, 20 pending source pairs**. Therefore `COMPONENT_RUNTIME_UPGRADE_MATRIX_PENDING` remains open and S2 stays blocked until exact historical source pairs and real runtime execution evidence exist.

## AI / MCP / Persian truth

- MCP route disposition remains **318/318 stable API routes**.
- AI-callable routes remain **281**: 147 read, 63 operate, 71 administration.
- AI-callable mutation coverage remains **134/134** through durable product jobs/operations.
- `persian-writing` 1.3.5 remains pinned offline and the Persian writing gate remains part of repository/UI validation.
- Named-client interoperability with ChatGPT, Claude, Gemini and Grok remains an external evidence blocker; local conformance does not substitute for it.

## Critical path

1. **S1** — exact upstream/source/image/build-toolchain acquisition.
2. **S2** — acquire two-version exact source pairs and execute real component upgrade matrices.
3. **H1** — connected Managed OKD Compact-3 on exact acquired artifacts.
4. **I1** — exact `oc-mirror v2` acquisition plus disconnected certification.
5. **C7W** — named-client OAuth/delegation/read/write/approval/revocation matrix.
6. **C9** — only after all mandatory branches and exact appliance bundle source locks are complete.

## Required current markers

- `PROGRAM_PHASE_MODEL_V49`
- release `0.0.343`
- `COMPONENT_RUNTIME_UPGRADE_MATRIX_V2`
- `FEATURE_CERTIFICATION_REGISTRY_V2`
- `FEATURE_CERTIFICATION_CONTRACT_COVERAGE_V1`
- `MCP_EXTERNAL_CLIENT_INTEROP_MATRIX_PENDING`
- `OKD_CONNECTED_MANAGED_INSTALL_PENDING`
- `OKD_OC_MIRROR_V2_ACQUISITION_PENDING`
- `RELEASE_BUILD_TOOLCHAIN_LOCK_PENDING`
- `COMPONENT_RUNTIME_UPGRADE_MATRIX_PENDING`
