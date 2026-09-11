# Current Phase Status — PROGRAM_PHASE_MODEL_V54

> Snapshot for release `0.0.348`. Source implementation, acquisition admission, integration/runtime certification and Exact-SHA Physical PASS remain separate truths.

- Total phases: **34**
- Core Freeze phases: **25**
- Core source-implemented: **19/25 = 76%**
- All source-implemented phases: **19**
- Blocked phases: **11**
- Deferred certification phases: **2**
- Not-evaluated optional phases: **2**

## V54 large bottleneck closure

V54 removes two execution gaps that previously required manual repository surgery:

1. `SUPPLY_CHAIN_HANDOFF_SEAL_V1` seals the complete connected-to-offline staging tree with a deterministic file inventory, byte counts, per-file SHA-256, inventory digest and binding to the exact `SUPPLY_CHAIN_HANDOFF_V1` plan. Symlinks, special files, tree tamper and plan drift fail closed. The seal is transport evidence only and cannot promote source resolution, runtime certification or Physical PASS.
2. `COMPONENT_UPGRADE_SOURCE_ADMISSION_V1` plus `CATALOG_HISTORICAL_SOURCE_IMPORT_V1` provide the missing S2 path for an explicitly reviewed previous exact release. `platformctl catalog-bundle assemble --historical` can create an older immutable bundle only against an already resolved newer target; `catalog-bundle install-historical` requires canonical admission, installs the historical runtime bundle without changing the current component contract, and admits only the exact source pair into `COMPONENT_RUNTIME_UPGRADE_MATRIX_V2`.

This closes the **manual historical-source repository mutation gap**. It does not fabricate previous versions: all 20 previous-version selections remain `review-required` until explicitly reviewed and acquired.

The current environment still cannot retrieve the exact upstream component/image/compiler bytes. The official Go 1.27.1 byte fetch was retried through the environment download path and did not complete, so `RELEASE_BUILD_TOOLCHAIN_LOCK_PENDING` remains truthful.

## Open Core Freeze phases

| Phase | Status | Current blockers |
|---|---|---|
| `C7W-mcp-user-admin-write-parity` | blocked | `MCP_EXTERNAL_CLIENT_INTEROP_MATRIX_PENDING` |
| `S1-exact-supply-chain-acquisition-closure` | blocked | `UPSTREAM_ADMISSION_REVIEWS_PENDING`, `COMPONENT_SOURCE_ACQUISITION_PENDING`, `SOURCE_LOCKS_PENDING`, `MANAGEMENT_WORKLOAD_OCI_ARCHIVE_PENDING`, `MANAGEMENT_IMAGE_DIGEST_LOCKS_PENDING`, `RELEASE_BUILD_TOOLCHAIN_LOCK_PENDING` |
| `S2-component-runtime-certification-authorities` | blocked | `COMPONENT_UPGRADE_SOURCE_ADMISSION_PENDING`, `COMPONENT_RUNTIME_UPGRADE_MATRIX_PENDING` |
| `H1-baremetal-connected-managed-okd` | blocked | `OKD_CONNECTED_MANAGED_INSTALL_PENDING` |
| `I1-disconnected-okd-core` | blocked | `OKD_OC_MIRROR_V2_ACQUISITION_PENDING` |
| `C9-pre-certification-feature-freeze-exact-bundle` | blocked | `PRE_CERTIFICATION_REQUIRED_FEATURES_OPEN`, `LAB_CANONICAL_BUNDLE_SOURCE_LOCKS_PENDING` |

## S1 truth

- upstream component queue: **14 ready / 3 review**;
- real current component source locks: **3/20**;
- external management image acquisition: **0/4 committed into exact release authority**;
- manifest image-resolution sets: **0/3 sealed**;
- exact Go release compiler archive: **not acquired**;
- management workload OCI archive: **not sealed from exact acquired bytes**.

The three review blockers remain intentional: Cilium 1.20.1 requires a newer Gateway API baseline than the currently resolved 1.5.1; Kyverno 3.8.2 still has an upstream CRD rendering issue under review; MetalLB 0.16.1 still lacks a released security-bump tag. No automatic risk acceptance is permitted.

## S2 truth

- target components: **20**;
- previous-source admission: **0 admitted / 20 review-required**;
- exact source pairs: **0/20 admitted**;
- runtime upgrade certification: **0/20 complete**.

The software path is now complete for a reviewed historical source: assemble historical bundle -> verify immutable evidence -> canonical previous-source admission -> historical install -> exact pair admission -> runtime-upgrade execution/evidence. The remaining blockers are reviewed previous-version selection, exact bytes/source locks and real runtime execution evidence.

## H1 / I1 truth

The managed OKD and disconnected workflows remain source-present and fail closed, but they cannot close without exact acquired OKD installer/release/FCOS/`oc-mirror v2` inputs and real connected/disconnected execution. No fake rollback or Physical PASS is inferred.

## AI / MCP / Persian truth

- stable API disposition: **318/318**;
- AI-callable routes: **281**;
- AI-callable mutations through durable Jobs/Operations: **134/134**;
- MCP action registry remains **70 actions**;
- Persian Writing gate remains pinned to the project-owned offline integration;
- C7W remains externally blocked on real ChatGPT/Claude/Gemini/Grok OAuth/delegation/read/write/approval/revocation interoperability evidence.

## Critical path after V54

1. **S1 actual bytes** — execute connected handoff for 14 component bundles, four external management images, three manifest image sets and Go 1.27.1; resolve the three review candidates only when upstream/dependency evidence permits.
2. **S2 previous releases** — review one exact previous release per component, acquire it using the new historical path, reach 20/20 exact source-pair admission, then execute lifecycle/upgrade/failure certification.
3. **H1** — run connected Compact-3 Managed OKD using exact acquired artifacts.
4. **I1** — acquire exact `oc-mirror v2` and execute disconnected Compact-3/upgrade certification.
5. **C7W** — execute named-client interoperability matrix with real clients.
6. **C9** — freeze only after all mandatory branches and exact bundle inputs are closed.

## Required current markers

- `PROGRAM_PHASE_MODEL_V54`
- release `0.0.348`
- `SUPPLY_CHAIN_HANDOFF_V1`
- `SUPPLY_CHAIN_HANDOFF_SEAL_V1`
- `COMPONENT_UPGRADE_SOURCE_ADMISSION_V1`
- `CATALOG_HISTORICAL_SOURCE_IMPORT_V1`
- `COMPONENT_RUNTIME_UPGRADE_MATRIX_V2`
- `MCP_EXTERNAL_CLIENT_INTEROP_MATRIX_PENDING`
- `OKD_CONNECTED_MANAGED_INSTALL_PENDING`
- `OKD_OC_MIRROR_V2_ACQUISITION_PENDING`
- `RELEASE_BUILD_TOOLCHAIN_LOCK_PENDING`
- `COMPONENT_UPGRADE_SOURCE_ADMISSION_PENDING`
- `COMPONENT_RUNTIME_UPGRADE_MATRIX_PENDING`

Additional retained authorities: `MANAGEMENT_WORKLOAD_STAGED_BATCH_V1`, `UPSTREAM_STAGED_BATCH_V1`, `FEATURE_CERTIFICATION_REGISTRY_V2`, `FEATURE_CERTIFICATION_CONTRACT_COVERAGE_V1`.
