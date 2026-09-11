# Current Phase Status — PROGRAM_PHASE_MODEL_V55

> Snapshot for release `0.0.349`. Source implementation, source acquisition, runtime suitability, runtime certification and Exact-SHA Physical PASS remain independent truths.

- Total phases: **34**
- Core Freeze phases: **25**
- Core source-implemented: **19/25 = 76%**
- All source-implemented phases: **19**
- Blocked phases: **11**
- Deferred certification phases: **2**
- Not-evaluated optional phases: **2**

## V55 large bottleneck closure

V55 removes a cross-layer S1 bottleneck: unresolved source acquisition no longer depends on runtime suitability review. `CatalogUpstreamAdmission` now carries two independent decisions:

1. `status` governs **exact immutable source acquisition**;
2. `runtimeStatus` governs **whether the acquired candidate can proceed toward runtime certification**.

All **17/17 unresolved Helm candidates** now have an exact source candidate and are `ready-for-acquisition`. Cilium, Kyverno and MetalLB remain **3 runtime holds**, so no install/certification authority is weakened.

`RUNTIME_DEPENDENCY_TRANSITION_V1` also establishes the product-owned gateway/network transition without claiming bytes as acquired:

- current Gateway API: `1.5.1` with existing resolved source;
- target Gateway API: `1.6.1`, official release asset metadata exact-pinned but bytes pending;
- kgateway target: `2.4.1`, compatible with Gateway API 1.4-1.6;
- Cilium target: `1.20.1`, runtime-held until Gateway API 1.6.1 transition certification;
- mutation before source resolution and Physical PASS inference are forbidden.

The same split is carried by `SUPPLY_CHAIN_HANDOFF_V1`: `ready`, `reviewBlocked`, and `runtimeHolds` are separate derived sets. A runtime hold never becomes a reason to skip exact source acquisition.

## Open Core Freeze phases

| Phase | Status | Current blockers |
|---|---|---|
| `C7W-mcp-user-admin-write-parity` | blocked | `MCP_EXTERNAL_CLIENT_INTEROP_MATRIX_PENDING` |
| `S1-exact-supply-chain-acquisition-closure` | blocked | `COMPONENT_SOURCE_ACQUISITION_PENDING`, `SOURCE_LOCKS_PENDING`, `MANAGEMENT_WORKLOAD_OCI_ARCHIVE_PENDING`, `MANAGEMENT_IMAGE_DIGEST_LOCKS_PENDING`, `RELEASE_BUILD_TOOLCHAIN_LOCK_PENDING` |
| `S2-component-runtime-certification-authorities` | blocked | `UPSTREAM_RUNTIME_SUITABILITY_HOLDS_PENDING`, `COMPONENT_UPGRADE_SOURCE_ADMISSION_PENDING`, `COMPONENT_RUNTIME_UPGRADE_MATRIX_PENDING` |
| `H1-baremetal-connected-managed-okd` | blocked | `OKD_CONNECTED_MANAGED_INSTALL_PENDING` |
| `I1-disconnected-okd-core` | blocked | `OKD_OC_MIRROR_V2_ACQUISITION_PENDING` |
| `C9-pre-certification-feature-freeze-exact-bundle` | blocked | `PRE_CERTIFICATION_REQUIRED_FEATURES_OPEN`, `LAB_CANONICAL_BUNDLE_SOURCE_LOCKS_PENDING` |

## S1 truth

- unresolved Helm source admission: **17 ready / 0 source-selection review**;
- runtime suitability holds carried separately: **3** (`cilium`, `kyverno`, `metallb`);
- real current component source locks: **3/20**;
- external management image acquisition: **0/4 committed into exact release authority**;
- manifest image-resolution sets: **0/3 sealed**;
- exact Go `1.27.1 linux/amd64` release compiler archive: **not acquired**;
- management workload OCI archive: **not sealed from exact acquired bytes**;
- Gateway API `1.6.1` official asset size/SHA metadata: **admitted as acquisition metadata, bytes still pending**.

S1 is therefore no longer blocked by a product/runtime review decision. It is blocked by actual external byte acquisition and exact lock creation.

## Runtime-hold truth

- Cilium `1.20.1`: source acquisition allowed; runtime remains `dependency-transition-required` until exact Gateway API `1.6.1` transition evidence exists.
- Kyverno `3.8.2`: source acquisition allowed; runtime remains `review-required` while the recorded upstream chart/CRD defect blocker remains open.
- MetalLB `0.16.1`: source acquisition allowed; runtime remains `review-required` while the recorded release/security dependency blocker remains open.

Runtime hold evidence is mandatory and source acquisition cannot clear it.

## S2 truth

- target components: **20**;
- previous-source admission: **0 admitted / 20 review-required**;
- exact historical source pairs: **0/20 admitted**;
- runtime upgrade certification: **0/20 complete**.

Historical source import remains first-class through `COMPONENT_UPGRADE_SOURCE_ADMISSION_V1` + `CATALOG_HISTORICAL_SOURCE_IMPORT_V1`; no previous release is guessed or auto-selected.

## H1 / I1 truth

Managed OKD connected/disconnected source workflows remain present and fail closed. Closure still requires exact OKD installer/release/FCOS/`oc-mirror v2` inputs plus real connected/disconnected runtime execution. Physical PASS is not inferred.

## AI / MCP / Persian truth

- stable API disposition remains contract-covered;
- MCP action registry remains **70 actions**;
- Persian Writing gate remains part of repository validation;
- C7W remains blocked only on real named-client ChatGPT/Claude/Gemini/Grok interoperability evidence, not MCP core architecture;
- catalog API/Console now expose source-admission readiness and runtime holds separately, so AI/UI cannot misread an acquirable candidate as runtime-certified.

## Critical path after V55

1. **S1 byte closure** — execute all 17 exact source acquisitions, four management external image acquisitions, three manifest image resolutions and exact Go toolchain acquisition; raise source locks from 3/20 toward 20/20.
2. **Gateway/network transition** — acquire and verify Gateway API 1.6.1 + kgateway 2.4.1 + Cilium 1.20.1, then perform ordered runtime transition certification before clearing the Cilium hold.
3. **S2 previous releases** — explicitly review/acquire one exact previous source per component, reach 20/20 source-pair admission and execute lifecycle/upgrade/failure evidence.
4. **H1** — execute connected Compact-3 Managed OKD using exact acquired artifacts.
5. **I1** — execute disconnected Compact-3/upgrade using exact `oc-mirror v2` acquisition.
6. **C7W** — execute real named-client OAuth/delegation/read/write/approval/revocation matrix.
7. **C9** — freeze only after all mandatory branches and exact bundle inputs are closed.

## Required current markers

- `PROGRAM_PHASE_MODEL_V55`
- release `0.0.349`
- `SUPPLY_CHAIN_HANDOFF_V1`
- `SUPPLY_CHAIN_HANDOFF_SEAL_V1`
- `RUNTIME_DEPENDENCY_TRANSITION_V1`
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
