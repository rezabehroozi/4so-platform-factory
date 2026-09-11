# Current Phase Status — PROGRAM_PHASE_MODEL_V58

Release **0.0.352** closes the S2 previous-release **selection/review** bottleneck while preserving the separation between admission, byte acquisition, source-pair admission, runtime certification and Physical PASS.

## Dual closure truth

| Metric | Current truth |
| --- | ---: |
| Mandatory Core phases | 25 |
| Core source/software closure | **25/25 (100%)** |
| Core phase-ready / release closure | **19/25 (76%)** |
| Core source/software blockers | **0 known** |
| Core externally/evidence blocked phases | **6** |
| Feature Freeze ready | **No** |
| Physical / production PASS | **No** |

The six open Core phases remain C7W, S1, S2, H1, I1 and C9. Source/software closure does not imply that upstream bytes, historical pairs, runtime upgrades, named external clients, OKD or any Physical scenario have passed.

## S1 exact supply-chain truth

Current source acquisition remains the dominant byte bottleneck. The current-source queue is **17 ready / 0 source-review**, but only **3/20** component releases have real exact source locks. Four external management images, three manifest image-resolution sets, the sealed management OCI archive and the exact Go 1.27.1 release compiler archive also remain externally byte-bound. Cilium, Kyverno and MetalLB retain three separate runtime-suitability holds; those holds do not block immutable source acquisition.

## S2 previous-release selection closure

`COMPONENT_UPGRADE_SOURCE_ADMISSION_V1` now contains:

- **19 admitted-for-acquisition** exact predecessor rows;
- **0 review-required** rows;
- **1 install-only-first-product-release** row (`secure-namespace-foundation 1.0.0`).

Every admitted predecessor is strictly lower than its target, uses an explicit HTTPS/OCI source and carries machine-readable upstream release-history evidence. Admission is not source acquisition and is not runtime certification.

The embedded `secure-namespace-foundation 1.0.0` has no earlier product release. V58 forbids fabricating a `0.x` predecessor simply to satisfy a matrix count. Its current release must be certified for install/readiness/dependency/remove/failure behavior; upgrade evidence becomes applicable only when a real later product release exists.

`COMPONENT_RUNTIME_UPGRADE_MATRIX_V2` therefore reports **0 admitted source pairs / 19 pending upgrade-applicable pairs / 1 install-only first release**. S2 no longer carries `COMPONENT_UPGRADE_SOURCE_ADMISSION_PENDING`; its truthful byte blocker is now `COMPONENT_HISTORICAL_SOURCE_ACQUISITION_PENDING` plus the runtime matrix and runtime-suitability holds.

## Historical acquisition execution

`HISTORICAL_UPGRADE_STAGED_BATCH_V1` consumes only the canonical upgrade-source admission. It never selects a version itself. For Helm/OCI components it supports connected acquisition, staged ExternalCatalogBundle transfer, digest/admission re-verification and offline `install-historical` with checkpoint-safe resume. Because historical assembly is intentionally bound to an already resolved exact target, the 17 currently unresolved Helm/OCI targets remain `waiting-current-source` until S1 installs their current source locks. Gateway API and Snapshot Controller are already target-source-resolved tagged-source-set components and remain separate tagged-source acquisition tasks.

The Go historical import owner path independently enforces all admission policy booleans and upstream review evidence before accepting an exact historical bundle.

## AI / MCP

C7W remains blocked only on real named-client execution under `MCP_EXTERNAL_CLIENT_INTEROPERABILITY_MATRIX_V2`: ChatGPT, Claude, Gemini and Grok still require real OAuth/delegation, scoped read/write, durable operation, approval and revocation evidence against a deployed system. No local conformance test substitutes for that evidence.

## OKD

H1 remains blocked on connected Managed OKD Compact-3 Exact-SHA physical execution. I1 remains blocked on exact `oc-mirror v2` acquisition plus disconnected Compact-3 execution. Source workflows and staging evidence do not imply those Physical PASSes.

## Critical path from V58

1. Execute S1 connected acquisition and sealed offline import, raising current exact source locks from **3/20 toward 20/20** and acquiring management image/toolchain bytes.
2. As each current target becomes source-resolved, acquire the already-reviewed historical predecessor; drive S2 from **0/19 source pairs toward 19/19**. No further predecessor-selection review is required unless upstream/product policy changes.
3. Execute exact two-version component runtime upgrade/failure/recovery evidence for all 19 upgrade-applicable components and install-only lifecycle evidence for the first product release.
4. Execute C7W named-client interoperability.
5. Execute H1 connected and I1 disconnected OKD physical certification.
6. Close C9 and freeze one Exact-SHA bundle only after all mandatory evidence is present.

V58 therefore removes a real human/release-decision bottleneck and makes historical acquisition executable, while leaving external-byte and runtime/physical truth fail-closed.

## Canonical retained authorities and explicit blockers

The V58 release continues to bind and validate the following authorities rather than replacing them with phase documents: `PROGRAM_PROGRESS_MODEL_V1`, `SUPPLY_CHAIN_HANDOFF_V1`, `SUPPLY_CHAIN_HANDOFF_SEAL_V1`, `UPSTREAM_STAGED_BATCH_V1`, `MANAGEMENT_WORKLOAD_STAGED_BATCH_V1`, `RELEASE_BUILD_TOOLCHAIN_LOCK_PENDING`, `RUNTIME_DEPENDENCY_TRANSITION_V1`, `COMPONENT_UPGRADE_SOURCE_ADMISSION_V1`, `CATALOG_HISTORICAL_SOURCE_IMPORT_V1`, `COMPONENT_RUNTIME_UPGRADE_MATRIX_PENDING`, `FEATURE_CERTIFICATION_REGISTRY_V2`, and `FEATURE_CERTIFICATION_CONTRACT_COVERAGE_V1`. Connected OKD still carries `OKD_CONNECTED_MANAGED_INSTALL_PENDING`; disconnected OKD still carries `OKD_OC_MIRROR_V2_ACQUISITION_PENDING`.
