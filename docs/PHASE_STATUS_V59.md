# Current Phase Status — PROGRAM_PHASE_MODEL_V59

Release **0.0.354** retains `PROGRAM_PHASE_MODEL_V59` and hardens the already-added S2 historical acquisition path at its canonical `catalog-bundle assemble` boundary. Bundle output is now durable/atomic and fail-closed for symlink or non-regular destinations, while admission, byte acquisition, source-pair admission, runtime certification and Physical PASS remain strictly separate.

## Dual closure truth

| Metric | Current truth |
| --- | ---: |
| Mandatory Core phases | 25 |
| Core source/software closure | **25/25 (100%)** |
| Core phase-ready / release closure | **19/25 (76%)** |
| Core source/software blockers | **0 known after 0.0.354 hardening** |
| Core externally/evidence blocked phases | **6** |
| Feature Freeze ready | **No** |
| Physical / production PASS | **No** |

The six open Core phases remain C7W, S1, S2, H1, I1 and C9. Release 0.0.354 does not convert staged metadata, reviewed recipes, source selection or test fixtures into external-byte or Physical evidence.

## S1 exact supply-chain truth

The current-source queue remains **17 ready / 0 source-review**, with only **3/20** current component releases carrying real exact source locks in this artifact. Four external management images, three manifest image-resolution sets, the sealed management OCI archive and the exact Go 1.27.1 release compiler archive remain byte-bound. Cilium, Kyverno and MetalLB retain three separate runtime-suitability holds; those holds do not block immutable source acquisition.

## S2 previous-release and historical execution truth

`COMPONENT_UPGRADE_SOURCE_ADMISSION_V1` remains fully decision-closed: **19 admitted-for-acquisition / 0 review-required / 1 install-only-first-product-release**. `secure-namespace-foundation 1.0.0` remains install-only because fabricating a historical product release is forbidden.

`COMPONENT_RUNTIME_UPGRADE_MATRIX_V2` still truthfully reports **0 admitted source pairs / 19 pending upgrade-applicable pairs / 1 install-only first release**. No historical source byte has been fabricated in 0.0.354.

## 0.0.354 supply-chain output hardening

The canonical `platformctl catalog-bundle assemble` owner path previously wrote the final ZIP in-place. A crash, kill or concurrent reader could therefore observe a truncated/intermediate bundle, and an already-present symlink destination was not explicitly rejected. Release 0.0.354 closes that defect without changing source/admission truth:

- existing symlink or non-regular output paths are rejected fail-closed before any write;
- existing regular files remain retryable and are replaced atomically through the durable-file boundary;
- data and parent-directory rename are synchronized before success is reported;
- negative regression coverage proves a symlink target remains untouched;
- the canonical test targets now directly execute tagged-source and historical-upgrade batch self-tests.

This is source/software hardening only. It does not raise the **3/20** exact-source-lock count, the **0/19** runtime-upgrade source-pair count, or any Physical certification state.

## V59 tagged-source acquisition closure

`TAGGED_SOURCE_ACQUISITION_RECIPE_V1` and `scripts/acquire_upstream_tagged_source.py` close the missing owner path for historical tagged source sets. The runner:

- binds only to reviewed `COMPONENT_UPGRADE_SOURCE_ADMISSION_V1` rows;
- pins a full 40-character upstream Git commit for the exact release tag;
- verifies live tag → commit identity before fetching any file;
- fetches only HTTPS GitHub API/raw content from the full pinned commit, never from a moving branch;
- rejects path traversal, duplicate archive names, tag drift, oversized files/sets and non-exact identity;
- creates a deterministic source-set ZIP with `source-index.json` and per-file SHA-256 evidence;
- renders Kubernetes resources and resolves any image reference to an immutable digest before bundle assembly;
- emits license/SBOM/image evidence and uses the canonical `catalog-bundle` verification/transaction boundary;
- supports offline staged verification and `install-historical` without implying runtime certification.

Two reviewed recipes are committed and authority-bound:

| Component | Historical release | Full pinned commit |
| --- | --- | --- |
| Gateway API | `1.5.0` | `3797b631d20f9ff4e2b4571f62d91d84a1fbdf5a` |
| Snapshot Controller | `8.4.0` | `f21cb02763e7cd6a7fc84846f106b83119b5371d` |

The commits are acquisition authority inputs, not claims that their bytes are already present in this artifact.

## Unified handoff integration

`SUPPLY_CHAIN_HANDOFF_V1` now includes `historicalComponentAcquisition` as first-class derived state. Current V59 truth is:

- historical tagged-source ready: **2**;
- historical Helm/OCI immediately ready: **0**;
- waiting for current target source resolution: **17**;
- already historical source-locked: **0**;
- install-only first product release: **1**.

The connected command plan now stages both current components and historical sources. The offline plan re-verifies and installs both. `SUPPLY_CHAIN_HANDOFF_SEAL_V1` requires the historical stage manifest whenever a historical source is immediately stageable, so transfer completeness covers this path rather than treating it as an out-of-band operator step.

## AI / MCP

C7W remains blocked only on real named-client execution under `MCP_EXTERNAL_CLIENT_INTEROPERABILITY_MATRIX_V2`: ChatGPT, Claude, Gemini and Grok require real OAuth/delegation, scoped read/write, durable-operation, approval and revocation evidence against a deployed system. Local conformance remains necessary but not sufficient evidence.

## OKD

H1 remains blocked on connected Managed OKD Compact-3 Exact-SHA physical execution. I1 remains blocked on exact `oc-mirror v2` acquisition and disconnected Compact-3 execution. Release 0.0.354 adds no Physical PASS claim.

## Critical path from current V59 roadmap

1. Execute S1 connected acquisition and sealed offline import, raising current exact source locks from **3/20 toward 20/20**, while acquiring management image and exact release-toolchain bytes.
2. Immediately acquire/install the two commit-pinned tagged historical predecessors; as each of the remaining 17 current targets becomes source-resolved, stage its already-reviewed historical Helm/OCI predecessor.
3. Drive S2 from **0/19** source pairs toward **19/19**, then execute exact two-version upgrade/failure/recovery certification plus install-only lifecycle certification for the first product release.
4. Execute C7W named-client interoperability.
5. Execute H1 connected and I1 disconnected OKD Physical certification.
6. Close C9 and freeze one Exact-SHA bundle only after all mandatory external/runtime/Physical evidence is present.

## Canonical retained authorities and explicit blockers

V59 binds `PROGRAM_PROGRESS_MODEL_V1`, `SUPPLY_CHAIN_HANDOFF_V1`, `SUPPLY_CHAIN_HANDOFF_SEAL_V1`, `UPSTREAM_STAGED_BATCH_V1`, `HISTORICAL_UPGRADE_STAGED_BATCH_V1`, `TAGGED_SOURCE_ACQUISITION_RECIPE_V1`, `MANAGEMENT_WORKLOAD_STAGED_BATCH_V1`, `RELEASE_BUILD_TOOLCHAIN_LOCK_PENDING`, `RUNTIME_DEPENDENCY_TRANSITION_V1`, `COMPONENT_UPGRADE_SOURCE_ADMISSION_V1`, `CATALOG_HISTORICAL_SOURCE_IMPORT_V1`, `COMPONENT_RUNTIME_UPGRADE_MATRIX_PENDING`, `FEATURE_CERTIFICATION_REGISTRY_V2`, and `FEATURE_CERTIFICATION_CONTRACT_COVERAGE_V1`. Connected OKD still carries `OKD_CONNECTED_MANAGED_INSTALL_PENDING`; disconnected OKD still carries `OKD_OC_MIRROR_V2_ACQUISITION_PENDING`.
