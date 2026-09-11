# Current Phase Status — PROGRAM_PHASE_MODEL_V52

> Snapshot for release `0.0.346`. The executable roadmap in `internal/targetmodel` remains canonical. `source-implemented` never implies Generated Runtime, Integration, Exact-SHA Physical or production PASS.

- Total phases: **34**
- Core Freeze phases: **25**
- Core source-implemented: **19/25 = 76%**
- All source-implemented phases: **19**
- Blocked phases: **11**
- Deferred certification phases: **2**
- Not-evaluated optional phases: **2**

## V52 S1 staged-batch handoff and installer parity closure

S1 now has a first-class connected-stage to disconnected-install workflow instead of requiring every acquisition host to mutate the source tree directly. `scripts/acquire_upstream_batch.py` supports:

- canonical queue inspection from `catalog/upstream-admission.json`;
- connected `--stage-out DIR` acquisition that produces verified ExternalCatalogBundle ZIPs without repository mutation;
- a derived `stage-manifest.json` under `UPSTREAM_STAGED_BATCH_V1` with exact component/version/source identities plus independently verified bundle and upstream-artifact digests;
- network-free `--install-staged DIR` verification/install through the existing `platformctl catalog-bundle` owner path;
- checkpoint-safe resume after partial staging or install without introducing a second progress database or source-of-truth authority.

The staged manifest is evidence and transport inventory only. Every unresolved component is rebound to the current canonical admission row before install, while already-resolved reruns remain owned by the idempotent catalog-bundle recovery path. Path escapes, symlinks/non-regular files, duplicate entries, release/source/admission drift, bundle digest mismatch and platformctl verification drift fail closed.

A production-path regression exposed by the rebuilt catalog-bundle smoke is also closed. V51 exact review candidates were accepted by the Python admission authority but the Go catalog-bundle installer still required every non-ready component release to equal its wildcard constraint. As a result, an unrelated ready component bundle could not be installed while Cilium/Kyverno/MetalLB remained pinned exact review candidates. The Go owner now mirrors the canonical rule: exact review candidates must stay pinned to their selected version with `exact-upstream-review-candidate-pending-decision`, while review status still blocks their own acquisition. Negative controls reject candidate release and version-policy drift.

The end-to-end ExternalCatalogBundle smoke again passes assemble → verify → install → admission retirement → idempotent retry → rebuild → repository validation → API catalog/render, proving the fix on the same owner path used by S1.

## Open Core Freeze phases

| Phase | Status | Current blockers |
|---|---|---|
| `C7W-mcp-user-admin-write-parity` | blocked | `MCP_EXTERNAL_CLIENT_INTEROP_MATRIX_PENDING` |
| `S1-exact-supply-chain-acquisition-closure` | blocked | `UPSTREAM_ADMISSION_REVIEWS_PENDING`, `COMPONENT_SOURCE_ACQUISITION_PENDING`, `SOURCE_LOCKS_PENDING`, `MANAGEMENT_WORKLOAD_OCI_ARCHIVE_PENDING`, `MANAGEMENT_IMAGE_DIGEST_LOCKS_PENDING`, `RELEASE_BUILD_TOOLCHAIN_LOCK_PENDING` |
| `S2-component-runtime-certification-authorities` | blocked | `COMPONENT_RUNTIME_UPGRADE_MATRIX_PENDING` |
| `H1-baremetal-connected-managed-okd` | blocked | `OKD_CONNECTED_MANAGED_INSTALL_PENDING` |
| `I1-disconnected-okd-core` | blocked | `OKD_OC_MIRROR_V2_ACQUISITION_PENDING` |
| `C9-pre-certification-feature-freeze-exact-bundle` | blocked | `PRE_CERTIFICATION_REQUIRED_FEATURES_OPEN`, `LAB_CANONICAL_BUNDLE_SOURCE_LOCKS_PENDING` |

## S1 retained truth

The upstream queue remains **14 ready-for-acquisition / 3 review-required** and only **3 of 20** catalog components carry real source locks. The new staged workflow makes those 14 rows operationally transferable into a disconnected build host, but this release does **not** fabricate or claim upstream chart/image bytes that the current environment could not fetch. Actual byte acquisition and source-lock installation remain required evidence.

## S2 retained truth

`COMPONENT_RUNTIME_UPGRADE_MATRIX_V2` remains **20 components / 0 admitted / 20 pending**. No missing two-version source pair is inferred from staging metadata.

## AI / MCP / Persian truth

- MCP route disposition remains **318/318 stable API routes**.
- AI-callable routes remain **281**: 147 read, 63 operate, 71 administration.
- AI-callable mutation coverage remains **134/134** through durable product jobs/operations.
- `persian-writing` 1.3.5 remains pinned offline and the Persian writing gate remains part of repository/UI validation.
- Named-client interoperability with ChatGPT, Claude, Gemini and Grok remains an external evidence blocker; local conformance does not substitute for it.

## Critical path

1. **S1** — run the 14 admitted acquisitions on a connected staging host, transfer the digest-bound batch, install offline, resolve the 3 review rows, acquire management workload/image/build-toolchain bytes and seal exact locks.
2. **S2** — acquire two-version exact source pairs and execute real component upgrade matrices.
3. **H1** — connected Managed OKD Compact-3 on exact acquired artifacts.
4. **I1** — exact `oc-mirror v2` acquisition plus disconnected certification.
5. **C7W** — named-client OAuth/delegation/read/write/approval/revocation matrix.
6. **C9** — only after all mandatory branches and exact appliance bundle source locks are complete.

## Required current markers

- `PROGRAM_PHASE_MODEL_V52`
- release `0.0.346`
- `UPSTREAM_ACQUISITION_TOOLCHAIN_V3`
- `UPSTREAM_STAGED_BATCH_V1`
- `COMPONENT_RUNTIME_UPGRADE_MATRIX_V2`
- `FEATURE_CERTIFICATION_REGISTRY_V2`
- `FEATURE_CERTIFICATION_CONTRACT_COVERAGE_V1`
- `MCP_EXTERNAL_CLIENT_INTEROP_MATRIX_PENDING`
- `OKD_CONNECTED_MANAGED_INSTALL_PENDING`
- `OKD_OC_MIRROR_V2_ACQUISITION_PENDING`
- `RELEASE_BUILD_TOOLCHAIN_LOCK_PENDING`
- `COMPONENT_RUNTIME_UPGRADE_MATRIX_PENDING`
