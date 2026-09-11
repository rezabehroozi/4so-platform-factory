# Current Phase Status — PROGRAM_PHASE_MODEL_V53

> Snapshot for release `0.0.347`. The executable roadmap in `internal/targetmodel` remains canonical. `source-implemented` never implies Generated Runtime, Integration, Exact-SHA Physical or production PASS.

- Total phases: **34**
- Core Freeze phases: **25**
- Core source-implemented: **19/25 = 76%**
- All source-implemented phases: **19**
- Blocked phases: **11**
- Deferred certification phases: **2**
- Not-evaluated optional phases: **2**

## V53 large S1/S2 supply-chain handoff convergence

V53 unifies the previously separate pre-certification acquisition branches under the derived `SUPPLY_CHAIN_HANDOFF_V1` contract. The committed `lab/supply-chain-handoff-plan.json` is regenerated from canonical catalog/source-lock, upstream-admission, management-workload-image and release-toolchain authorities. It is transport/evidence only: staging cannot promote source resolution, runtime certification or Physical PASS.

The handoff covers, in one deterministic plan:

- 14 admitted upstream component acquisitions and the 3 exact-but-review-blocked candidates;
- the 3 already source-locked component releases;
- all four external management images (`postgresql`, `forgejo`, `zot`, `keycloak`);
- the three manifest image-resolution sets;
- the exact Go release compiler candidate archive and digest;
- all 20 S2 component upgrade-pair requirements, preserving explicit reviewed previous-version selection and refusing inferred downgrade/reverse edges.

`scripts/acquire_management_workload_batch.py` adds an exact-release-bound connected stage/offline verify flow for the four external management images. It delegates registry acquisition and offline verification to the existing `platformctl workload-oci` owner path, records exact digest references and a deterministic regular-file tree digest for transfer integrity, rejects symlinks/non-regular content, and assembles only after re-verification against the exact release image plan.

`scripts/supply_chain_handoff.py` supplies deterministic plan generation/checking, staging presence/integrity auditing for digest-owned bytes, and operator command sequencing. It intentionally does not duplicate registry, catalog-bundle or runtime-upgrade authorities.

The current environment could not retrieve the exact Go 1.27.1 archive or upstream component/image bytes, so no missing source/image/toolchain lock is fabricated and S1 remains blocked.

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

- upstream queue: **14 ready-for-acquisition / 3 review-required**;
- real catalog source locks: **3/20**;
- external management image exact-digest acquisition: **0/4 installed into the release source authority**;
- exact release compiler archive: **not acquired**;
- management workload OCI archive: **not assembled from exact acquired bytes**.

`SUPPLY_CHAIN_HANDOFF_V1` makes these branches executable as one connected-to-offline workflow, but it does not count staged or planned inputs as acquired authority.

## S2 retained truth

`COMPONENT_RUNTIME_UPGRADE_MATRIX_V2` remains **20 components / 0 admitted / 20 pending**. V53 now exposes all 20 previous-source requirements in the unified handoff. Previous releases must still be explicitly reviewed exact versions with independent source locks before an edge can be admitted.

## AI / MCP / Persian truth

- MCP route disposition remains **318/318 stable API routes**.
- AI-callable routes remain **281**: 147 read, 63 operate, 71 administration.
- AI-callable mutation coverage remains **134/134** through durable product jobs/operations.
- `persian-writing` 1.3.5 remains pinned offline and its gate remains part of repository/UI validation.
- named-client interoperability with ChatGPT, Claude, Gemini and Grok remains external evidence; local MCP conformance does not substitute for that matrix.

## Critical path

1. **S1** — execute the unified connected handoff: 14 component bundles, four external management images, three manifest-resolution sets and exact Go toolchain bytes; resolve the three review candidates and seal the resulting exact locks/archive.
2. **S2** — explicitly admit previous exact releases, acquire independent source locks and execute real upgrade matrices.
3. **H1** — connected Managed OKD Compact-3 on exact acquired artifacts.
4. **I1** — exact `oc-mirror v2` acquisition plus disconnected certification.
5. **C7W** — named-client OAuth/delegation/read/write/approval/revocation matrix.
6. **C9** — only after mandatory branches and exact appliance bundle locks are complete.

## Required current markers

- `PROGRAM_PHASE_MODEL_V53`
- release `0.0.347`
- `SUPPLY_CHAIN_HANDOFF_V1`
- `MANAGEMENT_WORKLOAD_STAGED_BATCH_V1`
- `UPSTREAM_STAGED_BATCH_V1`
- `UPSTREAM_ACQUISITION_TOOLCHAIN_V3`
- `COMPONENT_RUNTIME_UPGRADE_MATRIX_V2`
- `FEATURE_CERTIFICATION_REGISTRY_V2`
- `FEATURE_CERTIFICATION_CONTRACT_COVERAGE_V1`
- `MCP_EXTERNAL_CLIENT_INTEROP_MATRIX_PENDING`
- `OKD_CONNECTED_MANAGED_INSTALL_PENDING`
- `OKD_OC_MIRROR_V2_ACQUISITION_PENDING`
- `RELEASE_BUILD_TOOLCHAIN_LOCK_PENDING`
- `COMPONENT_RUNTIME_UPGRADE_MATRIX_PENDING`
