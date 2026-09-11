# Current Phase Status — PROGRAM_PHASE_MODEL_V50

> Snapshot for release `0.0.344`. The executable roadmap in `internal/targetmodel` remains canonical. `source-implemented` never implies Generated Runtime, Integration, Exact-SHA Physical or production PASS.

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

## V50 S1 acquisition execution hardening

`UPSTREAM_ACQUISITION_TOOLCHAIN_V3` keeps Helm 4.2.4 and Crane 0.22.1 exact-pinned while adding a network-free staged bootstrap path for restricted build hosts. Staged filenames are derived only from the canonical lock URLs, every archive must be a regular file, SHA-256 must match the canonical platform asset, only the exact archive member is extracted, the extracted binary is size-bounded, and the resulting tool version is revalidated before use. A staged asset therefore cannot become an alternate version/source authority.

The upstream Helm acquisition path now also has machine-readable input limits: 32 MiB Helm index, 64 MiB compressed chart, 8,192 tar members, 512 MiB total expanded content and 1 MiB `Chart.yaml`. Oversized index bodies are detected instead of silently truncating; chart archives must be regular files and may contain only regular files/directories, with path, member-count, expanded-size and metadata-size controls. Negative controls cover staged-asset tampering, oversized metadata and tar-member-limit rejection.

This removes an execution-design gap discovered on restricted build hosts, but it does **not** fabricate component bytes. The canonical queue remains **14 ready-for-acquisition / 3 review-required**, and only **3 of 20** catalog components currently carry real source locks. S1 therefore remains blocked until the exact external bytes/image digests and remaining review decisions are actually acquired and committed to canonical authorities.

## S2 retained truth

`COMPONENT_RUNTIME_UPGRADE_MATRIX_V2` remains fail-closed on source-lock identity drift, wildcard/alias releases and reverse/newer-sibling upgrade edges. The catalog still reports **20 components, 0 admitted upgrade pairs, 20 pending source pairs**, so `COMPONENT_RUNTIME_UPGRADE_MATRIX_PENDING` remains open.

## AI / MCP / Persian truth

- MCP route disposition remains **318/318 stable API routes**.
- AI-callable routes remain **281**: 147 read, 63 operate, 71 administration.
- AI-callable mutation coverage remains **134/134** through durable product jobs/operations.
- `persian-writing` 1.3.5 remains pinned offline and the Persian writing gate remains part of repository/UI validation.
- Named-client interoperability with ChatGPT, Claude, Gemini and Grok remains an external evidence blocker; local conformance does not substitute for it.

## Critical path

1. **S1** — execute the 14 admitted upstream acquisitions, resolve the 3 review rows, acquire management workload/image/build-toolchain bytes and seal exact locks.
2. **S2** — acquire two-version exact source pairs and execute real component upgrade matrices.
3. **H1** — connected Managed OKD Compact-3 on exact acquired artifacts.
4. **I1** — exact `oc-mirror v2` acquisition plus disconnected certification.
5. **C7W** — named-client OAuth/delegation/read/write/approval/revocation matrix.
6. **C9** — only after all mandatory branches and exact appliance bundle source locks are complete.

## Required current markers

- `PROGRAM_PHASE_MODEL_V50`
- release `0.0.344`
- `UPSTREAM_ACQUISITION_TOOLCHAIN_V3`
- `COMPONENT_RUNTIME_UPGRADE_MATRIX_V2`
- `FEATURE_CERTIFICATION_REGISTRY_V2`
- `FEATURE_CERTIFICATION_CONTRACT_COVERAGE_V1`
- `MCP_EXTERNAL_CLIENT_INTEROP_MATRIX_PENDING`
- `OKD_CONNECTED_MANAGED_INSTALL_PENDING`
- `OKD_OC_MIRROR_V2_ACQUISITION_PENDING`
- `RELEASE_BUILD_TOOLCHAIN_LOCK_PENDING`
- `COMPONENT_RUNTIME_UPGRADE_MATRIX_PENDING`
