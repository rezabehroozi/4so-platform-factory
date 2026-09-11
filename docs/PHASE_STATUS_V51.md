# Current Phase Status — PROGRAM_PHASE_MODEL_V51

> Snapshot for release `0.0.345`. The executable roadmap in `internal/targetmodel` remains canonical. `source-implemented` never implies Generated Runtime, Integration, Exact-SHA Physical or production PASS.

- Total phases: **34**
- Core Freeze phases: **25**
- Core source-implemented: **19/25 = 76%**
- All source-implemented phases: **19**
- Blocked phases: **11**
- Deferred certification phases: **2**
- Not-evaluated optional phases: **2**

## V51 exact review-candidate authority convergence

S1 review state is now separated from runtime identity. Every unresolved Helm row that already has an exact `selectedVersion` must bind the corresponding component catalog release to that exact candidate even when policy/dependency/security review still blocks acquisition. Review rows use `exact-upstream-review-candidate-pending-decision`; `source.resolved` remains false and acquisition remains fail-closed until the row becomes `ready-for-acquisition`.

This closes a mutable-identity gap for Cilium, Kyverno and MetalLB: their catalog/runtime authorities now bind to exact candidates `1.20.1`, `3.8.2` and `0.16.1` while preserving their existing blockers. The catalog constraint remains separately recorded in `catalog/upstream-admission.json`; it is no longer overloaded as the runtime release identity.

Negative controls reject review-candidate release drift and review-candidate version-policy drift in both Go and Python validation paths. `COMPONENT_RUNTIME_UPGRADE_MATRIX_V2` is regenerated from the exact component identities and remains **20 components / 0 admitted / 20 pending** because no missing source lock or two-version source pair is fabricated.

A separate durability regression found during the full Go sweep is also closed: when the authoritative Kubernetes certificate Secret is accepted, failure to refresh the local agent certificate cache is now fail-closed instead of being silently tolerated. This prevents a later restart from resurrecting a stale cached certificate if the authoritative Secret is temporarily unavailable.

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

The upstream queue remains **14 ready-for-acquisition / 3 review-required**. Only **3 of 20** catalog components currently carry real source locks. Exact candidate pinning is authority hygiene, not byte acquisition; S1 remains blocked on real external bytes/image digests and the remaining review decisions.

## S2 retained truth

`COMPONENT_RUNTIME_UPGRADE_MATRIX_V2` remains fail-closed on source-lock identity drift, wildcard/alias releases, reverse/newer-sibling edges and missing two-version exact source pairs. The matrix remains **20 components, 0 admitted upgrade pairs, 20 pending source pairs**.

## AI / MCP / Persian truth

- MCP route disposition remains **318/318 stable API routes**.
- AI-callable routes remain **281**: 147 read, 63 operate, 71 administration.
- AI-callable mutation coverage remains **134/134** through durable product jobs/operations.
- `persian-writing` 1.3.5 remains pinned offline and the Persian writing gate remains part of repository/UI validation.
- Named-client interoperability with ChatGPT, Claude, Gemini and Grok remains an external evidence blocker; local conformance does not substitute for it.

## Critical path

1. **S1** — execute the 14 admitted acquisitions, resolve the 3 review rows, acquire management workload/image/build-toolchain bytes and seal exact locks.
2. **S2** — acquire two-version exact source pairs and execute real component upgrade matrices.
3. **H1** — connected Managed OKD Compact-3 on exact acquired artifacts.
4. **I1** — exact `oc-mirror v2` acquisition plus disconnected certification.
5. **C7W** — named-client OAuth/delegation/read/write/approval/revocation matrix.
6. **C9** — only after all mandatory branches and exact appliance bundle source locks are complete.

## Required current markers

- `PROGRAM_PHASE_MODEL_V51`
- release `0.0.345`
- `UPSTREAM_ACQUISITION_TOOLCHAIN_V3`
- `COMPONENT_RUNTIME_UPGRADE_MATRIX_V2`
- `FEATURE_CERTIFICATION_REGISTRY_V2`
- `FEATURE_CERTIFICATION_CONTRACT_COVERAGE_V1`
- `MCP_EXTERNAL_CLIENT_INTEROP_MATRIX_PENDING`
- `OKD_CONNECTED_MANAGED_INSTALL_PENDING`
- `OKD_OC_MIRROR_V2_ACQUISITION_PENDING`
- `RELEASE_BUILD_TOOLCHAIN_LOCK_PENDING`
- `COMPONENT_RUNTIME_UPGRADE_MATRIX_PENDING`
