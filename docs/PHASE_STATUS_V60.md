# Current Phase Status — PROGRAM_PHASE_MODEL_V60

Release **0.0.355** advances `PROGRAM_PHASE_MODEL_V60` by productizing the pre-physical part of J1 Automation & External Integrations. This release closes three J1 software blockers through explicit authority contracts, scoped API admission, MCP route parity and Operator Console workflows. It does **not** convert adapter contracts, previews or source tests into external-system execution, installation, runtime certification or Physical PASS.

## Dual closure truth

| Metric | Current truth |
| --- | ---: |
| Mandatory Core phases | 25 |
| Core source/software closure | **25/25 (100%)** |
| Core phase-ready / release closure | **19/25 (76%)** |
| Core source/software blockers | **0 known after 0.0.355 hardening** |
| Core externally/evidence blocked phases | **6** |
| J1 software blockers | **1 remaining: Terraform provider** |
| Feature Freeze ready | **No** |
| Physical / production PASS | **No** |

The six open Core phases remain C7W, S1, S2, H1, I1 and C9. Expansion work does not increase Core closure percentages and does not weaken those gates.

## J1 Automation & External Integrations

J1 remains **BLOCKED**, but its blocker set has been reduced from four software blockers to one real blocker: `TERRAFORM_PROVIDER_PENDING`.

Closed in 0.0.355:

- `EXTERNAL_REGISTRY_ADMISSION_AUTHORITY_V1` admits only absolute HTTPS registry endpoints and exact digest-pinned image references whose registry host matches the requested endpoint. Mutable tags are rejected, raw credentials are forbidden, credential references are bounded opaque server-side identifiers, and zot remains the managed registry system of truth.
- `NOTIFICATION_PROVIDER_ADAPTER_CONTRACT_V1` declares product-owned adapter capabilities for Console and Webhook delivery, including transport, external egress, authorization/HMAC support, organization-scoped secrets and durable retry/dead-letter semantics without exposing raw secret material.
- `NOTIFICATION_PREFERENCE_DIGEST_POLICY_V1` produces deterministic revision-independent SHA-256 policy evidence from normalized organization/project scope, route name, enabled state, event patterns, minimum severity and destination IDs.
- REST surfaces expose `POST /api/v1/external-registry/admission`, `GET /api/v1/notification-provider-contracts` and `GET /api/v1/notification-routes/{id}/policy-digest` with scope/RBAC checks where resource scope exists.
- MCP route parity classifies all three preview/read contracts as fixed typed read-only tool surfaces. No generic arbitrary-route mutation authority is introduced.
- Operator Console exposes notification-provider contract inspection, route-policy digest inspection and an external-registry admission preview. The external-registry path is explicitly a preview/admission check and does not mutate or configure a registry.

J1 cannot be promoted to source-implemented until a **real Terraform provider** consumes stable product APIs and proves it does not bypass RBAC, durable operations, idempotency, approval or evidence authority. A schema-only, generated stub or mock provider is not accepted as closure.

## Core pre-physical truth

Core source/software closure remains **25/25**. The remaining mandatory Core work is evidence/external-byte/runtime work rather than missing owner-layer software:

- **C7W** — real named-client MCP interoperability for ChatGPT, Claude, Gemini and Grok remains external execution evidence.
- **S1** — exact current-source acquisition remains **3/20** locked; management image/archive/toolchain bytes and runtime-suitability holds remain external-byte/runtime evidence.
- **S2** — `COMPONENT_RUNTIME_UPGRADE_MATRIX_V2` remains **0 admitted source pairs / 19 pending upgrade-applicable pairs / 1 install-only first release** until historical/current exact bytes converge and runtime certification executes.
- **H1** — connected Managed OKD Compact-3 remains physical/runtime evidence and is intentionally not claimed by source work.
- **I1** — the disconnected software workflow is source-complete, while exact `oc-mirror v2` acquisition and disconnected runtime execution remain open.
- **C9** — Feature Freeze cannot close until the mandatory Core external/runtime evidence and exact bundle state are present.

## Additional pre-physical expansion work available

The remaining software-only expansion tracks that can continue without physical installation are J1 Terraform provider, J2 FinOps usage/rate-card authority, J3 virtual-cluster profile/provider, H2 VMware provider authority and the software portions of I2 edge/sovereign local authority, UI, boot-security attestation and disconnected local-AI profile. KubeVirt workload-plane and accelerator/AI infrastructure remain optional product decisions and must not be treated as mandatory Core blockers.

## S1/S2 supply-chain truth retained

The current-source queue remains **17 ready / 0 source-review**, with **3/20** exact current source locks. Historical source admission remains **19 admitted-for-acquisition / 0 review-required / 1 install-only first product release**. The tagged-source and historical staged-batch acquisition contracts from V59 and catalog-bundle durable atomic output hardening from 0.0.354 remain canonical and unchanged.

## AI / MCP truth retained

MCP remains user-centric and typed. The J1 API additions are folded into `MCP_ROUTE_PARITY_AUTHORITY_V1`; external-registry admission is intentionally read-like because it is a fail-closed validation/preview and does not mutate external or product state. C7W still requires real named-client OAuth/delegation, scoped read/write, durable-operation, approval and revocation evidence against a deployed system.

## What 0.0.355 does not claim

No real registry was contacted or modified. No Terraform provider is claimed. No installer or physical lab was executed for this J1 closure. No exact external source byte count, S2 runtime pair count, named-client interoperability state, OKD Physical PASS or production readiness state is increased by this release.

## Canonical retained authorities and explicit blockers

V60 retains `PROGRAM_PROGRESS_MODEL_V1`, `SUPPLY_CHAIN_HANDOFF_V1`, `SUPPLY_CHAIN_HANDOFF_SEAL_V1`, `UPSTREAM_STAGED_BATCH_V1`, `HISTORICAL_UPGRADE_STAGED_BATCH_V1`, `TAGGED_SOURCE_ACQUISITION_RECIPE_V1`, `MANAGEMENT_WORKLOAD_STAGED_BATCH_V1`, `RELEASE_BUILD_TOOLCHAIN_LOCK_PENDING`, `RUNTIME_DEPENDENCY_TRANSITION_V1`, `COMPONENT_UPGRADE_SOURCE_ADMISSION_V1`, `CATALOG_HISTORICAL_SOURCE_IMPORT_V1`, `COMPONENT_RUNTIME_UPGRADE_MATRIX_PENDING`, `FEATURE_CERTIFICATION_REGISTRY_V2`, and `FEATURE_CERTIFICATION_CONTRACT_COVERAGE_V1`. Connected OKD still carries `OKD_CONNECTED_MANAGED_INSTALL_PENDING`; disconnected OKD still carries `OKD_OC_MIRROR_V2_ACQUISITION_PENDING`.
