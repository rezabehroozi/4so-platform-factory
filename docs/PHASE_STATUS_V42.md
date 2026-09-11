# Current Phase Status — PROGRAM_PHASE_MODEL_V42

> Snapshot for release `0.0.334`. The executable roadmap in `internal/targetmodel` is canonical. `source-implemented` is source-level only and never implies Generated Runtime, Integration, Exact-SHA Physical or production PASS.

- Total phases: **34**
- Core Freeze phases: **25**
- Core source-implemented: **19/25 = 76%**
- All source-implemented phases: **19**
- Blocked phases: **11**
- Deferred certification phases: **2**
- Not-evaluated optional phases: **2**

| # | Phase | Tier | Status | Freeze required | Blockers |
|---:|---|---|---|:---:|---|
| 1 | `A-architecture-authority-rebaseline` | `core-freeze` | `source-implemented` | Yes | — |
| 2 | `B-target-capability-supplychain-foundation` | `core-freeze` | `source-implemented` | Yes | — |
| 3 | `C1-operator-ia-scope-authority` | `core-freeze` | `source-implemented` | Yes | — |
| 4 | `C2-console-data-scale-refresh-semantics` | `core-freeze` | `source-implemented` | Yes | — |
| 5 | `C3-console-action-workflow-evidence-convergence` | `core-freeze` | `source-implemented` | Yes | — |
| 6 | `C4-console-e2e-ux-certification` | `core-freeze` | `source-implemented` | Yes | — |
| 7 | `E-certified-platform-template-workspace-foundation` | `core-freeze` | `source-implemented` | Yes | — |
| 8 | `C5-installer-production-lifecycle-closure` | `core-freeze` | `source-implemented` | Yes | — |
| 9 | `C6-multi-agent-test-autopilot` | `core-freeze` | `source-implemented` | Yes | — |
| 10 | `C7-ai-mcp-delegated-operations` | `core-freeze` | `source-implemented` | Yes | — |
| 11 | `C7R-mcp-remote-oauth-human-delegation` | `core-freeze` | `source-implemented` | Yes | — |
| 12 | `C7W-mcp-user-admin-write-parity` | `core-freeze` | `blocked` | Yes | MCP_WRITE_JOB_COVERAGE_PENDING<br>MCP_EXTERNAL_CLIENT_INTEROP_MATRIX_PENDING |
| 13 | `C8-console-operational-completion` | `core-freeze` | `source-implemented` | Yes | — |
| 14 | `F-okd-import-capability-certification` | `core-freeze` | `source-implemented` | Yes | — |
| 15 | `R0-release-authority-certification-rebaseline` | `core-freeze` | `source-implemented` | Yes | — |
| 16 | `S1-exact-supply-chain-acquisition-closure` | `core-freeze` | `blocked` | Yes | UPSTREAM_ADMISSION_REVIEWS_PENDING<br>COMPONENT_SOURCE_ACQUISITION_PENDING<br>SOURCE_LOCKS_PENDING<br>MANAGEMENT_WORKLOAD_OCI_ARCHIVE_PENDING<br>MANAGEMENT_IMAGE_DIGEST_LOCKS_PENDING<br>RELEASE_BUILD_TOOLCHAIN_LOCK_PENDING |
| 17 | `S2-component-runtime-certification-authorities` | `core-freeze` | `blocked` | Yes | COMPONENT_RUNTIME_UPGRADE_MATRIX_PENDING |
| 18 | `G1-operational-runtime-hardening` | `core-freeze` | `source-implemented` | Yes | — |
| 19 | `G2-generalized-day2-campaign-engine` | `core-freeze` | `source-implemented` | Yes | — |
| 20 | `G3-target-node-maintenance-lifecycle` | `core-freeze` | `source-implemented` | Yes | — |
| 21 | `G4-data-protection-productization` | `core-freeze` | `source-implemented` | Yes | — |
| 22 | `G5-enterprise-identity-compliance` | `core-freeze` | `source-implemented` | Yes | — |
| 23 | `H1-baremetal-connected-managed-okd` | `core-freeze` | `blocked` | Yes | BAREMETAL_MANAGED_INSTALL_WORKFLOW_PENDING<br>OKD_CONNECTED_MANAGED_INSTALL_PENDING |
| 24 | `H2-vmware-provider` | `expansion` | `blocked` | No | VMWARE_PROVIDER_AUTHORITY_PENDING |
| 25 | `I1-disconnected-okd-core` | `core-freeze` | `blocked` | Yes | OKD_OC_MIRROR_V2_ACQUISITION_PENDING<br>OKD_DISCONNECTED_INSTALL_WORKFLOW_PENDING |
| 26 | `I2-edge-sovereign-extension` | `expansion` | `blocked` | No | EDGE_LOCAL_AUTHORITY_PENDING<br>EDGE_LOCAL_UI_PENDING<br>BOOT_SECURITY_ATTESTATION_PENDING<br>LOCAL_AI_DISCONNECTED_PROFILE_PENDING |
| 27 | `J1-automation-external-integrations` | `expansion` | `blocked` | No | TERRAFORM_PROVIDER_PENDING<br>EXTERNAL_REGISTRY_ADMISSION_PENDING<br>NOTIFICATION_PROVIDER_ADAPTER_CONTRACT_PENDING<br>NOTIFICATION_PREFERENCE_DIGEST_POLICY_PENDING |
| 28 | `J2-finops-usage` | `expansion` | `blocked` | No | FINOPS_RATECARD_USAGE_PENDING |
| 29 | `J3-virtual-cluster-profile` | `expansion` | `blocked` | No | VIRTUAL_CLUSTER_PROVIDER_PENDING |
| 30 | `C9-pre-certification-feature-freeze-exact-bundle` | `core-freeze` | `blocked` | Yes | PRE_CERTIFICATION_REQUIRED_FEATURES_OPEN<br>LAB_CANONICAL_BUNDLE_SOURCE_LOCKS_PENDING<br>FEATURE_CERTIFICATION_CONTRACTS_INCOMPLETE |
| 31 | `D-exact-artifact-lab-ai-certification` | `certification` | `deferred-until-development-closure` | No | — |
| 32 | `K-optional-vm-workload-plane` | `optional` | `not-evaluated` | No | VM_WORKLOAD_PLANE_PRODUCT_DECISION_PENDING |
| 33 | `L-optional-accelerator-ai-infrastructure` | `optional` | `not-evaluated` | No | ACCELERATOR_INFRASTRUCTURE_PRODUCT_DECISION_PENDING |
| 34 | `M-full-product-certification-chaos-soak-ux-ai-evals` | `certification` | `deferred-until-development-closure` | No | — |

## Open Core Freeze phases

- **C7W-mcp-user-admin-write-parity** — MCP_WRITE_JOB_COVERAGE_PENDING, MCP_EXTERNAL_CLIENT_INTEROP_MATRIX_PENDING
- **S1-exact-supply-chain-acquisition-closure** — UPSTREAM_ADMISSION_REVIEWS_PENDING, COMPONENT_SOURCE_ACQUISITION_PENDING, SOURCE_LOCKS_PENDING, MANAGEMENT_WORKLOAD_OCI_ARCHIVE_PENDING, MANAGEMENT_IMAGE_DIGEST_LOCKS_PENDING, RELEASE_BUILD_TOOLCHAIN_LOCK_PENDING
- **S2-component-runtime-certification-authorities** — COMPONENT_RUNTIME_UPGRADE_MATRIX_PENDING
- **H1-baremetal-connected-managed-okd** — BAREMETAL_MANAGED_INSTALL_WORKFLOW_PENDING, OKD_CONNECTED_MANAGED_INSTALL_PENDING
- **I1-disconnected-okd-core** — OKD_OC_MIRROR_V2_ACQUISITION_PENDING, OKD_DISCONNECTED_INSTALL_WORKFLOW_PENDING
- **C9-pre-certification-feature-freeze-exact-bundle** — PRE_CERTIFICATION_REQUIRED_FEATURES_OPEN, LAB_CANONICAL_BUNDLE_SOURCE_LOCKS_PENDING, FEATURE_CERTIFICATION_CONTRACTS_INCOMPLETE

## V42 delta

- **0.0.334 / H1 foundation:** `BAREMETAL_MANAGED_INSTALL_AUTHORITY_FOUNDATION_V1` adds Compact-3 request validation, exact artifact digests, secret-reference-only machine inputs, independent approval, monotonic crash/reclaim fencing and deterministic step sequencing. The managed-install and connected-OKD blockers remain open until durable backend/API/worker and exact installer execution evidence are complete.
- **H1 / Bare Metal:** `REDFISH_BOOT_MEDIA_PROVIDER_V1` is now a concrete product-owned provider implementation, not only an interface. It uses TLS-only Redfish resource paths, server-side credential references, idempotent same-image insertion, one-time boot override, reset/power control and bounded observation. the former boot-media-provider blocker is removed; managed-install orchestration and connected OKD installation remain open.
- **C7W / MCP:** `support_bundle_request` now creates the same durable `support.bundle.generate` Operation used by the REST workflow. Diagnostic bytes are never returned inline through MCP; sealed evidence stays behind authenticated REST download. The action registry moves `support-bundle-jobs` to typed-tool-complete and explicitly security-excludes the synchronous binary bundle endpoint. Broader write-family coverage and real external-client interoperability remain open.
- **S1 / Build toolchain:** the official Go 1.27.1 Linux/amd64 candidate is exact-locked by upstream URL, size and SHA-256. `scripts/acquire_release_build_toolchain.py` provides an offline-only atomic admission transaction and never performs network auto-download. The archive itself is not present in this artifact, so `RELEASE_BUILD_TOOLCHAIN_LOCK_PENDING` remains open.
- **S2 / Runtime upgrade:** `COMPONENT_RUNTIME_UPGRADE_V1` adds a real exact-edge upgrade executor contract with distinct source/render digests, stage-specific idempotency tokens, fencing, readiness/failure-recovery/remove-old-version evidence and no fake rollback promise. The matrix remains **0 admitted / 20 pending-source-pair**, so S2 stays blocked on real second-version source pairs and execution evidence.
- **C9 / Feature freeze:** release identity is synchronized to `0.0.334 / managed-okd-install-authority-foundation-v42 / PROGRAM_PHASE_MODEL_V42`. C9 remains blocked by open mandatory branches and canonical source-lock/certification closure; no Physical PASS is inferred from this source release.
