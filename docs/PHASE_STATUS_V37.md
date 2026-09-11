# Current Phase Status — PROGRAM_PHASE_MODEL_V37

> Snapshot for release `0.0.327`. The executable `PROGRAM_PHASE_MODEL_V37` in source is the canonical authority. This document is a human-readable projection and must never override runtime/readiness evidence.

## Release truth

- Product release ready: **false**
- Physical runtime: **`not-evaluated`**
- Total blockers: **97**
- Product blockers: **96**
- Core roadmap blocker instances: **21**
- Deployment-context blockers: **1**
- Enabled blueprint components: **19**
- Upstream admission: **14 ready / 3 review / 17 applicable**

`source-implemented` is a source-level state only. It does not mean Generated/Installed Runtime PASS, Runtime-Realism PASS, Integration PASS, Exact-SHA Physical PASS, or production readiness.

## Roadmap composition

- Total phases: **34**
- Core Freeze phases: **25** — 18 source-implemented / 7 blocked
- Expansion phases: **5**
- Certification phases: **2**
- Optional phases: **2**
- All-phase statuses: **18 source-implemented / 12 blocked / 2 deferred / 2 not-evaluated**

## S2 component runtime-certification truth

- Registry authority: `COMPONENT_RUNTIME_CERTIFICATION_REGISTRY_V1`
- Contracts: **20/20**
- Source-ready: **3**
- Source-blocked: **17**
- Foundation-harness partial: **1**
- Component install/readiness/dependency/failure-recovery/remove partial: **2**
- Pending component executor: **17**
- Full six-stage lifecycle certified: **0**

External source acquisition and runtime certification are separate gates. A component can become source-ready without becoming runtime-certified. V35 preserves the exact build-time acquisition toolchain (`UPSTREAM_ACQUISITION_TOOLCHAIN_V2`) and adds safe failure-recovery/remove execution, but source-byte acquisition, the real two-version upgrade matrix and management image locks remain open.

## Complete phase matrix

| # | Phase | Tier | Status | Core Freeze | Blockers |
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
| 12 | `C7W-mcp-user-admin-write-parity` | `core-freeze` | `blocked` | Yes | `MCP_WRITE_JOB_COVERAGE_PENDING`<br>`MCP_APPROVAL_OPERATION_PARITY_PENDING`<br>`MCP_IDENTITY_ADMIN_JOB_ADAPTER_PENDING`<br>`MCP_EXTERNAL_CLIENT_INTEROP_MATRIX_PENDING` |
| 13 | `C8-console-operational-completion` | `core-freeze` | `source-implemented` | Yes | — |
| 14 | `F-okd-import-capability-certification` | `core-freeze` | `source-implemented` | Yes | — |
| 15 | `R0-release-authority-certification-rebaseline` | `core-freeze` | `source-implemented` | Yes | — |
| 16 | `S1-exact-supply-chain-acquisition-closure` | `core-freeze` | `blocked` | Yes | `UPSTREAM_ADMISSION_REVIEWS_PENDING`<br>`COMPONENT_SOURCE_ACQUISITION_PENDING`<br>`SOURCE_LOCKS_PENDING`<br>`MANAGEMENT_WORKLOAD_OCI_ARCHIVE_PENDING`<br>`MANAGEMENT_IMAGE_DIGEST_LOCKS_PENDING` |
| 17 | `S2-component-runtime-certification-authorities` | `core-freeze` | `blocked` | Yes | `COMPONENT_RUNTIME_EXECUTOR_PARITY_PENDING`<br>`COMPONENT_RUNTIME_UPGRADE_MATRIX_PENDING` |
| 18 | `G1-operational-runtime-hardening` | `core-freeze` | `source-implemented` | Yes | — |
| 19 | `G2-generalized-day2-campaign-engine` | `core-freeze` | `source-implemented` | Yes | — |
| 20 | `G3-target-node-maintenance-lifecycle` | `core-freeze` | `source-implemented` | Yes | — |
| 21 | `G4-data-protection-productization` | `core-freeze` | `source-implemented` | Yes | — |
| 22 | `G5-enterprise-identity-compliance` | `core-freeze` | `blocked` | Yes | `SAML_ENTERPRISE_SSO_PENDING`<br>`COMPLIANCE_DURABLE_SCAN_CENTER_PENDING` |
| 23 | `H1-baremetal-connected-managed-okd` | `core-freeze` | `blocked` | Yes | `BAREMETAL_BOOT_MEDIA_PROVIDER_PENDING`<br>`BAREMETAL_MANAGED_INSTALL_WORKFLOW_PENDING`<br>`OKD_CONNECTED_MANAGED_INSTALL_PENDING` |
| 24 | `H2-vmware-provider` | `expansion` | `blocked` | No | `VMWARE_PROVIDER_AUTHORITY_PENDING` |
| 25 | `I1-disconnected-okd-core` | `core-freeze` | `blocked` | Yes | `OKD_OC_MIRROR_V2_ACQUISITION_PENDING`<br>`OKD_DISCONNECTED_INSTALL_WORKFLOW_PENDING` |
| 26 | `I2-edge-sovereign-extension` | `expansion` | `blocked` | No | `EDGE_LOCAL_AUTHORITY_PENDING`<br>`EDGE_LOCAL_UI_PENDING`<br>`BOOT_SECURITY_ATTESTATION_PENDING`<br>`LOCAL_AI_DISCONNECTED_PROFILE_PENDING` |
| 27 | `J1-automation-external-integrations` | `expansion` | `blocked` | No | `TERRAFORM_PROVIDER_PENDING`<br>`EXTERNAL_REGISTRY_ADMISSION_PENDING`<br>`NOTIFICATION_PROVIDER_ADAPTER_CONTRACT_PENDING`<br>`NOTIFICATION_PREFERENCE_DIGEST_POLICY_PENDING` |
| 28 | `J2-finops-usage` | `expansion` | `blocked` | No | `FINOPS_RATECARD_USAGE_PENDING` |
| 29 | `J3-virtual-cluster-profile` | `expansion` | `blocked` | No | `VIRTUAL_CLUSTER_PROVIDER_PENDING` |
| 30 | `C9-pre-certification-feature-freeze-exact-bundle` | `core-freeze` | `blocked` | Yes | `PRE_CERTIFICATION_REQUIRED_FEATURES_OPEN`<br>`LAB_CANONICAL_BUNDLE_SOURCE_LOCKS_PENDING`<br>`FEATURE_CERTIFICATION_CONTRACTS_INCOMPLETE` |
| 31 | `D-exact-artifact-lab-ai-certification` | `certification` | `deferred-until-development-closure` | No | — |
| 32 | `K-optional-vm-workload-plane` | `optional` | `not-evaluated` | No | `VM_WORKLOAD_PLANE_PRODUCT_DECISION_PENDING` |
| 33 | `L-optional-accelerator-ai-infrastructure` | `optional` | `not-evaluated` | No | `ACCELERATOR_INFRASTRUCTURE_PRODUCT_DECISION_PENDING` |
| 34 | `M-full-product-certification-chaos-soak-ux-ai-evals` | `certification` | `deferred-until-development-closure` | No | — |

## Core critical path

- **C7W-mcp-user-admin-write-parity** — `MCP_WRITE_JOB_COVERAGE_PENDING`, `MCP_APPROVAL_OPERATION_PARITY_PENDING`, `MCP_IDENTITY_ADMIN_JOB_ADAPTER_PENDING`, `MCP_EXTERNAL_CLIENT_INTEROP_MATRIX_PENDING`
- **S1-exact-supply-chain-acquisition-closure** — `UPSTREAM_ADMISSION_REVIEWS_PENDING`, `COMPONENT_SOURCE_ACQUISITION_PENDING`, `SOURCE_LOCKS_PENDING`, `MANAGEMENT_WORKLOAD_OCI_ARCHIVE_PENDING`, `MANAGEMENT_IMAGE_DIGEST_LOCKS_PENDING`
- **S2-component-runtime-certification-authorities** — `COMPONENT_RUNTIME_EXECUTOR_PARITY_PENDING`, `COMPONENT_RUNTIME_UPGRADE_MATRIX_PENDING`
- **G5-enterprise-identity-compliance** — `SAML_ENTERPRISE_SSO_PENDING`, `COMPLIANCE_DURABLE_SCAN_CENTER_PENDING`
- **H1-baremetal-connected-managed-okd** — `BAREMETAL_BOOT_MEDIA_PROVIDER_PENDING`, `BAREMETAL_MANAGED_INSTALL_WORKFLOW_PENDING`, `OKD_CONNECTED_MANAGED_INSTALL_PENDING`
- **I1-disconnected-okd-core** — `OKD_OC_MIRROR_V2_ACQUISITION_PENDING`, `OKD_DISCONNECTED_INSTALL_WORKFLOW_PENDING`
- **C9-pre-certification-feature-freeze-exact-bundle** — `PRE_CERTIFICATION_REQUIRED_FEATURES_OPEN`, `LAB_CANONICAL_BUNDLE_SOURCE_LOCKS_PENDING`, `FEATURE_CERTIFICATION_CONTRACTS_INCOMPLETE`

V37 adds `4SO_KUBERNETES_SECURITY_BASELINE_V1` as executable G5 foundation while keeping G5 blocked until SAML and durable scan-center authority close. Current development priority remains quality-first: S1 exact supply-chain acquisition and S2 per-component runtime executors/lifecycle evidence precede new expansion breadth. C7W, G5, H1 and I1 remain independent mandatory Core closures; G4 is source-implemented but still awaits the higher certification levels required by the release gate. C9 may close only after all mandatory Core blockers are gone. Physical certification phases remain deferred until development closure and must use the exact frozen SHA/artifact.

## Related authorities

- `docs/QUALITY_FIRST_CORE_REBASELINE_V31.md` — why the roadmap was quality-first rebaselined.
- `docs/COMPONENT_RUNTIME_CERTIFICATION_V32.md` — S2 registry/source-binding foundation.
- `docs/COMPONENT_RUNTIME_EXECUTOR_V33.md` — historical install/readiness executor foundation.
- `docs/COMPONENT_RUNTIME_DEPENDENCY_NEGATIVE_CONTROL_V34.md` — historical dependency-stage evidence and duplicate-create negative control.
- `docs/COMPONENT_RUNTIME_FAILURE_RECOVERY_REMOVE_V35.md` — fenced failure recovery, crash resume and safe remove authority.
- `docs/TARGET_DATA_PROTECTION_PRODUCTIZATION_V36.md` — G4 durable policy/run/scheduler/restore-evidence and Operator Console authority.
- `docs/UPSTREAM_ACQUISITION_TOOLCHAIN_V34.md` — exact Helm/Crane build-time acquisition toolchain authority.
- `docs/MCP_OAUTH_DELEGATED_ACCESS_ARCHITECTURE.md` — C7R/C7W OAuth/MCP boundary.
- `docs/OPERATOR_CONSOLE_DESIGN_FOUNDATION.md` — Operator Console source/workflow authority.
- `catalog/component-runtime-certification.json` — machine-readable component runtime-certification registry.
- `internal/targetmodel/program.go` — canonical executable phase DAG.

- `docs/COMPLIANCE_SCAN_CENTER_V37.md` — deterministic compliance baseline engine foundation; durable scan-center and SAML lifecycle remain open.
