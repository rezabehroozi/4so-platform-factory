# Current Phase Status — PROGRAM_PHASE_MODEL_V62

Release **0.0.357** advances `PROGRAM_PHASE_MODEL_V62` by closing the software-only H2 VMware Provider authority. This release does **not** convert Cluster API/CAPV source contracts or simulated verification into connected vCenter execution, installation, runtime certification, Exact-SHA Physical PASS or production readiness.

## Dual closure truth

| Metric | Current truth |
| --- | ---: |
| Mandatory Core phases | 25 |
| Core source/software closure | **25/25 (100%)** |
| Core phase-ready / release closure | **19/25 (76%)** |
| Core source/software blockers | **0 known** |
| Core externally/evidence blocked phases | **6** |
| H2 VMware software status | **source-implemented** |
| J1 software blockers | **1 remaining: Terraform provider** |
| J2 FinOps software status | **source-implemented** |
| Feature Freeze ready | **No** |
| Physical / production PASS | **No** |

The six open mandatory Core phases remain C7W, S1, S2, H1, I1 and C9. Expansion work does not increase Core closure percentages or weaken those gates. Physical installation and Exact-SHA certification remain evidence gates and are explicitly non-blocking for continued pre-physical development.

## H2 VMware authority closed at source level

H2 now uses the existing product-owned provider-profile/provider-cluster lifecycle rather than introducing a second infrastructure authority:

- `VMWARE_PROVIDER_AUTHORITY_V1` binds a provider profile to `infrastructureProvider=vmware`.
- vCenter configuration is an HTTPS **origin** only; embedded username/password, path, query and fragment are rejected.
- Credentials are referenced only as `external-secret://4so-provider-system/<name>`; raw vCenter credentials never enter API, Agent task or Console authority.
- Current VMware source admission is deliberately `amd64` only. Unsupported architecture input fails closed rather than implying CAPV/runtime support.
- Provider-cluster desired state inherits `infrastructureProvider=vmware` from the verified provider profile; callers cannot silently fall back to `unspecified`.
- Management Agent verification requires the admitted ClusterClass infrastructure reference to use `infrastructure.cluster.x-k8s.io/VSphereClusterTemplate` and the admitted worker class to use `VSphereMachineTemplate`.
- Migration `0071_vmware_provider_authority.sql` is additive and `ROLLING_SAFE`: old writers keep the unchanged `unspecified` provider shape while new writers opt into VMware fields.
- REST and Operator Console expose provider identity, endpoint and opaque credential reference while the Agent verification task receives only the infrastructure identity and class names, not endpoint or credential data.

H2 is therefore `source-implemented`. Real vCenter connectivity, CAPV reconciliation/provisioning, failure recovery and Exact-SHA physical/runtime certification remain independent future evidence.

## Remaining software-only development before physical installation

The highest-value remaining branches that do not require a physical install are:

1. **J3 Virtual Cluster Profile** — workspace isolation profile/lifecycle authority, persistence, API/MCP/Console and negative controls.
2. **I2 Edge/Sovereign software-only** — bounded local authority, deterministic central/local conflict semantics, boot-security attestation model, local UI and disconnected local-AI profile work that can be proven without hardware.
3. **J1 Terraform Provider** — remains blocked on a real provider implementation using the official Terraform provider framework and stable 4SO APIs. A mock or schema-only substitute is not accepted as closure.
4. **Further hardening** — installer/bootstrap/upgrade/recovery source/generated-runtime semantics, Durable Ops/Queue/Job/Log/Observability, MCP/AI, supply-chain and Console negative controls whenever concrete gaps are found.

No physical environment is allowed to stop those software branches.

## Core external/runtime evidence retained

- **C7W** still requires real ChatGPT/Claude/Gemini/Grok OAuth/delegation interoperability evidence against a deployed system.
- **S1** current exact source acquisition remains **3/20** locked; missing external bytes are evidence/acquisition work, not a software-development blocker.
- **S2** remains **0 admitted runtime source pairs / 19 pending upgrade-applicable pairs / 1 install-only first release** until exact historical/current bytes and runtime evidence exist.
- **H1** Connected Managed OKD Compact-3 remains runtime/physical evidence.
- **I1** disconnected software workflow remains source-complete while exact `oc-mirror v2` acquisition and runtime execution remain open.
- **C9** remains blocked until mandatory evidence and exact bundle state converge.

## No physical-development blocker rule

Physical installation, physical testing and Exact-SHA runtime certification are evidence gates, not development scheduling gates. Every source-level, generated-runtime-semantic, API, MCP, Console, persistence, automation, FinOps, provider, supply-chain, installer/upgrade/recovery and validation improvement that can be completed without a physical environment continues before the physical campaign.

## What 0.0.357 does not claim

No vCenter connection, CAPV reconciliation, VMware VM creation, physical installer run, Connected/Disconnected OKD install, named-client live certification or production PASS is claimed. No missing external byte, runtime pair or Physical PASS is fabricated.

## Canonical retained authorities and blockers

V62 retains `PROGRAM_PROGRESS_MODEL_V1`, `SUPPLY_CHAIN_HANDOFF_V1`, `SUPPLY_CHAIN_HANDOFF_SEAL_V1`, `UPSTREAM_STAGED_BATCH_V1`, `HISTORICAL_UPGRADE_STAGED_BATCH_V1`, `TAGGED_SOURCE_ACQUISITION_RECIPE_V1`, `MANAGEMENT_WORKLOAD_STAGED_BATCH_V1`, `RUNTIME_DEPENDENCY_TRANSITION_V1`, `COMPONENT_UPGRADE_SOURCE_ADMISSION_V1`, `CATALOG_HISTORICAL_SOURCE_IMPORT_V1`, `COMPONENT_RUNTIME_UPGRADE_MATRIX_PENDING`, `FEATURE_CERTIFICATION_REGISTRY_V2`, `FEATURE_CERTIFICATION_CONTRACT_COVERAGE_V1`, `FINOPS_RATE_CARD_AUTHORITY_V1`, `FINOPS_USAGE_MEASUREMENT_AUTHORITY_V1`, `FINOPS_CAPACITY_OBSERVATION_AUTHORITY_V1`, `FINOPS_CHARGEBACK_AUTHORITY_V1` and `VMWARE_PROVIDER_AUTHORITY_V1`. J1 retains only `TERRAFORM_PROVIDER_PENDING`. Release tooling retains `RELEASE_BUILD_TOOLCHAIN_LOCK_PENDING`. Connected OKD retains `OKD_CONNECTED_MANAGED_INSTALL_PENDING`; disconnected OKD retains `OKD_OC_MIRROR_V2_ACQUISITION_PENDING`.
