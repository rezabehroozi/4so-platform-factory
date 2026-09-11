# Current Phase Status — PROGRAM_PHASE_MODEL_V63

Release **0.0.358** advances `PROGRAM_PHASE_MODEL_V63` with selective CloudSuite-derived contract hardening while preserving 4SO Platform Factory as the sole runtime/control-plane authority. No CloudSuite microservice, billing/CRM authority or duplicate state plane is introduced.

## Progress truth

| Metric | Current truth |
| --- | ---: |
| Mandatory Core phases | 25 |
| Core source/software closure | **25/25 (100%)** |
| Core phase-ready / release closure | **19/25 (76%)** |
| Core known source/software blockers | **0** |
| Core externally/evidence blocked phases | **6** |
| Competitive whole-product coding estimate | **~74%** |
| Product API stable routes | **332** |
| Resource-scope families | **73** |
| Explicitly owner-classified scope families | **6** |
| Owner-review-required scope families | **67** |
| Feature Freeze ready | **No** |
| Physical / production PASS | **No** |

The whole-product coding estimate is a weighted planning estimate across Core lifecycle, Installer/Recovery, Console, AI/MCP, Supply Chain, Kubernetes lifecycle/data protection, infrastructure providers, SDK/IaC, Virtual Cluster/Developer Mode, FinOps, Edge/Sovereign and Fleet Reliability. It is not a release gate and cannot replace exact evidence.

## Selective CloudSuite transfer

Three reusable patterns were transferred because they strengthen the existing Factory authority rather than duplicate it:

1. **MCP recovery resolution.** `MCP_CONTROL_JOB_RECOVERY_AUTHORITY_V1` allows a `RECOVERY_REQUIRED` MCP mutation to be terminally reconciled only by a human `platform-admin` holding the expected revision and supplying both authoritative readback and sealed evidence SHA-256 digests. `automaticRedispatch=false`; the initiating MCP client cannot invoke the recovery-resolution route because `POST /api/v1/ai/control-jobs/{id}/resolve-recovery` is security-excluded from MCP.
2. **Product API contract / SDK foundation.** `PRODUCT_API_CONTRACT_AUTHORITY_V1` is generated from `internal/api/server.go`, currently covers all 332 stable Product API routes and emits `sdk/product-api-contract.json` plus `sdk/go/routes_gen.go`. The dependency-light Go transport client never embeds product business logic, approval bypass or automatic mutation retries.
3. **Resource Scope Registry.** `RESOURCE_SCOPE_REGISTRY_V1` and `RESOURCE_SCOPE_OWNER_CLASSIFICATIONS_V1` enumerate every route family. Missing classifications remain exactly `UNCLASSIFIED / OWNER_REVIEW_REQUIRED`; route/table naming is never used to infer a broader authorization scope. Initial source-reviewed ownership is recorded for AI, FinOps, Projects, Workspaces, Provider Profiles and Provider Clusters; J5 owns the remaining 67-family review backlog.

PostgreSQL migration `0072_mcp_control_job_recovery_resolution.sql` is additive and `ROLLING_SAFE`; old writers leave recovery-resolution metadata empty while new operators write it only for terminal reconciliation.

## Re-phased pre-physical roadmap

- **J1 Automation Ecosystem:** Product API contract/Go SDK foundation is present; real Terraform and Crossplane providers remain software blockers and can be developed before physical installation.
- **J3 Virtual Cluster / Developer Mode:** lifecycle, workspace isolation, quota, FinOps and developer UX are active pre-physical work.
- **J4 Product API Contract & Recovery Foundation:** **source-implemented** in 0.0.358.
- **J5 Resource Scope Owner Closure:** owner-review the remaining 67 route families; no classification may be guessed.
- **H3 Public Cloud Providers:** AWS, Azure and GCP adapters are pre-physical software work built over shared Product API/provider contracts; runtime support claims remain separately certified.
- **J6 Fleet Reliability / Incident Intelligence:** Service Health, Incident, SLO/Error Budget and evidence-linked remediation over existing telemetry; no duplicate monitoring stack.
- **J7 FinOps v2:** budget, forecast, anomaly and rightsizing over the measured J2 authority; missing telemetry continues to fail closed.
- **I2 Edge/Sovereign:** local authority/UI, deterministic conflict semantics, boot-security model and local AI continue in parallel; I1 physical/disconnected evidence no longer serializes source development.

## Physical installation is not a development blocker

Physical installation, physical testing, Connected/Disconnected OKD execution, vCenter execution and Exact-SHA runtime certification are evidence gates only. They do not pause SDK/IaC, Virtual Cluster, provider, Fleet Reliability, FinOps, Edge/Sovereign, Console, AI/MCP, installer/recovery hardening or any other source/generated-runtime-semantic development that can be tested without hardware.

The six open mandatory Core phases remain C7W, S1, S2, H1, I1 and C9. Expansion work does not inflate Core closure percentages and missing physical evidence does not reduce the coding-completion estimate.

## Retained canonical authorities and blockers

V63 retains `PROGRAM_PROGRESS_MODEL_V1`, `SUPPLY_CHAIN_HANDOFF_V1`, `SUPPLY_CHAIN_HANDOFF_SEAL_V1`, `UPSTREAM_STAGED_BATCH_V1`, `HISTORICAL_UPGRADE_STAGED_BATCH_V1`, `TAGGED_SOURCE_ACQUISITION_RECIPE_V1`, `MANAGEMENT_WORKLOAD_STAGED_BATCH_V1`, `RUNTIME_DEPENDENCY_TRANSITION_V1`, `COMPONENT_UPGRADE_SOURCE_ADMISSION_V1`, `CATALOG_HISTORICAL_SOURCE_IMPORT_V1`, `FEATURE_CERTIFICATION_REGISTRY_V2`, `FEATURE_CERTIFICATION_CONTRACT_COVERAGE_V1`, `FINOPS_RATE_CARD_AUTHORITY_V1`, `FINOPS_USAGE_MEASUREMENT_AUTHORITY_V1`, `FINOPS_CAPACITY_OBSERVATION_AUTHORITY_V1`, `FINOPS_CHARGEBACK_AUTHORITY_V1`, `VMWARE_PROVIDER_AUTHORITY_V1`, `MCP_CONTROL_JOB_RECOVERY_AUTHORITY_V1`, `PRODUCT_API_CONTRACT_AUTHORITY_V1` and `RESOURCE_SCOPE_REGISTRY_V1`.

External/evidence blockers remain `COMPONENT_RUNTIME_UPGRADE_MATRIX_PENDING`, `OKD_CONNECTED_MANAGED_INSTALL_PENDING`, `OKD_OC_MIRROR_V2_ACQUISITION_PENDING` and `RELEASE_BUILD_TOOLCHAIN_LOCK_PENDING`. The automation expansion additionally retains `TERRAFORM_PROVIDER_PENDING` and `CROSSPLANE_PROVIDER_PENDING`; resource ownership retains `RESOURCE_SCOPE_OWNER_CLASSIFICATION_PENDING`. None of these expansion/software items is silently converted into Physical PASS.

## No claims beyond evidence

0.0.358 does not claim real Terraform/Crossplane provider completion, AWS/Azure/GCP runtime support, Virtual Cluster runtime support, vCenter provisioning, physical installer success, Connected/Disconnected OKD installation, named external MCP-client live certification or production readiness.
