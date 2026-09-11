# Current Phase Status — PROGRAM_PHASE_MODEL_V66

Release **0.0.360** closes the remaining software-only Resource Scope owner review and makes that ownership authority consumable by Product API, SDK, MCP and Operator Console paths. Physical installation, Exact-SHA runtime execution and production certification remain independent evidence gates and are intentionally excluded from the coding-progress metric.

## Progress authority

`PROGRAM_PROGRESS_MODEL_V2` is the executable progress model for this release. It separates three different questions instead of presenting one ambiguous percentage:

| Measure | Current | Meaning |
| --- | ---: | --- |
| Core source/software closure | **25/25 (100%)** | Mandatory Core phases are implemented or blocked only by external/evidence closure rather than known missing Core source code. |
| Core phase/release ready | **19/25 (76%)** | Mandatory Core phases already marked `source-implemented`; external acquisition/runtime evidence blockers still prevent the other six from release closure. |
| Pre-physical software closure | **29/35 (82%)** | Core + Expansion phases source-closed, excluding Certification/Physical and Optional tiers from both numerator and denominator. |

The six remaining pre-physical software phases are `I2-edge-sovereign-extension`, `J1-automation-external-integrations`, `J3-virtual-cluster-profile`, `H3-public-cloud-provider-adapters`, `J6-fleet-reliability-incident-intelligence`, and `J7-finops-v2-budget-forecast-rightsizing`. Their open software blockers are not hidden by Physical/Exact-SHA deferral.

## Resource Scope owner closure

`RESOURCE_SCOPE_REGISTRY_V1` now contains **73/73 OWNER_CLASSIFIED** stable Product API resource families and zero owner-review-required families. The reviewed mapping remains `RESOURCE_SCOPE_OWNER_CLASSIFICATIONS_V1`; classifications are based on source authorization/model ownership evidence, not route-name or table-name inference.

`RESOURCE_SCOPE_CONSUMER_AUDIT_V1` now binds the same scope authority into `sdk/product-api-contract.json`, generated Go SDK routes and `internal/api/mcp_route_parity_registry.json`. `PRODUCT_API_RESOURCE_SCOPE_PROPAGATION_V1` carries `resourceScope` and `resourceScopeStatus` per stable route. `CONSOLE_RESOURCE_SCOPE_FAIL_CLOSED_V1` requires the Operator Console to load `/api/v1/access/resource-scopes` and refuses Product API execution when the authority is unavailable or the route family is unknown/unclassified. Server-side authorization remains authoritative; the browser guard is only a fail-closed consumer constraint.

Repository validation also rejects classification evidence that does not reference an existing source file and rejects scope drift in Product API/MCP consumers. This prevents a syntactically valid but stale evidence map from being counted as ownership closure.

## Managed Git authorization correction

Global managed-Git authority remains platform-scoped. The revisions, pull-request and last-known-good read endpoints now invoke the existing platform-admin guard before store access, matching the privileged Git mutation boundary. Regression coverage proves anonymous callers are rejected with authentication failure and non-admin platform operators are rejected with authorization failure.

This correction does not make `/api/v1/system-services` itself admin-only; that endpoint is intentionally retained as authenticated-independent service status according to its established product contract. Privileged Git authority underneath the same resource family remains explicitly guarded.

## PostgreSQL boundary

`POSTGRES_BEHAVIORAL_INTEGRATION_V1` from the previous release remains the current real PostgreSQL service-container gate for migrations/idempotency/project isolation/lease fencing. V66 does **not** claim native PostgreSQL row-level-security policy closure. Application authorization and project-scoped persistence behavior are covered; if native RLS is added, its policies must consume the same canonical ownership authority rather than form a second scope source of truth.

## Unchanged external/runtime blockers

The current critical path still preserves `SUPPLY_CHAIN_HANDOFF_V1`, `SUPPLY_CHAIN_HANDOFF_SEAL_V1`, `UPSTREAM_STAGED_BATCH_V1`, `MANAGEMENT_WORKLOAD_STAGED_BATCH_V1`, `RUNTIME_DEPENDENCY_TRANSITION_V1`, `COMPONENT_UPGRADE_SOURCE_ADMISSION_V1`, `CATALOG_HISTORICAL_SOURCE_IMPORT_V1`, `HISTORICAL_UPGRADE_STAGED_BATCH_V1`, `TAGGED_SOURCE_ACQUISITION_RECIPE_V1`, `FEATURE_CERTIFICATION_REGISTRY_V2`, and `FEATURE_CERTIFICATION_CONTRACT_COVERAGE_V1`.

The external/runtime blockers remain explicit: `OKD_CONNECTED_MANAGED_INSTALL_PENDING`, `OKD_OC_MIRROR_V2_ACQUISITION_PENDING`, `RELEASE_BUILD_TOOLCHAIN_LOCK_PENDING`, and `COMPONENT_RUNTIME_UPGRADE_MATRIX_PENDING`. None is converted into software PASS by the new progress metric.

## Truth boundary

0.0.360 claims source-level Resource Scope owner/consumer closure, the managed-Git authorization correction, and deterministic pre-physical software progress accounting. It does **not** claim PostgreSQL native RLS closure, Terraform/Crossplane provider completion, AWS/Azure/GCP runtime support, Virtual Cluster runtime support, complete Edge/Sovereign autonomy, Fleet Incident/SLO completion, FinOps v2 completion, Connected/Disconnected OKD physical installation, Exact-SHA Physical Runtime PASS, named external MCP-client live certification, or production readiness.
