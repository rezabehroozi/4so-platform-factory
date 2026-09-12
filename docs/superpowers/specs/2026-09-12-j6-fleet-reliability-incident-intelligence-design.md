# J6 Fleet Reliability / Incident Intelligence Design

## Goal

Close J6 at the source/software layer without introducing a second monitoring stack or treating missing telemetry as healthy. Product authority remains PostgreSQL-backed state; existing cluster inventory, fleet health, durable operations, evidence and notification pipelines remain the observed truth inputs.

## Authority model

`SERVICE_HEALTH_AUTHORITY_V1` is a bounded read authority derived from existing `fleethealth.Evaluate()` output and durable health observations. It does not own raw telemetry and does not replace Prometheus or distribution-native monitoring.

`HEALTH_OBSERVATION_AUTHORITY_V1` stores immutable organization/project/cluster scoped observations emitted by the existing notification health scanner. Each observation records observed state, source digest and observation time; duplicate writes are idempotent by deterministic source identity.

`INCIDENT_AUTHORITY_V1` owns durable product incidents. Incidents are organization/project scoped, optionally linked to a cluster/service/operation, carry severity and state, and preserve evidence references. Lifecycle is `OPEN -> ACKNOWLEDGED -> RESOLVED`; reopening creates a new incident rather than mutating resolved history.

`SLO_ERROR_BUDGET_AUTHORITY_V1` owns immutable SLO policy revisions and deterministic read projections. Error budget is computed only from complete bounded health observations inside the selected window. Missing coverage yields `UNKNOWN`, never zero burn and never implicit healthy time.

## Components

1. `internal/reliability` contains domain types, validation, incident transitions and deterministic SLO projection logic. It must not import HTTP or UI packages.
2. `controlplane.Store` gains explicit methods for health observations, incidents and SLO policies. Memory/File/PostgreSQL implementations retain parity.
3. A new additive migration creates immutable health observation rows, incident rows plus transition metadata, and immutable SLO policy revisions with organization/project foreign-key scope.
4. `notification.Worker.routeClusterHealth()` records a health observation before routing degraded notifications. Notification delivery remains independent; failed notification routing must not erase the observation.
5. Product API exposes bounded service-health, incident and SLO/error-budget routes with existing RBAC/scope helpers and cursor/limit behavior. No endpoint exposes raw metrics or secrets.
6. Generated Product API contract, Go SDK and MCP parity expose the same bounded read/write surface. AI clients receive typed operations only and cannot access DB, SSH or raw credentials.
7. Operator Console adds reliability views under Fleet rather than a new top-level monitoring product. Persian/localized copy uses operator language: service health, incident impact, evidence, acknowledgement, resolution and error budget.

## API shape

Read routes:
- `GET /api/v1/reliability/service-health?projectId=&limit=&cursor=`
- `GET /api/v1/reliability/incidents?projectId=&state=&limit=&cursor=`
- `GET /api/v1/reliability/incidents/{id}`
- `GET /api/v1/reliability/slo-policies?projectId=&limit=&cursor=`
- `GET /api/v1/reliability/error-budgets?projectId=&window=`

Mutation routes:
- `POST /api/v1/reliability/incidents`
- `POST /api/v1/reliability/incidents/{id}/acknowledge`
- `POST /api/v1/reliability/incidents/{id}/resolve`
- `POST /api/v1/reliability/slo-policies`

Incident acknowledgement/resolution require authorized human/operator identity. AI/MCP may request these mutations through normal delegated scopes but never bypass approval/RBAC.

## Service-health semantics

Service-health severity is deterministic from current bounded cluster health plus latest durable observation. `CRITICAL`, `DEGRADED`, `WARNING`, `HEALTHY` and `UNKNOWN` are product states. Any missing inventory, stale observation coverage or unresolved data gap that prevents a safe conclusion becomes `UNKNOWN` or `DEGRADED`; it is never silently mapped to `HEALTHY`.

## Incident semantics

Incident identity is durable and server-generated. Evidence references are append-only. The server rejects cross-project links, invalid severity/state transitions, acknowledgement by an empty actor, and resolution without a resolution summary. Optimistic revision matching is required for lifecycle mutations.

## SLO and error-budget semantics

SLO policies use integer basis points for objectives, bounded windows, immutable revisions and project scope. Projection counts only observation intervals with authoritative coverage. Returned fields include objective, covered duration, bad duration, remaining error budget, burn ratio and coverage state. Incomplete coverage returns `coverageStatus=UNKNOWN` and omits numeric remaining/burn claims that would imply completeness.

## Failure handling

Persistence errors fail closed. Observation persistence and notification routing are separate steps so a webhook failure cannot destroy reliability truth. Pagination is bounded before response materialization. Unknown external outcomes are never retried as product mutations without the existing durable-operation/recovery rules.

## Testing

TDD is required per authority. Domain tests cover transitions, unknown-coverage SLO behavior and deterministic projection. Store tests cover memory/file/PostgreSQL parity, scope and idempotency. API tests cover RBAC, project isolation, pagination and negative controls. Runtime smoke proves observation -> service health -> incident -> acknowledgement/resolution -> SLO projection. Existing fleet health and notification tests must remain green.

## Roadmap closure

J6 may become `source-implemented` only when Product API, PostgreSQL migration/store parity, SDK, MCP parity, Console/localization, smoke tests and negative controls are all present. Exact-SHA and physical certification remain deferred until the user explicitly requests finalization.