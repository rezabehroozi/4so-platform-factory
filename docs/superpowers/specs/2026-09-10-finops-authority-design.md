# FinOps Usage / Capacity Authority Design

## Purpose

Close the software-only J2 FinOps gap without using physical-install evidence. The control plane must record measured usage and capacity observations, apply immutable versioned organization rate cards, expose scoped showback/chargeback summaries, and fail closed whenever telemetry or pricing coverage is missing. PostgreSQL remains the production SoT; File/Memory stores remain development/test authorities only.

## Authority boundaries

- `FINOPS_RATE_CARD_AUTHORITY_V1`: immutable organization-scoped pricing policy. Rates use integer currency micro-units per whole billed unit. No floating-point money.
- `FINOPS_USAGE_MEASUREMENT_AUTHORITY_V1`: immutable project-scoped measured usage. Measurements are idempotent by `(projectId, source, sourceEventId)` and carry cluster/workspace/namespace dimensions.
- `FINOPS_CAPACITY_OBSERVATION_AUTHORITY_V1`: immutable project/cluster-scoped capacity observations with the same explicit availability semantics as usage.
- `FINOPS_CHARGEBACK_AUTHORITY_V1`: deterministic derived view only. It never creates usage or fabricates missing telemetry.

## Metrics and missing-data semantics

Supported metrics are `CPU_CORE_HOUR`, `MEMORY_GIB_HOUR`, `STORAGE_GIB_HOUR`, and `ACCELERATOR_HOUR`. Quantities are integer millionths of the billed unit (`quantityMicros`). A metric sample has `available=true` even when its quantity is explicitly zero. An absent metric or `available=false` means telemetry is missing and must never be rendered or charged as zero.

Rate cards may price any subset of supported metrics. A measured metric without a matching rate is an incomplete cost result, not zero cost. A chargeback result exposes `knownCostMicros` always and exposes `totalCostMicros` only when every measured/required metric and rate-card interval is complete.

## Rate-card time model

Rate cards are immutable and organization scoped. Each has `effectiveFrom` and optional `effectiveUntil`; intervals are half-open `[from, until)`. Overlapping cards in the same organization/currency are rejected. A usage measurement must be fully covered by one card to produce complete cost; measurements crossing an uncovered or rate-card boundary remain visible as usage but cost is incomplete.

## Aggregation dimensions

Usage can be filtered and aggregated by project, cluster, workspace, and namespace. Project is authoritative; the API validates that optional cluster/workspace references belong to the same project when those resources exist. Namespace is a normalized bounded string and never grants Kubernetes mutation authority.

## Capacity

Capacity observations are point-in-time measured capacity, not priceable usage. They use explicit availability per metric and may include cluster/project scope. Showback responses keep capacity separate from billable usage so a capacity number is never accidentally treated as consumed usage.

## API and authorization

REST endpoints:

- `POST /api/v1/finops/rate-cards` — organization admin or platform-admin; immutable create.
- `GET /api/v1/finops/rate-cards` and `GET /api/v1/finops/rate-cards/{id}` — scoped read.
- `POST /api/v1/finops/usage-measurements` — platform-admin only because usage is financial evidence; idempotency is domain-enforced by source event identity.
- `GET /api/v1/finops/usage-measurements` — scoped read with bounded time window/result limit.
- `POST /api/v1/finops/capacity-observations` — platform-admin only.
- `GET /api/v1/finops/capacity-observations` — scoped read.
- `GET /api/v1/finops/showback` — scoped deterministic usage/cost aggregation.

MCP exposes all read/showback routes as typed read tools. Mutating FinOps routes may be MCP callable only through the existing durable MCP control-job bridge with idempotency; no direct AI-only write path is introduced.

## Persistence and audit

Migration 70 adds independent rate-card, usage-measurement, and capacity-observation tables. Creates are append-only/immutable, use serializable transactions, and append audit records. FileStore snapshots include all three authorities. PostgreSQL snapshot projection includes them for backend-contract parity.

## Console

The Operator Console gets a task-oriented FinOps page with: scope selectors, rate-card visibility, measured usage/capacity status, known-vs-total cost truth, missing-telemetry warnings, and a chargeback table grouped by the selected dimension. It does not imply billing collection, invoicing, or hyperscaler billing parity.

## Verification

Source verification requires normalization/digest tests, missing-telemetry negative controls, idempotency, rate-card overlap rejection, backend snapshot parity, REST RBAC/scope tests, MCP route parity, Console quality/localization coverage, migration compatibility classification, and repository validation. No physical PASS is claimed.
