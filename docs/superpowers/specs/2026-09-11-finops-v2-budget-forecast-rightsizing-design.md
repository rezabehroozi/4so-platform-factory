# FinOps v2 Budget / Forecast / Rightsizing Design

## Goal
Close software-only phase `J7-finops-v2-budget-forecast-rightsizing` by extending the existing measured FinOps authority without creating a second billing or telemetry authority.

## Authority boundary
- PostgreSQL remains the production SoT for immutable budget policies.
- Usage measurements, capacity observations and rate cards remain the only trusted cost/capacity inputs.
- Forecasts, anomaly signals and rightsizing recommendations are derived read models; they are never persisted as billing truth and never auto-apply infrastructure changes.
- Missing telemetry, missing rate coverage or missing capacity evidence yields explicit `UNKNOWN` / incomplete outputs, never a numeric zero substitute.

## Budget policy
`FinOpsBudgetPolicy` is immutable and versioned. It is scoped to one organization and optionally one project, has a currency, effective interval, budget limit in integer micro-currency, warning and critical thresholds in basis points, and a deterministic digest. Overlapping policies for the same `(organization, project, currency)` are rejected.

## Insight query
A FinOps insight query provides organization/project scope, currency, `windowStart`, `observedThrough`, and `forecastEnd`. The observed window is costed through existing `BuildFinOpsShowback`.

Forecast is produced only when the showback is complete, has at least one measurement, and the observed duration is positive. The deterministic linear projection is:

`forecastCost = knownCost * forecastDuration / observedDuration`

using integer HALF_UP arithmetic. Confidence is LOW for less than 72 observed hours, MEDIUM for less than 14 days, and HIGH otherwise.

## Budget evaluation
Only policies matching the exact query scope and currency and covering `observedThrough` participate. Each evaluation reports current spend and projected spend basis points against the limit. Incomplete cost evidence yields `UNKNOWN`. Otherwise status is `OK`, `WARNING`, or `CRITICAL` using the policy thresholds.

## Spend-rate anomaly
The last 24 hours are compared to the preceding baseline window. Both windows must be complete and contain measurements, and the baseline must cover at least 24 hours. Hourly known-cost rate is compared using integer basis points. A ratio >= 20000 bp is HIGH, >= 15000 bp is MEDIUM, otherwise NORMAL. Insufficient evidence yields UNKNOWN. This is an operational signal, not a billing correction.

## Rightsizing
The latest capacity observation at or before `observedThrough` is paired with measured usage in the observed window. CPU and memory recommendations are produced only when their telemetry and capacity are available. Average demand is calculated from usage-hours divided by observed hours and compared with capacity. <30% utilization yields `REVIEW_DOWNSIZE`, >85% yields `REVIEW_SCALE_UP`, otherwise `NO_CHANGE`. Recommendations never contain an automatic target and `automatable=false` is fixed.

## API and UI
- `POST /api/v1/finops/budget-policies`
- `GET /api/v1/finops/budget-policies`
- `GET /api/v1/finops/insights`

Budget creation uses the existing financial-admin boundary plus organization-admin scope validation. Reads use existing organization/project scoped authorization. The Operator Console shows budget state, forecast/anomaly status and rightsizing review guidance without implying invoices, hyperscaler billing parity or automatic infrastructure changes.

## AI/MCP
Generated Product API and MCP route parity must include the new routes. Reads are allowed as typed read tools according to existing route generation. Budget mutation remains a normal Product API write and must not create a privileged AI-only path.

## Validation
Repository validation must fail if J7 is marked source-implemented without the budget authority, API routes, PostgreSQL migration, console consumer, deterministic tests and generated Product API/MCP parity.
