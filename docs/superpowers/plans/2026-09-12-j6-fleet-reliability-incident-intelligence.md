# J6 Fleet Reliability / Incident Intelligence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close J6 source/software authority for Service Health, Incidents and SLO/Error Budget without introducing duplicate monitoring authority.

**Architecture:** Reuse existing `fleethealth.Evaluate()`, notification health scanning, durable operation/evidence and product scope infrastructure. Add a focused `internal/reliability` domain, additive durable persistence, bounded Product API routes, generated SDK/MCP parity and Fleet-console views. Missing telemetry remains UNKNOWN/fail-closed.

**Tech Stack:** Go 1.27.x, PostgreSQL 16, embedded SQL migrations, existing Memory/File/PostgreSQL stores, Product API, MCP parity registry, generated Go SDK, embedded HTML/JS Operator Console, Python smoke/validator tests.

**Spec:** `docs/superpowers/specs/2026-09-12-j6-fleet-reliability-incident-intelligence-design.md`

## Global Constraints

- Exact-SHA / physical certification is deferred until the user explicitly requests finalization.
- PostgreSQL remains the production SoT; no SQLite and no second monitoring database.
- Existing telemetry/cluster inventory stays observation input; do not deploy duplicate Prometheus/monitoring stacks.
- Missing observation coverage is UNKNOWN, never implicitly healthy.
- Product API is authoritative; SDK/MCP/Console are consumers and cannot bypass RBAC, approval, durable operations, scope or evidence.
- No raw DB, SSH or secret access is exposed to AI/MCP clients.
- Collection endpoints remain bounded and scope before LIMIT.

---

### Task 1: Reliability domain authorities

**Files:**
- Create: `internal/reliability/model.go`
- Create: `internal/reliability/model_test.go`

**Interfaces:**
- Produces `HealthObservation`, `Incident`, `SLOPolicy`, `ErrorBudgetProjection` and deterministic validation/transition/projection helpers.
- Consumed by stores, API and notification worker in later tasks.

- [ ] Write failing tests for immutable observation identity, valid incident transitions, invalid resolved->open transition, integer SLO objective validation and UNKNOWN projection when observation coverage is incomplete.
- [ ] Run `go test ./internal/reliability -count=1 -v` and confirm RED because the domain does not exist.
- [ ] Implement minimal focused domain code; no HTTP or persistence imports.
- [ ] Re-run `go test ./internal/reliability -count=1 -v` and require PASS.
- [ ] Commit `feat: add reliability domain authorities`.

### Task 2: Store contract and Memory/File parity

**Files:**
- Modify: `internal/controlplane/store.go`
- Modify/create focused Memory/File store files following existing repository patterns.
- Add owner tests beside those store implementations.

**Interfaces:**
- Consumes domain types from `internal/reliability`.
- Produces create/list/get/update methods for observations, incidents and immutable SLO policies with project-bounded pagination/idempotency.

- [ ] Add failing store contract tests proving project isolation, deterministic observation idempotency, incident revision fencing and immutable SLO revisions.
- [ ] Run only the new owner tests and confirm RED.
- [ ] Implement Memory/File parity without widening existing generic stores.
- [ ] Re-run owner tests plus `go test ./internal/controlplane/... -count=1` and require PASS.
- [ ] Commit `feat: add reliability store parity`.

### Task 3: PostgreSQL 16 authority

**Files:**
- Create: `migrations/0074_reliability_incident_slo_authority.sql`
- Create/modify focused `internal/persistence/postgres_reliability.go`
- Extend PostgreSQL integration tests.

**Interfaces:**
- Implements Task 2 store contract on PostgreSQL.
- Tables remain organization/project scoped; observation and SLO revision records are immutable.

- [ ] Write failing PostgreSQL behavioral tests for migrations, idempotency, cross-project rejection, incident optimistic revision and SLO immutability.
- [ ] Run PostgreSQL integration target and confirm RED before implementation.
- [ ] Add migration and PostgreSQL methods using bounded/scoped SQL before LIMIT.
- [ ] Re-run PostgreSQL 16 behavioral integration and require PASS with fresh DB cleanup.
- [ ] Commit `feat: persist reliability authorities in postgres`.

### Task 4: Health scanner and Service Health API

**Files:**
- Modify: `internal/notification/worker.go`
- Create: `internal/api/reliability.go`
- Add API and worker tests.

**Interfaces:**
- Notification worker writes one durable `HealthObservation` per deterministic health evaluation before attempting notification routing.
- `GET /api/v1/reliability/service-health` returns bounded project-scoped product health states.

- [ ] Write failing tests showing an observation survives notification-delivery failure and missing/stale coverage cannot return HEALTHY.
- [ ] Run targeted tests and confirm RED.
- [ ] Implement observation persistence and bounded Service Health projection.
- [ ] Re-run worker/API tests plus existing fleet-health/notification tests and require PASS.
- [ ] Commit `feat: add service health authority`.

### Task 5: Incident lifecycle Product API

**Files:**
- Extend: `internal/api/reliability.go`
- Add API owner tests and route registration using existing router patterns.

**Interfaces:**
- Routes: create/list/get/acknowledge/resolve incidents.
- Lifecycle mutations require actor identity, scope authorization and optimistic revision matching.

- [ ] Write failing tests for project isolation, actor requirement, invalid transition, stale revision and resolve-without-summary rejection.
- [ ] Run targeted API tests and confirm RED.
- [ ] Implement minimal handlers using Task 2 store contract.
- [ ] Re-run API owner tests and require PASS.
- [ ] Commit `feat: add incident lifecycle api`.

### Task 6: SLO policy and error-budget Product API

**Files:**
- Extend: `internal/api/reliability.go`
- Add API/domain tests.

**Interfaces:**
- `POST/GET /api/v1/reliability/slo-policies`
- `GET /api/v1/reliability/error-budgets`
- Projection omits numeric burn/remaining claims when coverage is UNKNOWN.

- [ ] Write failing tests for immutable policy revision, invalid objective/window and incomplete-coverage UNKNOWN response.
- [ ] Run targeted tests and confirm RED.
- [ ] Implement handlers and deterministic projection from bounded observations.
- [ ] Re-run targeted tests and require PASS.
- [ ] Commit `feat: add slo error budget authority`.

### Task 7: Product contract, SDK and MCP parity

**Files:**
- Regenerate/update `sdk/product-api-contract.json`
- Regenerate/update `sdk/go/routes_gen.go`
- Update `internal/api/mcp_route_parity_registry.json` and MCP typed-tool ownership/tests.

**Interfaces:**
- Consumers use the exact Product API routes from Tasks 4-6.
- MCP tools never embed business logic, auto-retry mutations or expose credentials.

- [ ] Add failing parity/contract tests for all reliability routes and typed lifecycle actions.
- [ ] Run contract/MCP owner tests and confirm RED.
- [ ] Regenerate/update consumers from Product API authority.
- [ ] Re-run parity, SDK and AI control-plane tests and require PASS.
- [ ] Commit `feat: expose reliability sdk and mcp parity`.

### Task 8: Operator Console and localization

**Files:**
- Modify: `webconsole/static/index.html`
- Modify: `webconsole/static/app.js`
- Modify focused CSS only if needed.
- Extend Console contract/UI smoke/localization tests.

**Interfaces:**
- Reliability is presented inside Fleet: Service Health summary, incident list/detail/actions and SLO/error-budget cards.
- All mutations remain scope/RBAC disabled when unauthorized.

- [ ] Add failing Console contract tests for reliability surfaces, scoped actions and operator-readable Persian copy.
- [ ] Run Console owner tests and confirm RED.
- [ ] Implement minimal accessible Fleet reliability UI consuming Product API only.
- [ ] Run Console tests, Persian QA, localization coverage/runtime, UI quality and live-authority smoke; require PASS.
- [ ] Commit `feat: add fleet reliability console`.

### Task 9: Runtime smoke, negative controls and roadmap closure

**Files:**
- Create: `scripts/smoke_reliability_incident_slo.py`
- Modify canonical smoke sharding/validator registrations only where existing owner patterns require it.
- Modify: `internal/targetmodel/program.go`
- Modify: `docs/PHASE_STATUS_V67.md`, `CHANGELOG.md`, version/release identity for 0.0.363 only after software closure.

**Interfaces:**
- Runtime smoke proves observation -> service health -> incident -> acknowledge -> resolve -> SLO projection.
- Negative controls prove cross-project access and incomplete telemetry fail closed.

- [ ] Write smoke/roadmap tests that remain RED while J6 blockers are present.
- [ ] Run targeted smoke/roadmap tests and confirm RED.
- [ ] Register evidence, mark J6 `source-implemented`, remove only its three software blockers, and update progress from 30/35 to 31/35 only if Tasks 1-8 are green.
- [ ] Run `go test ./...`, `go vet ./...`, Python suite, repository validator, Autopilot self-test and runtime/UI smokes; do not run Exact-SHA certification.
- [ ] Commit `feat: close J6 fleet reliability software authority` and push the branch.
