# FinOps v2 Budget / Forecast / Rightsizing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close J7 with immutable budget policies plus fail-closed derived forecast, anomaly and rightsizing views.

**Architecture:** Extend the existing FinOps model rather than introducing a new billing/telemetry system. Persist only policy authority; compute insights from measured usage/capacity and immutable rate cards.

**Tech Stack:** Go control plane/API/persistence, PostgreSQL migration, embedded Operator Console JS/HTML, Python repository validation/generators.

**Spec:** `docs/superpowers/specs/2026-09-11-finops-v2-budget-forecast-rightsizing-design.md`

## Global Constraints
- Missing telemetry must never be treated as zero cost or zero utilization.
- No forecast/rightsize result may auto-apply infrastructure changes.
- PostgreSQL is the production authority; Memory/File remain development/test authorities.
- Existing Product API/MCP resource-scope authority remains canonical.

---

### Task 1: FinOps v2 domain model and pure insight builder
**Files:** Create `internal/controlplane/finops_v2.go`, `internal/controlplane/finops_v2_test.go`.
- [ ] Write failing tests for policy normalization, incomplete-evidence forecast, deterministic forecast/budget evaluation, anomaly classification and rightsizing evidence.
- [ ] Run focused tests and confirm RED.
- [ ] Implement minimal domain/builder code.
- [ ] Run focused tests and confirm GREEN.

### Task 2: Durable budget policy store parity
**Files:** Modify `internal/controlplane/store.go`, `memory_store.go`; create `finops_v2_store.go`, `finops_v2_file_store.go`; modify snapshot load/save; create `migrations/0073_finops_budget_policy_authority.sql`; create `internal/persistence/postgres_finops_v2.go`.
- [ ] Write failing Memory/File tests for immutable overlap/scope behavior.
- [ ] Implement Memory/File parity.
- [ ] Implement PostgreSQL CRUD/list authority and migration.
- [ ] Run store/migration tests.

### Task 3: REST/Product API/MCP integration
**Files:** Modify `internal/api/finops.go`, `internal/api/server.go`, API tests and generated contracts.
- [ ] Write failing API tests for scoped create/list and insights fail-closed behavior.
- [ ] Implement routes and handlers.
- [ ] Regenerate Product API/MCP parity and verify scope propagation.

### Task 4: Operator Console and roadmap closure
**Files:** Modify `webconsole/static/index.html`, `webconsole/static/app.js`, console contract tests, `internal/targetmodel/program.go`, phase status/README/changelog/version authority, repository validator.
- [ ] Add contract test first for budget/insight endpoints and fail-closed copy.
- [ ] Implement task-oriented budget/forecast/anomaly/rightsizing UI.
- [ ] Add J7 closure evidence and repository gate.
- [ ] Rebaseline release version only after tests pass.
