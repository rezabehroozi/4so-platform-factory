# FinOps Usage / Capacity Authority Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close J2's software-only FinOps blocker with immutable measured usage/capacity, versioned rate cards, fail-closed chargeback, REST/MCP/Console parity, and durable PostgreSQL authority.

**Architecture:** Domain normalization and deterministic cost math live in `internal/controlplane/finops.go`; stores persist immutable authorities and API handlers enforce scope/RBAC. Chargeback is derived at read time from measured usage plus covering rate cards, preserving missing telemetry as incomplete rather than zero.

**Tech Stack:** Go 1.23, `database/sql` PostgreSQL, embedded SQL migrations, existing HTTP/MCP route-parity framework, static Operator Console JavaScript/HTML/CSS.

**Spec:** `docs/superpowers/specs/2026-09-10-finops-authority-design.md`

## Global Constraints

- PostgreSQL is the production control-plane SoT; no SQLite.
- Missing telemetry and missing rates must never render as zero cost.
- Money and usage arithmetic use integers; no floating-point billing math.
- AI/MCP writes use the existing durable MCP control-job bridge and never bypass RBAC/idempotency.
- Physical installation/testing is not required for source closure and is not a development blocker.

---

### Task 1: Domain authority and deterministic chargeback

**Files:**
- Create: `internal/controlplane/finops.go`
- Create: `internal/controlplane/finops_test.go`

**Interfaces:**
- Produces: `FinOpsRateCard`, `FinOpsUsageMeasurement`, `FinOpsCapacityObservation`, `NormalizeFinOpsRateCard`, `NormalizeFinOpsUsageMeasurement`, `NormalizeFinOpsCapacityObservation`, `BuildFinOpsShowback`.

- [ ] Write failing tests proving metric allow-listing, immutable digests, explicit-zero vs missing telemetry, rate-card interval coverage, aggregation dimensions, and integer cost behavior.
- [ ] Run `go test ./internal/controlplane -run 'FinOps' -count=1` and confirm RED because production symbols do not exist.
- [ ] Implement minimal domain normalization and deterministic chargeback.
- [ ] Re-run the focused tests and confirm PASS.

### Task 2: Memory/File persistence and snapshot integrity

**Files:**
- Modify: `internal/controlplane/store.go`
- Modify: `internal/controlplane/memory_store.go`
- Modify: `internal/controlplane/file_store.go`
- Create: `internal/controlplane/finops_store_test.go`

**Interfaces:**
- Produces Store methods for create/get/list rate cards, usage measurements and capacity observations.

- [ ] Write failing tests for overlap rejection, usage idempotency, project/org integrity, file snapshot round-trip, and immutable resources.
- [ ] Run focused store tests and confirm RED.
- [ ] Add store maps/methods, snapshot fields/canonicalization/restore validation, and FileStore mutation wrappers.
- [ ] Re-run focused tests and confirm PASS.

### Task 3: PostgreSQL authority and migration 70

**Files:**
- Create: `migrations/0070_finops_usage_ratecard_authority.sql`
- Modify: `migrations/embed.go`
- Create: `internal/persistence/postgres_finops.go`
- Modify: `internal/persistence/postgres_snapshot.go`
- Modify: `internal/persistence/postgres_store.go` only where snapshot orchestration requires it.
- Modify: `internal/persistence/postgres_contract_test.go`

**Interfaces:**
- Implements the same Store methods as Task 2.

- [ ] Add failing contract/migration tests for schema presence and compatibility classification.
- [ ] Run persistence/migration tests and confirm RED.
- [ ] Add additive rolling-safe migration, serializable creates, idempotent usage insert and scoped readers.
- [ ] Extend PostgreSQL snapshot projection.
- [ ] Re-run persistence tests and confirm PASS.

### Task 4: Scoped REST and MCP parity

**Files:**
- Create: `internal/api/finops.go`
- Create: `internal/api/finops_test.go`
- Modify: `internal/api/server.go`
- Regenerate: `internal/api/mcp_route_parity_registry.json` using the canonical project generator.

**Interfaces:**
- Produces the `/api/v1/finops/*` endpoints defined in the design.

- [ ] Write failing API tests for RBAC, cross-project isolation, missing telemetry, idempotent ingestion and showback.
- [ ] Run focused API tests and confirm RED.
- [ ] Register handlers and implement scope-aware reads/writes.
- [ ] Regenerate MCP route parity and verify FinOps reads are typed read tools while writes use durable mutation classification where admitted.
- [ ] Re-run API/MCP tests and confirm PASS.

### Task 5: Operator Console and Persian coverage

**Files:**
- Modify: `webconsole/static/index.html`
- Modify: `webconsole/static/app.js`
- Modify: `webconsole/static/styles.css` only if existing components cannot express the page cleanly.
- Modify the canonical Persian translation/coverage authority used by the repository.

**Interfaces:**
- Produces a task-first FinOps page with scope, rate cards, measured usage/capacity and truthful chargeback state.

- [ ] Add/extend static UI tests so the new workflow is required and missing-telemetry copy is asserted.
- [ ] Confirm the UI/localization test fails before implementation.
- [ ] Implement the page using existing console components and add human Persian translations.
- [ ] Re-run all console quality/localization/Persian-writing gates.

### Task 6: Roadmap/release authority and full non-physical verification

**Files:**
- Modify: `internal/targetmodel/program.go`
- Create: `docs/PHASE_STATUS_V61.md`
- Modify: `DESIGN.md`, `README.md`, `CHANGELOG.md`, `VERSION`, `RELEASE-NAME` and generated release authorities using canonical generators.

**Interfaces:**
- J2 may become `source-implemented` only if Tasks 1-5 and repository gates pass; no Physical PASS changes.

- [ ] Add/adjust roadmap tests first so J2 cannot close without the FinOps authorities.
- [ ] Move J2 blocker truth only after source gates pass.
- [ ] Bump to the next release version and regenerate derived authorities/binaries.
- [ ] Run focused tests, `go test ./...` in timeout-safe shards, `go vet ./...`, focused race tests, Python tests, UI gates, repository validation, artifact integrity/provenance/SBOM verification, and verify the extracted final ZIP.
