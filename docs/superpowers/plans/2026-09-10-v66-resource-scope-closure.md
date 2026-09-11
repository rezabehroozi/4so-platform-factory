# Resource Scope Owner Closure v66 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the remaining software-only Product API ownership classification gap without inferring scope from route/table names, and make the closure regression-resistant.

**Architecture:** Treat `internal/api/resource_scope_owner_classifications.json` as the reviewed source-evidence map and regenerate `resource_scope_registry.json` deterministically. Classification must come from API authorization behavior and authoritative model ownership fields; the generator remains fail-closed for missing entries. Program phase state may advance only after 73/73 classification and validation prove the registry is complete.

**Tech Stack:** Go 1.23, Python 3 repository generators/validators, JSON embedded API authority, standard Go/Python test suites.

**Spec:** `internal/targetmodel/program.go` (`J5-resource-scope-owner-closure`) plus `internal/api/resource_scope_registry.json` policy.

## Global Constraints

- Physical installation, Physical Runtime and Exact-SHA certification are independent and are not used as evidence for this work.
- Missing owner classification must remain `UNCLASSIFIED / OWNER_REVIEW_REQUIRED`; no route/table-name inference is allowed.
- PostgreSQL remains the control-plane source of truth; no SQLite authority is introduced.
- No SDK/MCP/IaC path may widen authorization beyond server-side Product API authority.
- Tests must prove behavior before production authority/state is changed.

---

### Task 1: Prove the current incomplete owner-classification state

**Files:**
- Test: `tests/test_resource_scope_registry.py`
- Read: `sdk/product-api-contract.json`
- Read: `internal/api/resource_scope_owner_classifications.json`

**Interfaces:**
- Consumes: stable Product API `family` names.
- Produces: a failing closure assertion that requires every stable family to be owner-classified.

- [ ] **Step 1: Add a focused test asserting 73/73 stable families have explicit source-reviewed classifications.**
- [ ] **Step 2: Run only that test and verify RED because 31 families are missing.**

### Task 2: Source-review and classify the remaining 31 families

**Files:**
- Modify: `internal/api/resource_scope_owner_classifications.json`
- Regenerate: `internal/api/resource_scope_registry.json`
- Read: relevant handlers under `internal/api/*.go` and ownership models under `internal/controlplane/*.go`

**Interfaces:**
- Consumes: authorization calls such as `requireProjectAccess`, `requireOrganizationAccess`, platform-admin fences, and resource `ProjectID`/`OrganizationID` fields.
- Produces: `RESOURCE_SCOPE_OWNER_CLASSIFICATIONS_V1` with explicit evidence for every stable family.

- [ ] **Step 1: Classify each remaining family as PLATFORM_SCOPED, ORGANIZATION_SCOPED, PROJECT_SCOPED, or DYNAMIC_SCOPED using source evidence only.**
- [ ] **Step 2: Run `python3 scripts/generate_resource_scope_registry.py .`.**
- [ ] **Step 3: Run the focused registry test and verify GREEN.**

### Task 3: Advance J5 only if the closure contract is actually met

**Files:**
- Modify: `internal/targetmodel/program.go`
- Test: `internal/targetmodel/model_test.go`

**Interfaces:**
- Consumes: 73/73 registry closure.
- Produces: phase status/evidence with no stale `RESOURCE_SCOPE_OWNER_CLASSIFICATION_PENDING` blocker.

- [ ] **Step 1: Add/adjust a test requiring J5 source-implemented when registry closure is complete.**
- [ ] **Step 2: Verify RED against the current blocked J5 state.**
- [ ] **Step 3: Change only J5 phase status/blocker/evidence text required by the proven closure.**
- [ ] **Step 4: Run targetmodel tests and verify GREEN.**

### Task 4: Release rebaseline and verification

**Files:**
- Modify/regenerate: `VERSION`, `RELEASE-NAME`, `CHANGELOG.md`, `README.md`, `DERIVED-AGENT-KNOWLEDGE.json`, `sdk/product-api-contract.json`, `ARTIFACT-MANIFEST.json`, `SBOM.spdx.json`, `BUILD-PROVENANCE.json` as required by existing release tooling.

**Interfaces:**
- Consumes: verified source tree.
- Produces: full cumulative v0.0.360 ZIP and integrity evidence.

- [ ] **Step 1: Rebaseline version/release name to 0.0.360 with a truthful software-only closure name.**
- [ ] **Step 2: Run repository validation, focused Go/Python tests, vet/build, and available non-physical gates.**
- [ ] **Step 3: Build the full release ZIP with existing tooling and run `verify_release.py --full`.**
- [ ] **Step 4: Recompute code-progress estimate excluding Physical/Exact-SHA gates from actual phase/code evidence and report unresolved software work separately.**
