# Quality-First Core Rebaseline — PROGRAM_PHASE_MODEL_V31

> Historical rebaseline note: this document records the V31 decision point. The current executable roadmap authority is `PROGRAM_PHASE_MODEL_V37`; V37 preserves this quality-first tiering; later S2 work remains source-bound and lifecycle certification stays open until its real executor/upgrade evidence closes.

## Decision

The architecture direction remains valid, but the delivery roadmap is rebaselined because breadth was expanding faster than core runtime closure. Phase-count completion is no longer an acceptable proxy for product readiness.

A `source-implemented` phase proves only source-level ownership/semantics. It does **not** imply Generated/Installed Runtime PASS, Runtime-Realism PASS, Integration-Lab PASS, Exact-SHA Physical Runtime PASS, or production readiness.

## Evidence from release 0.0.319 audit

The audit used the exact 0.0.319 FULL artifact and its executable release-readiness authority.

- `productReleaseReady=false`
- `physicalRuntimeStatus=not-evaluated`
- 108 total readiness blockers in the enterprise-private-cloud blueprint context.
- 19 enabled components and 19 `COMPONENT_NOT_RUNTIME_CERTIFIED` blockers.
- 17 catalog upstream components still have unresolved product source authority; only the product-owned Gateway API, secure namespace foundation, and snapshot-controller have shipped runtime bundle trees.
- Upstream admission has 17 applicable external component families: 14 ready for acquisition and 3 still under dependency/version review.
- The Lab appliance source lock is `incomplete`: RKE2, Argo CD, CloudNativePG and Longhorn source authorities are resolved, but the management-workload OCI archive is missing and therefore the input pack is absent.
- The enterprise blueprint still has a mutable Git revision context blocker (`GIT_REVISION_NOT_IMMUTABLE`).
- MCP has an explicit disposition for all 63 public route families, but only 3 are `typed-tool-complete`, 7 are `typed-tool-partial`, 52 are `pending-parity`, and 1 is security-excluded. Registry completeness is therefore not operation-parity completeness.
- Exact-SHA Physical Runtime has not been executed and is intentionally not inferred from source/runtime-semantic smoke tests.

## What remains architecturally correct

The following decisions are retained as core invariants:

1. The Factory management plane remains product-owned and self-contained on RKE2.
2. PostgreSQL is the product control-plane authority; Forgejo is desired-state history; Argo CD is reconciliation; zot is the canonical registry.
3. RKE2, OKD and imported Kubernetes are target identities behind explicit capability ownership rather than one genericized distribution abstraction.
4. Durable Job/Operation, fencing, approval, audit and evidence are the only mutation authority shared by UI/API/MCP/AI.
5. Keycloak is the self-hosted OIDC/OAuth identity authority; raw credentials, SSH, SQL, kubectl and Keycloak admin tokens are never model tools.
6. Supply-chain locks, SBOM, provenance and immutable artifact identity remain product authority.
7. Physical PASS remains a separate Exact-SHA evidence layer and cannot be inferred from source or simulated runtime checks.
8. Disconnected/sovereign operation remains a first-class architectural constraint.

## Problems in the previous roadmap

### 1. Breadth before closure

VMware, edge autonomy, FinOps, virtual clusters and broad external integration work were all mandatory Feature Freeze blockers while the core still lacked complete source acquisition, component runtime certification, data protection and MCP write parity. This creates a large horizontal surface with insufficient vertical proof.

### 2. One-dimensional status language

`source-implemented` was useful for source ownership, but became easy to read as overall completion. Installer, Console and Day-2 source closure can coexist with zero Exact-SHA physical evidence. V31 explicitly forbids using source status as release readiness.

### 3. Console certification too early in the lifecycle

C4 legitimately certifies the implemented console foundation, but cannot be the final whole-product UX certification while multiple backend product families remain unimplemented. V31 keeps the foundation evidence and requires final core workflow recertification at Core Freeze.

### 4. MCP registry coverage could be misread as MCP parity

63/63 route-family disposition coverage is a valuable fail-closed inventory gate, but actual typed parity is still low. V31 treats registry coverage as an inventory control, not a progress shortcut.

### 5. Supply chain is a critical path, not background hygiene

The management workload OCI archive is still missing and 17 component sources remain unresolved. Until exact bytes and image digests are acquired, disconnected install, component certification and Exact-SHA certification cannot become trustworthy.

## V31 delivery tiers

### Tier 1 — Core Freeze

These phases define the first complete product that may enter Exact-SHA certification:

- Architecture / authority boundary
- Target capability and supply-chain foundation
- Operator Console IA, bounded data access and durable-action grammar
- Certified Platform Template / Workspace foundation
- Management appliance install / upgrade / recovery source and generated-runtime closure
- Checkpoint-safe Autopilot
- AI/MCP delegated operation foundation
- Remote human OAuth delegation
- Full safe MCP user/admin typed-operation parity
- Existing OKD import authority
- Release/certification authority
- Exact supply-chain acquisition and byte locks
- Per-component runtime certification authority
- Operational queue/log/observability hardening
- Generalized Day-2 campaign engine
- Target node lifecycle
- Data protection workflows
- Enterprise identity/compliance core
- Bare-metal connected Managed OKD Compact-3
- Disconnected OKD core
- Core Feature Freeze / exact bundle

### Tier 2 — Expansion

These remain planned product capabilities but do not delay Core Freeze:

- VMware provider
- Edge/site-local autonomy extension
- Terraform/external registry/notification breadth
- FinOps/usage/rate-card
- Virtual-cluster profile

Expansion work can start in parallel only when it does not consume the critical-path engineering capacity required for Core Freeze.

### Tier 3 — Certification

- M00-M10 Exact-SHA functional physical certification
- M11-M13 chaos/load/soak/two-cluster and final adversarial UI/AI/MCP certification

### Tier 4 — Optional product decisions

- KubeVirt VM workload plane
- Accelerator/AI infrastructure plane

## New critical-path order

1. **S1 Exact Supply Chain Closure**
   - finish upstream review for the remaining 3 component families;
   - acquire all admitted component bytes;
   - produce exact source locks, image digests and license/provenance evidence;
   - build the real management-workload OCI archive and deterministic input pack;
   - remove mutable Git revision from the canonical enterprise blueprint.

2. **S2 Component Runtime Certification Authority**
   - every enabled component gets owner-specific install/readiness/dependency/upgrade/remove/failure contracts;
   - capability ownership suppresses duplicate stacks on OKD;
   - render/apply success is explicitly insufficient.

3. **Core Operation Closure in parallel**
   - C7W MCP typed parity and write-to-job coverage;
   - G4 data protection;
   - G5 enterprise SSO/compliance core;
   - repeat mutation-authority audit across UI/API/MCP.

4. **H1 Managed OKD Connected**
   - pinned openshift-install/FCOS/release payloads;
   - BootMediaProvider contract;
   - durable Agent ISO install workflow;
   - convergence to normal imported target authority.

5. **I1 Disconnected OKD Core**
   - oc-mirror v2 acquisition/mirror authority;
   - zot-backed disconnected payload flow;
   - install and upgrade from only locked inputs.

6. **C9 Core Freeze Reconciliation**
   - recertify final core Console workflows against the now-complete backend;
   - rerun source/generated/runtime-realism gates;
   - freeze exact immutable artifact;
   - reject any unresolved mandatory source/runtime certification contract.

7. **D Exact-SHA Physical Functional Certification**
   - execute M00-M10 from the exact frozen artifact.

8. **M Full Certification**
   - M11-M13 chaos/load/soak/two-cluster;
   - final security, UI, AI and MCP adversarial certification.

9. **Expansion tiers**
   - VMware, Edge, Terraform/integrations, FinOps and virtual-cluster features proceed after the core has an independently certifiable baseline.

## Progress policy

V31 intentionally does not publish a single phase-count progress percentage as product truth.

Progress must be reported in at least these independent dimensions when evidence exists:

- Source semantics
- Generated/installed runtime semantics
- Runtime-realism negative controls
- Integration-lab evidence
- Exact-SHA physical runtime
- Chaos/load/soak certification

A phase can be source-complete and still be 0% physically certified. This is expected and must not be hidden by an averaged headline number.

## Refactor/rewrite policy

Existing implementation is retained only when it preserves the architecture invariants and can pass the required certification dimension. Code may be rewritten or phases reopened without preserving historical completion percentages when any of the following is found:

- duplicate or conflicting authority;
- mutation bypassing durable Job/Operation and audit/evidence;
- installer/upgrade/recovery behavior that cannot safely resume after crash;
- source/runtime evidence that depends on mocks for a production claim;
- unbounded/high-cardinality control-plane behavior;
- distribution-specific duplication that should be capability-driven;
- hidden online dependency in a sovereign/disconnected path;
- UI status/action semantics not backed by authoritative API state;
- MCP or AI path with broader authority than the equivalent human API action.

Quality and evidence outrank historical phase completion.
