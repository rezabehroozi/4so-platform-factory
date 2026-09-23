
## V22 development / physical-boundary rule

`PROGRAM_PHASE_MODEL_V72` keeps Physical/Exact-SHA installation deferred until C9 development closure. It is not an Operator Console or development blocker. The Maintenance surface consumes `TARGET_NODE_LIFECYCLE_AUTHORITY_V1` so Add/Drain/Remove/Replace/Patch/Certificate/Remediation readiness is shown from live capability/executor truth instead of UI assumptions.

# Operator Console design foundation — 4SO Operator Horizon V3

## V28 human MCP and Persian product-copy rule

The normal MCP connection experience is task-first: **sign in with the organization account -> choose Organization/Project -> choose friendly access -> review -> follow the durable Job/Operation and evidence**. OAuth scopes, internal MCP tool names, token claims and revision identifiers are advanced/operator details and are not required in the ordinary user flow. Until revocable delegation grants, trusted-client admission and consent/revocation authority exist, the console must explain that the foundation is incomplete and must not render a fake enabled Connect action.

Persian copy is governed by `PERSIAN_PRODUCT_COPY_QA_V1` and `PERSIAN_UI_QA_V2`: complete localization alone is not sufficient. High-frequency user-facing copy must use natural, task-oriented Persian; literal English sentence structure and mixed jargon are rejected unless the technical noun is needed to identify an actual product/Kubernetes/OAuth concept.

## Product UX decision

4SO Platform Factory uses the product-owned **4SO Operator Horizon V3** design system and information architecture.

The primary external product-UX benchmark is **Spectro Cloud Palette** because its project-oriented console separates clusters from reusable configuration objects and makes profile/template-driven platform lifecycle understandable without exposing every implementation subsystem. **Rafay Platform** is the secondary benchmark for dense multi-cluster operations, health/resource visibility and operator dashboards. **SUSE Rancher Prime** is a targeted reference for Kubernetes resource exploration and direct cluster ergonomics. TailAdmin/CoreUI remain historical component/accessibility references only; they are no longer the product information-architecture reference.

No competitor UI source, asset, logo, stylesheet or framework is copied or vendored. The shipped console remains the embedded browser-native HTML/CSS/JavaScript surface served by `platform-api`; API authority, navigation taxonomy, workflows, design tokens and product identity remain owned by 4SO.

## Why the information architecture changes

The previous shell grouped product surfaces by implementation-oriented buckets such as `Infrastructure`, `Delivery` and `Administration`. Those terms are technically defensible but force an operator to understand the internal architecture before finding the workflow they need. They also create a naming collision: the existing `workspace` route represents organizations/projects while the product roadmap now reserves **Workspace** for a real cross-cluster team/application boundary.

Operator Horizon V3 therefore organizes the product around operator intent:

```text
Overview
  Platform readiness
  Blockers
  Next action

Platforms
  Clusters
  Infrastructure providers
  Install & import

Blueprints
  Platform blueprints
  Platform templates
  Component catalog
  Certified baselines
  Release catalog
  Planning tools

Fleet
  Fleet overview
  Workspaces
  Assurance

Operations
  Activity & audit
  AI Operator
  Lab & Certification
  Notifications

Admin
  Organizations & projects
  Tenant environments & branding
  Integrations & services
```

The internal route IDs are preserved where compatibility requires it; the user-facing taxonomy is authoritative for the product experience.

## Exact-source 0.0.272 deep panel audit and Phase C1-C4 contract

The 0.0.272 exact source audit found that the console's rendering mechanics are not the primary risk: the supported 320/390/768/1024/1440 viewport matrix, RTL/LTR, contrast, keyboard/focus and reduced-motion quality gates pass. The remaining product risk is architectural and operational.

PROGRAM_PHASE_MODEL_V19 decomposes the console closure into C1 IA/scope, C2 data scale/refresh, C3 action/workflow/evidence and C4 end-to-end UX certification. C1 is source-closed in 0.0.274, C2 in 0.0.276 and C3 in 0.0.279; C4 live end-to-end UX certification is source-closed; C8 is now the pre-certification operational-completion phase after Installer/MCP authority. Release 0.0.279 completes the C3 source action matrix with fail-closed coverage for every registered stateful action family, remaining maintenance/drift/Workspace/catalog-trust/admin stale-state fences, explicit access/token/upgrade review confirmations and owner-tested progressive-disclosure density contracts. Release 0.0.278 extended the earlier C3 enforcement layer into Notification, Git and Admin automation identities. Release 0.0.277 introduced the first C3 enforcement layer: stateful operational controls are rechecked against one central action-state contract before transport, and operational mutation responses surface accepted/queued authority without presenting terminal success. Release 0.0.276 extends the already bounded Overview hot path to the high-cardinality specialist resource pages through explicit result limits and authorization-before-LIMIT PostgreSQL pagers. These are release-facing correctness gates rather than visual-polish backlog:

- **Scope convergence:** Organization/Project context must be one authoritative console context across every route and mutation. A partial global scope switcher is worse than no global switcher.
- **Collection scale:** `GET /api/v1/control-plane/summary` and `GET /api/v1/control-plane/attention?limit=9` are bounded PostgreSQL hot paths. Overview polls only bounded Summary/Attention/Operations/Audit authorities. High-cardinality specialist pages now request explicit `limit=100` contracts; PostgreSQL applies project authorization and resource filters before stable newest-first `LIMIT`. Configuration-authority collections that are intentionally small and not polled remain outside the high-cardinality pager surface rather than being generalized prematurely.
- **Action-state matrix:** every mutating action must prove RBAC, allowed lifecycle state, disabled reason, impact/confirmation, durable-operation creation, retry/cancel/recovery rules and terminal evidence. Button presence is not action correctness.
- **Workflow convergence:** create/import platform, Blueprint publish, fleet upgrade, disconnected acquisition/bundle handling and failed-operation recovery must follow the same `Select -> Inspect -> Allowed Action -> Input -> Impact Preview -> Approval -> Execute -> Evidence` grammar against live API authority.
- **Density without dumping:** pages such as Fleet must progressively disclose support bundles, campaigns, drift, recovery and low-level configuration instead of turning one route into a vertical collection of unrelated operator jobs.

The user-facing primary taxonomy is now:

`Overview -> Platforms -> Blueprints -> Fleet -> Operations -> Assurance -> Admin`

Compatibility-only internal section IDs such as `delivery` and `administration` remain implementation details and are not a second product taxonomy.

### Operator Horizon V3 information architecture

The exact-source review plus current Palette benchmark confirms that project/scope selection and reusable profile/template mental models should stay obvious, while 4SO must surface its stronger evidence/supply-chain differentiators rather than burying them in Fleet or Operations. The visible primary navigation is therefore:

`Overview -> Platforms -> Blueprints -> Fleet -> Operations -> Assurance -> Admin`

`Assurance` owns **Runtime assurance**, **Supply-chain releases** and **Physical certification**. Internal page/route IDs remain compatibility details and must not leak into operator language. This IA change is intentionally separate from the still-blocked global Organization/Project scope selector: a partial scope switcher is forbidden until every scoped read and mutation is audited against the same authority.

## Reference patterns adopted deliberately

### From Spectro Cloud Palette

- explicit project/tenant mental model without mixing it with cluster runtime resources;
- clusters and reusable cluster/platform configuration as separate first-class destinations;
- configuration composition as a guided workflow rather than a raw manifest-first experience;
- template/profile version visibility before fleet rollout;
- task-focused drawers/details and progressive disclosure instead of one giant settings page;
- a clear path from reusable configuration to concrete cluster lifecycle.

### From Rafay Platform

- dense multi-cluster operational summaries rather than oversized decorative KPI cards;
- health, capacity, alerts and workload state grouped for fast triage;
- current-state plus trend/evidence thinking for troubleshooting and capacity planning;
- project/fleet views that help an operator find the unhealthy or expensive target quickly.

### From Rancher Prime

- resource exploration remains close to the cluster/context selected by the operator;
- common operational actions remain discoverable without forcing raw YAML;
- advanced YAML/technical details are progressive-disclosure tools, not the default path.

## 4SO-specific product identity

The Console must not become a renamed copy of Palette, Rafay or Rancher. The following are non-negotiable 4SO invariants:

1. **Authority is visible.** The Console never invents health, success, cost, progress or certification from static/mock data.
2. **Mutations use one workflow grammar:** `Select -> Inspect -> Allowed Action -> Input -> Impact Preview -> Approval -> Execute -> Evidence`.
3. **Impact preview is a product differentiator.** Disruption, compatibility, capacity, rollback feasibility, affected resources and required evidence are shown before approval whenever the backend can prove them.
4. **Evidence is not a log dump.** Every operation links to durable steps, attempts, evidence digests and exact release/runtime context where applicable.
5. **AI is an Operator assistant, not a terminal.** It explains evidence and proposes bounded actions; deterministic product authority performs mutations.
6. **Certified Platform Templates are more than configuration presets.** The implemented source-authority UI shows immutable template composition, variables, policies, target classes and certification requirements together while refusing direct deployment before target preview.
7. **Workspace is the cross-cluster product abstraction.** Organizations and Projects remain ownership boundaries; `WORKSPACE_AUTHORITY_V1` represents a project-scoped team/application boundary spanning authorized managed-cluster namespaces without copying runtime state.
8. **Dense does not mean cluttered.** Primary action count is intentionally small; expert JSON/YAML and low-frequency controls live behind disclosure.
9. **RTL/LTR, keyboard and small-screen paths are first-class.** The console must remain usable at the same supported viewports in Persian and English.
10. **No generic AI/dashboard aesthetic.** Decorative charts, arbitrary gradients, huge whitespace and card-inside-card composition are rejected unless they have a real operational consumer.

## Home / overview composition

The V2 overview begins with authoritative readiness and a **product workflow switchboard**:

```text
Configure
   ↓
Build or import
   ↓
Operate fleet
   ↓
Prove & recover
```

This switchboard is navigation only. It does not imply stage completion or synthesize progress. Actual readiness remains API-derived.

The default dashboard prioritizes:

1. next operator action;
2. blocked or degraded platform state;
3. fleet/cluster health and capacity exceptions;
4. active durable operations;
5. recent high-severity evidence/audit activity;
6. secondary historical analytics.

## Page composition rules

Every operational page should converge on the following layout when applicable:

```text
Page context / scope
Primary action

Status / readiness strip

Main data surface
  table / dense list / topology summary

Selection
  ↓
Inspector / detail drawer
  ↓
Allowed actions
  ↓
Impact preview / approval
  ↓
Operation + evidence
```

Rules:

- prefer dense tables/lists for 8+ comparable resources;
- use cards only for heterogeneous summaries or small resource sets;
- one visually primary action per page/flow;
- destructive actions are physically separated and never adjacent to routine confirmation controls;
- loading, stale, blocked, forbidden, empty and error states are distinct;
- timestamps and quantitative data use tabular numerals where practical;
- long technical IDs/digests are copyable and visually secondary;
- no page should require horizontal scrolling at the supported mobile widths except an explicitly scrollable technical table/code region.

## Future product surfaces reserved by the roadmap

These destinations are **not rendered as implemented navigation until their API/runtime authority exists**:

- Workload Explorer;
- Compliance Center;
- Usage & Cost;
- Edge Sites;
- Virtual Clusters;
- VM Workloads;
- Accelerator / GPU infrastructure.

This prevents the console from advertising roadmap items as working product features.

## UI implementation boundary

The embedded implementation remains dependency-light. A future framework migration is allowed only if it produces measurable maintainability/accessibility/performance value and passes supply-chain/admission review; appearance alone is insufficient justification.

The current runtime therefore continues to use:

- semantic HTML controls instead of clickable `div` elements;
- centralized design tokens and responsive breakpoints;
- existing command palette and route system;
- server/API-owned authorization;
- browser smoke validation at 320/390/768/1024/1440 widths;
- LTR/RTL and explicit light/dark checks;
- reduced-motion and focus-state negative controls.

The task-specific UI quality references for implementation are `interface-design` and `frontend-ui-engineering` from UI Skills: strong product hierarchy, non-generic dashboard composition, responsive behavior, keyboard accessibility and truthful loading/error states are mandatory engineering requirements rather than visual polish performed at the end.

## Competitive UX outcome

The intended result is not "Palette with a 4SO logo". The target experience is:

- **Palette-level clarity** for reusable platform configuration and lifecycle;
- **Rafay-level operational density** for fleets and capacity;
- **Rancher-level resource discoverability** where Kubernetes inspection is appropriate;
- **4SO-only impact/evidence/certification semantics** around every meaningful change.

That last layer is the competitive UX signature: an operator should be able to answer **what will change, why it is allowed, what can break, how it can recover, and what evidence proves the outcome** without leaving the product.

## Program binding

`PROGRAM_PHASE_MODEL_V72` makes Operator Experience both a cross-cutting track and an explicit C1-C4 closure sequence. C1 is source-implemented: the top-level Organization/Project scope is directory-backed, RBAC-aware, dirty-form safe, aborts superseded loads, scopes bounded Summary/Operations/Audit reads, filters project collections fail-closed and fences stale/out-of-scope mutations. C2 is also source-implemented with bounded high-cardinality specialist collection contracts; C3 is source-implemented with the fail-closed action/workflow/evidence matrix; C4 is source-implemented after live API-backed Create/Import, Blueprint Publish, Fleet Upgrade, Failed Operation Recovery/Evidence and Disconnected Installer journeys plus live-authority/responsive quality gates. Phase D is deferred until C9 Feature Freeze; C5 Installer Production Lifecycle Closure and C6 Autopilot are source-implemented; C7 AI/MCP and C8 Console operational completion are source-implemented; F OKD existing-cluster import, R0 release-authority rebaseline, G1 operational hardening, G2 generalized Day-2 campaign authority and G4 data-protection productization are source-implemented. The current critical path remains S1 exact supply-chain acquisition, while G3 target-node lifecycle is source-implemented on the shared campaign engine, while independent provider/automation work can continue in parallel; this does not weaken S1/S2 or Physical certification. A backend capability is not product-complete merely because its endpoint exists: the operator must be able to select it, inspect authoritative state, understand allowed actions and impact, execute through the durable-operation boundary, and inspect evidence truthfully.


## Agent/browser/search/Persian quality benchmark — 0.0.286

The Operator Console remains 4SO-owned. Release 0.0.286 adds deterministic Persian Unicode/bidi/terminology linting, a product-owned technical glossary, an optional isolated Chrome DevTools MCP browser-triage profile for developer agents, source-grounded derived architecture/knowledge evidence, and a machine-readable optional search-projection boundary. None of these tools may bypass UI/API product authority, manufacture runtime/Physical PASS, or become a second state store.

## Open-code component and communication workflow benchmark — 0.0.285

The console adopts a shadcn-style **open-code ownership** principle without changing its embedded delivery stack: 4SO owns component markup, design tokens, accessibility behavior, responsive/RTL contracts and tests in this repository. No React/Tailwind runtime dependency is introduced merely for visual parity. Novu is used only as a communication-workflow benchmark; its routing/workflow/inbox/preferences ideas may inform 4SO product flows, but notification authority remains the existing PostgreSQL/outbox model and external systems remain optional adapters. The first concrete operator workflow is the side-effect-free Notification Routing Preview, which explains matched rules/destinations before policy changes or delivery.


## MCP connection and consent UX — V27

The normal MCP user journey is `Sign in -> Select Organization/Project -> Friendly access -> Describe change -> Preview/Confirm -> Job/Evidence`. The Console must not require users to understand OAuth scope strings, internal MCP tool names or resource revisions. `Admin -> AI & Integrations -> MCP Connections` owns personal connections plus operator-only client/grant/revocation/interoperability details. The UI consumes `MCP_REMOTE_OAUTH_DELEGATION_ARCHITECTURE_V1`; it must not create a second grant/RBAC source of truth.
