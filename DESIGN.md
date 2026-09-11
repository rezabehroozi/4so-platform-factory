> **Current development roadmap authority:** `PROGRAM_PHASE_MODEL_V67`.


## Current roadmap authority — V64

`PROGRAM_PHASE_MODEL_V67` is canonical. Exact-SHA physical installation/certification is deferred until C9 development closure and never blocks pre-freeze coding. G3 uses `TARGET_NODE_LIFECYCLE_AUTHORITY_V1` plus `TARGET_NODE_PROVIDER_BINDING_AUTHORITY_V1` to separate truthful lifecycle planning/admission from real provider/node executors. Provider-backed Add scales only an explicitly bound ACTIVE Cluster API ProviderCluster and still requires independent provider approval; Remove/Replace/Certificate Renewal/Remediation use `TARGET_NODE_PROVIDER_MACHINE_LIFECYCLE_V1` with inventory/node/window fencing, management-capability revalidation, exact CAPI Machine recovery evidence, UID/resourceVersion delete preconditions and independent approval. Certificate Renewal is admitted only for Ready provider-managed workers and Remediation only for NotReady provider-managed workers; unsupported combinations remain fail-closed.


`TARGET_DATA_PROTECTION_AUTHORITY_V1` owns target backup/restore product state. Velero is execution-only: policy/run identity, idempotency, approval, lease/fence, evidence and recovery-checkpoint truth remain in PostgreSQL. `TARGET_DATA_PROTECTION_SCHEDULER_V1` materializes due UTC policies with minute-bucket idempotency across HA API replicas. Restore Drill must prove completed restore progress, zero warnings/errors and guarded cleanup before evidence can produce a checkpoint. `TARGET_DATA_PROTECTION_OPERATOR_WORKFLOW_V1` exposes the same workflow in Fleet/Recovery without accepting raw secret material.

# 4SO Platform Factory — Product Design System

This file is the canonical design language for the Operator Console and Bootstrap Installer. It records product decisions, not generic UI theory. Product UI changes must preserve runtime truth and follow this system unless a documented product requirement requires an exception.

### Remote MCP OAuth / human delegation rebaseline

`MCP_REMOTE_OAUTH_DELEGATION_ARCHITECTURE_V1` extends the already source-implemented C7 MCP delegated-operation base instead of replacing it. The remote `/mcp` endpoint must become an OAuth protected resource backed by the self-hosted Keycloak issuer; current product RBAC plus a revocable PostgreSQL `MCPDelegationGrant` remain authoritative on every invocation. C7R owns protected-resource discovery, token/client/grant/revocation and connection consent UX. C7W owns action-registry coverage, authorization-filtered tools, all-write-to-durable-job semantics, independent approval parity and ChatGPT/Claude/Gemini/Grok black-box interoperability. Full admin/user parity means all product-supported actions are covered for authorized principals, not arbitrary SSH/kubectl/SQL/secret or raw Keycloak-admin access.

## 1. Design principles

1. **Operate, do not decorate.** The interface exists to provision, verify, recover and govern infrastructure. Visual craft supports fast decisions; it never competes with them.
2. **Runtime truth is primary.** Live state, durable operation state, blockers, evidence and recovery paths outrank marketing copy or synthetic summaries.
3. **Workflow before subsystem.** Navigation and page composition follow what an operator is trying to accomplish, not Go packages, API grouping or Kubernetes implementation details.
4. **Quiet structure, strong exceptions.** Healthy routine state is visually calm. Failure, degraded state, destructive impact and required operator action gain contrast.
5. **Progressive disclosure for expert detail.** Digests, schema parity, low-level provider settings and evidence internals remain available, but they do not dominate the first reading path.
6. **Dense but breathable.** This is a desktop-first operations console used for hours. Prefer compact controls, aligned data and short copy over oversized headings, large cards or empty decorative space.
7. **No fabricated confidence.** Empty, stale, partial, unavailable and permission-restricted states are explicit. Never infer physical-runtime success from lower validation layers.
8. **One interaction grammar.** Create, inspect, approve, retry, recover, revoke and delete behave consistently across pages.

## 2. Product character

**Visual character:** industrial control plane; calm, technical, precise, restrained.

**Product UX foundation:** 4SO uses the product-owned **Operator Horizon V3** information architecture. Spectro Cloud Palette is the primary benchmark for project-aware platform configuration/lifecycle composition; Rafay is the secondary benchmark for dense multi-cluster operational dashboards; Rancher is a targeted reference for Kubernetes resource exploration. No competitor runtime, source or visual asset is shipped. The Console remains an embedded 4SO implementation with 4SO tokens, workflows, impact/evidence semantics and product identity.

**Rendered certification authority:** `OPERATOR_EXPERIENCE_VIEWPORT_ACCESSIBILITY_V1` is enforced by `scripts/smoke_ui_quality.py` and by full extracted-artifact verification. All Console/Installer routes are exercised across supported mobile/tablet/desktop widths, LTR/RTL and light/dark concerns; focus visibility, drawer focus traps, durable error feedback, effective control target sizing, reduced motion, horizontal overflow and WCAG text/control contrast are owner-level release contracts. Explicit theme choice must override the opposite OS preference. These tests certify rendered source/extracted-artifact behavior, not physical deployment or Phase-H performance.


The visual world comes from rack equipment, network control surfaces, terminal status lamps and engineering drawings: graphite chrome, cool neutral surfaces, blue selection/focus, green verified state, amber intervention, red failure/destructive state.

**Signature elements:**
- a narrow **status seam** on the left/start edge of critical operator briefings and degraded resources;
- compact **status strips** that read like instrumentation rather than KPI cards;
- **evidence rails/timelines** for durable operations;
- technical identifiers rendered with tabular/monospace treatment without turning the whole product into a terminal.

Avoid gradients, glass, ornamental illustrations, floating cards, soft/bubbly shapes, novelty motion and generic SaaS hero composition.

## 3. Information architecture

The navigation model uses **global operator domains plus contextual destinations**. This pattern is intentionally closer to mature infrastructure consoles than to a flat SaaS sidebar: the left navigation answers *which operational domain am I in?* and the secondary navigation answers *which resource/workflow inside that domain am I working on?*

Primary domains:

1. **Home** — platform readiness, blockers and next operator action.
2. **Infrastructure** — Clusters, Providers, Installation.
3. **Delivery** — Marketplace, Blueprints, Certified baselines, Catalog releases.
4. **Fleet** — Fleet overview and Assurance.
5. **Operations** — Activity & audit, Notifications.
6. **Administration** — Organizations & projects, Tenants & branding, Integrations & services.

`Planning tools` is not a primary destination. It remains reachable from Blueprint expert tools and by direct route because it is a planning/debugging surface rather than a daily operator workspace.

### Placement rules

- Ownership, RBAC, OIDC mapping, service accounts, tenant branding and system integrations belong to **Administration**, not the daily operational path.
- Catalog release governance belongs to **Delivery** because it governs deployable product supply, not generic system settings.
- Runtime verification/closure/certification belongs to **Fleet → Assurance** because it is evidence about target runtime state.
- Installation planning belongs to **Infrastructure** and must not dominate the normal post-install console.
- A feature must not gain a first-level navigation item merely because it has its own backend package or API family.

### Roles

- **Viewer / read-only:** inspect state, evidence and planning-safe results.
- **Platform operator:** create and mutate operational resources only inside Organization/Project scopes where the backend-derived effective role grants write authority. A global operator role is a ceiling, not proof of write access to every tenant.
- **Platform admin:** administer access and perform approval-bound or platform-global authority changes; self-approval remains prohibited where the runtime contract requires separation. Managed Git repository creation, signed desired-state publication, credential/provider mutation, pull-request authority and rollback are platform-global admin operations.

Disabled actions must explain why they are unavailable. Do not hide important actions solely because the user cannot execute them. Access-mode enforcement also applies to mutation controls rendered dynamically inside inspectors, dialogs or recovery detail views; runtime insertion must never bypass the page's read-only contract. The Console must consume backend-computed effective Organization/Project roles rather than reimplementing membership/OIDC precedence locally.

## 4. Page anatomy

Every primary page follows this order when applicable:

1. **Page header** — concise title + one-sentence operational purpose.
2. **Prerequisite / degraded strip** — only when action is required or data is incomplete.
3. **Compact command row** — optional create/configure disclosure; the form stays closed until the operator chooses to mutate.
4. **Current resources / state** — the main inventory, status or evidence surface.
5. **Contextual operations** — maintenance, verification, recovery or scoped administration near the resource it affects.
6. **History / evidence** — durable runs, audit and results.
7. **Advanced / expert controls** — inline disclosure, never a permanent primary form wall.

Resource-management pages are **resource-first**. Do not lead a page with a large Create form when the normal operator task is to inspect or manage existing resources. Creation remains discoverable in a compact command row above the collection, comparable to a table toolbar action.

Do not use an admin-page hero. Do not lead with four identical statistic cards.

## 5. Layout

- Desktop sidebar: **248px** target, compact labels, persistent on >= 960px.
- Main content max width: **1440px**; wide enough for data, never centered as a marketing column.
- Page gutters: **32px Operator Console / 30px Bootstrap Installer** on desktop, 18–24px tablet, 16px narrow.
- Top bar height: 68–72px.
- Base spacing unit: **4px**.
- Common spacing: 4, 8, 12, 16, 20, 24, 32, 40.
- Section separation uses whitespace + divider before adding a container.

### Responsive

Desktop is primary. At narrower widths:
- Sidebar becomes a modal navigation drawer and is `inert` while closed.
- Summary strips may wrap into two columns, then one column.
- Forms collapse 3 → 2 → 1 column according to field meaning, not arbitrary stacking.
- Long technical values wrap or horizontally scroll inside their own region; the page itself must not horizontally overflow at 320px.
- Data collections keep the most important fields visible; secondary metadata moves below or into disclosure.

Required browser widths for the full owner UI smoke: **320, 390, 768, 1024, 1440**. The quality gate additionally probes **280 and 414** to catch narrow-phone and transition-width regressions.

## 6. Typography

System stack only; do not add a font dependency for visual novelty.

- Body: 14px / 1.45.
- Metadata: 11–12px / 1.4.
- Labels: 12–13px, 600–680 weight.
- Section heading: 16–18px, 700–760 weight.
- Page heading: 20–22px, 740–780 weight.
- Briefing focal text: maximum 24px; never marketing-scale.
- Technical identifiers: system monospace, `font-variant-numeric: tabular-nums` where applicable.

Use `text-wrap: balance` for headings and `text-wrap: pretty` for explanatory copy.

## 7. Color and semantic status

Accent blue is for selected navigation, focus and primary actions — not decoration.

Focus is a semantic token, not a component-local color. `--focus-ring` and its halo must resolve in every supported theme; an undefined theme reference is a release-blocking UI defect.

Semantic meanings:
- **Healthy / Succeeded / Verified** → green.
- **Running / Pending** → blue or neutral + explicit text.
- **Warning / Degraded / Recovery required** → amber.
- **Failed / Offline / Destructive** → red.
- **Unknown / Not configured / Not run** → neutral.

Every semantic foreground/background/border has a light and dark token. Status must include text or icon shape; color is never the only carrier.

## 8. Surfaces, borders, radius, elevation

**Depth strategy:** borders + surface shifts. Shadows are reserved for true overlays (dialogs/drawers), not ordinary page sections.

- Page background: neutral cool gray.
- Primary surface: white / dark graphite.
- Secondary surface: subtle neutral tint for inline summaries and read-only regions.
- Divider: low-contrast 1px rule.
- Radius: 6px small controls, 8px inputs/buttons, 10px grouped objects, 12px dialogs. Avoid 16px+ rounded cards in routine UI.
- Resource collections should prefer rows/list structure. Use a bordered card only when a resource is genuinely self-contained and needs independent actions.

## 9. Controls and actions

Control height: **40px visual minimum on desktop, 44px hit area**. Touch/narrow views maintain 44px minimum.

Action hierarchy:
- One primary action per local workflow.
- Secondary actions are quiet outlined/text controls.
- Contextual row actions live with the resource.
- Dangerous actions use red text/border and impact-proportional confirmation.
- Approval, destructive restore/recovery, revoke and irreversible publish operations must expose impact before confirmation.

Do not use confirmation dialogs for harmless navigation, refresh, filters or planning-safe evaluations.

## 10. Tables and resource collections

Tabular data is first-class. When records have stable comparable fields, use a table/list rather than cards.

Required behavior for large datasets when an endpoint supports it:
- bounded collections / pagination;
- search/filter controls close to the data;
- stable row identity;
- numeric and timestamp alignment;
- long IDs wrap or truncate with explicit copy action where useful;
- contextual actions remain associated with the row;
- filtered-empty is distinct from first-empty.

When the backend does not expose sorting/filter/pagination, the UI must not fake server authority. Client filtering and ordering are acceptable only for the currently loaded bounded collection. Client ordering must use semantic column types (text, numeric, timestamp), expose `aria-sort`, preserve stable ties, and never imply that records outside the loaded bound were considered.

Operator-local data context is part of workflow continuity. A chosen sort order must survive ordinary authority refresh/auto-refresh while the same workspace schema remains valid. An active loaded-record filter must survive a temporary **Unavailable** authority state and resume when that collection recovers. Do not preserve a preference if the referenced table column no longer exists, and do not let stale filter criteria remain attached to a successfully returned small/empty dataset where filtering is no longer applicable.

A collection whose authority request failed must render **Unavailable**, never the same empty state used when the authority returned a successful zero-record result. Page-level partial-data banners complement this local state but do not replace it.

## 11. Navigation

- The sidebar exposes exactly the six primary operator domains: Home, Infrastructure, Delivery, Fleet, Operations, Administration.
- Contextual destinations are rendered in the secondary navigation below the page header. Do not duplicate all child pages in the sidebar.
- Active domain uses text + start-edge seam; active contextual destination uses a restrained underline.
- Icons use the bundled single stroke family and exist only where the action/concept benefits from one; do not add an icon to every contextual destination. Navigation, menu and close controls must use the same SVG stroke family rather than raw Unicode/emoji action glyphs.
- Advanced planning/debug surfaces remain reachable contextually but do not receive first-level navigation.
- Mobile drawer traps focus while open, returns focus on close, and leaves no off-canvas controls in tab order while closed.
- Deep links must continue to resolve directly to every existing route even when that route is no longer globally visible.

## 12. Forms

- Labels always visible; placeholders are examples, never labels.
- On list/management pages, Create and Configure forms are closed by default behind a clearly labeled command disclosure. Dedicated authoring/install pages may keep the primary workflow visible.
- Group fields by the decision the operator is making.
- Complex creation flows use staged sections/wizards only when this reduces simultaneous cognitive load; do not split simple forms.
- Technical fields retain LTR direction in RTL locales.
- Inline validation belongs next to the field; workflow-level blockers belong above the action.
- Save/publish controls appear when the operator has enough context to understand impact.

### Blueprint authoring

Blueprint authoring is a four-stage workflow:
1. Basics — project, release lineage, name/version, catalog.
2. Runtime & delivery — compatibility, architectures, distribution, Git/OCI delivery.
3. Policy & governance — policy, tenant and evidence requirements.
4. Scope & publish — scope review, resolved preview, immutable draft creation.

JSON round-trip parity and overlay ownership remain accessible as **Expert tools**, not the initial focal point.

Governed Catalog and Blueprint releases use an atomic revision-authority boundary. Creating a release, moving a draft to a new immutable revision, or cloning a Blueprint must not persist the prospective revision, audit event or outbox event unless the corresponding release mutation also commits. Optimistic `If-Match` checks and lifecycle/identity validation therefore precede revision commit under the same owner-store lock/transaction; PostgreSQL additionally row-locks the current release inside a serializable transaction. A stale or duplicate request is side-effect free and safe to retry after refreshing authority.

## 13. Status and feedback components

Canonical state labels use words first: Healthy, Running, Pending, Degraded, Warning, Failed, Offline, Unknown, Maintenance, Recovery required.

- Badges are compact and used only for status/type metadata.
- A page-level degraded banner explains impact and whether shown data may be stale.
- Running operations show durable phase/progress and next expected transition.
- Failed operations show error, last safe phase, evidence/log entry point, retry/recovery action and destructive impact when relevant.
- Error feedback is persistent until explicit dismissal; never auto-expire a mutation, authority, recovery or permission failure before the operator can inspect it. Routine success/status feedback may be transient.
- Runtime-generated feedback controls use the same canonical SVG action-icon family as static navigation/dialog controls; raw Unicode close/menu glyphs are not an exception.
- Success confirms the resulting authority, not just “Done”.

## 14. Loading, empty, stale and permission states

Direct Project authority and parent-Organization visibility are deliberately distinct. A direct Project grant may expose the parent Organization identity for hierarchy/breadcrumb navigation, but that visibility must never be expanded into sibling Project authority or Organization-owned resource authority. Collection endpoints must use effective Project roles for Project-scoped resources and effective Organization roles for Organization-scoped resources; their list semantics must not be broader than the corresponding detail authorization. For bounded collections, authorization predicates are applied before ordering limits/pagination so newer foreign-tenant rows cannot evict older authorized rows from a scoped principal's page. High-volume notification Event/Delivery collections follow the same rule at the store boundary: scoped requests must not disable the limit and scan global history, and Delivery authorization must be resolved by the store join rather than one event lookup per delivery.

Effective permission state is live authority, not a startup snapshot. OIDC/group-role changes may happen while a console tab remains open: re-synchronize session authority on explicit refresh/tab resume and after an authorization denial, and re-check authority before locally rejecting a mutation from a cached read-only state. Backend authorization remains authoritative. Organization/Project mutation controls are fenced by the backend-published effective scoped role, including OIDC direct mappings, durable memberships and API-token bounds; if that scoped authority cannot be loaded, non-admin mutations fail closed rather than falling back to the global role. Permission transitions are bidirectional: controls disabled solely by read-only or scoped access must be restored immediately after promotion without forcing a page rerender, while a demotion must invalidate any already-open destructive confirmation before it can be submitted.
Pure validation/planning/read-comparison POST operations that the backend explicitly authorizes for `platform-viewer` are not mutation controls. Their UI surfaces must remain executable in read-only sessions; permission fencing must not infer mutation solely from the HTTP method or from a submit/action button shape. Conversely, a POST that persists advisory/audit/desired-state authority remains a mutation even when it does not immediately execute workload changes.

Every page-level loader sets `aria-busy` and preserves the last safe state when appropriate. A superseded route load is cancellation, not degradation: aborted requests must not create Partial/Unavailable authority state, mutate the successor route, announce the stale route as loaded, or retain stale actions after a hard page-authority failure. Summary values must distinguish a successful zero from an unavailable source; unknown readiness must never become an actionable “create/connect” recommendation.

Distinct states:
- first load;
- empty (nothing exists yet);
- filtered empty;
- partial/degraded data;
- API unavailable;
- stale last-known state;
- permission denied/read-only;
- operation running;
- operation failed;
- operation succeeded;
- destructive recovery required.

Empty states say what is missing and the next legitimate action. No illustrations or generic encouragement.

## 15. Dialogs, drawers and inspectors

Use native `<dialog>` where available in the current stack.

- Every dialog has `aria-labelledby`; descriptive text uses `aria-describedby` when useful.
- Focus enters the dialog, remains contained, and returns to the initiator.
- Destructive dialogs state resource, impact and recovery implications. Typed confirmation is reserved for destructive restore/recovery or similarly high-impact actions.
- Detail inspection should prefer a dialog/inspector only when keeping list context matters.

## 16. Motion

Motion communicates state and hierarchy only.

- Routine transitions: 80–140ms.
- No spring/bounce/scroll spectacle.
- No staggered decorative entrances.
- `prefers-reduced-motion` removes nonessential transitions and smooth scrolling.

## 17. Accessibility

Required:
- WCAG AA text contrast in both themes;
- visible focus;
- semantic controls and labels;
- logical heading order;
- live regions appropriate to severity;
- `aria-busy` for page loading;
- accessible dialog names;
- keyboard-complete drawer/navigation behavior;
- 44px hit areas on narrow/touch surfaces;
- status understandable without color;
- no page-level horizontal overflow at required widths.

## 18. Copy

Voice: concise, technical, calm.

Prefer operator language: “Verify runtime”, “Recovery required”, “Connected clusters”.

Keep internal implementation terms (authority, digest, evidence, adapter, source lock) only where they are necessary for an operator decision or proof. Move deep implementation detail behind disclosure.

Never use consumer-style “Welcome back”, congratulations, inspirational copy or generic helper paragraphs under every heading.

## 19. Anti-patterns

Do not introduce:
- four equal KPI cards as a default page header;
- giant hero blocks;
- card-inside-card composition;
- decorative gradients/glass;
- pill controls for ordinary buttons;
- colored icon bubbles;
- random badge colors;
- duplicate explanatory copy;
- fake charts, fake activity or sample operational data;
- long backend terminology in the primary reading path;
- framework/library dependencies solely for appearance;
- page-specific CSS hacks that bypass tokens.

## 20. Verification contract

Before UI release:
1. Source owner tests pass.
2. Full browser UI runs at 320/390/768/1024/1440; the quality gate also probes 280/414.
3. Every CSS `var(--token)` reference resolves to a declared theme token; semantic focus tokens resolve in light and dark.
4. Both themes are checked where supported, including state-aware text contrast for representative interactive/status components.
5. EN and FA/RTL layout are exercised route-by-route; technical identifiers remain LTR.
6. Rendered DOM checks reject duplicate IDs, unnamed actions/dialogs, unlabeled visible form fields and sub-24px interactive targets.
7. Keyboard drawer focus is trapped while open, hidden while closed, Escape closes, and focus returns to the initiator.
8. No page-level horizontal overflow, including 280/414 quality probes.
9. Data Workspace owner harness covers semantic table structure, sort/filter continuity, Empty vs Unavailable and read-only mutation fidelity.
10. Anti-slop review rejects generic admin hero/welcome patterns and raw Unicode action icons; visual inspection remains required because gates do not prove pixels.
11. Live-authority smoke passes against the actual API binary.
12. No capability disappears from the implementation.
13. Generated/installed runtime semantics are tested on the exact release artifact.
14. Physical Runtime PASS remains a separate exact-SHA gate and is never inferred from UI or simulated runtime success.


## Cluster enrollment recovery lifecycle

Cluster enrollment manifests contain a one-time credential that is never retrievable from durable authority after issuance. Unclaimed imports therefore have an explicit recovery lifecycle: a project writer may revoke a `PENDING_APPROVAL` or `APPROVED` import with optimistic revision fencing and explicit destructive confirmation. Revocation invalidates the enrollment credential, preserves audit/outbox history, prevents claim, and releases the active project/name so a replacement enrollment can be created immediately. Approval remains an independent `platform-admin` action.

Enrollment TTL is authoritative rather than decorative. Once `expiresAt` is reached, an unclaimed pending/approved request is exposed as `EXPIRED` on reads and approve/claim/revoke are no longer valid transitions. A same-project/name replacement after natural expiry must materialize the previous request as `EXPIRED` in durable authority, invalidate its enrollment credential, emit the expiry audit/outbox event, and release the active-name fence in the same successful mutation boundary. Failed stale-token requests must not repeatedly increment the expired request revision.

## Cluster maintenance request atomicity

Creating a node-maintenance run is one authority mutation, not a sequence of loosely coupled API side effects. Window/inventory/node validation, linked durable-operation creation, transition to independent approval, and maintenance-run persistence must commit atomically. A rejected request must not create an orphan operation or reserve idempotency state. Retries of the same accepted request must resolve to the same run/operation pair.

## Drift remediation retry convergence

Generic drift remediation is an idempotent composite workflow, not a fire-and-forget create call. The idempotency key identifies one durable `Operation`. If a request is interrupted after operation creation or after the first pre-queue transition, replay must repair the same operation through `DRAFT → PLANNING → QUEUED`; it must never return a permanently stranded pre-queue record. Concurrent identical retries may race on optimistic revisions, but they must refresh authority and converge on the same operation rather than fail solely because another retry advanced it first. States at or beyond `QUEUED` are authoritative and are never rewound by replay.

### Notification scoped pagination NULL semantics

Organization-wide notification routes/events are stored with `project_id IS NULL` in PostgreSQL. Scoped notification collection queries MUST preserve that storage contract: organization authority is applied to rows whose project is NULL, while project authority is applied to explicit project IDs, and both predicates are evaluated before ordering/limit. Empty-string project predicates are invalid for PostgreSQL authority and would diverge from Memory/FileStore semantics.

### Audit scoped pagination and ordering

Interactive scoped Audit reads MUST resolve Organization/Project resource ownership inside the authority-store read path before pagination. The API must not materialize a full control-plane Snapshot merely to filter `/api/v1/audit-events`, because request cost must not scale with unrelated tenant state. PostgreSQL resolves eligible resource IDs and explicit audit metadata scopes in the query before `ORDER BY ... LIMIT`; Memory/FileStore use the same scope families without cloning Snapshot state. Audit collection chronology is canonical newest-first with a stable ID tie-break, and all authority adapters must preserve that ordering.

### Notification delivery deterministic ordering

Notification Delivery rows produced from a single routed event commonly share the same clock sample. Operator-facing delivery collections therefore MUST use a stable ID tie-break after creation time (`createdAt DESC`, `id DESC`) so bounded pages are deterministic across Memory, FileStore and PostgreSQL. Worker claiming MUST likewise use the canonical eligibility tuple (`nextAttemptAt ASC`, `createdAt ASC`, `id ASC`) so equal-time candidates converge on the same first claim across authorities and restarts. Go map iteration order is never authority for collection membership or worker selection.

### Operator collection chronology parity

Bounded `GET /api/v1/operations?...&limit=N` is an operator-facing page and MUST return the same chronology on every built-in authority backend: most recently updated first, then most recently created, then descending stable ID. Memory/FileStore implement the bounded pager directly rather than inheriting the legacy full-list chronology; the unbounded `ListOperations` method remains an internal reconciliation/snapshot primitive and is not the interactive page contract.

### Cluster maintenance deterministic queue ordering

Cluster Maintenance runs may share the same clock sample. Operator-facing maintenance-run lists and agent task claiming MUST therefore never rely on map iteration when `createdAt` ties. All built-in authority adapters use the canonical queue tuple `createdAt ASC, id ASC`; PostgreSQL enforces it in SQL and Memory/FileStore apply the same stable ID tie-break before returning a list or selecting the first queued task. This ordering rule does not alter maintenance admission, approval, inventory/node identity fencing, operation leases or recovery semantics.

Security Audit has a different correctness requirement because it is a cryptographic sequence/hash chain. Stores MAY select the newest bounded tail in reverse order for query efficiency, but the returned `ListSecurityAudit` slice MUST be sequence-ascending so `PreviousDigest` linkage and `ValidateSecurityAuditChain` semantics are backend-independent.
### Tenant deterministic task ordering

Tenant environments may be created or queued within the same clock sample. Operator-facing tenant collections and Agent task claiming MUST therefore use a stable ID tie-break after creation time (`createdAt ASC`, `id ASC`) on every built-in authority backend. PostgreSQL enforces the tuple in SQL; Memory/FileStore apply the same tuple before returning collections or selecting the first runnable tenant. Go map iteration is never authority for tenant chronology or task selection, including after FileStore restart. This ordering rule does not alter tenant lease/fence tokens, lifecycle transitions, approval, destructive recovery or runtime-contract reconciliation.


### Agent task deterministic ordering

Durable Agent/worker queues MUST have one deterministic candidate order on every built-in authority backend. Equal timestamps must never delegate first-task selection or operator-facing collection chronology to Go map iteration. Baseline Deployment, Runtime Verification, Runtime Certification, Provider Profile verification and Drift Scan use `createdAt ASC, id ASC`; Provider Cluster execution uses `updatedAt ASC, id ASC`, matching its PostgreSQL scheduling query. Memory/FileStore apply the same stable ResourceMeta comparator before list return or first-task selection, and FileStore restart must preserve the same result. This ordering contract does not alter lifecycle transitions, approvals, retry/recovery semantics, task lease duration or fence-token validation.

### Outbox scheduler ordering and lease fencing

Outbox candidate selection is authority, not an implementation detail. Every built-in store MUST select eligible outbox work by `availableAt ASC, id ASC`; random resource IDs or map iteration must never allow newer available work to jump ahead of older work. PostgreSQL candidate selection uses the same tuple, and because `UPDATE ... RETURNING` does not guarantee row order, the store boundary must normalize the returned claimed batch before handing it to consumers. FileStore inherits the same scheduler semantics across restart.

A claimed outbox event may be marked published only while the publishing worker still owns an unexpired lease at the actual completion time. Dispatchers MUST NOT reuse the timestamp captured before a batch claim when publishing after classification/routing. If processing outlives the claim TTL, publication is fenced with `ErrStaleFence` and the event remains recoverable/reclaimable rather than accepting stale ownership.

## Target architecture model

`TARGET_ARCHITECTURE_MODEL_V1` is a canonical product invariant. The following dimensions MUST NOT be conflated:

1. **Management plane** — the internal appliance remains RKE2 and self-contained. Its bootstrap/runtime is not made generic merely to achieve target symmetry.
2. **Distribution identity** — a runtime identity such as `kubernetes`, `rke2`, and later `okd`. Kubespray is an installer history, not a distribution. `generic-imported` is an enrollment/provisioning history, not a distribution.
3. **Provisioning mode** — `import-existing`, `cluster-api`, or a future admitted managed-target installer. Cluster API is a provisioning mode/adapter boundary.
4. **Infrastructure provider** — the infrastructure authority (for example existing infrastructure, bare metal, VMware) and must only be asserted when a real adapter/discovery authority can prove it.
5. **Capabilities** — runtime capability discovery/resolution is independent from distribution identity and is the future boundary for suppressing duplicate stacks on first-class targets such as OKD.

Current managed/install target identities are `kubernetes` and `rke2`. Existing-cluster import additionally admits `okd` only through its inventory-, health-, capability- and profile-gated import authority; managed OKD installation remains non-admitted until its dedicated managed-install phases are implemented and certified. Legacy `generic-imported` and `kubespray` values normalize to `kubernetes`; immutable historical release documents are not rewritten.

Provider Cluster desired state carries explicit `distributionIdentity`, `provisioningMode`, and `infrastructureProvider` fields while retaining the legacy `distribution` alias for mixed-version/API compatibility. Imported fleet responses expose a separate `target` object so UI and automation no longer infer provisioning semantics from the observed distribution string.

### Program phase authority

`PROGRAM_PHASE_MODEL_V67` is the canonical product-roadmap authority. R0 makes mandatory roadmap blockers part of product release readiness and the roadmap remains an explicit dependency DAG rather than a serial G→H→I→J chain. C1-C8, F, R0, G1, G2 and G4 are source-implemented; the current critical path is S1 exact supply-chain acquisition. G2 now provides the shared durable Day-2 campaign safety boundary; G3 target-node lifecycle work is explicitly allowed to advance in parallel with S1 and the subsequent S2 component-runtime-certification path; H2 VMware and J1 automation integrations remain independent parallel branches when their dependencies are satisfied. G3-G5 own node/data-protection/identity-compliance closure; H1 owns connected Managed OKD; I1/I2 own disconnected/edge; J1-J3 own automation/FinOps/virtual-cluster. C9 depends on all mandatory branches and exact bundle/certification-contract closure. D then executes M00-M10 Exact-SHA functional certification, while M owns M11-M13 final chaos/load/soak. K/L remain optional. Source implementation is never Physical PASS.


Release 0.0.287 closes C5 at Source Semantics with `INSTALLER_JOURNALED_RESET_AUTHORITY_V1`, `INSTALLER_OBJECT_STORAGE_READ_WRITE_PROBE_V1`, source-enforced appliance sizing/network admission and `INSTALLER_UPGRADE_INTERRUPTION_RECOVERY_MATRIX_V1`. The phase transition to C7 does **not** certify physical sizing, network/storage failure behavior or Exact-SHA runtime. High-impact MCP delegation now has an executable approval-handoff pattern: `cluster_maintenance_request` creates/replays the existing product maintenance authority and must stop at independent `AWAITING_APPROVAL`; no MCP self-approval tool is exposed.
#### AI-native control plane, Lab and MCP design boundary

`UNIFIED_AI_RUNTIME_V1` is a capability plane over existing 4SO authority, never a second orchestrator or SoT. Operator diagnosis, Marketplace advisory and cloud/local Lab diagnosis use one provider-neutral runtime with fail-closed configuration, central secret redaction, bounded context/output, immutable prompt IDs/digests and structured output. `AI_PROVIDER_TRANSPORT_AUTHORITY_V2` constrains provider egress: non-loopback endpoints require HTTPS, loopback HTTP exists only for local/test runtimes, URL credentials/fragments are rejected, redirects must remain on the exact same origin without transport downgrade, implicit environment proxies are excluded from the provider trust boundary, link-local/unspecified/multicast destinations fail closed, and each connection is dialed only to the exact DNS address set validated immediately beforehand so connect cannot perform a second resolution. Provider envelopes and structured output are duplicate-key-rejected before semantic parsing so ambiguous JSON cannot be normalized into durable authority. `PLATFORMCTL_CONTROL_PLANE_TRANSPORT_AUTHORITY_V1` applies the same explicit-network principle to credential-bearing Platform API and Bootstrap Installer traffic: no implicit environment proxy is trusted, redirects are denied, link-local/unspecified/multicast resolutions fail closed, and each socket dials only the DNS address set validated inside that connection attempt; token files are private regular non-symlink inputs opened with no-follow/inode checks. `LAB_CONTROL_PLANE_TRANSPORT_AUTHORITY_V1` independently enforces the equivalent boundary in the Python M00-M03 Lab harness: bearer-authenticated Installer requests ignore environment proxies, deny redirects, pin each HTTP(S) socket to one validated resolution set, reject link-local/unspecified/multicast targets, and allow plaintext HTTP only on loopback SSH-tunnel endpoints so physical certification cannot silently use weaker transport semantics than `platformctl`. `PLATFORMCTL_EXACT_RELEASE_SELF_BINDING_V1` closes the local orchestrator attribution boundary for exact-release-producing CLI workflows: AI provider certification, appliance-bundle build, field-campaign prepare/collect and zero-to-HA must hash `/proc/self/exe` and match the verified release-manifest digest for `bin/linux-amd64/platformctl` before producing exact-release-bound output. `FIELD_CAMPAIGN_PLATFORMCTL_CONTINUITY_AUTHORITY_V1` extends that identity through campaign continuation: schema v5 seals the packaged platformctl digest into the tamper-evident campaign state, and every start/watch/resume/diagnose continuation checks the actual `/proc/self/exe` digest before contacting the Installer or mutating/recording campaign state. Legacy campaign schemas remain recoverable but are explicitly outside this continuity guarantee. `AI_EXTERNAL_PROVIDER_RUNTIME_CERTIFICATION_V2` is the live external-provider evidence contract: the exact-release `platformctl` must inspect and SHA-bind its own release ZIP, prove the actually executing `/proc/self/exe` digest equals the packaged `bin/linux-amd64/platformctl` digest, use an HTTPS provider endpoint, execute bounded diagnosis and Marketplace structured-output probes through the same runtime/transport, prove synthetic-secret redaction, allowlist-only recommendation semantics and non-negative internally consistent usage counters, then seal a tamper-evident evidence document. This provider-specific PASS is never product PASS or Physical PASS and cannot be inferred from mock/local tests. `AI_PROVIDER_DISPATCH_AUTHORITY_V1` adds a durable pre-egress `ai_execution_claims` fence for canonical Operator diagnosis and Marketplace model advisory. The project/key uniqueness claim is written before provider dispatch; concurrent duplicates fail without a second call, successful claims bind to the durable `ai_run`, and FAILED or crash-left DISPATCHED claims are not automatically redispatched. Explicit retry therefore requires a new Idempotency-Key, preferring at-most-once provider dispatch over hidden duplicate cost when the prior remote outcome is uncertain. `AI_PROVIDER_RESULT_COMMIT_AUTHORITY_V2` makes successful result persistence atomic with claim terminalization: `ai_runs`, audit/outbox emission and `DISPATCHED→COMPLETED` are committed together in one PostgreSQL serializable transaction or one FileStore durable mutation. `FinalizeAIExecution` is the only Store write that creates a durable AI run; standalone run creation/completion mutations are removed, and Marketplace may only be configured with the product-owned controlled advisor whose provider-dispatch decision is known before egress. The exact legacy 0.0.240 orphan-run + DISPATCHED-claim state remains recoverable without provider redispatch. This removes both the post-provider crash window and the alternate write surface that could otherwise reintroduce a durable run with a non-terminal claim. `AI_RUN_POSTGRES_DURABILITY_RUNTIME_AUTHORITY_V1` extends the production-HA M03 certifier so the installed PostgreSQL runtime must physically prove one-winner dispatch contention, rollback without split claim/run state, atomic successful result/audit/outbox/claim commit, survival across a real postmaster restart, and survival through backup/restore. `LAB_M03_EXACT_RELEASE_EVIDENCE_AUTHORITY_V1` binds that runtime evidence to the exact release byte stream: the certifier requires the exact release digest as an explicit runtime prerequisite, stores it in schema-v2 evidence before computing the evidence digest, and the Lab harness validates plus hashes one stable no-follow evidence inode before sealing the evidence-file digest into the outer run result. The source automation does not close `AI_RUN_POSTGRES_DURABILITY_RUNTIME_CERTIFICATION_PENDING`; only exact-release physical M03 evidence may do that. Successful advisory calls become project-scoped `ai_runs`; raw prompts and credentials are not persisted. `OutputDigest` is defined over canonical JSON and is recomputed at every persistence boundary so PostgreSQL `jsonb` reformatting is harmless while content tampering fails closed.

`RUNTIME_CLOSURE_EXACT_RELEASE_BINDING_AUTHORITY_V1` makes runtime closure evidence attributable to exact shipped bytes instead of only a product version. Bootstrap passes the appliance bundle `sourceReleaseDigest` into Platform API; the API hashes its live `/proc/self/exe`, stores both digests as immutable campaign identity under evidence schema v2, and includes them in the evidence digest. Migration 0055 carries those fields through PostgreSQL without breaking old writers. Independent CLI verification of schema-v2 closure reports requires the exact release archive and cross-checks the release digest plus the packaged `bin/linux-amd64/platform-api` digest; schema-v1 reports remain historical integrity evidence only and never acquire exact-release status retroactively.


The Operator Console exposes only live AI/MCP authority: configuration/budgets, usage/redaction counters, linked resource context, durable run evidence, read-only MCP discovery and separately scoped delegated product operations. It does not provide a free-form shell, direct kubectl, RBAC escalation or synthetic provider-health claim. API tokens use distinct `mcp.read`, `mcp.operate` and `ai.diagnose` capabilities. `mcp.operate` is operator-only and allow-listed mutations must reuse normal project authorization, revision, approval and durable audit/state-machine authority.

The MCP edge is pinned to sessionless revision `2026-07-28` and validates the wire envelope rather than merely advertising the version: per-request protocol/client-capability `_meta`, routable method/name headers, header/body equality, protocol-specific mismatch/version errors, `resultType` on every successful result, server identity metadata and private bounded cache hints on discovery/list. `MCP_EXTERNAL_CLIENT_INTEROPERABILITY_V1` is generated by a separate-process Python standard-library client over actual TCP and includes a cross-project denial control. In-process handler tests alone are therefore insufficient to close the interoperability exit criterion, and the default read-only authority and delegated-operation authority both remain independent from Physical Runtime certification.

`LAB_CERTIFICATION_MATRIX_V2` remains the canonical machine-readable lab guide. The Operator Console, API and `scripts/lab_runner.py` consume this authority rather than duplicating server counts or matrix truth. The deterministic runner owns preflight, install orchestration, matrix execution, evidence and PASS/FAIL. AI is invoked only after a deterministic failure and receives a bounded normalized/redacted failure packet; it may diagnose or recommend repair but cannot promote any gate.

`LAB_EXACT_RELEASE_SNAPSHOT_AUTHORITY_V2` closes the local exact-artifact identity boundary before Lab planning, preflight or execution. The runner snapshots the operator-supplied release ZIP once into a private non-symlink regular file, hashes the copied byte stream, requires the opened inode/size/mtime/ctime to remain unchanged across that read, atomically publishes the snapshot, and then reuses the same snapshot for release verification, bundle source binding, field-campaign inputs, installation and evidence collection. Replacing the original release path or rewriting the same inode during snapshot creation therefore cannot silently change the artifact being certified. Release ZIP admission also rejects duplicate paths, directory/encrypted/non-regular members, ambiguous/non-canonical paths, missing Unix modes, multiple roots and bounded-size/file-count violations before extraction. `M00` and later rows may report only the digest of this private execution snapshot; a hash read from one path followed by execution from a later reopening of an untrusted mutable path is not Exact-SHA evidence. `LAB_EXACT_RELEASE_EXECUTION_AUTHORITY_V1` extends that invariant through every reopen needed by plan/preflight/execution: release identity and SHA are computed from one no-follow opened inode, extraction is performed from that opened inode only after its digest equals the sealed release authority, and inode/size/mtime/ctime plus digest are revalidated after extraction. The independent release verifier likewise refuses source metadata drift while making its private verification snapshot. Exact-SHA therefore refers to the bytes actually parsed/extracted, not merely to an earlier pathname hash.

`LAB_APPLIANCE_BUNDLE_ACQUISITION_LOCK_V8` is the sole automatic Lab bundle-source authority and is physically shipped under `lab/appliance-bundle-acquisition-lock.json` inside the exact release ZIP. `LAB_APPLIANCE_BUNDLE_ACQUISITION_EXACT_RELEASE_BINDING_V1` defines the consumption boundary: plan/run read the lock member directly from one stable `O_NOFOLLOW` Exact Release ZIP inode, require the full ZIP SHA-256 to equal the already sealed release authority before and after member access, and hash the exact member bytes used for acquisition. The mutable extracted copy is never an automatic source authority. The run spec cannot inject acquisition URLs. V8 carries five canonical external/source authorities and requires every source authority to be exactly one of fully resolved, partially pinned, or missing; `digest-pinned-core-workload-images` is explicitly derived from the product-owned management OCI archive rather than maintained as a sixth parallel source authority; overlap, duplicate IDs, duplicate staging paths and silent omissions fail closed. Every locked or pending artifact has one canonical relative `stagingPath`; a fully resolved artifact also has exact SHA-256/byte-size evidence. A partial authority separates locked artifacts from pending artifacts and may retain immutable Git commit/blob provenance without being eligible for `ready` state. A ready lock additionally supplies 1-4 public HTTPS sources for one deterministic input-pack ZIP plus exact SHA-256, byte size, build-spec path and staging root. After extraction, the runner re-hashes every resolved artifact at its locked staging path before invoking any bundle build, requires the build-spec RKE2/workload/Argo CD/CloudNativePG/storage paths to exactly equal the corresponding authority paths, and requires the management workload archive to be a real OCI Image Layout, verifies every content-addressed blob/descriptor and its embedded `MANAGEMENT_WORKLOAD_OCI_ARCHIVE_INVENTORY_V2`, requires top-level descriptors to bind the exact inventory reference through both containerd and OCI reference-name annotations under `MANAGEMENT_WORKLOAD_OCI_IMPORT_ADDRESSABILITY_V2`, and derives the digest-pinned core-image authority from the archive image manifests. The OCI parser intentionally supports producer-realistic standard Image Index metadata (index `mediaType`/annotations plus descriptor platform metadata) while keeping the appliance workload contract image-only: artifact/referrer `artifactType`/`subject` semantics are not silently admitted. The independent Python Lab parser streams TAR entries and enforces the same 100,000-entry ceiling as the Go OCI authority so pre-build source inspection cannot materialize an unbounded member set. Optional build inputs without a canonical authority, including `ocmManifest` in this automatic path, fail closed. The input build spec is release-version-bound and must carry an all-zero `sourceReleaseDigest` placeholder; after the exact release ZIP is hashed, the runner replaces only that placeholder, invokes the `platformctl appliance-bundle build` binary extracted from the same release, then verifies the sealed bundle before remote installation. An incomplete lock enumerates unresolved source authorities and blocks before input-pack acquisition. Arbitrary latest downloads are forbidden. V8 also makes the network/path boundary explicit: an initial lock URL is public HTTPS without credentials/query/fragment; immediately before egress the hostname is resolved and every address must be globally routable; the TLS connection is pinned to that admitted address set while certificate/SNI validation remains bound to the original hostname; implicit environment proxies are disabled; every HTTP redirect and the final response URL are revalidated under the same public-destination rule (redirect query strings may carry opaque signed parameters); and canonical relative paths reject whitespace repair, backslash conversion, NUL, absolute paths and dot traversal instead of normalizing ambiguous input.

`LAB_RUN_STATE_BINDING_AUTHORITY_V2` owns mutating Lab state continuity. One `--state-dir` is exclusively locked for the full physical run and, after successful preflight, is immutably bound to the exact release SHA-256, canonical server inventory, execution-relevant Lab spec, `LAB_SSH_CREDENTIAL_SNAPSHOT_AUTHORITY_V2`, and verified bundle/lock digest authority. The SSH authority snapshots the exact private key and `known_hosts` bytes with no-follow source opens into read-only private state before SSH preflight and rejects same-inode size/mtime/ctime drift across the copy; retry with different credential or host-trust bytes fails closed and requires a new state root. OpenSSH argv must place `--` before the destination so it terminates local option parsing rather than becoming the first remote command token. The exact-release and SSH snapshots are persistent across re-entry and may not be replaced by different bytes. A state-directory binding mismatch fails closed before physical install mutation. Atomic unique temporary files are mandatory for root-owned snapshot/download/evidence writes; predictable `.tmp` names are not an authority boundary. Advisory AI configuration is excluded from this physical binding because AI cannot authorize mutation or PASS.

`REMOTE_BOOTSTRAP_STREAMING_STAGE_AUTHORITY_V1` owns the local-to-remote staging byte boundary used by `installer-remote`. Stage-source paths are not trusted after directory enumeration: every file source is reopened with no-follow semantics, must still be the same regular inode, and must retain its observed size/modification identity across the streamed read. The TAR is written to a private mode-`0600` temporary file and streamed to SSH, then removed locally, rather than retaining all source bytes plus a second TAR copy in process memory. The remote receiver remains independently digest-bound to the generated stage manifest before deployment. This closes both the symlink-swap disclosure path and the production-bundle OOM failure mode without inferring runtime certification. `REMOTE_BOOTSTRAP_EXPECTED_BUNDLE_AUTHORITY_V1` closes the adjacent preflight-to-mutation authority gap: `InstallerRemoteBootstrap.spec.expectedBundle` is mandatory and carries the canonical appliance `bundleDigest` plus `lockDigest`; local source inspection must match, and the remote plan computed from the exact staged bytes must match again before host deployment apply. Continuation status/verify/rollback/recovery surfaces are checked against the same binding. A later same-version but byte-different valid bundle therefore cannot replace the Lab-preflight authority before physical mutation.

`MANAGEMENT_PLANE_STORAGE_AUTHORITY_V1` fixes the previously ambiguous replicated-storage provider for the internal production-HA appliance: Longhorn `v1.12.1`, V1 data engine, three replicas, scoped only to the RKE2 Management Plane. Its official `longhorn.yaml` release asset is the resolved `replicated-storage-install-manifest` source lock. `iscsiadm` and `iscsid` remain runtime prerequisites that must be proven on all three management nodes before storage can be runtime-certified. Longhorn is not a target default; OKD and other target platforms continue to resolve storage from their own observed distribution capabilities and later target-phase policy. The overall production bundle remains blocked as `LAB_CANONICAL_BUNDLE_SOURCE_LOCKS_PENDING`, but external/upstream source locking is now materially narrower: Longhorn, CloudNativePG, RKE2 and Argo CD are all fully exact-byte resolved. RKE2 `install.sh` is commit/blob/SHA-256/size bound and Argo CD `install.yaml` is commit/blob/SHA-256/size bound. The product-owned management workload OCI archive is now the only missing source authority; the core-image authority is derived from that archive once present.

Phase F has source-level authority for first-class OKD existing-cluster import and capability-gated mutation admission; managed OKD installation and Exact-SHA Physical certification remain separate later evidence. `platform-agent` treats a real `config.openshift.io/v1` `ClusterVersion/version` singleton with UID/version evidence as OpenShift-family authority, requires complete API/CRD discovery, rejects a same-name CRD spoof, and classifies it as `okd` only when the release version is an OKD build; Red Hat OpenShift/OCP remains the distinct non-admitted `openshift` identity. The control plane independently rejects a native ClusterVersion surface presented as `kubernetes`/`rke2` and recomputes the inventory digest instead of trusting an Agent-provided digest. Imported identity continuity is also re-attested on every inventory/heartbeat using the live `kube-system` UID captured at claim. The HTTP boundary preserves an explicit mismatch response, but the authoritative Memory/File/PostgreSQL Store layer independently owns the same invariant so in-process consumers cannot bypass it. Only the server may add `target-cluster-uid-attested`; a missing legacy inventory attestation is normalized read-only, a legacy heartbeat cannot refresh liveness, and a non-empty mismatch is rejected before target state changes. For unsupported distributions the control plane removes mutation capabilities and adds `target-read-only-admission`; OKD existing imports instead pass through the dedicated native capability/profile/health admission gates before mutation RBAC can be issued. For admitted distributions, mutation RBAC activation additionally requires a fresh identity-attested inventory epoch. New imports persist an import-scoped Kubernetes ServiceAccount and both enrollment and activation RBAC bind to that generation-specific principal; a revoked generation can therefore remain as historical state without authorizing a later re-enrollment. Hub revocation and target-local Kubernetes authorization are deliberately distinct authorities: Hub credentials/certificates are invalidated immediately, while the revoke response (and a retrievable post-revoke endpoint) supplies an idempotent target RBAC fence that empties the subjects of the enrollment bindings and, only when mutation had actually been activated, all mutation bindings. Until that fence is physically applied, the API reports `targetRBACRevocationStatus=APPLY_REQUIRED` rather than claiming target-side revocation. Re-enrollment of the same physical UID is blocked until the operator posts the exact canonical `targetRBACRevocationFenceDigest` returned for the revoked generation; this acknowledgement is revisioned/audited and explicitly is not Physical Runtime proof. Migration `0050` is quiesced-required, reconstructs sticky mutation-RBAC history from immutable `cluster.mutation_rbac_activation.authorized` audit events, and removes mutation authority from legacy unsafe same-UID successors until their revoked predecessor's fence is acknowledged. Migration `0051` is a rolling-safe data parity repair that leaves `0050` immutable and adds the explicit `target-read-only-admission` marker only to already-inventoried repaired successors whose generation predates (or still awaits) the predecessor acknowledgement. Mutation freshness is also bound to the target observation epoch rather than merely to Hub receipt time: `ManagedCluster.inventoryObservedAt` records the authenticated inventory's own observation time, new task claims require both that epoch and the Hub receipt epoch to be fresh, and stale, missing, excessively future or backwards observations fail closed at the Store boundary. Migration `0052` adds this epoch as nullable/default-free rolling-safe state and deliberately does not backfill `inventory_updated_at`, because Hub receipt time is not target observation evidence; upgraded rows must submit fresh inventory before new mutation work can be claimed. The Agent also rejects a revoked activation marker before permission proof. Existing pre-authority imports retain the legacy fixed principal for mixed-version compatibility, and the migration that first permits physical-UID reuse after revocation is quiesced-required so an old writer cannot create a new fixed-principal enrollment across that semantic boundary. Enrollment expiry is a Store-level authority as well: PostgreSQL now matches Memory/File by rejecting already-expired creation, presenting elapsed pending/approved generations as `EXPIRED`, and materializing an expired same-name generation with credential invalidation and audit/outbox evidence before replacement creation. Mutation activation issuance is independently server-owned: Agent inventory cannot create `target-mutation-rbac-activation-issued`, and an Agent-reported `target-mutation-rbac-active` is stripped until the Store has recorded issuance for that ManagedCluster. Activation issuance is explicitly state-changing: `POST /api/v1/clusters/{id}/mutation-rbac-manifest` issues/re-issues authority, while `GET` only retrieves a current issuance and cannot create authorization through read-side effects. The activation manifest writes a proof ConfigMap containing the managed-cluster ID, claimed physical UID and the stable authorization-basis digest for which activation was issued; `ManagedCluster` persists both the current basis and issued-for digest. That basis includes only stable target-authorization facts: distribution/evidence, Kubernetes version and identity/principal attestations. Unrelated API/CRD/OpenAPI discovery churn, node readiness, capacity, certificate lifetimes, add-on health, storage/network telemetry and observability capabilities remain visible in the full authenticated inventory digest and can invalidate stale task plans, but do not revoke Kubernetes RBAC. Stable target-authority drift invalidates the issuance marker and active proof, returning the target to read-only until explicit re-issuance for the new basis. Sticky server-owned `target-mutation-rbac-ever-issued` history survives that drift so later revocation still fences mutation bindings that may remain on the target. Modern imports additionally require the running Agent to attest the expected import-scoped ServiceAccount before activation is issued. The Agent verifies the cluster/UID/basis binding before `SelfSubjectAccessReview` and `target-mutation-rbac-active`, so the admitted sequence is identity/principal attestation → digest-bound server issuance → target permission proof rather than Agent self-authorization. A heartbeat without fresh inventory still breaks the mutation authority epoch. These source semantics admit only capability-gated OKD **existing-import** mutation; they do not admit managed OKD installation and do not constitute Exact-SHA Physical PASS.

`TARGET_CAPABILITY_RESOLVER_V1` is the target-selection boundary. Kubernetes/RKE2 decisions are admitted directly; OKD existing-import decisions are admitted only when fresh native identity plus inventory-bound required capabilities are present. Until then the same target remains `DISCOVERED_BLOCKED`, never optimistically mutation-capable. The resolver suppresses duplicate defaults such as Cilium networking, Capsule tenancy and VictoriaMetrics platform monitoring on admitted OKD targets, and keeps infrastructure/policy/snapshot/runtime-security choices conditional where runtime discovery is required. Managed OKD install, disconnected acquisition and Exact-SHA runtime certification remain later authorities.

### Catalog upstream admission authority

Unresolved third-party Helm components have one product-owned upstream-selection authority: `catalog/upstream-admission.json`. Version selection, source acquisition and runtime certification are three independent gates. A component may move from a minor-series constraint to an exact version only when its admission row is `ready-for-acquisition`; this exact pin is **not** evidence that the source is resolved or the component is runtime-certified. `source.resolved`, source-lock digests and certification evidence remain false/empty until their owning workflows produce real immutable artifacts/evidence.

The authority MUST cover every unresolved Helm component exactly once, use official HTTPS/OCI sources, reject prerelease/latest inference, and fail closed when a component requires architecture, dependency or version review. Review-required components MUST retain the existing catalog constraint so a candidate version cannot silently become executable policy. Acquisition tooling consumes the authority directly and refuses caller overrides, and the lower-level catalog-bundle install boundary independently revalidates that authority plus the existing repository component contract before mutation. A Helm import may change only the source-resolution fields owned by the import transaction; it cannot smuggle unrelated catalog-policy changes under the same component identity. After runtime bundle and component durability are established, the consumed authority row is atomically retired so exact unresolved-set coverage remains true; retry converges safely across crashes before or after that retirement. Because the admission document is shared authority across components, the complete repository import transaction is serialized with a repository-scoped lock under excluded `.state/`; independent concurrent imports must never race read/modify/write retirement and resurrect a consumed row. Catalog constraints are never auto-widened merely because upstream has moved to a newer series.


## AI-native operator experience authority

The compatibility appliance-bundle builder is not allowed to weaken canonical bundle authority: it inspects supplied management-workload OCI Image Layout archives using the independent Lab Python authority, rejects duplicate references, and requires the exact archive image set to equal all required digest-pinned product/operator/storage images before it can seal a lock. This is parser/authority parity only; it is not a substitute for the still-missing product-owned workload archive source lock.

Phase-D Lab authority closes source automation for M00-M03 without claiming physical certification. M01/M02 now validate the Installer inputs required by the real planner before any remote mutation: all server-driven tiers require managed-identity `adminEmail` plus appliance `dnsZone`, while three-management-node tiers also require an explicit HTTPS public endpoint and external S3 URL/bucket/secret reference. The runner always submits its exact verified appliance bundle as `disconnected` authority, and `LAB_INSTALLER_ACCESS_TOKEN_FILE_AUTHORITY_V1` seals each exported Installer credential through a unique no-follow private file before atomic promotion into the resume state, so same-binding reruns do not depend on an overwrite-prone stale token. M03 is deliberately bound to the `production-ha` runtime installed by the same M02 execution rather than accepting an unrelated database endpoint: the runner derives the active CloudNativePG primary/service/server-CA from live cluster status, creates one ephemeral certifier-owned database identity over a credential-private channel, tunnels with strict SSH and TLS `verify-full`, executes the PostgreSQL migration/concurrency/restart/backup/restore harness, requires full API/PostgreSQL HA recovery, and removes all certifier-owned databases plus the role before PASS. Secret-bearing bootstrap fields are not persisted or admitted into public stage output. This removes `LAB_PHASE_C_MATRIX_M00_M03_AUTOMATION_PENDING` only; Phase D remains blocked on physical server-driven certification and its other explicit exit criteria.

`BUNDLE_SOURCE_ARTIFACT_BINDING_AUTHORITY_V1` closes the Source Lock -> Bundle Build byte-continuity gap. A ready acquisition lock no longer proves bytes only before invoking the builder: the normalized `ApplianceBundleBuild` spec is populated from the lock with an exact path/size/SHA-256 binding for the complete artifact universe, and the Go builder walks the staging path through no-follow directory descriptors before copying and hashing the single opened regular-file descriptor. Path substitution, final/parent symlink traversal and in-place byte drift therefore fail before a sealed bundle can be produced. The compatibility builder follows the same outcome semantics by no-follow opening the caller source, rejecting basename role collisions and parsing manifests/OCI inventory only from the copied bundle bytes. The independent Go OCI inspector also rejects a symlink archive. This is source/generated-artifact hardening only; it does not resolve the missing product-owned management workload OCI source authority or imply runtime/Physical PASS.

`MANAGEMENT_WORKLOAD_IMAGE_BUILD_PLAN_V5` makes the last missing bundle-source authority explicit instead of treating it as an opaque OCI tar. `MANAGEMENT_WORKLOAD_EXTERNAL_IMAGE_ACQUISITION_V2` additionally preserves the exact registry tag-root document as content-addressed evidence and `platformctl workload-oci verify-external` replays tag-root → linux/amd64 manifest → config/layers validation on a disconnected host without registry access, so transferred acquisition evidence no longer relies on the acquisition host's JSON assertion alone. `MANAGEMENT_WORKLOAD_EXTERNAL_VERSION_SELECTION_V1` pins the product-selected external management versions/tags and separates immutable image identity from the Registry V2 transport endpoint; `MANAGEMENT_WORKLOAD_EXTERNAL_IMAGE_ACQUISITION_V2`, exposed as `platformctl workload-oci acquire-external`, binds the exact release and plan digests, resolves only that selected tag, selects exactly one linux/amd64 manifest, verifies every config/layer byte by digest and emits a local OCI layout plus acquisition lock. Registry JSON with duplicate keys, tag/document media-type ambiguity, artifact/referrer descriptors, unsafe Bearer scope/realm, private-address transport, HTTPS downgrade, excessive redirect chains and cross-origin Authorization forwarding fail closed. CDN redirects remain supported only through HTTPS/public-address transport, with byte digest/size as final authority. `MANAGEMENT_WORKLOAD_MANIFEST_IMAGE_RESOLUTION_V1` separately binds exact-byte upstream operator/storage manifests to the exact OCI payloads that will execute: runtime image tokens are extracted from the locked source YAML, mutable tags must resolve by unchanged repository to a unique digest-pinned image in the same offline OCI archive, and the exact-release `platformctl` produces digest-pinned runtime manifests plus resolution locks. Lab source-binding re-hashes the generated manifest and lock before bundle construction, validates their image sets against the same OCI inventory, and refuses post-resolution byte substitution. It owns eight core roles (PostgreSQL, Forgejo, zot, Keycloak, platform-api, maintenance, platform-agent and platform-probe), three external base-image compatibility roles for product images, exact-release binary/recipe ownership for product-built images, and the three operator/storage image sets derived from already locked manifests. `MANAGEMENT_WORKLOAD_PRODUCT_IMAGE_CERTIFICATION_V1`, exposed as `platformctl workload-oci certify-product`, binds the running CLI to the exact release ZIP and then proves the product image repository, linux/amd64 config, numeric non-root identity, entrypoint, exact-release labels and final layered binary payload. It evaluates whiteouts, requires agent CA trust, and derives ELF linkage/DT_NEEDED from the binary bytes in the image: API remains dynamic with libpq/libc while agent/probe remain static. Runtime-closure PASS is deliberately false until the selected base/image is physically executed. The maintenance recipe performs no live package-manager access; it consumes a pending exact `maintenance-toolchain-base` whose required tools/root-override semantics must be certified before admission. `MANAGEMENT_WORKLOAD_OCI_ASSEMBLY_AUTHORITY_V1`, exposed as `platformctl workload-oci assemble`, remains the deterministic merge boundary after exact refs are resolved: every input is bound to a local OCI root descriptor; reachable blobs are size/digest verified and re-hashed during streaming copy; ambiguous shared root digests, symlink traversal and unbound refs fail closed; the output inventory is sorted and reference-addressable before independent `MANAGEMENT_WORKLOAD_OCI_ARCHIVE_INVENTORY_V2` inspection. These closures still leave `LAB_CANONICAL_BUNDLE_SOURCE_LOCKS_PENDING` open until real external/base digests, product builds and runtime compatibility evidence exist.

Phase E is closed at the source-authority layer rather than by roadmap claim. `VARIABLE_SCHEMA_AUTHORITY_V1`, `PLATFORM_POLICY_SET_AUTHORITY_V1` and `PLATFORM_TEMPLATE_AUTHORITY_V1` form the configuration composition boundary: immutable project-scoped schemas and reusable operating policies are digest-bound, and a PlatformTemplate can reference only an exact same-project published/execution-ready BlueprintRelease plus those immutable authorities. `WORKSPACE_AUTHORITY_V1` adds the complementary cross-cluster product boundary without becoming another runtime SoT: a Workspace stores only immutable project identity plus explicit managed-cluster/namespace references, while workload, quota, health, observability and cost remain authoritative on their existing runtime/telemetry surfaces. Active namespace ownership is unique per project/cluster/namespace, cross-project references fail closed, revocation is revision-guarded and retained, and Memory/File/PostgreSQL snapshot semantics revalidate the same contract. Migrations 0057/0058 enforce template and Workspace reference guards in PostgreSQL. Template admission remains deliberately source-only (`adoptionReady=false` until target impact/certification evidence exists), and Workspace UI explicitly labels runtime state as derived rather than persisted. Operator Horizon exposes `Blueprints -> Platform templates` and `Fleet -> Workspaces`; organizations/projects remain under the explicit `Admin` domain rather than an ambiguous Governance bucket. This source closure does not close C5-C9 pre-certification blockers or imply Physical PASS; physical Lab/AI certification remains deferred to Phase D after C9 Feature Freeze.

`PROGRAM_PHASE_MODEL_V67` treats Operator Experience, Certified Platform Templates/Workspaces, infrastructure providers, Day-2 resilience, security/compliance/identity, usage/FinOps, edge/sovereign autonomy, automation integrations, communication/notification automation, AI, MCP, Lab/Certification, supply chain and developer/agent experience as cross-cutting product tracks. The embedded console uses product-owned **4SO Operator Horizon V3**: Palette informs information architecture, Rafay informs operational density and Rancher informs resource-explorer ergonomics, but all implementation and authority semantics remain 4SO-owned. Every new capability must converge API/runtime truth, console workflow, evidence, AI/MCP read surfaces where appropriate and deterministic tests before phase closure.


Release 0.0.298 closes **R0 — Release Authority & Certification Rebaseline**. `PROGRAM_PHASE_MODEL_V19` replaces the artificial G→H→I→J serial chain with explicit mandatory DAG branches: immediate exact-supply-chain acquisition (`S1/S2`), operational/day-2/data-protection/identity tracks (`G1-G5`), connected Managed OKD plus independent VMware (`H1/H2`), disconnected/edge (`I1/I2`) and automation/FinOps/virtual-cluster (`J1-J3`). `ProductReleaseReady` now fails closed while any mandatory pre-C9 roadmap phase is blocked, and `platformctl release-readiness` exposes separate `roadmapFeatureBlockers`/codes while including them in product readiness. `FEATURE_CERTIFICATION_REGISTRY_V1` declares required Source/Generated Runtime/Negative Control/Integration/Exact-SHA/Chaos levels per feature. `LAB_CERTIFICATION_MATRIX_V2` schema v3 separates `featureOwnerPhase` from physical `executionPhase`: M00-M10 execute only in D, M11-M13 only in M, while M07/M08/M09-M10 retain explicit G3/H1/I1 feature ownership. V19 also makes Connected Managed OKD, target Add/Drain/Remove/Replace lifecycle and Backup/Restore/Restore Drill explicit blockers rather than implicit roadmap assumptions. Enterprise SAML is rebaselined to Keycloak SAML brokering into the product OIDC authority unless a separate native-SP requirement is explicitly admitted. These are release/source-governance corrections only; Exact-SHA Physical Runtime remains independently `NOT_EVALUATED`.

Release 0.0.297 closes the product-owned Queue/Job and Product Log Center blockers without pretending that live target workload logs are already solved. `OPERATIONS_QUEUE_CENTER_V1` uses scoped PostgreSQL aggregates for exact Operation state, notification-delivery state and transactional-outbox pending counts while keeping detail lists bounded; it is read-only and never exposes worker claim/transition controls. `PRODUCT_LOG_CENTER_V1` merges sealed Operation step-trace metadata, Audit events and Notification events under project/organization scope, intentionally omits raw evidence payload bytes, and reports bounded-window search truth. The Operator Console links each Operation directly into the Log Center and exposes queue pending/executing/retry/dead-letter/expired-claim state. `PROGRAM_PHASE_MODEL_V18` removes only the broad Queue Center/Product Log Center blockers and replaces the latter with the narrower `TARGET_WORKLOAD_LOG_TAIL_PENDING`; live pod/workload tail remains open until a capability-gated target log transport is implemented.

Release 0.0.296 closes `AGENT_SCHEDULER_V2`: Agent liveness/inventory polling is isolated from the single-writer mutation lane, so long-running task execution no longer suppresses fresh inventory/heartbeat cycles. The mutation lane remains sequential and bounded to one pending accepted inventory epoch, avoiding concurrent Kubernetes writers while coalescing redundant polls. Upgraded Agents advertise `agent-scheduler-v2`, and `PROGRAM_PHASE_MODEL_V17` removes only the Scheduler blocker; unified Queue/Job and Log Centers and the remaining Phase G product work stay explicit blockers.

Release 0.0.295 adds `CHECKPOINT_SAFE_FULL_VERIFIER_V2` and upgrades deterministic test orchestration to `AUTOPILOT_STAGE_SHARD_AUTHORITY_V2`: package and smoke gates are bounded, replayable checkpoints and the extracted-artifact verifier owns the same Lab/upstream/AI/Persian/C4-workflow evidence expected from the canonical release graph. Production TLS generation remains RSA-3072; only simulation receives an injected lower-cost key generator. Release 0.0.294 added `OPERATION_EXECUTOR_AUTHORITY_V1` and bounded diagnostic execution contracts discovered during the post-0.0.293 architecture audit. Generic raw Operation execution is no longer a human operator/admin capability in production: state transitions, claims, attempts, step trace/evidence and compensation execution require an authenticated platform-operator service-account token carrying `operation.execute`, worker identity is principal-derived, and long-running workers renew the same fenced lease through the executor-only lease-renew endpoint. Cluster timeline/resource resolution is store-native and cluster-scoped before `LIMIT`; support diagnostics no longer Snapshot the entire Control Plane, Fleet Health declares a bounded returned-cluster scope, and oversized synchronous Fleet Support Bundles fail closed pending the explicit async job authority. `PROGRAM_PHASE_MODEL_V16` deliberately keeps Scheduler/Queue/Log/notification-scan/support-bundle/localization debt visible rather than treating these hardening changes as Phase G completion.

Release 0.0.293 hardens the Phase G workload/search surface for high-cardinality and multi-tenant execution. Search projection now requires scope-aware authority-store paging for managed clusters, operations, evidence and audit before any source LIMIT; PostgreSQL evidence lookup joins through project-owned operations and the search path has no global evidence scan or global-audit-before-scope fallback. Workload Explorer acquisition uses Kubernetes native `limit`/`continue` pagination and stops at product bounds rather than downloading an entire cluster collection before truncation. Event normalization uses deterministic tie-breakers after observation time so equal-timestamp event sets cannot churn inventory digests merely because API order changed. These are Source/Generated-runtime correctness claims only: OpenSearch remains an optional scale-backend contract rather than a shipped product-state authority, all five remaining Phase G blockers stay open, and Exact-SHA Physical PASS remains deferred behind C9.

Release 0.0.286 adds a derived developer/agent evidence layer without introducing a parallel architecture or documentation truth. `platformctl target-architecture` emits `TARGET_ARCHITECTURE_MODEL_V1`; `scripts/generate_agent_knowledge.py` projects that authority into `DERIVED_AGENT_KNOWLEDGE_V1` and `DERIVED_ARCHITECTURE_EVIDENCE_V1`, binds every material claim to exact source-file SHA-256 evidence, omits runtime-impact assertions and marks the whole artifact discardable/rebuildable. Release packaging includes the derived knowledge file only as evidence/agent context. OpenWiki and Archify remain optional development adapters. `BROWSER_TRIAGE_PROFILE_V2` pins Chrome DevTools MCP 1.8.0 with isolated/headless/no-telemetry/no-CrUX/update-check-disabled defaults for browser diagnosis while Playwright remains the deterministic UI gate. `PERSIAN_UI_QA_V1` performs Unicode/bidi/product-glossary checks using only 4SO-owned rules; external Salsi/Pasban data is not shipped. `SEARCH_PROJECTION_AUTHORITY_V1` makes OpenSearch an optional projection candidate, never a source of product state or a direct unrestricted AI administration surface.

Release 0.0.285 records two implementation benchmarks without changing product authority. **shadcn/ui** contributes the open-code/component-ownership principle: 4SO keeps its existing embedded console stack and owns primitives, design tokens, accessibility and behavior tests locally instead of importing a React/Tailwind runtime just before certification. **Novu** contributes communication workflow, routing/condition preview, inbox/preferences/digest and agent-channel concepts; it is not adopted as a control-plane dependency. The 4SO transactional outbox plus PostgreSQL notification event/route/delivery state stays canonical, and any external communication system is an adapter behind product RBAC/audit/evidence. `NOTIFICATION_ROUTING_PREVIEW_AUTHORITY_V1` is intentionally read-only and creates neither event nor delivery. Mixed-license upstream Enterprise code is not vendored.



### External source publication is non-gating

As of `0.0.228`, external GitHub publication/synchronization is an operator-deferred workflow, not a product runtime, release-certification, or active phase authority. Source completeness for active phase work is proven by the exact downloadable release artifact, its generated manifest/provenance/SBOM, and deterministic validation from a clean extraction. This does not assert that any external repository is synchronized. If external publication is resumed later, parity must be proven atomically before any sync claim.


Release 0.0.306 closes three remaining G1 runtime-observability boundaries without creating parallel authorities. Target workload logs are now read-only durable Operations bound to fresh authoritative inventory and executed by the connected Agent through bounded Kubernetes workload→pod resolution and bounded Loki query semantics; results are sealed evidence and the Operator Console exposes a scoped Project→Cluster→Workload QUERY/TAIL workflow rather than accepting raw LogQL. Notification health uses incremental `(changedAt, clusterId)` paging with a race-safe observed cursor, and Support Bundles use durable idempotent Operation jobs with lease/fence/retry and verified sealed ZIP evidence. A scheduler defect that left workload-log tasks permanently unprocessed was discovered and fixed. G1 now remains blocked only by full mandatory Console localization; S1 remains 14-ready/3-review and Exact-SHA Physical Runtime remains `NOT_EVALUATED`.


### V53 supply-chain handoff

`SUPPLY_CHAIN_HANDOFF_V1` provides one derived connected-to-offline staging contract across catalog sources, management images, exact release toolchain bytes and S2 previous-source requirements. Staging is evidence only and cannot promote source resolution, runtime certification or Physical PASS. `MANAGEMENT_WORKLOAD_STAGED_BATCH_V1` uses the existing exact-release-bound `platformctl workload-oci` owner path for external image acquire/verify/assemble.
