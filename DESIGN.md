# 4SO Platform Factory — Product Design System

This file is the canonical design language for the Operator Console and Bootstrap Installer. It records product decisions, not generic UI theory. Product UI changes must preserve runtime truth and follow this system unless a documented product requirement requires an exception.

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

**Visual foundation:** 4SO uses the MIT TailAdmin Community shell/component language as a reference baseline for navigation density, sticky header behavior, data-card geometry, dark mode, command search, tables and responsive composition. It does **not** ship the TailAdmin runtime stack or copy its demo information architecture. The Console remains an embedded 4SO implementation with 4SO tokens, workflows, authority semantics and product identity. CoreUI and AdminMart were evaluated but are not runtime/design dependencies.


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

Current admitted target identities are `kubernetes` and `rke2`. `okd` may be recognized for identity parsing but MUST remain non-admitted until import, capability discovery/resolution, catalog behavior and runtime certification exist. Legacy `generic-imported` and `kubespray` values normalize to `kubernetes`; immutable historical release documents are not rewritten.

Provider Cluster desired state carries explicit `distributionIdentity`, `provisioningMode`, and `infrastructureProvider` fields while retaining the legacy `distribution` alias for mixed-version/API compatibility. Imported fleet responses expose a separate `target` object so UI and automation no longer infer provisioning semantics from the observed distribution string.

### Program phase authority

`PROGRAM_PHASE_MODEL_V3` is the canonical product-roadmap authority and is intentionally separate from per-blueprint release blockers. Work is grouped into eight large phases rather than narrow release-sized steps: A) architecture rebaseline, B) target capability-contract foundation, C) AI-Native Control Plane + Lab + MCP Foundation, D) OKD import runtime certification, E) OKD capability/profile/catalog integration, F) imported Day-2 + managed Compact-3, G) disconnected + CVO upgrade/recovery, and H) full Exact-SHA physical certification including chaos, soak/load and multi-cluster evidence. The lab phase is intentionally pulled forward so every later capability is admitted through the same server-driven deterministic matrix instead of building a separate certification framework at the end. A source-implemented phase is not a Physical PASS.

#### AI-native control plane, Lab and MCP design boundary

`UNIFIED_AI_RUNTIME_V1` is a capability plane over existing 4SO authority, never a second orchestrator or SoT. Operator diagnosis, Marketplace advisory and cloud/local Lab diagnosis use one provider-neutral runtime with fail-closed configuration, central secret redaction, bounded context/output, immutable prompt IDs/digests and structured output. Successful advisory calls become project-scoped `ai_runs`; raw prompts and credentials are not persisted. `OutputDigest` is defined over canonical JSON and is recomputed at every persistence boundary so PostgreSQL `jsonb` reformatting is harmless while content tampering fails closed. Idempotency is resolved before provider execution where durable replay exists, so retries do not spend a second model call.

The Operator Console exposes only live AI authority: configuration/budgets, usage/redaction counters, linked resource context, durable run evidence and read-only MCP access. It does not provide a free-form shell, direct kubectl, mutation button or synthetic provider-health claim. API tokens use dedicated `mcp.read` and `ai.diagnose` capabilities; MCP project-resource tools independently enforce project authorization and remain read-only in Phase C.

`LAB_CERTIFICATION_MATRIX_V1` remains the canonical machine-readable lab guide. The Operator Console, API and `scripts/lab_runner.py` consume this authority rather than duplicating server counts or matrix truth. The deterministic runner owns preflight, install orchestration, matrix execution, evidence and PASS/FAIL. AI is invoked only after a deterministic failure and receives a bounded normalized/redacted failure packet; it may diagnose or recommend repair but cannot promote any gate. Open-source acquisition must resolve through immutable product-owned version/digest authority before installation; arbitrary latest downloads are forbidden.

Phase C now has source-level authority for OKD identity and read-only admission but remains `blocked` on real runtime certification. `platform-agent` treats a real `config.openshift.io/v1` `ClusterVersion/version` singleton with UID/version evidence as OpenShift-family authority, requires complete API/CRD discovery, rejects a same-name CRD spoof, and classifies it as `okd` only when the release version is an OKD build; Red Hat OpenShift/OCP remains the distinct non-admitted `openshift` identity. The control plane independently rejects a native ClusterVersion surface presented as `kubernetes`/`rke2` and recomputes the inventory digest instead of trusting an Agent-provided digest. Imported identity continuity is also re-attested on every inventory/heartbeat using the live `kube-system` UID captured at claim. The HTTP boundary preserves an explicit mismatch response, but the authoritative Memory/File/PostgreSQL Store layer independently owns the same invariant so in-process consumers cannot bypass it. Only the server may add `target-cluster-uid-attested`; a missing legacy inventory attestation is normalized read-only, a legacy heartbeat cannot refresh liveness, and a non-empty mismatch is rejected before target state changes. For preview/unsupported distributions the control plane removes mutation capabilities and adds `target-read-only-admission`. For admitted distributions, mutation RBAC activation additionally requires a fresh identity-attested inventory epoch. New imports persist an import-scoped Kubernetes ServiceAccount and both enrollment and activation RBAC bind to that generation-specific principal; a revoked generation can therefore remain as historical state without authorizing a later re-enrollment. Hub revocation and target-local Kubernetes authorization are deliberately distinct authorities: Hub credentials/certificates are invalidated immediately, while the revoke response (and a retrievable post-revoke endpoint) supplies an idempotent target RBAC fence that empties the subjects of the enrollment bindings and, only when mutation had actually been activated, all mutation bindings. Until that fence is physically applied, the API reports `targetRBACRevocationStatus=APPLY_REQUIRED` rather than claiming target-side revocation. Re-enrollment of the same physical UID is blocked until the operator posts the exact canonical `targetRBACRevocationFenceDigest` returned for the revoked generation; this acknowledgement is revisioned/audited and explicitly is not Physical Runtime proof. Migration `0050` is quiesced-required, reconstructs sticky mutation-RBAC history from immutable `cluster.mutation_rbac_activation.authorized` audit events, and removes mutation authority from legacy unsafe same-UID successors until their revoked predecessor's fence is acknowledged. Migration `0051` is a rolling-safe data parity repair that leaves `0050` immutable and adds the explicit `target-read-only-admission` marker only to already-inventoried repaired successors whose generation predates (or still awaits) the predecessor acknowledgement. Mutation freshness is also bound to the target observation epoch rather than merely to Hub receipt time: `ManagedCluster.inventoryObservedAt` records the authenticated inventory's own observation time, new task claims require both that epoch and the Hub receipt epoch to be fresh, and stale, missing, excessively future or backwards observations fail closed at the Store boundary. Migration `0052` adds this epoch as nullable/default-free rolling-safe state and deliberately does not backfill `inventory_updated_at`, because Hub receipt time is not target observation evidence; upgraded rows must submit fresh inventory before new mutation work can be claimed. The Agent also rejects a revoked activation marker before permission proof. Existing pre-authority imports retain the legacy fixed principal for mixed-version compatibility, and the migration that first permits physical-UID reuse after revocation is quiesced-required so an old writer cannot create a new fixed-principal enrollment across that semantic boundary. Enrollment expiry is a Store-level authority as well: PostgreSQL now matches Memory/File by rejecting already-expired creation, presenting elapsed pending/approved generations as `EXPIRED`, and materializing an expired same-name generation with credential invalidation and audit/outbox evidence before replacement creation. Mutation activation issuance is independently server-owned: Agent inventory cannot create `target-mutation-rbac-activation-issued`, and an Agent-reported `target-mutation-rbac-active` is stripped until the Store has recorded issuance for that ManagedCluster. Activation issuance is explicitly state-changing: `POST /api/v1/clusters/{id}/mutation-rbac-manifest` issues/re-issues authority, while `GET` only retrieves a current issuance and cannot create authorization through read-side effects. The activation manifest writes a proof ConfigMap containing the managed-cluster ID, claimed physical UID and the stable authorization-basis digest for which activation was issued; `ManagedCluster` persists both the current basis and issued-for digest. That basis includes only stable target-authorization facts: distribution/evidence, Kubernetes version and identity/principal attestations. Unrelated API/CRD/OpenAPI discovery churn, node readiness, capacity, certificate lifetimes, add-on health, storage/network telemetry and observability capabilities remain visible in the full authenticated inventory digest and can invalidate stale task plans, but do not revoke Kubernetes RBAC. Stable target-authority drift invalidates the issuance marker and active proof, returning the target to read-only until explicit re-issuance for the new basis. Sticky server-owned `target-mutation-rbac-ever-issued` history survives that drift so later revocation still fences mutation bindings that may remain on the target. Modern imports additionally require the running Agent to attest the expected import-scoped ServiceAccount before activation is issued. The Agent verifies the cluster/UID/basis binding before `SelfSubjectAccessReview` and `target-mutation-rbac-active`, so the admitted sequence is identity/principal attestation → digest-bound server issuance → target permission proof rather than Agent self-authorization. A heartbeat without fresh inventory still breaks the mutation authority epoch. These source semantics do not admit OKD mutation or satisfy `OKD_IMPORT_RUNTIME_CERTIFICATION_PENDING`.

`TARGET_CAPABILITY_RESOLVER_V1` is the target-selection boundary. Kubernetes/RKE2 decisions are admitted; OKD decisions remain preview-only until import and inventory-bound capability evidence exist. The preview MUST suppress known duplicate defaults such as Cilium networking, Capsule tenancy and VictoriaMetrics platform monitoring on OKD, and MUST keep infrastructure/policy/snapshot/runtime-security choices conditional where runtime discovery is required. Downstream OKD source acquisition and runtime certification are performed only after target-aware catalog resolution, not against the unfiltered generic blueprint.

### Catalog upstream admission authority

Unresolved third-party Helm components have one product-owned upstream-selection authority: `catalog/upstream-admission.json`. Version selection, source acquisition and runtime certification are three independent gates. A component may move from a minor-series constraint to an exact version only when its admission row is `ready-for-acquisition`; this exact pin is **not** evidence that the source is resolved or the component is runtime-certified. `source.resolved`, source-lock digests and certification evidence remain false/empty until their owning workflows produce real immutable artifacts/evidence.

The authority MUST cover every unresolved Helm component exactly once, use official HTTPS/OCI sources, reject prerelease/latest inference, and fail closed when a component requires architecture, dependency or version review. Review-required components MUST retain the existing catalog constraint so a candidate version cannot silently become executable policy. Acquisition tooling consumes the authority directly and refuses caller overrides, and the lower-level catalog-bundle install boundary independently revalidates that authority plus the existing repository component contract before mutation. A Helm import may change only the source-resolution fields owned by the import transaction; it cannot smuggle unrelated catalog-policy changes under the same component identity. After runtime bundle and component durability are established, the consumed authority row is atomically retired so exact unresolved-set coverage remains true; retry converges safely across crashes before or after that retirement. Because the admission document is shared authority across components, the complete repository import transaction is serialized with a repository-scoped lock under excluded `.state/`; independent concurrent imports must never race read/modify/write retirement and resurrect a consumed row. Catalog constraints are never auto-widened merely because upstream has moved to a newer series.


## AI-native operator experience authority

`PROGRAM_PHASE_MODEL_V3` treats Operator Experience/UI/UX, AI, MCP, Lab/Certification, Security/Evidence, Supply Chain and Developer/Agent Experience as cross-cutting product tracks. The embedded console uses the product-owned **4SO Operator Horizon V1** theme; TailAdmin Community is a layout reference and CoreUI an accessibility reference, not runtime dependencies. Every new capability must converge API/runtime truth, console workflow, evidence, AI/MCP read surfaces where appropriate and deterministic tests before phase closure.
