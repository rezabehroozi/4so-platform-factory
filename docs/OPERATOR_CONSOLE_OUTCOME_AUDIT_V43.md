# Operator Console Outcome Audit — V43 / 0.0.337

## Scope

This audit treats the console as an operator product, not a visual skin. Every page was reviewed for: primary user outcome, information architecture, forms and field burden, action reachability, progressive disclosure, truthful async state, permission/approval semantics, Persian product copy, RTL/LTR, keyboard-safe controls, loading/error/empty/forbidden truth, and responsive behavior at 320, 390, 768, 1024 and 1440 CSS pixels.

The bootstrap Installer console is included in the responsive/browser smoke matrix, but the page-by-page table below covers the 20-page product Operator Console.

## Measured surface

After this release the console contains **20 product pages, 46 forms, 288 input/select/textarea controls and 91 buttons**. The control count increased because the previously backend-only managed OKD Compact-3 authority now has a real console journey. The additional 28 controls are isolated behind a three-stage advanced workflow rather than exposed in the default page surface.

## Cross-console changes made in this release

1. Added a compact `Outcome / Done when` strip to all 20 pages. The page must explain what result it produces and what observable condition means the operator is finished.
2. Reframed `Platforms` as a task entry point instead of an import-only cluster list.
3. Added three explicit platform outcomes: connect an existing cluster; provision via an admitted infrastructure profile; install managed OKD Compact-3.
4. Added a three-stage Managed OKD form bound to the existing `POST /api/v1/managed-okd-installs` authority. It accepts opaque credential references only, normalizes SHA-256 input, requires exact Redfish resource paths and preserves independent approval.
5. Added Managed OKD independent approval directly in Operations for `managed.okd.install` operations in `AWAITING_APPROVAL`, using the dedicated approval endpoint and revision precondition.
6. Fixed misleading navigation: `Component catalog` → `Marketplace`, `Install & import` → `Control-plane install`, `Clusters` → `Create & manage platforms`, `Infrastructure providers` → `Infrastructure profiles`, `Workspaces` → `Application workspaces`.
7. Clarified that the Installation page installs the Platform Factory management/control plane, not a target Kubernetes platform.
8. Fixed high-visibility Persian copy defects and robotic phrases, including duplicated Baseline wording, the tenant branding typo, StorageClass wording and mixed Trace/Evidence prose.
9. Added regression contracts for the new platform journey, outcome guidance, Managed OKD mutation outcome and approval path.
10. Extended browser smoke so every product page is checked for its outcome guidance and horizontal overflow at every supported viewport.

## Page-by-page outcome review

| Page | Primary operator outcome | Forms / controls | UX disposition after audit | Remaining truth / dependency |
|---|---|---:|---|---|
| Overview | Understand readiness, blockers and next safe action | 0 / 0 | Keep read-first. Existing bounded summary/attention authorities are correct; added explicit completion grammar. | Depends on API authority freshness; degraded sources remain visibly partial. |
| Organizations & Projects | Establish ownership and scoped human/automation access | 5 / 19 | Creation and identity changes stay behind action disclosures; page outcome now separates ownership from infrastructure. | Backend RBAC/OIDC authority remains authoritative. |
| Control-plane install | Produce a validated Platform Factory management-plane install plan | 1 / 14 | Renamed/reframed to remove confusion with target platform creation. Core install form remains visible because it is the page's only task; recovery center remains distinct. | Planning is not installation success; bootstrap/runtime gates stay independent. |
| Create & manage platforms | Create/import a target and obtain authoritative inventory | 4 / 40 | Major rework. Added task-first chooser and staged Managed OKD flow; import and maintenance remain collapsed until selected. | Managed OKD connected runtime certification remains blocked by `OKD_CONNECTED_MANAGED_INSTALL_PENDING`. |
| Infrastructure profiles | Verify reusable infrastructure and provision a dedicated target | 2 / 19 | Reworded around operator outcome; low-level target/provisioning distinction remains secondary explanatory text. | Only admitted profiles/distributions are selectable; execution truth comes from provider authority. |
| Platform templates | Compose reusable typed schema, policy and template authority | 3 / 30 | Dense but acceptable because all three forms are numbered, sequential and individually disclosed. Outcome strip explains that templates are reusable authority, not runtime truth. | Direct deploy remains intentionally forbidden. |
| Platform blueprints | Create an immutable reviewed platform standard and upgrade intent | 2 / 41 | Existing four-stage wizard is the correct density-control mechanism; expert raw/API parity remains separate. | Publication/certification rules remain backend authoritative. |
| Marketplace | Install a published offer on an eligible target | 1 / 3 | Navigation label corrected. Small primary form can remain visible; advisory recommendations are explicitly non-mutating. | Requires connected eligible platform and published offer. |
| Certified baselines | Preview impact and apply only admitted baseline resources | 1 / 3 | Primary action remains disclosed; Persian duplicated heading fixed; completion semantics emphasize sealed evidence rather than accepted request. | Runtime inventory/capability evidence must be current. |
| Runtime assurance | Convert runtime observations into verifiable evidence/certification | 3 / 8 | Three actions are separate workflows and already progressive; outcome wording reduces internal-authority ambiguity. | Physical/production claims still require higher evidence layers. |
| Application workspaces | Bind team/application boundaries to exact namespaces | 2 / 7 | Renamed in navigation to avoid collision with organization/project concepts. Two small creation/binding forms remain visible because they are the page's paired primary task. | Runtime state stays on referenced clusters; workspace is reference authority only. |
| Fleet overview | Resolve drift or execute controlled fleet campaigns | 4 / 22 | Search remains visible; mutating recovery/backup/group operations remain disclosed. Outcome strip makes desired/observed/recovery completion explicit. | Actual execution requires connected target capability and approval where applicable. |
| Tenant environments | Create tenant namespaces with entitlement and branding | 3 / 14 | Existing grouping retained; branding typo fixed; user-facing completion now joins entitlement, namespace lifecycle and organization branding. | Tenant plan catalog and cluster agent remain authoritative. |
| Activity & audit | Explain what happened and choose a valid recovery action | 3 / 13 | Read-oriented controls stay visible. Added Managed OKD approval action here so creation → independent approval → progress/evidence is a complete console journey. | Terminal success is never inferred from queue acceptance. |
| AI Operator | Obtain context-bound diagnosis without direct infrastructure authority | 1 / 6 | Single diagnosis form is appropriate. Completion wording reinforces advisory boundary and normal approval path for mutations. | Model output is advisory; server-side authorization remains mandatory. |
| Physical certification | Collect exact-SHA physical evidence | 0 / 0 | Read/guidance surface is intentionally non-form-heavy. Outcome strip clarifies that command execution is evidence collection, not source completion. | Deferred until development closure; no source-side UI change can create Physical PASS. |
| Notifications | Route the correct event to the correct destination | 3 / 17 | Configuration remains disclosed, preview remains visible and side-effect-free. Completion now explicitly requires preview + delivery history agreement. | External delivery depends on configured adapters/destination health. |
| Integrations & services | Connect product-owned services with explicit credential/revision authority | 5 / 20 | High density is contained by disclosures and expert separation. Outcome wording centers provider/revision/reconciliation state rather than implementation terms. | External service health and reconciliation evidence remain authoritative. |
| Supply-chain releases | Admit trusted signed governed catalog releases | 2 / 7 | Existing governance/action disclosure is appropriate; outcome makes upstream/trust/shipped inventory convergence explicit. | S1 source acquisition/locks remain open in roadmap truth. |
| Planning tools | Produce validation/compatibility results without runtime mutation | 1 / 5 | Small form remains visible. Strong planning-only boundary retained; outcome points users back to executable workflows. | Never implies apply, runtime or certification success. |

## Device / responsive verification

`python scripts/smoke_ui.py .` renders the product console and bootstrap installer through Playwright with mocked empty/authoritative API responses. Product pages are activated one-by-one at **320×900, 390×844, 768×900, 1024×900 and 1440×900**. For every product page the smoke now checks route activation, browser errors, horizontal overflow and presence of the page outcome contract. It also checks RTL→LTR restoration and mobile navigation behavior. The Managed OKD chooser is additionally checked for three distinct paths and a three-stage advanced flow.

Current result in the 0.0.337 source tree: **PASS, no horizontal overflow on any of the 20 product pages at any supported viewport; no browser errors in the smoke matrix.**

### Rendered quality and accessibility checkpoints

The heavier `smoke_ui_quality.py` gate was executed checkpoint-safely as four route shards plus independent Console and Installer auxiliary checks. All four route shards PASS, and both auxiliary surfaces PASS. During the first shard the gate found one real regression in the new platform-path focus style: `var(--focus)` was referenced even though the canonical token is `--focus-ring`. The source was corrected to use `var(--focus-ring)` and the affected shard was rerun to PASS. `smoke_ui_localization_runtime.py` also PASSes, and the rebuilt `platform-api` passes `smoke_ui_live.py`, so the result is not limited to static HTML.

A final static accessibility sweep counts all controls in the console document (including global/modal controls, not only page-local counts above) and finds **zero unlabeled input/select/textarea controls**.

## Form/action safety conclusions

- All product-console forms have JavaScript handlers; no orphan submit form was found in the static wiring audit.
- Non-submit action buttons with stable IDs have handlers; action delegation is used for generated record rows.
- Inputs/selects/textareas are label-bound or carry accessible labeling; no unlabeled icon-button defect was found in the audited surface.
- High-risk mutations remain approval/revision/fence/evidence bound where their backend authority requires it.
- The new Managed OKD journey does not accept raw BMC credentials and does not claim success on request creation or approval.
- Read-only/viewer-safe planning behavior remains separate from mutation authorization.

## Roadmap truth

This UX/product closure does **not** change `PROGRAM_PHASE_MODEL_V43` or Core Freeze counts. Core source implementation remains **19/25 = 76%**. In particular, the console can now request and approve the source-implemented managed OKD workflow, but `H1-baremetal-connected-managed-okd` remains blocked on `OKD_CONNECTED_MANAGED_INSTALL_PENDING`; no Connected Runtime, Exact-SHA Physical or Production PASS is inferred.
