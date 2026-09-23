> **Current development roadmap authority:** `PROGRAM_PHASE_MODEL_V71`. Core Freeze is quality-gated and intentionally narrower than the competitive whole-product software roadmap. `source-implemented` is source-level only and never implies Generated Runtime, Integration, Physical or production PASS. Physical/Exact-SHA evidence gates never block pre-physical software development.

Current `main` uses `PROGRAM_PHASE_MODEL_V71` and `PROGRAM_PROGRESS_MODEL_V2`: mandatory Core source/software closure is **25/25 (100%)**, Core closure/release readiness remains **19/25 (76%)**, and Core+Expansion pre-physical software closure is **34/36 (94%)**. J3 Virtual Cluster is source-implemented with durable executor/lifecycle fencing, bounded diagnostics and measured FinOps attribution; the new J8 Application Platform Composition phase makes the remaining OpenChoreo-inspired WorkloadType/CapabilityTrait, ManagedResourceType, WorkspaceProfile/release-binding, Fleet session-hardening, delivery-insight projection and optional target-adapter work explicit rather than hiding it in documentation. V71 separates `sourceStatus` from `closureStatus`, so external/runtime/physical evidence can remain BLOCKED without turning completed software back into source debt. The current execution wave is `W1-core-closure-blitz`; S1 acquisition and S2 component certification are streamed rather than serialized, while MCP/OKD evidence and the two remaining expansion software phases can advance independently. Physical/Exact-SHA certification remains deferred until C9 and is never inferred from source progress. See `docs/PROGRAM_STATUS.md`.

# 4SO Platform Factory

4SO Platform Factory is a self-contained platform control plane for catalog-driven Kubernetes platform delivery. The repository ships the API, web console, installer, fleet agent, runtime probe, CLI, schemas, migrations, embedded catalog data, deployment assets, tests, and deterministic release tooling.

`VERSION` and `RELEASE-NAME` define the packaged release identity. Git history, not version-numbered Markdown files, is the historical record.




Release 0.0.347 advances the executable roadmap to `PROGRAM_PHASE_MODEL_V53` without progress inflation. S1 now has a first-class connected-stage → controlled-transfer → disconnected verify/install batch path under `UPSTREAM_STAGED_BATCH_V1`; the manifest is derived transport evidence and every mutation still flows through canonical admission plus `catalog-bundle install`. The same work closes a Go installer parity regression that rejected unrelated ready imports while exact review candidates were present. S1 remains 14 ready / 3 review with only 3/20 real source locks, and S2 remains 0 admitted / 20 pending source pairs. See `docs/PHASE_STATUS_V53.md`.

Release 0.0.339 advances the executable roadmap to `PROGRAM_PHASE_MODEL_V45` while preserving Core source closure at **19/25 = 76%**. C7W moves Workspaces (6/6 routes), Projects (2/2 routes), Version, Baselines, Tenancy Plans, Day-2 Campaign Engine and Catalog Governance signing identity to typed MCP parity using the same product authorities as REST. I1 now has a distinct durable disconnected Managed OKD source workflow with exact ImageSetConfiguration/inventory digests, sealed offline archive verification, exact-SHA `oc-mirror v2` execution boundary and mode-specific Console/API/MCP readiness. `OKD_DISCONNECTED_INSTALL_WORKFLOW_PENDING` is removed; `OKD_OC_MIRROR_V2_ACQUISITION_PENDING` remains, so no disconnected or Physical PASS is claimed. See `docs/MCP_PARITY_DISCONNECTED_OKD_HARDENING_V45.md` and `docs/PHASE_STATUS_V45.md`.

Release 0.0.338 advances the living roadmap authority to `PROGRAM_PHASE_MODEL_V44` while keeping Core source closure at **19/25 = 76%**. The Managed OKD Compact-3 path now has production `platform-api` worker wiring, scoped Redfish credentials, content-addressed Agent ISO serving, lease/fence renewal for long steps, exact-SHA `openshift-install`/`oc` workspace execution, health verification and retry-safe convergence into normal Cluster Import authority. The Console reads runtime truth and disables a dead-end install action when execution is not configured. `OKD_CONNECTED_MANAGED_INSTALL_PENDING` remains open because exact acquisition/workspace preparation, real connected execution and Exact-SHA Physical evidence are not yet proven. See `docs/MANAGED_OKD_PRODUCTION_RUNTIME_HARDENING_V44.md` and `docs/PHASE_STATUS_V44.md`.

Release 0.0.333 advances the executable roadmap to `PROGRAM_PHASE_MODEL_V42` and continues C7W, S1, S2, H1 and C9 hardening in parallel. H1 now has a concrete TLS-only Redfish BootMediaProvider with server-side credential references, so only managed-install orchestration and connected OKD installation remain blocked there. C7W adds a durable MCP support-bundle job without exposing diagnostic payloads inline. S1 exact-locks the official Go 1.27.1 Linux/amd64 candidate and adds an offline-only atomic acquisition transaction, but the compiler archive is not present so toolchain admission remains blocked. S2 adds the real `COMPONENT_RUNTIME_UPGRADE_V1` executor contract while the exact two-version matrix remains 0/20 admitted. Core source closure remains 19/25 = 76%; H1/I1/C9 and all Physical certification remain open. See `docs/PHASE_STATUS_V42.md`.

Release 0.0.327 is a truth-gate hardening release under the unchanged `PROGRAM_PHASE_MODEL_V37`. It repairs retry-unstable Data Protection evidence identity, explicit compliance severity ordering, `ephemeralContainers` coverage and digest-pin enforcement discovered by deep audit of 0.0.326. No roadmap blocker is hidden or promoted: S1/S2, MCP parity, G5 durable Scan Center/SAML, Managed/Disconnected OKD and Exact-SHA Physical certification remain open. Release provenance now records the exact Go compiler used for generated binaries; production toolchain support/locking remains part of release-closure truth rather than an inferred PASS. See `docs/TRUTH_GATE_HARDENING_0_0_327.md` and `docs/PHASE_STATUS_V37.md`.

Release 0.0.326 advances G5 under `PROGRAM_PHASE_MODEL_V37` with `4SO_KUBERNETES_SECURITY_BASELINE_V1`, a deterministic compliance-evaluation foundation exposed through `platformctl compliance evaluate`. The evaluator produces stable finding fingerprints for cluster-admin RBAC bindings, host namespace use, privileged containers and mutable `:latest`/untagged images while accepting digest-pinned hardened workloads. This release does **not** close G5: SAML broker lifecycle and the durable ScanRun/Finding/Waiver/Recheck authority remain explicit blockers. Physical/production truth is unchanged. See `docs/COMPLIANCE_SCAN_CENTER_V37.md` and `docs/PHASE_STATUS_V37.md`.

Release 0.0.325 closes G4 at the **source-implementation** level under `PROGRAM_PHASE_MODEL_V36` without changing Physical/production truth. `TARGET_DATA_PROTECTION_AUTHORITY_V1` now provides durable BackupPolicy/BackupRun/RestoreRun/RestoreDrill state across Memory/File/PostgreSQL, HA-safe UTC scheduled backup materialization, optimistic enable/disable controls, independent restore approval, lease/fence Agent execution, restart-safe idempotency, strict BackupStorageLocation/credential-reference binding and recovery checkpoints. Restore Drill success now requires complete Velero restore progress, zero warnings/errors and UID/resourceVersion guarded isolated-namespace cleanup. The Fleet/Recovery console exposes the same policy, backup, drill, restore and approval workflow without accepting secret material. S1/S2 and all non-source certification levels remain open. See `docs/TARGET_DATA_PROTECTION_PRODUCTIZATION_V36.md` and `docs/PHASE_STATUS_V36.md`.

Release 0.0.324 advances S2 under `PROGRAM_PHASE_MODEL_V35` without declaring S1 or S2 complete. `COMPONENT_RUNTIME_V1` now executes install/readiness/dependency/failure-recovery/remove for Gateway API 1.5.1 and Snapshot Controller 8.5.0 with fenced crash-resume semantics, same-UID drift recovery, UID/resourceVersion delete preconditions, zero-live-instance CRD removal guards and zero-orphan cleanup evidence. Upgrade remains independently blocked until an exact admitted two-version matrix exists, so full six-stage lifecycle certification remains zero. The V34 exact Helm/Crane acquisition toolchain remains authoritative; actual source-byte acquisition is still blocked in network-isolated build environments rather than bypassing digest/version policy. See `docs/COMPONENT_RUNTIME_FAILURE_RECOVERY_REMOVE_V35.md` and `docs/PHASE_STATUS_V35.md`.

Release 0.0.321 advances the quality-first Core path under `PROGRAM_PHASE_MODEL_V32` by making S2 component runtime-certification ownership executable and source-bound instead of advisory. `COMPONENT_RUNTIME_CERTIFICATION_REGISTRY_V1` now covers all 20 catalog components with exact release/source-lock binding and explicit install/readiness/dependency/upgrade/remove/failure contracts. The current truth remains intentionally incomplete: only three components are source-ready, 17 remain source-blocked, `secure-namespace-foundation` has only partial foundation-harness execution, and no component has full lifecycle certification. External catalog bundle import now transactionally rebinds the component contract, runtime-certification registry and Helm admission authority with crash-recovery journaling, so source acquisition cannot silently drift from certification authority. A stale runtime-certification fence token is also exercised as a negative control. S1 and S2 remain blocked until actual source acquisition, component executors and lifecycle negative controls are complete. See `docs/COMPONENT_RUNTIME_CERTIFICATION_V32.md` and `docs/PHASE_STATUS_V32.md`.

Release 0.0.320 performs a quality-first roadmap rebaseline after a full 0.0.319 artifact audit. The core architecture remains intact, but `PROGRAM_PHASE_MODEL_V31` adds machine-readable delivery tiers (`core-freeze`, `expansion`, `certification`, `optional`) and removes VMware, Edge extension, broad automation integrations, FinOps and Virtual Cluster from the **Core Freeze blocker set** without deleting them from the roadmap. The critical path is now exact supply-chain acquisition -> component runtime certification -> MCP/data-protection/identity closure -> connected Managed OKD -> disconnected OKD core -> Core Freeze -> Exact-SHA physical certification. The audit also records the truthful 0.0.319 baseline: 108 readiness blockers, 19/19 enabled components not runtime-certified, an incomplete Lab bundle because the management workload OCI archive is missing, and MCP typed parity still far below the 63-family registry inventory. See `docs/QUALITY_FIRST_CORE_REBASELINE_V31.md`.

Release 0.0.319 advances C7W under `PROGRAM_PHASE_MODEL_V30` without overstating parity: `MCP_PRODUCT_ACTION_REGISTRY_V1` now provides fail-closed, exact-count coverage for all 63 public `/api/v1` route families (280 routes / 153 mutations), explicitly distinguishing typed coverage, partial parity, pending parity and narrow security exclusions. `MCP_EFFECTIVE_TOOL_FILTERING_V1` converges `tools/list` and `tools/call` on the same authorization decision so mutation tools are neither advertised nor dispatched without effective operate authority, including defense-in-depth at the inner handler. C7R documentation drift is corrected to source-implemented; C7W remains blocked on full write-to-job coverage, approval-operation parity, identity/admin job adapters and external-client interoperability. Physical installation/certification remains deferred until development closure.

Release 0.0.318 closes C7R remote human OAuth delegation under `PROGRAM_PHASE_MODEL_V29`: trusted MCP clients and revocable product-owned delegation grants are durable in Memory/File/PostgreSQL, every human `/mcp` request rechecks trusted-client state, active grant scope and current RBAC, and platform-wide delegation remains restricted to current platform administrators. Grant/client revocation takes effect immediately even for an otherwise cryptographically valid access token. C7W full Admin/User operation parity remains an explicit blocker; Physical installation/certification remains deferred until development closure.

Release 0.0.317 closes the runtime/UI release regression discovered during the V28 MCP/OAuth and Persian product-copy hardening. The Operator Console now has a real `localizeDynamicText` helper used by the human MCP connection journey, so loading the AI workspace no longer aborts before durable AI-run history renders. The owner-level UI smoke now awaits asynchronous AI navigation rather than relying on a fixed delay, making Console auxiliary verification deterministic under the additional delegated-access fetches. The MCP/OAuth phase authority remains `PROGRAM_PHASE_MODEL_V29`; no open C7R/C7W blocker is hidden or promoted, and Physical installation/certification remains deferred until development closure.

Release 0.0.316 advances human MCP access under `PROGRAM_PHASE_MODEL_V29` and closes the first two C7R implementation blockers without pretending human delegation is complete. `/mcp` now publishes OAuth Protected Resource Metadata, unauthenticated MCP requests receive a standards-oriented `WWW-Authenticate` discovery challenge, and MCP bearer validation uses a dedicated `platform-mcp` audience instead of accepting a generic API audience. The Operator Console adds a user-facing **AI account connections** journey that hides scope/tool/revision internals and deliberately remains non-connectable until revocable delegation grants, trusted-client admission and consent/revocation enforcement are implemented. Persian product copy was also reworked across Console and Installer and is now guarded by `PERSIAN_PRODUCT_COPY_QA_V1` plus `PERSIAN_UI_QA_V2`; localization coverage remains zero-gap. Physical installation/certification remains deferred until development closure and is not a development blocker.

Release 0.0.315 rebaselines remote MCP human access under `PROGRAM_PHASE_MODEL_V27` without pretending OAuth/write parity is already implemented. Existing C7 delegated-operation foundation remains source-implemented, while mandatory C7R (`Remote OAuth Human Delegation`) and C7W (`User/Admin Write Parity`) are explicit pre-C9 phases. `MCP_REMOTE_OAUTH_DELEGATION_ARCHITECTURE_V1` makes Keycloak the single self-hosted OIDC/OAuth authority, adds a revocable product-owned `MCPDelegationGrant` boundary, requires OAuth Protected Resource Metadata/401 discovery, short-lived audience-bound tokens, authorization-filtered tools, all MCP writes as durable product Jobs/Operations, separate approval tools, and a normal user journey that hides scope/tool/revision internals. See `docs/MCP_OAUTH_DELEGATED_ACCESS_ARCHITECTURE.md`. Physical installation/certification remains deferred until development closure and is not a coding blocker.

Release 0.0.314 closes G3 under `PROGRAM_PHASE_MODEL_V26`. Certificate Renewal for a Ready provider-managed worker and Remediation for a NotReady provider-managed worker now reuse the exact CAPI Machine replacement engine: inventory/node/window identity is pinned, management-cluster `provider-machine-lifecycle-v1` capability is enforced again at the durable Store boundary, exact Machine recovery evidence is persisted before deletion, and retry cannot resolve a second target. G3 is now source-implemented across Add, Drain, Remove, Replace, OS Patch, Certificate Renewal and Remediation. Unsupported control-plane/imported/provider-unbound combinations remain fail-closed. Physical installation/certification is still deferred until C9 development closure and is not a development blocker.

Release 0.0.313 adds `TARGET_NODE_PROVIDER_MACHINE_LIFECYCLE_V1` and exact CAPI Machine Remove/Replace execution. Destructive provider node mutations are pinned to target inventory digest, node UID, maintenance window and one authoritative CAPI Machine identity; recovery evidence is persisted before mutation and Machine deletion uses UID/resourceVersion preconditions. Remove uses CAPI delete-priority plus an exact one-worker topology decrease; Replace deletes only the pinned Machine and waits for another Ready Machine in the same MachineDeployment. G3 execution coverage is now 5/7; Certificate Renewal and Node Remediation remain the only G3 development blockers. Physical certification remains deferred until development closure and is not a development blocker.

Release 0.0.312 adds authoritative Target↔ProviderCluster binding and a real provider-backed ADD executor on top of the existing Cluster API topology lifecycle. ADD is executable only when the bound ProviderCluster is ACTIVE and admitted; it increases worker topology by exactly one replica, then stops at the existing independent provider approval boundary before management-agent APPLY/INSPECT. Drain and OS Patch remain executable, while Remove/Replace/Certificate/Remediation stay fail-closed. Physical certification remains deferred until development closure and is not a development blocker.

Release 0.0.310 establishes the G3 target-node lifecycle planning/admission foundation. `TARGET_NODE_LIFECYCLE_AUTHORITY_V1` binds plans to current inventory/node identity and exposes real executor readiness without promoting missing provider, OS-patch, certificate-renewal or remediation adapters. `PROGRAM_PHASE_MODEL_V22` also makes Exact-SHA physical installation/certification explicitly deferred until development closure, so Physical `NOT_EVALUATED` is not a pre-freeze development blocker.

## What this product is and why it exists

4SO Platform Factory is not intended to be only a Kubernetes installer, a cluster dashboard, or another wrapper around individual infrastructure tools. It is a **Platform Engineering / Private Cloud Factory**: a product control plane that turns raw servers or existing Kubernetes environments into standardized, repeatable, governable application platforms and then owns their lifecycle through one API and Operator Console.

The problem it addresses is organizational as much as technical. A production platform normally requires many independently operated systems—Kubernetes, Git, registry, GitOps, identity, PostgreSQL, monitoring, backup, policy, cluster lifecycle, disconnected delivery, upgrades, recovery and operational evidence. When these are assembled as unrelated tools and scripts, operational knowledge becomes fragmented across people, shell history, CI jobs and undocumented procedures. The result can work, but it is difficult to reproduce, audit, upgrade and recover consistently.

4SO Platform Factory turns that distributed operational knowledge into **productized operations**: explicit workflows, durable state, policy-aware actions, evidence, repeatable installation and recovery, and a self-service surface that does not require every user to understand each underlying implementation detail.

### Product value

The product is designed to reduce the cost, risk and time required to operate an internal application platform by providing four core outcomes:

1. **Lifecycle automation** — create, import, expand, upgrade, repair, recover and retire platforms through durable product workflows rather than ad-hoc commands.
2. **Operational safety** — preflight checks, explicit approvals, bounded mutations, evidence, negative controls and truthful failure states are part of the product contract.
3. **Standardization** — teams receive approved platform profiles, capabilities and release paths instead of building a different Kubernetes stack for every project.
4. **Self-service** — application/platform consumers request an outcome such as a production platform; the Factory resolves and operates the underlying components.

A typical desired user intent is therefore closer to:

```text
Create a production Kubernetes platform for Project X
```

than to:

```text
Install these fifteen operators and run these twenty shell commands
```

The Factory owns the implementation workflow behind that intent:

```text
Inventory
   -> Preflight
   -> Provision / Import
   -> Install / Register
   -> Capability Discovery
   -> Policy Admission
   -> Runtime Verification
   -> Certification / Ready
```

### High-level architecture

```text
Servers / Existing Clusters
          |
          v
+--------------------------------+
|       4SO Platform Factory     |
|                                |
|  Organizations / Projects      |
|  Catalog / Blueprints          |
|  Cluster Lifecycle             |
|  GitOps / Releases             |
|  Registry / Supply Chain       |
|  Policies / Evidence           |
|  Operations / Recovery         |
|  AI Operator                   |
+---------------+----------------+
                |
        +-------+---------+
        |       |         |
        v       v         v
      RKE2     OKD   Existing Kubernetes
```

The **Factory Management Plane remains self-contained on RKE2**. OKD is a first-class target platform, not a requirement to run the Factory itself. Existing Kubernetes and managed RKE2 targets are separate target identities behind the same product boundary.

### What the Factory is expected to manage

The long-term product boundary includes:

- creation and import of Kubernetes platforms;
- server inventory, host/runtime preflight and installation;
- organization/project/tenant and access boundaries;
- catalog and blueprint-driven platform profiles;
- release, registry and software-supply-chain authority;
- GitOps reconciliation and desired-state delivery;
- Day-2 operations such as add, drain, remove and replace node;
- upgrade, restart, repair and recovery workflows;
- backup/restore and disaster-recovery workflows;
- diagnostics, health translation and operational evidence;
- disconnected / air-gapped acquisition and delivery;
- multi-cluster/fleet lifecycle;
- AI-assisted diagnosis and safe action planning.

Installing a cluster is only the beginning. A major part of the product value is the **Day-2 lifecycle**:

```text
Add Node
Drain Node
Remove Node
Replace Node
Upgrade
Restart
Repair
Recover
Backup
Restore
Rotate Credentials
Renew Certificates
Diagnostics
```

These operations are expected to be durable and resumable where appropriate. A control-plane restart must not silently lose an operation or cause an unsafe duplicate mutation.

### Authority and responsibility boundaries

4SO intentionally separates product authority from reconciliation/runtime mechanisms:

```text
PostgreSQL  -> product authority / source of truth
Forgejo     -> desired-state Git
Argo CD     -> reconciliation
zot         -> canonical product registry
RKE2 / OKD  -> runtime target
```

PostgreSQL owns authoritative product state such as organizations, projects, clusters, policies, approvals, release/operation state and evidence. Git is not used as a substitute product database, and Argo CD availability does not determine whether the Factory remembers its own operations.

The product-owned registry is **zot** so that release acquisition, mirroring and disconnected operation can be governed as part of the Factory rather than delegated to an unspecified external registry.

### Capability-driven targets, not duplicate stacks

A target distribution may already own important capabilities. For example, OKD commonly provides its own networking, monitoring, operator lifecycle and security primitives. The Factory should discover those capabilities and avoid installing duplicate infrastructure merely for symmetry.

Conceptually:

```text
Discover target capabilities
          |
          v
Resolve required platform profile
          |
          +--> use distribution-native capability when suitable
          +--> provide only the missing/approved capability
```

This is why OKD is not treated as "RKE2 with extra manifests". Distribution identity and capability ownership are explicit product concepts.

### How this differs from Rancher and OpenShift/OKD

4SO Platform Factory is not intended to be a direct clone of Rancher or the OpenShift Console.

- **Rancher** is primarily a Kubernetes management platform. Rancher/Fleet can be an optional integration in environments that already use it, but the Factory's product authority, release lifecycle, evidence, catalog, durable operations and supply-chain model remain product-owned.
- **OpenShift/OKD** is a Kubernetes distribution/platform runtime. In 4SO, OKD is one target that the Factory can import, certify and eventually create/manage. The Factory decides *what platform outcome the organization wants and how its lifecycle is governed*; OKD owns the distribution-specific runtime mechanisms that belong to OKD.

### Catalog and blueprints

The intended self-service experience is outcome-oriented. Instead of asking a user to author every Kubernetes YAML object, a catalog/blueprint can describe an approved platform profile such as:

```text
Production Kubernetes Platform
  Distribution: RKE2
  Topology: 3-node HA
  Storage: replicated
  GitOps: enabled
  Registry: enabled
  Backup: enabled
  Monitoring: enabled
  Policy profile: production
```

or an OKD-oriented profile whose implementation is resolved against capabilities already owned by the distribution.

Blueprints are therefore product contracts, not static manifest dumps: the Factory resolves them against target identity, discovered capabilities, policy and release authority.

### AI Operator

The AI capability is intended to become an **AI Operator**, not just a chat box embedded in the console. It should consume bounded product evidence—cluster state, nodes, operations, recent releases, storage/networking health, GitOps state and logs—and translate that into impact, probable cause, supporting evidence and safe next actions.

A desired interaction is:

```text
User: Why is Cluster A degraded?

AI Operator:
Impact:
  Two workloads cannot schedule.

Probable cause:
  node-03 storage is unavailable.

Evidence:
  ...

Safe next actions:
  1. Inspect storage health.
  2. Drain node-03 if admission permits.
  3. Replace or recover the node through a durable workflow.
```

AI does not become an alternate mutation authority. Security-sensitive or destructive actions still pass through the same RBAC, policy, approval, impact-preview and durable-operation boundaries as non-AI actions.

### Example end-to-end outcome

A team with three fresh servers should ultimately be able to request a production platform through the Console/API rather than manually assemble all internal components:

```text
Infrastructure -> Add Servers
Platform       -> Create Platform
Profile        -> Production HA
Distribution   -> RKE2
Action         -> Create
```

The Factory then owns inventory, preflight, installation, storage, platform services, identity, GitOps, registry, verification and evidence. A successful result should be expressed in product language, for example:

```text
Platform: Production-01
Status: Ready

Nodes:       3/3 Healthy
Storage:     Healthy
GitOps:      Healthy
Registry:    Healthy
Database:    Healthy
Backup:      Ready
Identity:    Ready
```

Release certification is still governed by the independent four-layer gate described later in this README. A healthy UI or successful source test never permits the Factory to claim physical-runtime certification without exact-artifact physical evidence.

### The shortest description

**4SO Platform Factory converts complex, fragmented Platform Engineering work into a repeatable product for building, operating, upgrading and recovering internal Kubernetes platforms through one governed API and Operator Console.**

The core commercial value is not Kubernetes itself. It is **lifecycle automation + operational safety + standardization + self-service**.

## Operator Console design foundation

The Operator Console uses the product-owned **4SO Operator Horizon V3** design system. **Spectro Cloud Palette** is the primary product information-architecture/workflow benchmark, **Rafay Platform** is the secondary benchmark for dense multi-cluster operations and capacity visibility, and **SUSE Rancher Prime** is a targeted resource-explorer ergonomics reference. No competitor source, asset, logo or runtime framework is copied. The embedded 4SO HTML/CSS/JavaScript implementation, navigation taxonomy, RBAC, workflows, impact preview, evidence and API authority remain product-owned.

The user-facing primary navigation is now **Overview → Platforms → Blueprints → Fleet → Operations → Assurance → Admin**. Internal route IDs remain compatibility details. The product term **Workspace** is reserved for the cross-cluster team/application abstraction; Organizations & Projects live under **Admin**, while runtime evidence, supply-chain releases and physical certification live under **Assurance**. The Overview also provides a navigation-only workflow switchboard: **Configure → Build or import → Operate fleet → Prove & recover**. Current shell features continue to include `Ctrl/Cmd+K` navigation search, explicit persisted light/dark mode, RTL/LTR support and Release Gate browser checks across 320/390/768/1024/1440 widths. See `docs/OPERATOR_CONSOLE_DESIGN_FOUNDATION.md`.

## Competitive product direction

The canonical `PROGRAM_PHASE_MODEL_V22` positions 4SO as an **Enterprise / Sovereign Platform Factory**, not a Rancher/OpenShift clone. The product should turn raw or existing infrastructure into certified, repeatable application platforms while keeping deterministic supply chain, durable lifecycle operations, evidence and bounded AI assistance as first-class authority.

The roadmap deliberately adopts the capabilities that strengthen that identity: **Certified Platform Templates + variable/policy composition, cross-cluster Workspaces, workload visibility, generalized Day-2 maintenance campaigns, SAML, evidence-native compliance, Managed Bare Metal, VMware, disconnected edge autonomy, Terraform automation, external-registry admission, private-cloud showback and virtual clusters**. VM/KubeVirt and accelerator/GPU infrastructure are later optional planes with independent product-decision gates.

Parity is intentionally deferred where it would dilute the product: hosted multi-tenant SaaS is not a current goal; AWS/Azure/GCP breadth follows private/sovereign provider depth; Crossplane follows Terraform only if a real consumer justifies another reconciliation surface; VMware-to-KubeVirt migration waits for a certified VM plane; model serving waits for accelerator authority; and MCP remains read-only by default rather than becoming an unrestricted agent mutation channel.

The competitive signature is the combination of **Certified Platform Templates + Impact Preview + Durable Operation + Evidence + Exact-SHA Physical Certification**. A reusable platform definition is therefore expected to become more than a configuration preset: it will bind immutable blueprint content, variables, lifecycle/security policies, supply-chain locks, target classes and runtime-certification requirements.

## Start here: clone, build, test, install

Canonical repository:

```bash
git clone https://github.com/rezabehroozi/4so-platform-factory.git
cd 4so-platform-factory
```

The repository is intentionally usable in three different modes. Keep them separate because they prove different things:

1. **Developer/local correctness** — build, unit tests, race tests, headless UI and local executable smoke tests.
2. **Deterministic Lab** — bind an exact release ZIP and immutable appliance bundle to real servers, install the Factory, collect evidence and invoke AI only after a deterministic failure.
3. **Physical release certification** — run the required real PostgreSQL/target/HA/DR/security/load/upgrade scenarios against the exact artifact SHA. Local or AI success never substitutes for this layer.

### Developer workstation prerequisites

The Go module targets **Go 1.23**. On a Debian/Ubuntu development workstation, install the common native/test prerequisites first (install Go 1.23+ from the official Go distribution if your OS repository is older):

```bash
sudo apt-get update
sudo apt-get install -y \
  build-essential gcc make git pkg-config libpq-dev \
  python3 python3-venv python3-pip \
  jq curl unzip ca-certificates openssh-client

go version
python3 --version
```

Use an isolated Python environment for browser/test tooling:

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements-test.txt
python3 -m playwright install chromium
```

For a disposable CI/lab workstation where Playwright may install OS packages too:

```bash
python3 -m playwright install --with-deps chromium
```

Do not install product runtime dependencies such as PostgreSQL server, Forgejo, zot, Keycloak or RKE2 manually on target management hosts merely to satisfy a test. The product installer owns those runtime components from the immutable appliance bundle.

### First local validation

Run the fast structural/self-test layer first:

```bash
python3 scripts/validate_repository.py .
python3 scripts/lab_runner.py self-test
make autopilot-self-test
```

Then run the deterministic repository gates:

```bash
make test
make vet
make race
make build
make smoke
make smoke-ui
```

For a complete release build from the working tree:

```bash
make release
make verify-release
```

`make release` is intentionally strict. A timeout or missing physical/external input is not converted into PASS. Release artifacts are written below the ignored `release/` directory and must be verified before use in the Lab.

### Local API and Operator Console

For explicit non-production local development, use the file-backed development authority:

```bash
mkdir -p .state
PLATFORM_FACTORY_DEVELOPMENT_MODE=true \
PLATFORM_FACTORY_STATE_FILE=.state/control-plane.json \
./bin/platform-api
```

Then open the address printed by `platform-api`. This development state file is not a production database and must not be used as evidence for PostgreSQL/HA certification.

For a PostgreSQL-backed runtime, use `PLATFORM_FACTORY_POSTGRES_DSN` instead. The API refuses to silently fall back from a configured production database to an in-memory/file authority.

## Installing the Factory on fresh servers

There are two supported installation boundaries in the repository:

- **Host/remote installer commands** for bootstrap and field workflows.
- **Deterministic Lab Runner** for reproducible release testing on supplied servers.

Production/lab installation always requires the exact `4so-platform-factory-<version>-<release>.zip` release artifact plus one immutable appliance-bundle authority. The Lab runner accepts either an explicitly supplied, already sealed `bundleDirectory`, or it uses `LAB_APPLIANCE_BUNDLE_ACQUISITION_LOCK_V8` from `lab/appliance-bundle-acquisition-lock.json` inside that exact release. `LAB_APPLIANCE_BUNDLE_ACQUISITION_EXACT_RELEASE_BINDING_V1` requires physical Lab plan/run paths to read those lock bytes directly from one stable no-follow Exact Release ZIP inode whose full SHA-256 matches the sealed release authority; a later mutation of the extracted filesystem copy cannot alter automatic source acquisition.

Before plan/preflight/run authority is derived, `LAB_EXACT_RELEASE_SNAPSHOT_AUTHORITY_V2` copies the operator-supplied release ZIP into private run state, hashes that copied byte stream, atomically publishes it as a read-only snapshot and uses only that snapshot for subsequent verification, extraction, bundle binding, installation and evidence. The source inode, size, mtime and ctime must remain unchanged across the streamed snapshot read, so same-inode/same-size concurrent rewrites cannot create a mixed byte stream and still become Exact-SHA authority. Replacing the original release path after the snapshot is created cannot change the artifact attributed to the run. Ambiguous release ZIPs with duplicate paths, directory/encrypted/non-regular entries, non-canonical paths or inconsistent identity files fail closed before extraction. `LAB_EXACT_RELEASE_EXECUTION_AUTHORITY_V1` closes the later reopen boundary: release identity (VERSION/RELEASE-NAME plus SHA-256) is derived from one no-follow opened inode, and every Lab extraction hashes that same opened inode, requires the digest to equal the previously sealed exact-release SHA, extracts through a duplicated descriptor for that inode, then rechecks inode/size/mtime/ctime and digest after extraction. Path replacement or same-inode mutation between identity/preflight and execution therefore fails before packaged binaries are used.

The Lab SSH invocation also terminates local OpenSSH option parsing **before** the destination (`ssh ... -- root@host sh -ceu ...`). The option terminator is never sent as the first remote-command token; this keeps M01/M02 remote scripts executable under OpenSSH command semantics while preserving strict host-key checking against the snapshotted trust file.

For mutating `run`, `LAB_RUN_STATE_BINDING_AUTHORITY_V2` additionally fences the whole `--state-dir` with one exclusive process lock and makes that directory a single-run authority. Before SSH preflight or mutation, `LAB_SSH_CREDENTIAL_SNAPSHOT_AUTHORITY_V2` snapshots the exact private-key and `known_hosts` byte streams into read-only private run state with no-follow source opens and rejects same-inode source drift across inode, size, mtime and ctime; retry/re-entry must present the same bytes or use a new state directory. The successful preflight binding therefore covers the exact release digest, canonical physical server inventory, execution-relevant Lab spec, SSH credential/host-trust digest authority and verified immutable bundle/lock digests. Re-entry with the same authority can reuse checkpoints, but a different release/topology/spec/SSH trust/bundle must use a new state directory. The private release and SSH snapshots cannot be silently replaced on reuse. Lab state/evidence writes use unique atomic temporary files, so a pre-created predictable `.tmp` symlink cannot redirect root-owned certification writes. AI settings are advisory and are deliberately outside this physical run-state digest.

Automatic acquisition never chooses `latest` and never accepts caller-supplied URLs. `LAB_APPLIANCE_BUNDLE_ACQUISITION_LOCK_V8` partitions the five external/source production authorities into mutually exclusive `resolvedAuthorities`, `partialAuthorities`, and `missingAuthorities`, while `derivedAuthorities` records image truth that must be computed from a source artifact rather than independently authored, so a required source cannot silently disappear from the lock. Every locked or pending artifact has a unique canonical `stagingPath`; every fully resolved artifact additionally carries public HTTPS URL(s), exact byte size and SHA-256. Partial authorities preserve already locked artifacts plus immutable pending-source provenance but can never qualify a lock as `ready`. A `ready` product-shipped lock may additionally name only public HTTPS input-pack URLs with an exact size and SHA-256, but the pack digest is not sufficient authority: after safe extraction the runner re-hashes every resolved artifact at its locked staging path, requires each RKE2/workload/Argo CD/CloudNativePG/storage build-spec source path to equal the owner authority paths exactly, parses the management workload OCI Image Layout itself, verifies its content-addressed blob graph and embedded `MANAGEMENT_WORKLOAD_OCI_ARCHIVE_INVENTORY_V2`, requires every top-level image descriptor to bind the exact inventory reference through both `io.containerd.image.name` and `org.opencontainers.image.ref.name` under `MANAGEMENT_WORKLOAD_OCI_IMPORT_ADDRESSABILITY_V2`, admits only exact OCI Image Index/Image Manifest or Docker v2 Manifest List/Image Manifest media types for parsed descriptors, requires descriptor/document media-type agreement, and keeps the independent Go and Lab-Python OCI schema validators semantically aligned, derives the core-image authority from those image manifest digests, and rejects unowned automatic inputs such as `ocmManifest` before `platformctl appliance-bundle build` runs. It then replaces only the canonical zero `sourceReleaseDigest` placeholder with the exact release ZIP digest, builds with the `platformctl` binary from that same release, and verifies the resulting `bundle.lock.json` before any server installation. An `incomplete` lock performs **no input-pack network access** and returns `BLOCKED` with its explicit unresolved authorities. In `0.0.272`, Longhorn `v1.12.1`, CloudNativePG `v1.30.0`, RKE2 `v1.34.10+rke2r1`, and Argo CD `v3.5.0` are fully resolved exact-byte authorities. RKE2 `install.sh` is bound to tag commit `d419f09226d50a4777d348e5c53ea1bce3849b77`, Git blob `88c5f55bdfde94f2277465ece2b749c52d86c69b`, SHA-256 `2d24db2184dd6b1a5e281fa45cc9a8234c889394721746f89b5fe953fdaaf40a`, and 25288 bytes; Argo CD `manifests/install.yaml` is bound to commit `e95e1be88a2da6c06bff5c2fe1791e4d233ed810`, Git blob `e0ff6c401aa18c2c67ba9dcb5f68f2f15853281f`, SHA-256 `a32bf36a437071a1f563ebf9e81c8a39fba9057c17db7d5d041afb7b6e3f4afe`, and 1917766 bytes. The RKE2 release tar/image/checksum locks were additionally cross-checked against GitHub Release asset digest metadata. The product-owned management workload OCI archive remains the only completely missing source authority. `MANAGEMENT_WORKLOAD_IMAGE_BUILD_PLAN_V5` now decomposes that gap into eight core image roles, three exact base-image compatibility roles and three image sets derived from the already locked Argo CD/CloudNativePG/Longhorn manifests. External management versions are no longer selected implicitly: `MANAGEMENT_WORKLOAD_EXTERNAL_VERSION_SELECTION_V1` pins PostgreSQL 17.11 (`17.11-bookworm`), Forgejo 15.0.7 LTS, zot 2.1.20 and Keycloak 26.7.3, while `MANAGEMENT_WORKLOAD_EXTERNAL_IMAGE_ACQUISITION_V2` resolves only those tags through explicit Registry V2 endpoints and creates verified linux/amd64 OCI layouts bound to the exact release/plan digests. `platformctl workload-oci acquire-external` does not accept `latest`; it verifies the tag-root/child manifest, config and every layer digest/size, rejects ambiguous platform indexes and duplicate JSON keys, separates source image identity from transport endpoint, and supports only bounded HTTPS/public-address CDN redirects with cross-origin Authorization stripped. Acquisition V2 also preserves the exact tag-root document as a content-addressed OCI-layout blob and records its byte size. After transfer, `platformctl workload-oci verify-external` performs no registry access: it binds to the exact FULL release and V5 plan, re-hashes that tag-root evidence, re-selects linux/amd64, then verifies the selected manifest/config/layers, byte accounting and owned layout file set before the layout may enter offline assembly. `MANAGEMENT_WORKLOAD_MANIFEST_IMAGE_RESOLUTION_V1` closes the remaining manifest/image identity gap: exact-byte upstream YAML is inspected for actual runtime image references, every mutable tag must resolve to an exact `registry/repository@sha256` already present in the same management workload OCI archive, and `platformctl workload-oci resolve-manifest` emits a digest-pinned runtime manifest plus a source/resolved byte lock. The Lab runner re-hashes both generated files immediately before bundle build, rejects post-resolution substitution, and rewrites the bundle build spec to consume only those generated runtime manifests while preserving the original exact source YAML solely as provenance. Product API/agent/probe images are exact-release-binary builds using release-only recipes with numeric UID/GID and exact-release labels. `MANAGEMENT_WORKLOAD_PRODUCT_IMAGE_CERTIFICATION_V1` verifies the final OCI-layer payload digest, image config and ELF linkage against that release; agent certification additionally requires CA trust. The API base must satisfy the full dynamic dependency closure rather than a libpq-only check. Maintenance no longer runs mutable `apk add` during image construction: its deterministic wrapper consumes a pending exact maintenance-toolchain base whose complete PostgreSQL/S3/archive/diagnostic command set and root-override behavior must be compatibility-certified. No mutable image tag, network package install or placeholder digest is promoted to authority. `platformctl workload-oci assemble` implements `MANAGEMENT_WORKLOAD_OCI_ASSEMBLY_AUTHORITY_V1`: it accepts only exact `registry/repository@sha256` roots from local OCI layouts, verifies the complete reachable blob graph, rejects symlink traversal/shared-root ambiguity, and writes a canonical streaming OCI tar with deterministic ordering/metadata plus the existing inventory/import-addressability authorities. This narrows the remaining blocker to resolving and compatibility-certifying the pending image/base digests and executing their real image builds/acquisitions; it does not close the production source lock by itself. `digest-pinned-core-workload-images` is no longer a parallel source of truth: V8 derives it from the verified OCI archive inventory once that archive is produced. V8 also admits producer-realistic OCI Image Index metadata (`mediaType`, annotations and platform descriptors) while keeping workload artifact/referrer semantics fail-closed, and the independent Lab TAR parser streams with the same 100,000-entry ceiling used by the Go OCI authority instead of materializing an unbounded archive member list. V8 additionally treats acquisition as a public-network trust boundary: locked initial URLs are query-free public HTTPS, runtime DNS resolution and every redirect/final response destination must resolve only to globally routable addresses, the HTTPS socket is pinned to that admitted address set so connect cannot perform a second DNS lookup, and loopback/private/link-local destinations fail closed before download. Implicit environment proxies are disabled on this automatic path because an undeclared proxy hop is not part of the source authority. Canonical staging paths are never repaired by normalization; surrounding whitespace, backslashes, NUL, absolute paths and dot/dot-dot segments are rejected. `BUNDLE_SOURCE_ARTIFACT_BINDING_AUTHORITY_V1` now carries the verified acquisition-lock path, exact byte size and SHA-256 for every builder input into `spec.sourceArtifacts`; the canonical Go builder opens each path component under the non-symlink staging root with no-follow semantics, copies and hashes the single opened file descriptor, and rejects any size/digest mismatch. This closes the previous lock-check/build-reopen TOCTOU boundary. The compatibility flag builder likewise rejects symlink sources, rejects flattened basename collisions and derives manifest/OCI claims only from the bytes already copied into the bundle rather than reopening mutable originals.

### Direct host workflow

Inspect the shipped example first:

```bash
cat examples/installer-host/deployment.example.json
./bin/linux-amd64/platformctl installer-host preflight \
  --spec examples/installer-host/deployment.example.json
./bin/linux-amd64/platformctl installer-host plan \
  --spec examples/installer-host/deployment.example.json
```

A destructive host apply requires the explicit confirmation token:

```bash
sudo ./bin/linux-amd64/platformctl installer-host apply \
  --spec examples/installer-host/deployment.example.json \
  --confirmation DEPLOY
```

Then verify the durable installer state rather than assuming that a successful process exit means the platform is healthy:

```bash
sudo ./bin/linux-amd64/platformctl installer-host status
sudo ./bin/linux-amd64/platformctl installer-host verify
```

Rollback and recovery are separate explicit actions:

```bash
sudo ./bin/linux-amd64/platformctl installer-host rollback --confirmation ROLLBACK
sudo ./bin/linux-amd64/platformctl installer-host recover --confirmation RECOVER
```

### Remote bootstrap workflow

The canonical remote example is:

```bash
cp examples/installer-remote/bootstrap.example.json /tmp/4so-remote.json
./bin/linux-amd64/platformctl installer-remote preflight --spec /tmp/4so-remote.json
./bin/linux-amd64/platformctl installer-remote plan --spec /tmp/4so-remote.json
./bin/linux-amd64/platformctl installer-remote apply --spec /tmp/4so-remote.json --confirmation DEPLOY
./bin/linux-amd64/platformctl installer-remote verify --spec /tmp/4so-remote.json
```

The coordinated single-node-to-three-node management handoff is exposed through `platformctl zero-to-ha ...`. Use `platformctl --help` for the required request/state/token/identity inputs; do not bypass its confirmation and known-host checks with ad-hoc SSH.

## Physical Lab: give the runner servers and let it install/test

The canonical machine-readable Lab contract is `LAB_CERTIFICATION_MATRIX_V2`; the schema is `schemas/lab-execution.schema.json`, the canonical example is `examples/lab/lab-execution.example.json`, and the runner is `scripts/lab_runner.py`.

Always inspect the current guide from the exact checkout you will use:

```bash
python3 scripts/lab_runner.py guide | jq .
```

The runner sequence is intentionally simple:

```text
guide -> self-test -> plan -> preflight -> run
```

The deterministic scripts own execution and PASS/FAIL. AI is invoked only after a deterministic stage fails, receives a bounded centrally-redacted failure packet, and returns advisory diagnosis only.

### Lab server tiers

| Tier | Physical servers | Intended coverage |
|---|---:|---|
| `current-import-minimum` | 4 | 1 Factory management node + Compact-3 OKD target; M00/M01 foundation and later OKD import certification |
| `production-ha` | 6 | 3 Factory management nodes + Compact-3 OKD; management HA/quorum/restart plus same-runtime PostgreSQL M03 certification |
| `day2-replacement` | 7 | production HA topology + one spare target for add/remove/replace/failure recovery |
| `full-multicluster` | 10 | 3 management + two Compact-3 targets + spare; disconnected/upgrade/chaos/soak/multi-cluster |

If a real OKD cluster already exists, it supplies the target roles; the minimum tier therefore needs only the additional Factory management server. In the Phase-D physical-certification runner, SSH preflight/install is performed only for management roles. Target roles are retained in the inventory so later Phase D+ target API/Agent certification is bound to an explicit physical topology rather than inferred.

Each physical role must map to a **distinct host**. The runner canonicalizes that topology into `serverInventoryDigest` and binds the digest into the plan, preflight and run result so evidence cannot be moved silently to a different server inventory.

Current management-host lab floor: **4 vCPU, 16 GiB RAM, 100 GiB free disk**. Target requirements are printed by `lab_runner.py guide`; never rely on this README if the machine-readable guide in a newer release differs.

### SSH preparation

The Lab intentionally requires root SSH for Factory management hosts because the installer owns system services, storage paths and RKE2 bootstrap. It requires strict host-key verification.

```bash
install -m 600 ~/.ssh/id_ed25519 /tmp/4so-lab-id
ssh-keyscan -H 10.0.0.11 > /tmp/4so-known-hosts
ssh -i /tmp/4so-lab-id \
  -o UserKnownHostsFile=/tmp/4so-known-hosts \
  -o StrictHostKeyChecking=yes root@10.0.0.11 true
```

Do not use `StrictHostKeyChecking=no` in certification input.

### Example `LabExecution`

Start from `examples/lab/lab-execution.example.json` (documentation-only TEST-NET addresses), copy it to `/tmp/4so-lab.json`, then change paths/hosts to the real environment:

```json
{
  "apiVersion": "platform.4so.io/v1alpha1",
  "kind": "LabExecution",
  "metadata": {"name": "factory-import-lab"},
  "spec": {
    "releaseArtifact": "/srv/4so/release/4so-platform-factory-release.zip",
    "bundleDirectory": "/srv/4so/bundle",
    "serverTier": "current-import-minimum",
    "ssh": {
      "user": "root",
      "identityFile": "/tmp/4so-lab-id",
      "knownHostsFile": "/tmp/4so-known-hosts"
    },
    "servers": [
      {"role": "management-primary", "host": "10.0.0.11"},
      {"role": "okd-control-1", "host": "10.0.1.11"},
      {"role": "okd-control-2", "host": "10.0.1.12"},
      {"role": "okd-control-3", "host": "10.0.1.13"}
    ],
    "management": {
      "publicEndpoint": "https://factory.lab.example",
      "adminEmail": "admin@factory.lab.example",
      "dnsZone": "lab.example"
    },
    "ai": {
      "provider": "none",
      "maxOutputTokens": 800,
      "maxTurns": 2,
      "maxBudgetUSD": 1
    }
  }
}
```

`bundleDirectory` is optional at the Lab contract level. Remove it only when the exact release ships a `ready` `lab/appliance-bundle-acquisition-lock.json`; with the current intentionally incomplete production lock, omission returns `LAB_CANONICAL_BUNDLE_SOURCE_LOCKS_PENDING` before any network request.

The server-driven installer contract validates management inputs before any remote mutation. Every tier requires `management.adminEmail` for the managed identity bootstrap and a valid `management.dnsZone` for appliance DNS. Three-management-node tiers additionally require an explicit HTTPS `management.publicEndpoint` plus external S3-compatible object storage (`url`, `bucket`, and an `external-secret://platform-system/...` credential reference). Phase D always submits the exact verified appliance bundle to Installer in `disconnected` mode; it cannot silently fall back to mutable connected upstream bytes. Installer access credentials are exported to a unique private pending file, verified with no-follow inode/mode/size checks, sealed read-only under `LAB_INSTALLER_ACCESS_TOKEN_FILE_AUTHORITY_V1`, and atomically promoted to the canonical state token so a same-binding resume can refresh access without weakening the state-directory authority. Field Campaign state and Lab runtime JSON authorities are likewise bounded, regular, non-symlink inputs opened no-follow and checked for stable file identity before JSON decode.

Validate the plan without mutation:

```bash
python3 scripts/lab_runner.py plan --spec /tmp/4so-lab.json | jq .
python3 scripts/lab_runner.py preflight --spec /tmp/4so-lab.json | tee /tmp/4so-preflight.json
```

Execute only after reviewing the exact artifact SHA, server inventory and destructive matrix rows:

```bash
mkdir -p /srv/4so/lab-state
python3 scripts/lab_runner.py run \
  --spec /tmp/4so-lab.json \
  --state-dir /srv/4so/lab-state \
  --confirmation RUN_LAB
```

The state directory is evidence/checkpoint data and an enforced run authority. Use one directory per exact release/topology/spec/bundle binding. Re-entering the same binding is allowed; attempting to reuse it for a different binding fails closed. Never copy a PASS state to another release artifact.

### Certification matrix M00-M13

The guide and Operator Console are the canonical source for current automation status. The large matrix is:

| ID | Scope | Current ownership |
|---|---|---|
| M00 | exact SHA, archive integrity, provenance, binary version binding | Phase D |
| M01 | fresh single-node Factory management installation | Phase D |
| M02 | fresh three-node Factory management HA | Phase D |
| M03 | PostgreSQL exact-runtime migration/CRUD/restart/backup/restore | Phase D |
| M04 | OKD existing-import identity, capability admission and reconnect fencing | Phase D |
| M05 | revocation fence and same-UID re-enrollment | Phase D |
| M06 | OKD capability ownership and health translation | Phase E |
| M07 | imported Day-2 lifecycle | Phase F |
| M08 | managed connected Compact-3 | Phase F |
| M09 | disconnected acquisition/install | Phase G |
| M10 | upgrade and recovery | Phase G |
| M11 | chaos/failure controls | Phase H |
| M12 | load and 24-hour soak | Phase H |
| M13 | two-cluster/multi-cluster certification | Phase H |

In the prebuilt Phase-D certification automation, **M00-M03 are implemented and M04-M13 remain phase-gated**. Physical execution is intentionally deferred until C9 Feature Freeze closes. M01 requires validated managed-identity/DNS inputs, an exact verified disconnected bundle, a resumable sealed Installer access token, a real single-node boot-ID change, installer-service recovery, post-reboot installer verification and exact-SHA evidence recollection. M02 adds explicit HA endpoint/external-S3 inputs and deterministically interrupts the installer on a replay-safe post-quorum step, proves the durable run becomes `INTERRUPTED`, explicitly resumes the same run/digests, verifies full HA, restarts a real `rke2-server` peer, re-verifies HA, reboots another management peer, proves degraded two-node quorum, requires a new boot ID, and waits for full three-node recovery. M03 runs only on `production-ha` after that M02 recovery and binds itself to the exact CloudNativePG runtime created by the same run: it discovers the current primary, RW service and operator-reported server CA, creates a unique ephemeral certifier role/database without writing its password to run state, uses a strict SSH tunnel plus TLS `verify-full`, runs migration/CRUD/concurrency/restart/backup/restore certification, and under `AI_RUN_POSTGRES_DURABILITY_RUNTIME_AUTHORITY_V1` additionally proves the AI pre-egress idempotency claim has one contention winner, a forced result-commit failure leaves neither `ai_execution_claims` nor `ai_runs` split state, a successful `DISPATCHED → ai_run + audit/outbox → COMPLETED` transaction is atomic, and that exact claim/run pair survives both a real PostgreSQL postmaster restart and backup/restore. Under `LAB_M03_EXACT_RELEASE_EVIDENCE_AUTHORITY_V1`, runtime-mode M03 evidence schema v2 also seals the exact release ZIP SHA-256 inside its own evidence digest; Lab verifies that release binding from one stable no-follow opened evidence inode, computes a SHA-256 over those same verified evidence bytes, and records that `m03EvidenceDigest` plus authority in `result.json`. A report from another same-version build or a post-verification evidence-file replacement therefore cannot masquerade as this run's M03 authority. M03 then re-verifies three-node PostgreSQL/API recovery and deletes all databases owned by that certifier plus the role. The production-HA preflight therefore also requires local `psql`, `pg_dump`, `pg_restore`, `createdb` and `dropdb`; absence is `BLOCKED`, never skipped. None of these row-level results imply the independent four-layer Physical PASS. Presence in this table never means later rows are already executable.

## Testing with Codex, Claude Code, Antigravity and model APIs

The cost/token rule is simple: **do not ask an AI agent to rediscover the test suite**. The deterministic scripts execute first. Only a normalized failure packet is sent to an AI worker.

### Codex: bounded repair worker

Codex is the preferred repository repair worker when automatic source repair is wanted. It is not the release authority.

```bash
make autopilot-preflight
make autopilot-self-test
make autopilot-test
```

To allow bounded repair after confirmed deterministic failures:

```bash
make autopilot
```

The underlying runner is:

```bash
python3 scripts/codex_autopilot.py --repair --max-repairs 3
```

Use `PLATFORM_FACTORY_CODEX_COMMAND` only when a managed wrapper is required. The default command is non-interactive `codex exec` with a workspace-write sandbox. Interrupted runs checkpoint under ignored `.state/` and resume only when the workspace/test graph still matches.

### Claude Code: failure-only Lab diagnosis

Set the Lab AI provider to `claude-code`. The runner uses a non-persistent/bare invocation, JSON schema, bounded turns and an explicit USD budget. Example Lab fragment:

```json
"ai": {
  "provider": "claude-code",
  "maxOutputTokens": 800,
  "maxTurns": 2,
  "maxBudgetUSD": 1
}
```

The runner does not give Claude shell authority over the target. It supplies only the redacted failure prompt and validates the structured result.

### Codex CLI as a Lab diagnosis provider

```json
"ai": {
  "provider": "codex-cli",
  "maxOutputTokens": 800
}
```

For Lab diagnosis, Codex is invoked in read-only/ephemeral mode. This is separate from `codex_autopilot.py`, which may be explicitly allowed to repair the repository workspace.

### Antigravity command adapter

Antigravity is intentionally an optional command adapter rather than a certification dependency. Configure a command that reads the diagnosis prompt on stdin and emits the exact JSON diagnosis contract on stdout:

```json
"ai": {
  "provider": "antigravity-command",
  "command": "/opt/4so/bin/antigravity-diagnose"
}
```

If the command is absent, times out or returns invalid JSON, the AI result is `BLOCKED`; deterministic test truth is unchanged.

### OpenAI Responses API

The Unified AI Runtime is the canonical cloud-provider path. Keep the API key outside Git and inject it only into the process environment. `AI_PROVIDER_TRANSPORT_AUTHORITY_V2` requires HTTPS for every non-loopback provider endpoint; plain HTTP is admitted only for explicit loopback/local test endpoints. Redirects may change only the request path/query on the same origin, so an API-key-bearing request cannot be downgraded to HTTP or redirected to another host. The provider transport does not inherit implicit `HTTP_PROXY`/`HTTPS_PROXY` authority, rejects link-local/unspecified/multicast destinations, validates the complete DNS result set before connect, and dials only those validated IP bytes so DNS rebinding cannot insert a second resolution between admission and the socket. RFC1918/loopback HTTPS remains supported for explicitly configured private/self-hosted providers. Provider envelopes and structured JSON output with duplicate object keys are rejected as ambiguous before durable AI-run admission:

```bash
export PLATFORM_FACTORY_AI_PROVIDER=openai-responses
export PLATFORM_FACTORY_AI_MODEL='<approved-model>'
export PLATFORM_FACTORY_AI_API_KEY='...'
export PLATFORM_FACTORY_AI_MAX_OUTPUT_TOKENS=800
```

Lab fragment:

```json
"ai": {
  "provider": "openai-responses",
  "model": "<approved-model>",
  "apiKeyEnv": "PLATFORM_FACTORY_AI_API_KEY",
  "maxOutputTokens": 800
}
```

Inspect effective non-secret policy:

```bash
./bin/linux-amd64/platformctl ai policy
```

Test redaction locally before enabling egress:

```bash
./bin/linux-amd64/platformctl ai redact -f /path/to/context.json
```

Certify an approved live external provider against the exact release before closing the Phase D provider blocker:

```bash
./bin/linux-amd64/platformctl ai certify-provider \
  --release-artifact /path/to/4so-platform-factory-0.0.251-*.zip \
  --out /secure/evidence/ai-provider-certification.json \
  --confirmation CERTIFY
```

`PLATFORMCTL_CONTROL_PLANE_TRANSPORT_AUTHORITY_V1` governs credential-bearing `platformctl` traffic to the Platform API and Bootstrap Installer. The client never consumes implicit `HTTP_PROXY`/`HTTPS_PROXY` settings, never follows redirects, resolves each hostname inside the socket dial boundary, rejects link-local/unspecified/multicast destinations, and connects only to an address from that exact validated resolution set while preserving private/loopback HTTPS support. When a bearer token is supplied by `--token-file`, the file must be a private regular non-symlink file; it is opened with no-follow semantics, inode-checked before reading, bounded, and rejected if group/other permissions are present. Environment-provided tokens remain supported for managed secret injection.

`LAB_CONTROL_PLANE_TRANSPORT_AUTHORITY_V1` applies the same explicit-network trust model inside the independent Python physical Lab runner itself. M01/M02 bearer-authenticated Installer health and JSON calls never inherit environment proxies, never follow redirects, resolve once inside the request connection boundary, reject link-local/unspecified/multicast destinations, pin the socket to that validated address set, and permit plaintext HTTP only for loopback SSH-tunnel endpoints. This prevents the certification harness from using a weaker network authority than the packaged `platformctl` it is certifying.

`PLATFORMCTL_EXACT_RELEASE_SELF_BINDING_V1` requires exact-release-producing `platformctl` commands to hash the inode actually executing through `/proc/self/exe` and match it to `bin/linux-amd64/platformctl` in the verified release manifest. It applies to AI provider certification, appliance-bundle build, field-campaign prepare/collect and zero-to-HA orchestration. `FIELD_CAMPAIGN_PLATFORMCTL_CONTINUITY_AUTHORITY_V1` carries that trust boundary across the long-lived Field Campaign: schema v5 seals the packaged `platformctl` digest into campaign state at prepare time, and start/watch/resume/diagnose require the currently executing `/proc/self/exe` digest to match before any installer connection, physical mutation, resume request or campaign-state observation is accepted. Older schema v1-v4 campaign files remain readable for recovery but do not gain this new assurance retroactively. `AI_EXTERNAL_PROVIDER_RUNTIME_CERTIFICATION_V2` performs two bounded live advisory calls through the same `UNIFIED_AI_RUNTIME_V1` and `AI_PROVIDER_TRANSPORT_AUTHORITY_V2` used by the product. It requires an HTTPS provider endpoint, proves strict diagnosis and Marketplace structured output, synthetic-secret redaction, allowlist-only Marketplace selection and sane non-negative usage counters, and requires the running `platformctl` inode SHA-256 to equal the packaged `bin/linux-amd64/platformctl` digest, then seals both that certifier digest and the exact release ZIP SHA-256 into evidence. The evidence is advisory-provider certification only: `canDecidePass=false` and `canDecidePhysicalPass=false`. Source/unit/mock success does not close `AI_UNIFIED_RUNTIME_EXTERNAL_PROVIDER_CERTIFICATION_PENDING`; the command must PASS against the approved real provider using the exact release.

`RUNTIME_CLOSURE_EXACT_RELEASE_BINDING_AUTHORITY_V1` closes downstream runtime-closure attribution. The appliance bundle injects its exact `sourceReleaseDigest` into Platform API as `PLATFORM_FACTORY_SOURCE_RELEASE_DIGEST`; Platform API hashes the inode actually executing as `/proc/self/exe`; every newly created runtime-closure campaign durably seals evidence schema v2, the exact release ZIP digest and the running `platform-api` binary digest before any runtime-verification success can become closure evidence. PostgreSQL migration 0055 persists those immutable fields with rolling-safe legacy defaults. Independent `platformctl runtime-closure verify-report` / `fetch-report` require the exact release ZIP for schema-v2 reports, bind the running `platformctl` to that release, and prove both the report release digest and producer digest match `bin/linux-amd64/platform-api` in the verified artifact. Historical schema-v1 reports remain verifiable but are explicitly `exactReleaseBound=false`; active legacy campaigns must be recreated rather than silently upgraded into stronger evidence.


### Local/self-hosted vLLM or another compatible endpoint

Use the OpenAI-compatible path and point it at the explicitly configured endpoint/model. This keeps disconnected/private deployments possible without making cloud AI an availability dependency:

```bash
export PLATFORM_FACTORY_AI_PROVIDER=openai-compatible-chat
export PLATFORM_FACTORY_AI_ENDPOINT='http://127.0.0.1:8000'
export PLATFORM_FACTORY_AI_MODEL='<local-model>'
export PLATFORM_FACTORY_AI_API_KEY='local-or-provider-key'
```

The loopback HTTP example above is intentionally local-only. A remote/self-hosted provider must use an `https://` endpoint; URL-embedded credentials/fragments and cross-origin redirects fail startup/runtime admission. The core platform remains functional when the AI provider is disabled or unavailable. AI diagnosis is advisory and must not block unrelated deterministic control-plane operation.

### AI diagnosis output contract

A valid diagnosis is structured and bounded. The classification is one of:

```text
product-defect | test-defect | environment | supply-chain | unknown
```

It contains a confidence score and at most five recommended checks. Raw prompts, API keys and credentials are not durable authority. Durable `ai_runs` retain provider/model/prompt/context/output digests, usage counters, redaction counts and secret-safe structured output so retries and audits do not need to resend the original secret-bearing context. `AI_PROVIDER_DISPATCH_AUTHORITY_V1` additionally persists an `ai_execution_claims` record **before** model egress for the canonical Operator diagnosis and Marketplace model-advisory paths. The `(projectId, Idempotency-Key)` claim is unique and fail-closed: concurrent duplicates cannot spend a second provider call, a completed claim binds to the durable `ai_run`, and a provider failure or process crash after dispatch does not automatically redispatch the same key. If an outcome is failed or unknown, an operator must use a new Idempotency-Key to explicitly authorize another model call. This deliberately prefers bounded at-most-once dispatch over silently duplicating external AI cost or side effects. `AI_PROVIDER_RESULT_COMMIT_AUTHORITY_V2` closes the opposite side of that failure boundary: once a valid provider result exists, persisting the `ai_run`, its audit/outbox records and terminalizing the matching execution claim to `COMPLETED` is one Store-level atomic operation. PostgreSQL performs the whole result commit in one serializable transaction; FileStore performs one durable snapshot mutation. The old standalone `CreateAIRun` / `CompleteAIExecution` Store mutation surfaces are removed, and Marketplace configuration accepts only the product-owned controlled advisor so an alternate advisor cannot silently bypass the pre-egress dispatch claim. A model result returned without declared provider-dispatch authority is rejected instead of being persisted through a legacy write path. Upgrade reconciliation still accepts the exact 0.0.240 interrupted shape where a durable run already exists beside a matching `DISPATCHED` claim and terminalizes that claim without redispatch. A crash can therefore leave an unknown `DISPATCHED` provider outcome, but current code cannot create a new split-brain state where a durable `ai_run` exists while its execution claim remains `DISPATCHED`. `AI_RUN_POSTGRES_DURABILITY_RUNTIME_AUTHORITY_V1` now makes this same invariant a mandatory M03 physical-runtime evidence surface: exact-runtime certification must prove atomic rollback/success, one-winner dispatch contention, post-restart durability and post-restore durability. This is certification automation only; `AI_RUN_POSTGRES_DURABILITY_RUNTIME_CERTIFICATION_PENDING` remains open until those checks PASS on the exact physical release runtime.

## MCP: connect external agents to authoritative 4SO context

The MCP boundary is stateless, **read-only by default**, and uses protocol `2026-07-28` over Streamable HTTP. A separate operator-only `mcp.operate` capability exposes only explicitly allow-listed product operations; it never grants shell, kubectl, RBAC escalation or certification authority:

```text
POST /mcp
read permission: mcp.read
delegated-operation permission: mcp.operate
```

The read tool set is intentionally bounded:

- `lab_guide`
- `target_architecture_model`
- `ai_runtime_policy`
- `project_clusters`
- `project_operations`
- `cluster_summary`
- `cluster_maintenance_context`
- `operation_status`
- `ai_run`

Delegated mutation is still allow-listed. `operation_cancel` requires `mcp.operate`, the normal project write boundary, an exact expected revision and durable actor/audit authority. `cluster_maintenance_request` is the first high-impact handoff: it creates/replays the same durable cluster-maintenance run/operation used by REST/UI but must stop in `AWAITING_APPROVAL`; the requesting Agent has no MCP approval tool and the underlying authority requires a different approver. A token carrying only `mcp.read` does not discover or execute either mutation tool.

Create/use an API token carrying `mcp.read` for external MCP clients. Grant `mcp.operate` only to an operator service account when delegated product mutation is required. Resource tools re-apply organization/project authorization inside the product; MCP is not a cross-tenant bypass and mutation tools reuse the product state machine rather than implementing an LLM-owned write path. The `2026-07-28` wire contract is enforced rather than treated as a version label: every request carries its protocol version and client capabilities in `params._meta`, routing headers must agree with the JSON-RPC body, and every successful result carries `resultType=complete` plus server identity metadata.

A generic request shape is:

```bash
curl -sS -X POST 'https://factory.example/mcp' \
  -H 'Authorization: Bearer <token-with-mcp.read>' \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2026-07-28' \
  -H 'Mcp-Method: tools/list' \
  --data '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"example-client","version":"1.0.0"},"io.modelcontextprotocol/clientCapabilities":{}}}}'
```

The repository also ships an independent black-box certifier that uses only the Python standard library and talks to the API over TCP from a separate process:

```bash
python3 scripts/mcp_external_client_certify.py \
  --endpoint 'https://factory.example/mcp' \
  --token '<token-with-mcp.read>'
```

`MCP_EXTERNAL_CLIENT_INTEROPERABILITY_V1` requires discovery, repeated deterministic/cacheable tool listing, canonical read-tool calls and project-scope authorization/negative controls. `MCP_AGENT_DELEGATED_OPERATION_AUTHORITY_V1` additionally requires mutation discovery to be capability-filtered and every delegated mutation to pass the existing RBAC/project/revision/durable-operation audit boundary. High-impact lifecycle mutations remain C7 work and must use preview/approval rather than arbitrary shell/Kubernetes commands. MCP can never decide Exact-SHA Physical PASS.

## Release Gate: what may be called PASS

A certifiable release has four independent layers:

```text
1. Source Semantics
2. Generated/Installed Runtime Semantics
3. Runtime-Realism Negative Controls
4. Exact-SHA Physical Runtime
```

Passing layers 1-3 never authorizes a claim that layer 4 passed. AI diagnosis, Codex repair, a green local test run, a browser smoke test or an acknowledgement record cannot manufacture Physical PASS. Every physical certification must be bound to the exact release ZIP SHA and freshly collected evidence.

For the current program roadmap, `platformctl release-readiness` is the machine-readable truth. `productReleaseBlockers` includes both selected-blueprint/component blockers and mandatory pre-C9 roadmap blockers; `roadmapFeatureBlockers` and `roadmapFeatureBlockerCodes` expose the roadmap portion separately so feature-governance debt cannot disappear behind a clean component plan:

```bash
./bin/linux-amd64/platformctl release-readiness \
  -f blueprints/enterprise-private-cloud.json | jq .
```


## Runtime components

- **platform-api** — authoritative control-plane API and embedded web console. Production runtime requires durable PostgreSQL state. A file store exists only for explicit development persistence.
- **platformctl** — blueprint validation/planning, offline catalog/image bundle operations, installer host/remote workflows, field campaigns, support-bundle verification, and agent PKI bootstrap.
- **platform-installer** — local appliance planning/execution service with explicit mutation enablement, durable journal/state, rollback/recovery, and a browser console.
- **platform-agent** — outbound managed-cluster agent for inventory, execution tasks, runtime certification, maintenance, evidence, and reconnect behavior.
- **platform-probe** — digest-pinnable probe used by target runtime certification for storage/network checks.

The control plane owns desired state, operations, approvals, audit/evidence references, inventory projections, tenant/provider/fleet lifecycle state, and compatibility decisions. Managed clusters remain the observed runtime surface. PostgreSQL is the production authority for control-plane state; Kubernetes objects and external systems are not a replacement database for the product.

### Target architecture boundary

`TARGET_ARCHITECTURE_MODEL_V1` keeps four concerns independent:

- **Distribution identity** — `kubernetes` and `rke2` are admitted target identities, and `okd` is a first-class **existing-cluster import** identity. OKD import/mutation admission is not unconditional: it is derived from fresh native `ClusterVersion`/ClusterOperator identity, inventory health, required intrinsic capabilities and desired/observed profile convergence. Missing or stale evidence remains fail-closed/read-only. Managed OKD installation is a separate later phase and is not implied by existing-cluster admission. Red Hat OpenShift/OCP remains the distinct `openshift` identity and is not silently admitted through the OKD path. Imported physical-cluster continuity is enforced again inside the authoritative Store using the claim-bound `kube-system` UID, so missing legacy identity evidence remains read-only and a mismatched cluster cannot refresh inventory or heartbeat state.
- **Provisioning mode** — `import-existing`, `cluster-api`, or the internal-management-plane-only `managed-install`. Installer history such as Kubespray is not a distribution identity.
- **Infrastructure provider** — a separate infrastructure fact. Imported targets currently use `existing`; external Cluster API profiles remain `unspecified` until an admitted infrastructure adapter reports an authoritative identity.
- **Provisioning adapter** — the concrete mechanism such as `cluster-api-topology-v1beta2` or fleet-agent enrollment. It is not an infrastructure provider.

The management appliance remains a self-contained RKE2 boundary and is not generalized into the target abstraction. Legacy `generic-imported` and `kubespray` compatibility values are normalized to the canonical `kubernetes` identity so existing stored releases remain readable without rewriting immutable history.

Imported targets use a two-stage RBAC boundary. The initial enrollment manifest grants only credential maintenance, inventory/read access, OpenShift `ClusterVersion/version` observation, `SelfSubjectAccessReview`, and the minimum Pod metadata/status reads required by runtime evidence. Every inventory and fallback heartbeat re-attests the live `kube-system` UID against the physical cluster UID captured at claim; only the control plane may publish `target-cluster-uid-attested`, while older Agents that cannot attest remain read-only. Mutation roles are generated separately only for a supported distribution with a fresh identity-attested inventory epoch. Mutation activation issuance is an explicit state-changing `POST /api/v1/clusters/{id}/mutation-rbac-manifest`; `GET` only retrieves an already-current issuance and cannot create authorization state as a read side effect. The control plane records issuance as the server-owned `target-mutation-rbac-activation-issued` authority; Agent-supplied copies of that marker are removed, and `target-mutation-rbac-active` is ignored until issuance exists. Issuance is bound through `mutationRbacBasisDigest` / `mutationRbacIssuedForDigest` only to stable target-authorization facts—distribution/evidence, Kubernetes version, physical-identity continuity and enrollment-principal isolation. Runtime telemetry and unrelated API/CRD/OpenAPI discovery churn remain part of the full authenticated inventory digest used by planning/task revalidation, but do not unnecessarily revoke Kubernetes RBAC. Stable target-authority drift invalidates the old issuance and returns the target to read-only until an explicit POST re-issues activation. The server also retains sticky `target-mutation-rbac-ever-issued` history so a later authority drift cannot erase evidence that target-local mutation RoleBindings may still exist. Revocation is generation-ordered: Hub credential revocation returns an idempotent target-side RBAC fence plus a canonical `targetRBACRevocationFenceDigest`; the same physical `kube-system` UID cannot be re-enrolled until an operator explicitly acknowledges that exact digest. The acknowledgement is durable/audited but is not physical proof. Migration `0050` is quiesced-required, backfills sticky mutation-RBAC history from immutable activation audit, and removes unsafe mutation authority from legacy same-UID successors until an unacknowledged revoked predecessor is fenced. Migration `0051` preserves the immutable `0050` checksum and brings PostgreSQL upgrade-state capability truth into parity with FileStore by adding the explicit `target-read-only-admission` marker only to already-inventoried repaired successors that predate (or still await) the predecessor acknowledgement. The activation manifest carries the managed-cluster ID, physical UID and issued-for basis digest in a read-only proof ConfigMap; the Agent verifies all three before proving representative permissions through `SelfSubjectAccessReview` and reporting `target-mutation-rbac-active`. Unsupported distributions have mutation capability claims stripped even if a stale or compromised Agent reports them. OKD existing imports are handled separately: mutation authority is admitted only after the server-owned OKD capability/profile/identity gates and digest-bound target-RBAC activation are satisfied. Cluster-import expiry is also backend-consistent: PostgreSQL rejects already-expired enrollment requests, renders elapsed pending/approved requests as `EXPIRED`, and atomically materializes an expired same-name generation with credential invalidation plus audit/outbox evidence before allowing replacement enrollment. New task claims require two bounded freshness facts: the Hub must have received the authoritative inventory within three minutes and the target-reported `inventoryObservedAt` must itself be within the same bounded observation window (with bounded clock skew). Stale, missing, excessively future or backwards observation epochs fail closed at the Store boundary. Migration `0052` adds this nullable observation epoch without backfilling Hub receipt time as fake target evidence, so upgraded rows remain read-only for new mutation claims until a fresh target inventory arrives. Once a task is leased, its result is judged by the unchanged authority epoch plus the task lease/fence rather than by that claim-time freshness TTL, so a legitimate long-running operation is not invalidated merely because the inventory window elapsed while it was running.

## Major product surfaces

- Catalog and immutable component release contracts under `catalog/`.
- Blueprint authoring, lifecycle, overlays, compatibility, planning, approvals, rollback feasibility, and evidence planning.
- Imported fleet registration, mTLS agent enrollment/rotation, inventory, drift, support bundles, maintenance, and upgrade campaigns.
- Tenant lifecycle, policy/evidence enforcement, resize, protected delete, recovery checkpoints, and scoped RBAC.
- Provider lifecycle and Cluster API integration boundaries.
- Git delivery through credential references, signed revisions, atomic multi-file publication, full immutable commit authority, pull-request flow, and last-known-good observation.
- Internal service lifecycle for PostgreSQL, Forgejo, zot, Keycloak, Argo CD and appliance support services where enabled by the selected profile.
- Backup/restore and disaster-recovery orchestration with durable state and explicit failure handling.
- Notification routing and observability/runtime-certification adapters.
- Offline catalog and OCI image bundle assembly/verification/mirroring.

## Build requirements

The Go module targets Go 1.23. Linux `platform-api` builds use CGO and system `libpq` headers/library (`libpq-fe.h`, `-lpq`). Other shipped binaries are built without CGO.

```bash
make test
make vet
make race
make build
```

`make test` runs all Go tests and the Python unittest suites. `make race` runs the race detector over `./...`.

### Codex Autopilot test environment

The repository includes a bounded Codex repair/test orchestrator at `scripts/codex_autopilot.py`. Codex itself is an external CLI prerequisite and is intentionally not vendored into the product artifact. The deterministic local test path requires Go, Make, a C compiler plus libpq development files, Python test dependencies and Chromium. Install the Python/browser test dependencies in a disposable development environment with:

```bash
python3 -m pip install -r requirements-test.txt
python3 -m playwright install chromium
```

Then use the stable entry points:

```bash
make autopilot-preflight       # verify repair prerequisites, including Codex CLI
make autopilot-self-test       # bounded repair/regression/no-progress contract tests
make autopilot-test            # deterministic local correctness; no source mutation
make autopilot                # same graph with bounded Codex repair on confirmed local failures
make autopilot-release-test    # additionally require resolved third-party supply-chain inputs
make autopilot-real-test       # destructive/live PostgreSQL + field campaign boundary
```

The default repair command is non-interactive `codex exec` with an explicit `workspace-write` sandbox; `PLATFORM_FACTORY_CODEX_COMMAND` can override the executable/arguments when a managed Codex wrapper is required. Incomplete Autopilot runs use an atomic `.state/codex-autopilot-run.json` checkpoint: a runner/process interruption or non-PASS terminal outcome retains the resumable boundary, while a successful PASS clears it. Resume is admitted only when the workspace and selected graph are unchanged; a recorded active stage is terminated only after its process-start identity still matches, preventing PID-reuse cleanup, and descendant processes are terminated with the owning stage. Local code correctness and external release readiness are separate outcomes: `platformctl release-readiness` is the canonical machine-readable phase authority derived from the enterprise deployment plan plus the embedded upstream-admission authority, and `autopilot-release-test` / `autopilot-real-test` consume that same authority rather than maintaining a second blocker classifier. Product-owned release blockers remain fail-closed; the runtime Git-commit blocker is reported separately as deployment context because its immutable commit can exist only after the real Forgejo publication/handover boundary. A planning-only baseline does not turn a clean repository into a code defect. The real-test boundary additionally requires the live PostgreSQL/field-campaign environment documented by its preflight; it is not simulated by the local repair loop. A live `FAILED` or `INTERRUPTED` Field Campaign is never resumed merely because Autopilot was rerun: the operator must explicitly export `PLATFORM_FACTORY_AUTOPILOT_FIELD_RESUME_CONFIRMATION=RESUME`; FAILED state is diagnosed first, and any resumed run still has to reach SUCCEEDED, recollect evidence from the live Installer, and pass independent exact-release verification.

## Local development

Build the binaries:

```bash
make build
```

`platform-api` refuses an implicit in-memory authority. For explicit development persistence use a state file:

```bash
mkdir -p .state
PLATFORM_FACTORY_DEVELOPMENT_MODE=true PLATFORM_FACTORY_STATE_FILE=.state/control-plane.json ./bin/platform-api
```

For PostgreSQL-backed runtime, set `PLATFORM_FACTORY_POSTGRES_DSN`. `PLATFORM_FACTORY_STATE_FILE` and `PLATFORM_FACTORY_POSTGRES_DSN` are mutually exclusive.

The Compose file at `deploy/compose/docker-compose.yaml` is a loopback-bound integration profile with PostgreSQL authority. It requires digest-pinned images plus explicit OIDC/session/catalog-signing configuration; PostgreSQL-backed runtime never enables the local-development admin fallback. It is not the production appliance profile.

## API runtime configuration

Important settings are environment based. Production configuration should be injected by the installer/orchestrator rather than committed to the repository.

- `PLATFORM_FACTORY_POSTGRES_DSN` — production durable authority.
- `PLATFORM_FACTORY_POSTGRES_DRIVER` — optional explicit PostgreSQL driver name; Linux CGO builds include the built-in `4so-libpq` adapter.
- `PLATFORM_FACTORY_POSTGRES_MIGRATION_MODE` — defaults to `rolling`; use `quiesced` only after old API writers are intentionally stopped for a migration classified as mixed-version unsafe.
- `PLATFORM_FACTORY_POSTGRES_QUIESCED_MIGRATIONS` — comma-separated exact migration versions approved for one quiesced upgrade (for example `21`). A stale approval never authorizes a different future migration.
- `PLATFORM_FACTORY_LISTEN` — API listen address.
- `PLATFORM_FACTORY_TLS_CERT_FILE`, `PLATFORM_FACTORY_TLS_KEY_FILE` — API TLS.
- `PLATFORM_FACTORY_OIDC_ENABLED`, issuer/client/redirect/session settings — browser/API identity integration.
- `PLATFORM_FACTORY_INTERNAL_GIT_URL`, credential reference, registry, identity and GitOps URLs — managed internal integrations.
- `PLATFORM_FACTORY_AGENT_LISTEN` plus agent TLS/CA settings — dedicated mTLS agent endpoint.
- `PLATFORM_FACTORY_FLEET_AGENT_IMAGE`, `PLATFORM_FACTORY_RUNTIME_PROBE_IMAGE` — digest-pinned runtime images used by fleet/certification flows.
- `PLATFORM_FACTORY_NOTIFICATION_SECRET_<ORG_ID>_*` — process-level webhook credentials. `<ORG_ID>` is the immutable organization id upper-cased with non-alphanumeric characters replaced by `_`; credential-bearing notification destinations require platform-admin authority, while credentialless destinations remain organization-admin manageable.

PostgreSQL binary/schema rollback is also fail-closed: an existing `schema_migrations` authority must be an exact contiguous prefix of the migrations embedded in the running binary. If the database contains a newer migration than the binary knows, or the migration history has a gap, `platform-api` refuses startup before schema mutation. Runtime compatibility admission is evaluated while holding the same PostgreSQL advisory migration authority used by migration execution, so rollback/version fencing is not a separate check-then-apply window.

PostgreSQL migration admission is fail-closed for mixed-version compatibility. Fresh databases may apply the full embedded schema automatically. Existing installations use `rolling` mode by default; if a pending migration is classified `QUIESCED_REQUIRED`, startup fails before that schema mutation. To cross that boundary, stop old `platform-api` writers, set `PLATFORM_FACTORY_POSTGRES_MIGRATION_MODE=quiesced`, explicitly list the exact migration version in `PLATFORM_FACTORY_POSTGRES_QUIESCED_MIGRATIONS`, perform the migration, and then restore `rolling` mode before normal HA replicas resume.

Secrets must be injected through environment/secret files or runtime secret stores. Raw Git credentials are represented by `env://` or `file://` references and must not be persisted in product state. Notification credential references are additionally organization-bound and may not read arbitrary process environment variables.

## Installer and appliance workflows

The installer defaults to loopback and mutation-disabled operation. Relevant settings include:

- `PLATFORM_INSTALLER_BUNDLE_DIR`
- `PLATFORM_INSTALLER_STATE_DIR` (live appliance execution uses the canonical `/var/lib/4so-platform-installer` authority; alternate roots are for isolated simulation/test workflows)
- `PLATFORM_INSTALLER_LISTEN`
- `PLATFORM_INSTALLER_ALLOW_EXECUTION=true` only after plan review
- installer TLS certificate/key settings for non-loopback access

Host deployment is available through `platformctl installer-host ...`; remote bootstrap through `platformctl installer-remote ...`; the coordinated three-host path uses `platformctl zero-to-ha ...`. All destructive transitions require their explicit confirmation tokens shown by `platformctl --help`. `REMOTE_BOOTSTRAP_STREAMING_STAGE_AUTHORITY_V1` makes remote staging production-scale and fail-closed: local bundle/installer/TLS files are opened with no-follow semantics, rechecked for identity/size/modification drift while copied, and streamed through a mode-`0600` disk-backed TAR rather than materializing the bundle and a second TAR copy in RAM. The local temporary archive is removed after each remote operation, while the remote receiver still verifies the manifest digest before deployment. `REMOTE_BOOTSTRAP_EXPECTED_BUNDLE_AUTHORITY_V1` additionally binds every remote bootstrap specification to the preflight-sealed appliance `bundleDigest` and `lockDigest`. The locally inspected source must match that pair, and the independently staged remote `installer-host plan` must report the same pair before `apply` may execute; status/verify/rollback/recovery continuations reject a different installed bundle. This prevents a valid but different same-release bundle from being substituted after Lab preflight and physically mutated before the mismatch is noticed.

The installer itself consumes only a local, digest-locked appliance bundle. Network acquisition, when available, happens before installation through the exact-release-shipped Lab acquisition lock and produces a locally sealed bundle. Missing/invalid production source authority is `BLOCKED`; installer execution never falls back to a moving upstream. See `examples/appliance-bundle/README.md` for bundle build semantics.

## Catalog and air-gap workflow

Blueprint inspection:

```bash
./bin/linux-amd64/platformctl validate -f blueprints/enterprise-private-cloud.json
./bin/linux-amd64/platformctl plan -f blueprints/enterprise-private-cloud.json
./bin/linux-amd64/platformctl release-readiness -f blueprints/enterprise-private-cloud.json
./bin/linux-amd64/platformctl catalog-summary
```

Offline external catalog bundles:

```bash
./bin/linux-amd64/platformctl catalog-bundle assemble --help
./bin/linux-amd64/platformctl catalog-bundle verify --help
./bin/linux-amd64/platformctl catalog-bundle install --help
```

OCI mirror bundles:

```bash
./bin/linux-amd64/platformctl image-bundle assemble --help
./bin/linux-amd64/platformctl image-bundle verify --help
./bin/linux-amd64/platformctl image-bundle push --help
```

A component with `source.resolved=true` must have the exact digest-bound bundle material under `catalog/runtime/<bundleKey>/`. Unresolved catalog entries remain non-executable for channels that require resolved supply-chain material. Helm-sourced bundles additionally require `render-generation` evidence binding the Helm/Crane versions, release name, namespace, CRD inclusion, Kubernetes render window and repository-retained values-file digests; `scripts/acquire_upstream_helm.py` produces this contract and rejects values inputs outside the repository.

Unresolved Helm acquisition is itself governed by `catalog/upstream-admission.json`. This authority separates **exact version/source selection** from **immutable acquisition** and **runtime certification**: a `ready-for-acquisition` row may exact-pin the catalog release, but it MUST remain `source.resolved=false` until the real chart, upstream digest, render, image digests, licenses, SBOM and provenance are verified and installed. Review-required rows stay on their existing catalog constraint and cannot be acquired through the authority path. Use:

```bash
make upstream-admission-validate
make upstream-admission-plan
python3 scripts/acquire_upstream_helm.py --from-admission --component <name> --install
```

`--from-admission` refuses version/source overrides and refuses components whose architecture, dependency or version decision remains open. The lower-level `catalog-bundle install` boundary independently rechecks the canonical admission row and binds the resolved payload to the repository's existing component contract, so direct bundle assembly/install cannot bypass product policy. After a successful durable Helm import, the consumed admission row is retired; the authority therefore continues to cover exactly the remaining unresolved Helm components and idempotent replay remains safe. Catalog imports that mutate this shared authority are serialized by a repository-scoped transaction lock under excluded `.state/`, so simultaneous imports cannot lose one another's retirement update. It never resolves `latest`, widens a catalog constraint, or manufactures source/runtime evidence.

## Agent and fleet security

Agent transport uses a dedicated TLS listener when mTLS is required. Bootstrap bearer enrollment can issue only the first agent certificate; later rotation/re-enrollment follows the certificate authority workflow and does not reuse the bootstrap bearer as a standing credential. New cluster imports also receive an import-scoped Kubernetes ServiceAccount persisted in ClusterImport authority. Revoking and explicitly re-enrolling the same physical cluster therefore creates a new principal instead of inheriting mutation RoleBindings from the revoked enrollment generation. Hub revocation invalidates Hub credentials immediately but does not pretend that target-local Kubernetes RBAC vanished remotely: the revoke response and `/api/v1/clusters/{id}/revocation-rbac-manifest` expose an idempotent fence that clears the old generation from read-only/credential bindings and, when mutation had been activated, from mutation bindings before re-enrollment. The API keeps this target-side step explicit as `APPLY_REQUIRED`. Historical imports created before this authority existed retain the legacy `4so-platform-agent` principal until they are explicitly re-enrolled; migration 0047 that enables post-revocation physical-UID reuse is quiesced-required so old fixed-principal writers cannot cross that boundary.

`platformctl agent-pki init ... --confirmation INIT` creates the local agent CA/server material. Do not commit generated private keys.

## Backup, restore, recovery and upgrade

Lifecycle and disaster-recovery state is durable and startup fails on corrupt state instead of silently resetting it. Queue/state persistence failures reject the mutation. Interrupted runs block overlapping mutation until the existing run is reconciled. Whole-appliance backup/restore quiesces platform writers before cross-component capture or replacement; RWO backup placement is durably recorded before quiesce so restart/reconcile does not depend on a live service pod. Failed restores remain quiesced rather than serving mixed state. Upgrade/restore paths must surface rollback/scale/system-service failures rather than reporting a false success.

Target-runtime and upgrade certification are separate from unit/local smoke success. PostgreSQL live certification procedures are in `docs/POSTGRESQL-RUNTIME-CERTIFICATION.md`.

## Validation and release

Canonical developer/release commands are:

```bash
python3 scripts/validate_repository.py .
make test
make vet
make race
make smoke
make smoke-ui
make release
make verify-release
```

Validation responsibilities are intentionally separated:

- Go/Python tests own functional and regression behavior.
- `scripts/smoke_*.py` own cross-component/local executable behavior.
- `scripts/validate_repository.py` checks current repository/package/config/supply-chain structural invariants; it does not police historical prose.
- `scripts/verify_release.py` checks the packaged archive, generated manifest/provenance/SBOM and, with `--full`, re-runs the executable suites from the extracted artifact.
- `scripts/postgresql_runtime_certify.py` is the PostgreSQL live-certification harness and distinguishes PASS, FAIL and BLOCKED.

A release-number bump does not require a new validator file. Regression coverage belongs in the stable owner package/smoke suite.

### AI-native control plane, Lab and MCP authority

`UNIFIED_AI_RUNTIME_V1` is the single provider-neutral AI boundary used by Operator diagnosis, Marketplace advisory and cloud/local Lab diagnosis. Provider configuration is fail-closed; all model egress is centrally redacted and bounded, output is structured, and successful advisory calls become project-scoped durable `ai_runs` containing only digests/usage/redaction metadata plus secret-safe structured output. Raw prompts and credentials are not durable authority. AI never owns RBAC, deterministic PASS, runtime certification or Exact-SHA Physical PASS.

`GET /api/v1/ai/policy`, `POST /api/v1/ai/diagnose` and `GET /api/v1/ai/runs` power the Operator Console **AI Control Plane**, which shows effective provider/model/budgets, actual token/cache/redaction usage, linked authoritative resources and inspectable durable advisory evidence. `mcp.read`, `mcp.operate`, `ai.diagnose` and the worker-only `operation.execute` permission are distinct API-token capabilities. `operation.execute` is valid only for platform-operator service accounts and never grants human approval authority. MCP remains read-only by default; `mcp.operate` exposes only allow-listed product operations and reuses normal project/RBAC/revision/audit authority. AI diagnosis is advisory, and neither MCP nor AI can manufacture PASS or Physical PASS.

`GET /api/v1/lab/guide` and the Operator Console **Physical certification** page consume the same `LAB_CERTIFICATION_MATRIX_V2` authority. It defines four server tiers and M00-M13 with phase ownership, destructive scope, actions, AI eligibility and executable automation status. The canonical runner is `scripts/lab_runner.py` (`guide`, `self-test`, `plan`, `preflight`, `run`). AI is failure-only and bounded; it never owns PASS/FAIL. `LAB_APPLIANCE_BUNDLE_ACQUISITION_LOCK_V8` is the only automatic bundle-source authority and `LAB_APPLIANCE_BUNDLE_ACQUISITION_EXACT_RELEASE_BINDING_V1` binds its consumed bytes to the Exact Release ZIP: it is shipped inside the exact release, cannot be replaced by run-spec URLs or by mutating the extracted release tree, and is either `ready` with every source authority fully byte-locked plus a digest/size-locked input-pack whose exact staged bytes and build-spec roles are independently rebound to those authorities, or `incomplete` with explicit partial/missing authorities. Missing source locks or required physical infrastructure are reported as `BLOCKED`, never replaced by an unpinned latest download or inferred success.

`OPERATOR_EXPERIENCE_VIEWPORT_ACCESSIBILITY_V1` is the stable rendered-source authority for the embedded Console and Bootstrap Installer. `scripts/smoke_ui_quality.py` checks all 20 Console routes and 6 Installer routes at 320, 390, 768, 1024 and 1440 pixels; DOM/accessibility/overflow is exercised in both LTR and RTL, route-visible contrast is exercised in light and dark, explicit theme overrides are tested against the opposite OS preference, and keyboard focus, durable feedback and reduced motion retain dedicated negative controls. `scripts/verify_release.py --full` runs the same quality gate from the extracted release ZIP after live/headless UI smoke. This contributes to the C4 source/extracted-artifact Operator Experience gate only; final physical UI/performance certification remains part of Phase M.

## Current limitations

### UI component and communication benchmarks

Release 0.0.287 closes **C5 Installer Production Lifecycle Closure at source semantics**. Live preflight now enforces the product sizing baseline plus `/var/lib` capacity/local-filesystem, default-route/MTU evidence and proxy bypass; production HA must prove credentialed encrypted external-S3 write/read-back/delete before install success. `INSTALLER_JOURNALED_RESET_AUTHORITY_V1` adds explicit source-bound reset/uninstall with durable resume and clean reinstall while preserving installer access and pinned SSH trust. `INSTALLER_UPGRADE_INTERRUPTION_RECOVERY_MATRIX_V1` records every replay/recovery boundary and forbids automatic replay once an upgrade is `RECOVERY_REQUIRED`. These are source/generated-local truths only: physical sizing tuning and real network/storage failure injection remain Phase D exact-artifact evidence. At release 0.0.287 the roadmap phase was C7. MCP now adds read-only `cluster_maintenance_context` plus approval-gated `cluster_maintenance_request`; high-impact AI requests stop in `AWAITING_APPROVAL` and cannot self-approve through MCP.

Release 0.0.286 extends the same pre-certification discipline to agent knowledge, browser diagnostics, search projections and Persian localization. Executable installation profiles also expose `APPLIANCE_SIZING_AUTHORITY_V1`: evaluation starts at a source baseline of 4 vCPU / 8 GiB RAM / 80 GiB disk (8 / 16 / 150 recommended), while production-standard-ha declares 8 vCPU / 16 GiB / 160 GiB minimum per management node (12 / 32 / 300 recommended). These are product-owned source-enforced pre-certification baselines; exact sizing tuning remains a Phase D physical evidence requirement. `platformctl target-architecture` provides an offline machine-readable view of the same target/program authority served by the API/MCP surface. Release packaging generates `DERIVED-AGENT-KNOWLEDGE.json`: a discardable `DERIVED_AGENT_KNOWLEDGE_V1` projection whose claims carry exact source-file SHA-256 evidence and whose architecture view is explicitly not runtime-impact proof or product SoT. The Autopilot also validates a pinned `BROWSER_TRIAGE_PROFILE_V1` for Chrome DevTools MCP (`1.8.0`, isolated/headless, CrUX/usage/update checks disabled) without making Node/Chrome MCP a shipped runtime dependency, and runs the product-owned `PERSIAN_UI_QA_V1` gate plus `PERSIAN_PRODUCT_GLOSSARY_V1` without bundling Salsi/Pasban lexicon data. `SEARCH_PROJECTION_AUTHORITY_V1` records OpenSearch only as an optional rebuildable search/analytics projection; PostgreSQL, durable evidence and metrics authority remain canonical.

Release 0.0.285 evaluates **shadcn/ui** and **Novu** without adding either as a mandatory runtime dependency. The console keeps its 4SO-owned embedded HTML/CSS/JS architecture and adopts the shadcn-style open-code principle: component source, design tokens, accessibility behavior and tests stay owned by this repository instead of introducing a React/Tailwind migration immediately before certification. Novu informs notification workflow/channel/agent ergonomics, but notification event, route, delivery, retry and dead-letter authority remains inside the existing PostgreSQL/outbox control plane. External communication systems may be added only behind provider adapters and cannot become a second source of truth.

`NOTIFICATION_ROUTING_PREVIEW_AUTHORITY_V1` is the first concrete convergence: operators and `mcp.read` agents can preview rule/destination matches for an organization/project event without creating an event or delivery. Preferences, digest policy and external provider adapters remain explicit Phase J work rather than hidden dependencies.



Release 0.0.309 closes **G2 — Generalized Day-2 Campaign Engine** at the source-authority layer. `GENERALIZED_DAY2_CAMPAIGN_ENGINE_V1` now defines one machine-readable `Plan → Impact → Window → Approval → Canary/Waves → Fence → Execute → Verify → Evidence → Recovery` contract used by both node-maintenance and fleet-upgrade adapters. The safety contract is enforced in the durable Memory/File and PostgreSQL store boundaries, not only in REST handlers: independent approval, bounded windows, lease/fence identity, immutable upgrade wave topology, immutable recovery baseline identity and required recovery evidence fail closed. REST and MCP share rollout-bound normalization, including safe single-cluster defaults. `GET /api/v1/day2-campaign-engine` exposes the owned model and Operator Console surfaces the same authority for maintenance and fleet upgrade. `PROGRAM_PHASE_MODEL_V21` marks G2 `source-implemented`, unlocks G3 as the next Day-2 branch that may proceed in parallel with S1/S2, and leaves S1 exact supply-chain acquisition as the current critical path. Exact-SHA Physical Runtime remains `NOT_EVALUATED`.

Release 0.0.308 closes **G1 — Operational Runtime Hardening** at the source-authority layer. All 363 reviewed static-text gaps and 31 user-facing attribute gaps from 0.0.307 now resolve through the owned Persian localization dictionary; three older English-only pseudo-translations were corrected as well. `CONSOLE_LOCALIZATION_COVERAGE_V2` no longer treats key presence as sufficient: eligible copy must resolve to Persian or an explicitly protected technical term, and the baseline writer refuses any non-zero gap. The canonical coverage baseline is therefore 0 text / 0 attribute gaps and `CONSOLE_FULL_LOCALIZATION_PENDING` is retired. `PROGRAM_PHASE_MODEL_V20` marks G1 `source-implemented` and explicitly parallelizes G2 Generalized Day-2 Campaign Engine with the continuing S1/S2 supply-chain/runtime-certification path. S1 remains the current critical path; exact source/image locks remain open and Exact-SHA Physical Runtime remains `NOT_EVALUATED`.

Release 0.0.307 hardens the remaining G1 Console-localization boundary without falsely declaring it complete. Locale changes now translate existing eligible DOM text and user-facing attributes immediately, translate later DOM mutations, and restore the exact English source when switching back. `CONSOLE_LOCALIZATION_RUNTIME_V1` proves that behavior in Chromium. `CONSOLE_LOCALIZATION_COVERAGE_V1` locks a reviewed machine-readable gap baseline and rejects any new unlocalized operator copy or silent baseline weakening; the current baseline still records 363 static-text and 31 attribute gaps, so `CONSOLE_FULL_LOCALIZATION_PENDING` remains the sole G1 blocker. S1 remains 14-ready/3-review and Exact-SHA Physical Runtime remains `NOT_EVALUATED`.

Release 0.0.306 closes three remaining G1 runtime-observability boundaries without creating parallel authorities. Target workload logs are now read-only durable Operations bound to fresh authoritative inventory and executed by the connected Agent through bounded Kubernetes workload→pod resolution and bounded Loki query semantics; results are sealed evidence and the Operator Console exposes a scoped Project→Cluster→Workload QUERY/TAIL workflow rather than accepting raw LogQL. Notification health uses incremental `(changedAt, clusterId)` paging with a race-safe observed cursor, and Support Bundles use durable idempotent Operation jobs with lease/fence/retry and verified sealed ZIP evidence. A scheduler defect that left workload-log tasks permanently unprocessed was discovered and fixed. G1 now remains blocked only by full mandatory Console localization; S1 remains 14-ready/3-review and Exact-SHA Physical Runtime remains `NOT_EVALUATED`.

Release 0.0.305 closes the G1 Agent task queue observability boundary while preserving the S1 fail-closed supply-chain state. Queue Center now exposes project-scoped aggregate Agent task pending/executing/attention, expired claims, retry count, maximum attempt and oldest pending/executing age across Baseline, Runtime Verification, Runtime Certification, Tenant, Provider Profile and Provider Cluster authorities. Memory/File and PostgreSQL use one classifier and PostgreSQL aggregates before returning any result; task payloads, claim/fence tokens, credentials and worker mutation controls remain non-exported. The G1 Agent queue blocker is retired, but the other G1 blockers and S1 14-ready/3-review blockers remain open, and Exact-SHA Physical Runtime remains `NOT_EVALUATED`.

Release 0.0.304 closes the Operator-facing S1 admission visibility and release-tooling checkpoint boundary without weakening supply-chain admission. Catalog Summary and the Supply-chain Releases surface now render the canonical `catalog/upstream-admission.json` readiness/review authority, including blocker rationale and review evidence, as read-only derived state. The heavy rendered UI Quality owner gate is checkpoint-safe through deterministic Console/Installer route shards plus explicit auxiliary checkpoints while its default invocation remains the same full gate. Cilium, Kyverno and MetalLB remain fail-closed review rows; no unresolved upstream review is promoted by this release, immutable source acquisition and S2 runtime certification remain separate, and Exact-SHA Physical Runtime remains `NOT_EVALUATED`.

Release 0.0.303 makes a larger S1 supply-chain/architecture convergence without claiming unresolved bytes as acquired. OSS Loki is rebaselined to the maintained `grafana-community/helm-charts` line with exact chart `18.12.1`. Ceph CSI is moved from the legacy direct Helm assumption to the upstream-supported Ceph-CSI Operator architecture: `ceph-csi-operator` and `ceph-csi-drivers` are exact `1.0.4` acquisition candidates while the stable product capability id `ceph-csi-rbd` is retained for consumers. A cross-component dependency fence prevents Cilium 1.20.x from becoming ready until exact Gateway API `1.6.1` bytes are resolved and prevents kgateway admission from drifting away from the product-owned Gateway API baseline. `scripts/acquire_upstream_batch.py` adds checkpoint-safe sequential acquisition/install over only canonical ready rows; successful component imports retire their own row so restart naturally resumes without a shadow state database. Release 0.0.346 extends this owner path with `--stage-out DIR` and `--install-staged DIR`: connected hosts can produce digest-verified ExternalCatalogBundle ZIPs plus a derived `UPSTREAM_STAGED_BATCH_V1` manifest, while disconnected build hosts re-verify every bundle and bind unresolved entries back to the live admission/component authorities before atomic install. The staged manifest never becomes a second SoT and partial staging/install is checkpoint-safe. S1 is now 14 ready-for-acquisition / 3 review-required; the remaining reviews are Cilium, Kyverno and MetalLB. Immutable source acquisition, S2 runtime certification and Exact-SHA Physical Runtime remain independent gates, and Physical Runtime remains `NOT_EVALUATED`.

Release 0.0.302 hardens crash/restart authority for stateful lifecycle operations. Each newly admitted lifecycle run now persists the exact accepted appliance-bundle digest, and Kubernetes Job replay is bound to the exact generated manifest digest plus durable UID/owner/operation identity; bundle or manifest drift and legacy missing-digest authority fail closed before blind replay. Durable lifecycle state is validated for canonical service/profile/action/state/backup/digest authority before reconciliation, preventing corrupt service records from falling through to the Zot workload target. S1 also admits kgateway `2.3.6` for acquisition after reconciling its official 2.3 Gateway API 1.3–1.5 support with the product Gateway API `1.5.1` baseline. The S1 queue is therefore 11 ready-for-acquisition / 5 review-required; actual immutable source acquisition, S2 runtime certification and Exact-SHA Physical Runtime remain independent gates, and Physical Runtime remains `NOT_EVALUATED`.

Release 0.0.301 closes three correctness boundaries while advancing the existing S1 supply-chain phase without overstating readiness. Invalid retry claims are now side-effect-free before `RETRY_WAIT` promotion, operation worker identities are canonical across lease claim/renew/release paths, and Installer resume rejects missing or already-succeeded durable bootstrap authority before returning `202`. Upstream admission now carries structured review evidence across every strict parser: Grafana uses the official migrated community Helm repository with exact candidate `12.10.0` admitted for acquisition, while Kyverno `3.8.2` and MetalLB `0.16.1` remain exact but blocked review candidates. Standalone smoke harnesses no longer inherit development authentication from Makefile. The S1 queue is therefore 10 ready-for-acquisition / 6 review-required; immutable acquisition, runtime certification and Exact-SHA Physical Runtime remain separate gates, and Physical Runtime remains `NOT_EVALUATED`.

Release 0.0.300 hardens the durable generic Operation execution boundary without advancing the roadmap. Matching lease owner/fence identity is no longer sufficient after lease expiry: verification, failure, completion, cancellation acknowledgement, step writes and compensation mutations all require a live lease in both in-memory and PostgreSQL authorities. Generic `TransitionOperation` is restricted to orchestration-only pre-execution states so execution workers cannot bypass claim/attempt/verification/retry/recovery semantics with raw state transitions. PostgreSQL operation-step replay is attempt-scoped, matching its uniqueness contract, and same-key replay now rejects divergent state/error content instead of silently hiding a conflicting worker outcome. Notification classification is now terminal-state authoritative for Operation failures across generic retry, owner-destructive and cluster-maintenance producers, while `RETRY_WAIT` remains non-terminal. `PROGRAM_PHASE_MODEL_V19` and the S1 Exact Supply Chain Acquisition critical path remain unchanged; Exact-SHA Physical Runtime remains independently `NOT_EVALUATED`.

Release 0.0.298 closes **R0 — Release Authority & Certification Rebaseline**. `PROGRAM_PHASE_MODEL_V19` replaces the artificial G→H→I→J serial chain with explicit mandatory DAG branches: immediate exact-supply-chain acquisition (`S1/S2`), operational/day-2/data-protection/identity tracks (`G1-G5`), connected Managed OKD plus independent VMware (`H1/H2`), disconnected/edge (`I1/I2`) and automation/FinOps/virtual-cluster (`J1-J3`). `ProductReleaseReady` now fails closed while any mandatory pre-C9 roadmap phase is blocked, and `platformctl release-readiness` exposes separate `roadmapFeatureBlockers`/codes while including them in product readiness. `FEATURE_CERTIFICATION_REGISTRY_V1` declares required Source/Generated Runtime/Negative Control/Integration/Exact-SHA/Chaos levels per feature. `LAB_CERTIFICATION_MATRIX_V2` schema v3 separates `featureOwnerPhase` from physical `executionPhase`: M00-M10 execute only in D, M11-M13 only in M, while M07/M08/M09-M10 retain explicit G3/H1/I1 feature ownership. V19 also makes Connected Managed OKD, target Add/Drain/Remove/Replace lifecycle and Backup/Restore/Restore Drill explicit blockers rather than implicit roadmap assumptions. Enterprise SAML is rebaselined to Keycloak SAML brokering into the product OIDC authority unless a separate native-SP requirement is explicitly admitted. These are release/source-governance corrections only; Exact-SHA Physical Runtime remains independently `NOT_EVALUATED`.

Release 0.0.297 closes the product-owned Queue/Job and Product Log Center blockers without pretending that live target workload logs are already solved. `OPERATIONS_QUEUE_CENTER_V1` uses scoped PostgreSQL aggregates for exact Operation state, notification-delivery state and transactional-outbox pending counts while keeping detail lists bounded; it is read-only and never exposes worker claim/transition controls. `PRODUCT_LOG_CENTER_V1` merges sealed Operation step-trace metadata, Audit events and Notification events under project/organization scope, intentionally omits raw evidence payload bytes, and reports bounded-window search truth. The Operator Console links each Operation directly into the Log Center and exposes queue pending/executing/retry/dead-letter/expired-claim state. `PROGRAM_PHASE_MODEL_V18` removes only the broad Queue Center/Product Log Center blockers and replaces the latter with the narrower `TARGET_WORKLOAD_LOG_TAIL_PENDING`; live pod/workload tail remains open until a capability-gated target log transport is implemented.

Release 0.0.296 closes `AGENT_SCHEDULER_V2`: Agent liveness/inventory polling is isolated from the single-writer mutation lane, so long-running task execution no longer suppresses fresh inventory/heartbeat cycles. The mutation lane remains sequential and bounded to one pending accepted inventory epoch, avoiding concurrent Kubernetes writers while coalescing redundant polls. Upgraded Agents advertise `agent-scheduler-v2`, and `PROGRAM_PHASE_MODEL_V17` removes only the Scheduler blocker; unified Queue/Job and Log Centers and the remaining Phase G product work stay explicit blockers.

Release 0.0.295 hardens the complete deterministic release path with `CHECKPOINT_SAFE_FULL_VERIFIER_V2` and `AUTOPILOT_STAGE_SHARD_AUTHORITY_V2`. Unit, vet, race and backend smoke now run as replayable bounded shards with fail-closed command deadlines; the extracted-artifact Full Gate explicitly includes Lab/upstream acquisition checks, AI smoke, Persian UI QA and C4 workflow E2E. Production bootstrap TLS remains RSA-3072 while simulation uses an injected lower-cost test-only key generator so constrained Agent/CI environments do not manufacture false hangs. Release 0.0.294 closed the generic Operation executor authority gap and bounded the highest-risk diagnostic hot paths discovered by the 0.0.293 ultra-deep audit. Production raw Operation transition/claim/attempt/trace/compensation execution now requires a service-account API token with the dedicated `operation.execute` permission; human OIDC operator/admin sessions retain intent/approval/recovery workflows but cannot impersonate a worker, and lease ownership is bound to the authenticated service principal. The executor contract includes fenced lease renewal. Cluster timeline and project-audit support diagnostics now scope before `LIMIT` without a full authority Snapshot, Fleet Health declares a bounded 200-cluster returned scope, and synchronous Fleet Support Bundle creation fails closed above 50 clusters or 200 recent operations until the explicit async job authority is implemented. `PROGRAM_PHASE_MODEL_V16` keeps Agent Scheduler V2, unified Operations/Queue Center, Product Log Center, incremental notification health scanning, asynchronous Support Bundles and full Console localization as explicit Phase G blockers alongside OS patch, certificate renewal, node remediation, SAML SSO and Compliance. Existing-import OKD remains capability-gated/admitted while managed OKD installation and Exact-SHA Physical certification remain later work.

Release 0.0.293 is a high-scale correctness closure for the workload/search capabilities introduced in 0.0.292. Search now fails closed unless the authority store can apply project scope before source LIMIT for clusters, operations, evidence and audit; the PostgreSQL evidence path is project-scoped in SQL and the hot path never performs a global evidence scan. Workload Explorer now honors Kubernetes `limit`/`continue` pagination and product collection budgets while preserving truthful truncation. Equal-timestamp events receive deterministic canonical tie-breakers before inventory digesting, eliminating order-only churn. OpenSearch remains optional and is not represented as a second product source of truth or a completed direct administration backend. No Phase G blocker is removed by this correctness release: OS patch campaigns, certificate renewal campaigns, node remediation campaigns, SAML enterprise SSO and the Compliance Scan Center remain required before G can close. Physical certification remains explicitly unevaluated until C9.

Release 0.0.292 closes the Workload Explorer and search-projection/rebuild blockers inside Phase G without pretending the whole phase is complete. Managed-cluster Agents now report bounded controller/service/ingress/PVC/event observations through `WORKLOAD_EXPLORER_READ_AUTHORITY_V1`; the Console exposes that live observational state with freshness truth. `SEARCH_PROJECTION_AUTHORITY_V2` selects PostgreSQL-backed bounded search as the default product projection and OpenSearch only as an optional scale backend under `SEARCH_PROJECTION_REBUILD_CONTRACT_V1`; project-scoped REST and MCP `ops_search` never expose direct OpenSearch administration or make search a source of truth. That release used `PROGRAM_PHASE_MODEL_V16`; at that point G still carried OS patch, certificate renewal, node remediation, SAML and Compliance blockers.

Release 0.0.291 closes F OKD existing-cluster import/capability certification at Source Semantics. Imported OKD targets now derive admission only from fresh ClusterVersion/ClusterOperator and native capability inventory, expose health and desired/observed profile convergence in the Console, preserve reconnect versus revoked re-enrollment fencing, and provide target mutation-RBAC activation/revocation cleanup actions without treating managed OKD installation or Physical certification as complete. That release used `PROGRAM_PHASE_MODEL_V14`; the roadmap later advanced through V16 and now uses V19. Physical certification remains deferred behind C9 Feature Freeze.

Release 0.0.289 hardens the optional Browser Triage Specialist with `BROWSER_TRIAGE_PROFILE_V2` and `BROWSER_TRIAGE_PREREQUISITE_AUTHORITY_V1`. On Windows and Linux, `scripts/browser_triage_bootstrap.py --ensure` verifies Node/npm/npx and supported Google Chrome/Chrome for Testing before the MCP process starts; missing prerequisites are provisioned user-locally without requiring Administrator/root. The fallback Node toolchain is pinned to Node.js 22.12.0 and verified against Node.js release SHA-256 values; Chrome for Testing is pinned to 152.0.7977.75 for this release and its extracted binary must report the expected version. `--run-mcp` then launches exact-pinned `chrome-devtools-mcp@1.8.0` with isolated/headless mode and usage/CrUX/update checks disabled. Chromium alone is not treated as an officially supported Chrome DevTools MCP prerequisite; Playwright/Chromium remains valid for deterministic 4SO UI gates.

`platformctl release-readiness` reports selected-blueprint/component gates and the canonical `PROGRAM_PHASE_MODEL_V19` mandatory product DAG as one fail-closed product-release decision while keeping their blocker classes separate. C1-C8 and F remain source-implemented; **R0 — Release Authority & Certification Rebaseline is source-implemented in 0.0.298 and the current critical path is S1 — Exact Supply Chain Acquisition**, with G1 operational hardening, H2 VMware and J1 external automation allowed to progress in parallel where their explicit dependencies are satisfied. C6 — Multi-Agent Test Autopilot is source-implemented from 0.0.284 with deterministic race/smoke sharding, an isolated Installer smoke shard, read-only triage before a single-writer repair worker, secret-redacted failure packets and a hard C9 Feature-Freeze guard on `--real-test`. C7 is source-implemented with project-scoped discovery plus allow-listed operation-control, assurance, maintenance and fleet-upgrade request families (`operation_cancel`, `drift_scan_request`, `runtime_verification_request`, `cluster_maintenance_request`, `upgrade_campaign_request`). High-impact maintenance and upgrade requests stop at independent approval and no MCP approval tool exists. C8 Console Operational Completion and F OKD existing-cluster import/capability certification are source-implemented. G-J remain mandatory feature-closure phases before C9. C9 is the explicit feature-freeze/exact-bundle gate. **Phase D Exact-SHA Physical Certification is no longer a development prerequisite and may start only after C9 closes.** Source implementation, local loopback evidence, preflight hardening and Autopilot execution never imply Generated/Installed Runtime or Exact-SHA Physical PASS.

External GitHub publication/synchronization is explicitly deferred by operator policy as of 0.0.228 and is not a source or physical-certification blocker or exit criterion. This is not a GitHub PASS claim; exact-release ZIP clean extraction and repository validation are the active source-artifact gate.

Phase D physical certification has a deterministic automatic bundle-acquisition mechanism, but `lab/appliance-bundle-acquisition-lock.json` is deliberately `incomplete`. The Management Plane replicated-storage authority remains source-locked to Longhorn `v1.12.1`, and CloudNativePG `v1.30.0` is fully byte-locked to its official release manifest. RKE2 `v1.34.10+rke2r1` is now fully exact-byte locked: its server tarball, offline image tarball, checksum file, and tagged `install.sh` are all SHA-256/size bound, with `install.sh` additionally verified against release-tag commit `d419f09226d50a4777d348e5c53ea1bce3849b77` and Git blob `88c5f55bdfde94f2277465ece2b749c52d86c69b`. Argo CD `v3.5.0` is likewise fully exact-byte locked to commit `e95e1be88a2da6c06bff5c2fe1791e4d233ed810`, upstream HA manifest `manifests/ha/install.yaml`, Git blob `8e0ff973a33bf12ec6e9c1554029cb36931945e8`, SHA-256 `65d9d4ff520ddb40bad2c39b1f44188ceecfe96b5dd29c8ead569b52d6c6b8c6`, and 1969264 bytes so the production-standard-ha appliance does not install the single-replica standard GitOps topology. The management workload OCI archive remains the product-owned missing source authority, while `digest-pinned-core-workload-images` is a derived authority computed from the archive rather than a separately authored inventory. V8 includes source-byte binding, canonical files-only ZIP extraction, strict duplicate-key-free JSON, bounded pack/archive entry counts and unpacked size, exact pack-file ownership, producer-realistic OCI index metadata admission, and OCI-layout content authority: a future `ready` pack must prove the bytes of every resolved authority at its canonical staging path; the workload archive must be a valid OCI Image Layout whose `MANAGEMENT_WORKLOAD_OCI_ARCHIVE_INVENTORY_V2` exactly matches its top-level manifest digests, whose top-level descriptors are import-addressable by the exact digest-pinned inventory references, and whose referenced manifest/config/layer blobs verify cryptographically; the eight core workload references are then derived from that archive before the build can begin. The Management Plane storage policy is Longhorn V1 data engine with three replicas on the three-node RKE2 production-HA appliance; it is **not** a target default and does not change OKD storage ownership/capability resolution. Runtime certification must still prove the required `iscsiadm`/`iscsid` host prerequisites. This remains tracked as `LAB_CANONICAL_BUNDLE_SOURCE_LOCKS_PENDING`; source locking is not runtime or Physical PASS.

Local tests and smoke suites are not external target certification. The repository contains unresolved external catalog components that remain non-executable until their exact source/image/license/SBOM/provenance closure is supplied. Production readiness must therefore be established by the required disposable-target, PostgreSQL, HA/DR, security, load/soak and supported-upgrade certification evidence; it is not inferred from static or local test success.


## Exact source artifact authority and deferred Git publication

For the active local release workflow, the FULL exact-release ZIP and its clean extraction are the canonical source-artifact authority. External Git/GitHub publication is explicitly deferred by operator policy and is not used to infer source completeness, release readiness or physical certification. No local release may claim repository synchronization merely because Git metadata or an older remote exists.

The exact downloadable release source artifact must contain the backend, frontend/Operator Console, API, migrations, schemas, installers/deployment assets, configuration/templates, scripts/tools, tests/validators, documentation, phase authority, `VERSION`, release instructions and `AGENTS.md`. Build outputs inside `/bin` are generated and independently verified; `/release`, runtime evidence, state, caches, logs and real secret material are reconstructed by build/test/runtime workflows and are not source authority. If external publication is explicitly resumed later, it must be full-tree and parity-verified against the exact release rather than inferred from selected-file pushes.

The source tree uses neither Git submodules nor Git LFS. The retained `snapshot-controller-v8.5.0-official-tag-source-set.zip` and `catalog/runtime/.../artifact.bin` inputs are small, digest-bound vendored supply-chain material. Product-owned large runtime dependencies that are not vendored must be acquired only through the documented exact-version/digest bundle/bootstrap path; arbitrary `latest` downloads are not a valid substitute.

Canonical synchronization check:

```bash
pwd
git rev-parse --show-toplevel
git remote -v
git branch --show-current
git status --short --untracked-files=all
git ls-files
git ls-files --others --exclude-standard
git ls-files --others --ignored --exclude-standard
git submodule status --recursive || true
find . -name .git -print
find . -name .gitignore -print
git config --get core.excludesfile || true
git lfs ls-files || true
git lfs status || true
```

Before pushing, run the repository validator/owner suites and secret scan, review `git diff --cached`, then verify after push with `git fetch origin`, local/remote SHA equality and a fresh clone. A network/authentication/branch-protection failure is a failed GitHub gate; it must never be reported as a completed sync.

## Repository layout

- `cmd/` — five shipped binaries.
- `internal/` — product/domain/runtime implementation.
- `catalog/` — component contracts, policies, tenancy plans and resolved runtime bundles.
- `blueprints/` — current blueprint inputs.
- `schemas/` — machine contracts.
- `migrations/` — PostgreSQL schema evolution.
- `deploy/` — systemd, Compose and image assets.
- `scripts/` — build, validation, smoke and certification tooling.
- `tests/` — Python functional tests.
- `webconsole/` — product console assets/tests.
- `evidence/` — generated executable/runtime evidence only; ignored by Git and regenerated by validation/certification runs. Historical planning/audit prose is not stored here.

Third-party redistribution/license notes are in `THIRD_PARTY_COMPONENTS.md`. The repository license is `LICENSE.txt`.

### Persian typography

When the Operator Console locale is `fa`, both the main console and Bootstrap Installer switch to the local-only `Vazirmatn` family through CSS `local()` sources. English keeps the existing Inter/system stack. Runtime CSS contains no Google Fonts, gstatic, or font CDN dependency; if Vazirmatn is not installed on the operator workstation, the Persian stack falls back to Tahoma/system sans-serif without making a network font request.


### V53 supply-chain handoff

`SUPPLY_CHAIN_HANDOFF_V1` provides one derived connected-to-offline staging contract across catalog sources, management images, exact release toolchain bytes and S2 previous-source requirements. Staging is evidence only and cannot promote source resolution, runtime certification or Physical PASS. `MANAGEMENT_WORKLOAD_STAGED_BATCH_V1` uses the existing exact-release-bound `platformctl workload-oci` owner path for external image acquire/verify/assemble.
