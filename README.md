# 4SO Platform Factory

4SO Platform Factory is a self-contained platform control plane for catalog-driven Kubernetes platform delivery. The repository ships the API, web console, installer, fleet agent, runtime probe, CLI, schemas, migrations, embedded catalog data, deployment assets, tests, and deterministic release tooling.

`VERSION` and `RELEASE-NAME` define the packaged release identity. Git history, not version-numbered Markdown files, is the historical record.

## Operator Console design foundation

The Operator Console uses the product-owned **4SO Operator Horizon V1** theme, with **TailAdmin Community** as its primary visual/layout reference and CoreUI as an accessibility reference after a deep CoreUI/AdminMart/TailAdmin comparison. 4SO does not ship the TailAdmin demo or migrate the console to Tailwind/Alpine/React merely for appearance: the embedded 4SO HTML/CSS/JavaScript implementation, navigation taxonomy, RBAC, workflows, evidence and API authority remain product-owned. The reference is used for shell density, sidebar/header behavior, command search, dark mode, cards/tables/forms and responsive composition. See `docs/OPERATOR_CONSOLE_DESIGN_FOUNDATION.md`.

Current shell features include `Ctrl/Cmd+K` navigation search, explicit persisted light/dark mode, RTL/LTR support and Release Gate browser checks across 320/390/768/1024/1440 widths.

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

Production/lab installation requires two immutable inputs:

1. the exact `4so-platform-factory-<version>-<release>.zip` release artifact;
2. a verified appliance `bundleDirectory` containing the product-owned open-source runtime inputs and their digests.

The installer does **not** download an arbitrary `latest` dependency to make a run pass. If a required digest-locked dependency is absent, the correct result is `BLOCKED` until the canonical acquisition/bundle authority is complete.

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

The canonical machine-readable Lab contract is `LAB_CERTIFICATION_MATRIX_V1`; the schema is `schemas/lab-execution.schema.json`, the canonical example is `examples/lab/lab-execution.example.json`, and the runner is `scripts/lab_runner.py`.

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
| `production-ha` | 6 | 3 Factory management nodes + Compact-3 OKD; management HA/quorum/restart coverage |
| `day2-replacement` | 7 | production HA topology + one spare target for add/remove/replace/failure recovery |
| `full-multicluster` | 10 | 3 management + two Compact-3 targets + spare; disconnected/upgrade/chaos/soak/multi-cluster |

If a real OKD cluster already exists, it supplies the target roles; the minimum tier therefore needs only the additional Factory management server. In the current Phase C runner, SSH preflight/install is performed only for management roles. Target roles are retained in the inventory so later Phase D+ target API/Agent certification is bound to an explicit physical topology rather than inferred.

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
      "publicEndpoint": "https://factory.lab.example"
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

The state directory is evidence/checkpoint data for the run. Keep it with the exact release SHA; do not copy a PASS state to another release artifact.

### Certification matrix M00-M13

The guide and Operator Console are the canonical source for current automation status. The large matrix is:

| ID | Scope | Current ownership |
|---|---|---|
| M00 | exact SHA, archive integrity, provenance, binary version binding | Phase C |
| M01 | fresh single-node Factory management installation | Phase C |
| M02 | fresh three-node Factory management HA | Phase C |
| M03 | PostgreSQL exact-runtime migration/CRUD/restart/backup/restore | Phase C |
| M04 | OKD identity and read-only import/reconnect | Phase D |
| M05 | revocation fence and same-UID re-enrollment | Phase D |
| M06 | OKD capability ownership and health translation | Phase E |
| M07 | imported Day-2 lifecycle | Phase F |
| M08 | managed connected Compact-3 | Phase F |
| M09 | disconnected acquisition/install | Phase G |
| M10 | upgrade and recovery | Phase G |
| M11 | chaos/failure controls | Phase H |
| M12 | load and 24-hour soak | Phase H |
| M13 | two-cluster/multi-cluster certification | Phase H |

At the current `0.0.220` foundation, **M00 and M01 are implemented, M02 is partial, M03 is pending runner wiring, and M04-M13 are phase-gated**. M01 now requires a real single-node boot-ID change, installer-service recovery, post-reboot installer verification and exact-SHA evidence recollection; it still does not imply four-layer Physical PASS. Presence in this table never means later rows are already executable.

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

The Unified AI Runtime is the canonical cloud-provider path. Keep the API key outside Git and inject it only into the process environment:

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

### Local/self-hosted vLLM or another compatible endpoint

Use the OpenAI-compatible path and point it at the explicitly configured endpoint/model. This keeps disconnected/private deployments possible without making cloud AI an availability dependency:

```bash
export PLATFORM_FACTORY_AI_PROVIDER=openai-compatible-chat
export PLATFORM_FACTORY_AI_ENDPOINT='http://127.0.0.1:8000'
export PLATFORM_FACTORY_AI_MODEL='<local-model>'
export PLATFORM_FACTORY_AI_API_KEY='local-or-provider-key'
```

The core platform remains functional when the AI provider is disabled or unavailable. AI diagnosis is advisory and must not block unrelated deterministic control-plane operation.

### AI diagnosis output contract

A valid diagnosis is structured and bounded. The classification is one of:

```text
product-defect | test-defect | environment | supply-chain | unknown
```

It contains a confidence score and at most five recommended checks. Raw prompts, API keys and credentials are not durable authority. Durable `ai_runs` retain provider/model/prompt/context/output digests, usage counters, redaction counts and secret-safe structured output so retries and audits do not need to resend the original secret-bearing context.

## MCP: connect external agents to authoritative 4SO context

The current MCP boundary is stateless/read-only and uses protocol `2026-07-28` over Streamable HTTP:

```text
POST /mcp
permission: mcp.read
```

The current tool set is intentionally read-only:

- `lab_guide`
- `target_architecture_model`
- `ai_runtime_policy`
- `cluster_summary`
- `operation_status`
- `ai_run`

Create/use an API token carrying `mcp.read` for external MCP clients. Resource tools re-apply organization/project authorization inside the product; the MCP connection itself is not a cross-tenant bypass.

A generic request shape is:

```bash
curl -sS -X POST 'https://factory.example/mcp' \
  -H 'Authorization: Bearer <token-with-mcp.read>' \
  -H 'Content-Type: application/json' \
  -H 'MCP-Protocol-Version: 2026-07-28' \
  -H 'Mcp-Method: tools/list' \
  --data '{}'
```

For a tool call, use the method/name metadata required by the MCP `2026-07-28` contract and the input schema returned by discovery. Do not hard-code a mutating tool: **this phase exposes no MCP mutation tools**. Future mutations must enter the existing RBAC/preview/approval/durable-operation boundary rather than execute arbitrary shell/Kubernetes commands from an LLM.

## Release Gate: what may be called PASS

A certifiable release has four independent layers:

```text
1. Source Semantics
2. Generated/Installed Runtime Semantics
3. Runtime-Realism Negative Controls
4. Exact-SHA Physical Runtime
```

Passing layers 1-3 never authorizes a claim that layer 4 passed. AI diagnosis, Codex repair, a green local test run, a browser smoke test or an acknowledgement record cannot manufacture Physical PASS. Every physical certification must be bound to the exact release ZIP SHA and freshly collected evidence.

For the current program roadmap, `platformctl release-readiness` is the machine-readable truth:

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

- **Distribution identity** — currently admitted mutation-capable target identities are `kubernetes` and `rke2`. `okd` is authoritatively detectable through an OKD `ClusterVersion/version` release and may be imported into the read-only observation boundary, but it remains preview-only and mutation-fail-closed until its runtime certification and later capability-ownership phases are completed. Red Hat OpenShift/OCP is represented separately as `openshift`; the shared ClusterVersion API never causes OCP to be silently classified or admitted as OKD. Imported physical-cluster continuity is enforced again inside the authoritative Store using the claim-bound `kube-system` UID, so missing legacy identity evidence remains read-only and a mismatched cluster cannot refresh inventory or heartbeat state.
- **Provisioning mode** — `import-existing`, `cluster-api`, or the internal-management-plane-only `managed-install`. Installer history such as Kubespray is not a distribution identity.
- **Infrastructure provider** — a separate infrastructure fact. Imported targets currently use `existing`; external Cluster API profiles remain `unspecified` until an admitted infrastructure adapter reports an authoritative identity.
- **Provisioning adapter** — the concrete mechanism such as `cluster-api-topology-v1beta2` or fleet-agent enrollment. It is not an infrastructure provider.

The management appliance remains a self-contained RKE2 boundary and is not generalized into the target abstraction. Legacy `generic-imported` and `kubespray` compatibility values are normalized to the canonical `kubernetes` identity so existing stored releases remain readable without rewriting immutable history.

Imported targets use a two-stage RBAC boundary. The initial enrollment manifest grants only credential maintenance, inventory/read access, OpenShift `ClusterVersion/version` observation, `SelfSubjectAccessReview`, and the minimum Pod metadata/status reads required by runtime evidence. Every inventory and fallback heartbeat re-attests the live `kube-system` UID against the physical cluster UID captured at claim; only the control plane may publish `target-cluster-uid-attested`, while older Agents that cannot attest remain read-only. Mutation roles are generated separately only for a supported distribution with a fresh identity-attested inventory epoch. Mutation activation issuance is an explicit state-changing `POST /api/v1/clusters/{id}/mutation-rbac-manifest`; `GET` only retrieves an already-current issuance and cannot create authorization state as a read side effect. The control plane records issuance as the server-owned `target-mutation-rbac-activation-issued` authority; Agent-supplied copies of that marker are removed, and `target-mutation-rbac-active` is ignored until issuance exists. Issuance is bound through `mutationRbacBasisDigest` / `mutationRbacIssuedForDigest` only to stable target-authorization facts—distribution/evidence, Kubernetes version, physical-identity continuity and enrollment-principal isolation. Runtime telemetry and unrelated API/CRD/OpenAPI discovery churn remain part of the full authenticated inventory digest used by planning/task revalidation, but do not unnecessarily revoke Kubernetes RBAC. Stable target-authority drift invalidates the old issuance and returns the target to read-only until an explicit POST re-issues activation. The server also retains sticky `target-mutation-rbac-ever-issued` history so a later authority drift cannot erase evidence that target-local mutation RoleBindings may still exist. Revocation is generation-ordered: Hub credential revocation returns an idempotent target-side RBAC fence plus a canonical `targetRBACRevocationFenceDigest`; the same physical `kube-system` UID cannot be re-enrolled until an operator explicitly acknowledges that exact digest. The acknowledgement is durable/audited but is not physical proof. Migration `0050` is quiesced-required, backfills sticky mutation-RBAC history from immutable activation audit, and removes unsafe mutation authority from legacy same-UID successors until an unacknowledged revoked predecessor is fenced. Migration `0051` preserves the immutable `0050` checksum and brings PostgreSQL upgrade-state capability truth into parity with FileStore by adding the explicit `target-read-only-admission` marker only to already-inventoried repaired successors that predate (or still await) the predecessor acknowledgement. The activation manifest carries the managed-cluster ID, physical UID and issued-for basis digest in a read-only proof ConfigMap; the Agent verifies all three before proving representative permissions through `SelfSubjectAccessReview` and reporting `target-mutation-rbac-active`. Preview/unsupported distributions, including OKD in the current phase, have mutation capability claims stripped even if a stale or compromised Agent reports them. Cluster-import expiry is also backend-consistent: PostgreSQL rejects already-expired enrollment requests, renders elapsed pending/approved requests as `EXPIRED`, and atomically materializes an expired same-name generation with credential invalidation plus audit/outbox evidence before allowing replacement enrollment. New task claims require two bounded freshness facts: the Hub must have received the authoritative inventory within three minutes and the target-reported `inventoryObservedAt` must itself be within the same bounded observation window (with bounded clock skew). Stale, missing, excessively future or backwards observation epochs fail closed at the Store boundary. Migration `0052` adds this nullable observation epoch without backfilling Hub receipt time as fake target evidence, so upgraded rows remain read-only for new mutation claims until a fresh target inventory arrives. Once a task is leased, its result is judged by the unchanged authority epoch plus the task lease/fence rather than by that claim-time freshness TTL, so a legitimate long-running operation is not invalidated merely because the inventory window elapsed while it was running.

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

The default repair command is non-interactive `codex exec` with an explicit `workspace-write` sandbox; `PLATFORM_FACTORY_CODEX_COMMAND` can override the executable/arguments when a managed Codex wrapper is required. Incomplete Autopilot runs use an atomic `.state/codex-autopilot-run.json` checkpoint: a runner/process interruption resumes the proven stage prefix only when the workspace and selected graph are unchanged, and any stale active stage process group is terminated before resume. Normal terminal outcomes remove the checkpoint, so subsequent intentional runs execute fresh. Local code correctness and external release readiness are separate outcomes: `platformctl release-readiness` is the canonical machine-readable phase authority derived from the enterprise deployment plan plus the embedded upstream-admission authority, and `autopilot-release-test` / `autopilot-real-test` consume that same authority rather than maintaining a second blocker classifier. Product-owned release blockers remain fail-closed; the runtime Git-commit blocker is reported separately as deployment context because its immutable commit can exist only after the real Forgejo publication/handover boundary. A planning-only baseline does not turn a clean repository into a code defect. The real-test boundary additionally requires the live PostgreSQL/field-campaign environment documented by its preflight; it is not simulated by the local repair loop.

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

Host deployment is available through `platformctl installer-host ...`; remote bootstrap through `platformctl installer-remote ...`; the coordinated three-host path uses `platformctl zero-to-ha ...`. All destructive transitions require their explicit confirmation tokens shown by `platformctl --help`.

An appliance bundle must be local and digest-locked. Missing artifacts are not downloaded during installation. See `examples/appliance-bundle/README.md` for the required bundle-input intent.

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

`GET /api/v1/ai/policy`, `POST /api/v1/ai/diagnose` and `GET /api/v1/ai/runs` power the Operator Console **AI Control Plane**, which shows effective provider/model/budgets, actual token/cache/redaction usage, linked authoritative resources and inspectable durable advisory evidence. `mcp.read` and `ai.diagnose` are dedicated API-token capabilities; project-scoped MCP/AI reads re-apply product project authorization. `POST /mcp` is stateless/read-only on protocol `2026-07-28` in this phase and exposes only tools declared by the same lab authority.

`GET /api/v1/lab/guide` and the Operator Console **Lab & Certification** page consume the same `LAB_CERTIFICATION_MATRIX_V1` authority. It defines four server tiers and M00-M13 with phase ownership, destructive scope, actions, AI eligibility and executable automation status. The canonical runner is `scripts/lab_runner.py` (`guide`, `self-test`, `plan`, `preflight`, `run`). AI is failure-only and bounded; it never owns PASS/FAIL. Missing digest-locked dependency acquisition or required physical infrastructure is reported as `BLOCKED`, never replaced by an unpinned latest download or inferred success.

## Current limitations

`platformctl release-readiness` reports two distinct truths: selected-blueprint release gates and the canonical `PROGRAM_PHASE_MODEL_V3` product roadmap. The current product phase is `C-ai-native-operator-experience-lab-mcp-foundation`. The roadmap is deliberately grouped into eight large phases: A) architecture/authority rebaseline, B) target capability/supply-chain foundation, C) AI-native Operator Experience + Lab + MCP foundation, D) OKD import identity/security certification, E) capability/catalog/blueprint + AI explainability, F) Day-2/managed Compact-3 workflow convergence, G) disconnected/upgrade/recovery + local AI, and H) full product certification including chaos/soak/UI/accessibility/AI/MCP evaluation. Source implementation is never evidence for Generated/Installed Runtime, runtime-realism or Exact-SHA Physical PASS.

Local tests and smoke suites are not external target certification. The repository contains unresolved external catalog components that remain non-executable until their exact source/image/license/SBOM/provenance closure is supplied. Production readiness must therefore be established by the required disposable-target, PostgreSQL, HA/DR, security, load/soak and supported-upgrade certification evidence; it is not inferred from static or local test success.


## Canonical GitHub repository and Definition of Done

The canonical repository is `https://github.com/rezabehroozi/4so-platform-factory` on branch `main`. GitHub is part of product Definition of Done, not a selected-file publishing destination. A meaningful feature, bugfix, refactor, phase/UI/installer/documentation change or release is complete only after the full source-of-truth working tree is reviewed, staged with `git add -A`, committed, pushed to canonical `main`, remote HEAD is verified against local HEAD, and releases/major changes pass a clean-clone verification. `.github/workflows/repository-integrity.yml` performs an independent clean checkout/clone plus repository validation, Go build/test/vet and Python tests on GitHub runners.

A clean clone must contain the backend, frontend/Operator Console, API, migrations, schemas, installers/deployment assets, configuration/templates, scripts/tools, tests/validators, documentation, phase/checkpoint authority, `VERSION`, release instructions and `AGENTS.md`. Build outputs and local runtime evidence are intentionally excluded. In particular `/bin`, `/release`, `/.smoke-evidence`, `/evidence`, `.state`, caches, logs and real secret material are reconstructed by build/test/runtime workflows and are not source-of-truth Git content.

The repository currently uses neither Git submodules nor Git LFS. The retained `snapshot-controller-v8.5.0-official-tag-source-set.zip` and `catalog/runtime/.../artifact.bin` inputs are small, digest-bound vendored supply-chain material and therefore remain ordinary tracked Git files. Product-owned large runtime dependencies that are not vendored must be acquired only through the documented exact-version/digest bundle/bootstrap path; arbitrary `latest` downloads are not a valid substitute.

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
