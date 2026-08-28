# 4SO Platform Factory

4SO Platform Factory is a self-contained, catalog-driven enterprise platform control plane for delivering and operating Kubernetes platforms while keeping product authority, durable operations, evidence, policy, supply-chain state, and release truth inside 4SO.

Current development line: **0.0.217 — `ai-native-control-plane-foundation`**.

The product is intentionally **AI-native but not AI-authoritative**: AI can explain, diagnose, compare evidence, and propose safe next checks; it cannot bypass RBAC, approvals, durable operations, deterministic test truth, or Exact-SHA Physical Runtime certification.

## Project goals

4SO Platform Factory owns:

- organizations, projects, tenants and RBAC;
- PostgreSQL control-plane source of truth;
- catalog, blueprint, target and fleet authority;
- durable operations, retry/resume/idempotency/fencing;
- evidence, audit, release readiness and certification state;
- Forgejo/Git desired-state integration;
- zot as the canonical product registry;
- target distribution capability discovery and translation;
- installer/bootstrap/upgrade/recovery workflows;
- Operator Console and API;
- deterministic Lab certification;
- AI diagnosis/control-plane context and read-only MCP access.

Target distributions remain responsible for their native internals. In particular OKD owns its Cluster Operators/CVO/MCO/OVN-Kubernetes/OLM/SCC/monitoring/ingress/registry/upgrade semantics. 4SO does not clone the OKD Console or replace native distribution controllers.

## Program phases

`PROGRAM_PHASE_MODEL_V2` is grouped into eight large phases:

1. **A — Architecture Rebaseline** — source implemented.
2. **B — Target Capability Contract Foundation** — source implemented.
3. **C — AI-Native Control Plane + Lab + MCP Foundation** — current phase.
4. **D — OKD Import Runtime Certification**.
5. **E — OKD Capability + Profile + Catalog Integration**.
6. **F — Imported Day-2 + Managed Compact-3**.
7. **G — Disconnected + Upgrade + Recovery**.
8. **H — Full Exact-SHA Physical Certification + Chaos + Soak + Multi-cluster**.

Source completion never implies physical certification. The current Phase C remains blocked until its real-server/runtime exit criteria are evidenced.

## Release Gate — non-negotiable

A certifiable release must independently pass all four layers:

```text
1. Source Semantics
2. Generated / Installed Runtime Semantics
3. Runtime-Realism Negative Controls
4. Exact-SHA Physical Runtime
```

Passing layers 1–3 never authorizes a Physical PASS claim. AI output, local unit tests, browser smoke tests, acknowledgement records, or a successful source build cannot manufacture layer 4.

## Repository contents

The canonical source tree contains:

- `cmd/` — shipped binaries;
- `internal/` — domain/control-plane/runtime implementation;
- `catalog/` — component contracts and resolved runtime material;
- `blueprints/` — product blueprints;
- `schemas/` — machine-readable contracts;
- `migrations/` — PostgreSQL schema evolution;
- `deploy/` — systemd/Compose/image deployment assets;
- `scripts/` — build, validation, Lab and certification tooling;
- `tests/` — Python functional/regression tests;
- `webconsole/` — Operator Console;
- `docs/` — current operational documentation only.

Git history is the history. Do not create release-numbered audit/handoff/roadmap Markdown mirrors.

# Clone, build and local test

Canonical repository:

```bash
git clone https://github.com/rezabehroozi/4so-platform-factory.git
cd 4so-platform-factory
```

## Developer prerequisites

The module targets Go 1.23. On a Debian/Ubuntu development workstation:

```bash
sudo apt-get update
sudo apt-get install -y \
  build-essential gcc make git pkg-config libpq-dev \
  python3 python3-venv python3-pip jq curl unzip \
  ca-certificates openssh-client

go version
python3 --version
```

Browser/UI tooling should be isolated:

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements-test.txt
python3 -m playwright install chromium
```

For a disposable CI/lab host:

```bash
python3 -m playwright install --with-deps chromium
```

Do **not** manually install product runtime services merely to satisfy a test. PostgreSQL/RKE2/Forgejo/zot/Keycloak and other product-owned runtime inputs are owned by the installer/appliance bundle path.

## First validation

```bash
python3 scripts/validate_repository.py .
python3 scripts/lab_runner.py self-test
make autopilot-self-test
```

Then:

```bash
make test
make vet
make race
make build
make smoke
make smoke-ui
```

Release tooling:

```bash
make release
make verify-release
```

A timeout or missing physical/external dependency is not converted into PASS.

## Local API / Operator Console

Explicit development-only file authority:

```bash
mkdir -p .state
PLATFORM_FACTORY_DEVELOPMENT_MODE=true \
PLATFORM_FACTORY_STATE_FILE=.state/control-plane.json \
./bin/platform-api
```

For production-like runtime use PostgreSQL:

```bash
export PLATFORM_FACTORY_POSTGRES_DSN='postgres://...'
./bin/platform-api
```

The API must not silently fall back from configured production PostgreSQL to in-memory/file state.

# Fresh-server installation

Production/Lab installation is bound to two immutable inputs:

1. the exact `4so-platform-factory-<version>-<release>.zip`;
2. a verified appliance `bundleDirectory` with exact versions/digests/licenses/provenance for product-owned open-source runtime inputs.

The installer must never download an arbitrary `latest` dependency just to make a run pass. Missing immutable acquisition authority is `BLOCKED`.

## Direct host workflow

```bash
cat examples/installer-host/deployment.example.json
./bin/linux-amd64/platformctl installer-host preflight \
  --spec examples/installer-host/deployment.example.json
./bin/linux-amd64/platformctl installer-host plan \
  --spec examples/installer-host/deployment.example.json
```

Explicit apply:

```bash
sudo ./bin/linux-amd64/platformctl installer-host apply \
  --spec examples/installer-host/deployment.example.json \
  --confirmation DEPLOY
```

Then verify durable state:

```bash
sudo ./bin/linux-amd64/platformctl installer-host status
sudo ./bin/linux-amd64/platformctl installer-host verify
```

Recovery actions remain explicit:

```bash
sudo ./bin/linux-amd64/platformctl installer-host rollback --confirmation ROLLBACK
sudo ./bin/linux-amd64/platformctl installer-host recover --confirmation RECOVER
```

## Remote bootstrap

```bash
cp examples/installer-remote/bootstrap.example.json /tmp/4so-remote.json
./bin/linux-amd64/platformctl installer-remote preflight --spec /tmp/4so-remote.json
./bin/linux-amd64/platformctl installer-remote plan --spec /tmp/4so-remote.json
./bin/linux-amd64/platformctl installer-remote apply --spec /tmp/4so-remote.json --confirmation DEPLOY
./bin/linux-amd64/platformctl installer-remote verify --spec /tmp/4so-remote.json
```

Use `platformctl zero-to-ha ...` for the coordinated single-management to three-management handoff. Do not bypass known-host, identity, confirmation, fencing, or durable-state checks with ad-hoc SSH.

# Deterministic Physical Lab

The machine-readable Lab authority is `LAB_CERTIFICATION_MATRIX_V1`; the execution schema is `schemas/lab-execution.schema.json`; the runner is `scripts/lab_runner.py`.

Always inspect the guide from the exact checkout/artifact being tested:

```bash
python3 scripts/lab_runner.py guide | jq .
```

Canonical sequence:

```text
guide -> self-test -> plan -> preflight -> run
```

The deterministic runner owns execution and PASS/FAIL. AI is invoked only after a deterministic failure and sees only a bounded centrally-redacted failure packet.

## Server tiers

| Tier | Servers | Purpose |
|---|---:|---|
| `current-import-minimum` | 4 | 1 Factory management + Compact-3 OKD target |
| `production-ha` | 6 | 3 Factory management + Compact-3 OKD |
| `day2-replacement` | 7 | production HA + spare target |
| `full-multicluster` | 10 | 3 management + two Compact-3 targets + spare |

If a real OKD cluster already exists, its three target nodes satisfy the target roles. The minimum import tier therefore needs one additional Factory management server.

Current management-host Lab floor is **4 vCPU / 16 GiB RAM / 100 GiB free disk**. Always trust the machine-readable guide in the exact release over copied prose if they differ.

## SSH preparation

The current Phase-C management installer requires root SSH because it owns system services/storage/RKE2 bootstrap. Strict host-key verification is mandatory:

```bash
install -m 600 ~/.ssh/id_ed25519 /tmp/4so-lab-id
ssh-keyscan -H 10.0.0.11 > /tmp/4so-known-hosts
ssh -i /tmp/4so-lab-id \
  -o UserKnownHostsFile=/tmp/4so-known-hosts \
  -o StrictHostKeyChecking=yes \
  root@10.0.0.11 true
```

Do not use `StrictHostKeyChecking=no` for certification.

## Example LabExecution

```json
{
  "apiVersion": "platform.4so.io/v1alpha1",
  "kind": "LabExecution",
  "metadata": {"name": "factory-0217-import-lab"},
  "spec": {
    "releaseArtifact": "/srv/4so/release/4so-platform-factory-0.0.217-ai-native-control-plane-foundation.zip",
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
    "management": {"publicEndpoint": "https://factory.lab.example"},
    "ai": {
      "provider": "none",
      "maxOutputTokens": 800,
      "maxTurns": 2,
      "maxBudgetUSD": 1
    }
  }
}
```

Plan/preflight without mutation:

```bash
python3 scripts/lab_runner.py plan --spec /tmp/4so-lab.json | jq .
python3 scripts/lab_runner.py preflight --spec /tmp/4so-lab.json | tee /tmp/4so-preflight.json
```

Run after reviewing exact SHA/topology/destructive rows:

```bash
mkdir -p /srv/4so/lab-state
python3 scripts/lab_runner.py run \
  --spec /tmp/4so-lab.json \
  --state-dir /srv/4so/lab-state \
  --confirmation RUN
```

Keep the state/evidence directory bound to the exact release SHA. Never reuse a PASS state for another artifact.

## Matrix M00–M13

| ID | Scope | Phase |
|---|---|---|
| M00 | Exact SHA/archive/provenance/binary identity | C |
| M01 | Fresh single-management install | C |
| M02 | Fresh three-management HA | C |
| M03 | PostgreSQL migration/CRUD/restart/backup/restore | C |
| M04 | OKD identity + read-only import/reconnect | D |
| M05 | Revocation fence + same-UID re-enrollment | D |
| M06 | Capability ownership + health translation | E |
| M07 | Imported Day-2 lifecycle | F |
| M08 | Managed connected Compact-3 | F |
| M09 | Disconnected acquisition/install | G |
| M10 | Upgrade + recovery | G |
| M11 | Chaos/failure controls | H |
| M12 | Load + 24-hour soak | H |
| M13 | Two-cluster/multi-cluster certification | H |

Current automation truth: **M00 IMPLEMENTED; M01/M02 PARTIAL; M03 PENDING; M04–M13 PENDING_PHASE.** Presence in the roadmap never means automation is already complete.

# Testing with Codex, Claude Code, Antigravity and AI APIs

The token/cost rule is simple: **do not ask an LLM to rediscover the repository test suite**. Deterministic scripts run first. Only failures are reduced to bounded redacted packets for AI diagnosis/repair.

## Codex — bounded repair worker

```bash
make autopilot-preflight
make autopilot-self-test
make autopilot-test
```

Explicit bounded repair:

```bash
python3 scripts/codex_autopilot.py --repair --max-repairs 3
```

Codex repair is a repository worker, never Release PASS authority.

## Claude Code — failure-only Lab diagnosis

Lab fragment:

```json
{
  "provider": "claude-code",
  "maxOutputTokens": 800,
  "maxTurns": 2,
  "maxBudgetUSD": 1
}
```

The runner uses non-persistent/bare structured output with bounded turns/budget. Claude is not given target shell authority by the Lab diagnosis path.

## Codex CLI — Lab diagnosis

```json
{"provider": "codex-cli", "maxOutputTokens": 800}
```

Lab diagnosis uses read-only/ephemeral semantics and is separate from the explicitly repair-capable repository autopilot.

## Antigravity

Antigravity is optional and not a certification dependency:

```json
{
  "provider": "antigravity-command",
  "command": "/opt/4so/bin/antigravity-diagnose"
}
```

The adapter reads the bounded diagnosis prompt and must emit the exact structured JSON diagnosis contract. Invalid output/timeout is `BLOCKED`; deterministic truth is unchanged.

## OpenAI Responses

Keys stay outside Git:

```bash
export PLATFORM_FACTORY_AI_PROVIDER=openai-responses
export PLATFORM_FACTORY_AI_MODEL='<approved-model>'
export PLATFORM_FACTORY_AI_API_KEY='...'
export PLATFORM_FACTORY_AI_MAX_OUTPUT_TOKENS=800
```

Inspect non-secret effective policy:

```bash
./bin/linux-amd64/platformctl ai policy
```

Test redaction before egress:

```bash
./bin/linux-amd64/platformctl ai redact -f /path/to/context.json
```

Lab fragment:

```json
{
  "provider": "openai-responses",
  "model": "<approved-model>",
  "apiKeyEnv": "PLATFORM_FACTORY_AI_API_KEY",
  "maxOutputTokens": 800
}
```

## Local/self-hosted model (vLLM or compatible endpoint)

```bash
export PLATFORM_FACTORY_AI_PROVIDER=openai-compatible-chat
export PLATFORM_FACTORY_AI_ENDPOINT='http://127.0.0.1:8000'
export PLATFORM_FACTORY_AI_MODEL='<local-model>'
export PLATFORM_FACTORY_AI_API_KEY='local-or-provider-key'
```

Cloud AI is optional. Core platform availability must not depend on an external model provider.

## Unified AI safety boundary

`UNIFIED_AI_RUNTIME_V1` enforces:

- fail-closed provider configuration;
- central pre-egress secret redaction;
- bounded input/output budgets;
- structured diagnosis output;
- durable project-scoped `ai_runs` containing digests/usage/redaction metadata and secret-safe output;
- no raw secret-bearing prompt as control-plane SoT;
- idempotent replay without a second model call when durable result already exists;
- project validation for linked operations/clusters;
- advisory-only AI result.

AI classification is one of:

```text
product-defect | test-defect | environment | supply-chain | unknown
```

AI cannot declare PASS/Physical PASS and cannot directly execute shell/kubectl mutations.

# MCP for external agents

Current MCP boundary:

```text
POST /mcp
protocol: 2026-07-28
scope: mcp.read
mode: stateless/read-only
```

Current tools:

- `lab_guide`
- `target_architecture_model`
- `ai_runtime_policy`
- `cluster_summary`
- `operation_status`
- `ai_run`

Generic discovery request:

```bash
curl -sS -X POST 'https://factory.example/mcp' \
  -H 'Authorization: Bearer <token-with-mcp.read>' \
  -H 'Content-Type: application/json' \
  -H 'MCP-Protocol-Version: 2026-07-28' \
  -H 'Mcp-Method: tools/list' \
  --data '{}'
```

Resource tools re-apply organization/project authorization. This phase exposes no mutating MCP tools. Future mutation tools must create/inspect the existing RBAC + impact-preview + approval + durable-operation workflow; an LLM never gets a parallel shell authority.

# Operator Console

The Operator Console is workflow-first and consumes live authorities rather than mock/stale duplicate data.

AI Control Plane shows:

- effective provider/model/configuration;
- input/output token budgets;
- actual input/output/cached-token usage;
- redaction counts;
- MCP protocol/endpoint/scopes/tools;
- context-bound diagnosis for real Operation/Cluster resources;
- project-filtered durable AI run history;
- inspectable structured advisory evidence;
- explicit `advisory-only` / `executionAllowed=false` boundary.

Lab & Certification shows the same `LAB_CERTIFICATION_MATRIX_V1` used by the runner: server tiers, roles, M00–M13, destructive scope, actions, AI eligibility, automation status and phase ownership.

UI Release Gate must exercise AI and Lab pages across desktop/mobile viewports; those pages are not exempt from responsive/accessibility/runtime-truth tests.

# Security and control-plane rules

- PostgreSQL is the production control-plane SoT.
- Secrets/credentials are references or injected through explicit secret boundaries; they are not copied into durable API/audit/AI payloads.
- Agent bootstrap bearer enrollment is one-shot; certificate lifecycle owns later rotation/re-enrollment.
- New target enrollment gets generation-scoped Kubernetes identity/RBAC; revoked generation mutation authority is not inherited.
- Resolved catalog sources are exact and digest-bound.
- Missing source/runtime/physical evidence remains unresolved/blocked; validators must not invent it.
- Correct product behavior wins over stale source-text validators; stale validators are fixed rather than weakening runtime behavior.

# Current limitations

Phase C is not Physical PASS. Remaining large closures include:

- real server-driven M00–M03 execution;
- immutable automatic open-source acquisition from product-shipped version/digest authority;
- PostgreSQL-backed AI durability runtime proof;
- external MCP interoperability with real clients;
- physical failure → AI diagnosis evidence;
- later OKD import/Day-2/disconnected/upgrade/chaos/soak/multi-cluster phases.

Use:

```bash
./bin/linux-amd64/platformctl release-readiness \
  -f blueprints/enterprise-private-cloud.json | jq .
```

for the machine-readable current release/program truth.

## Documentation policy

Documentation must describe commands/paths/features that exist in the same source release. Historical project state belongs in Git history. Third-party redistribution/license information is in `THIRD_PARTY_COMPONENTS.md`; repository licensing is in `LICENSE.txt`.
