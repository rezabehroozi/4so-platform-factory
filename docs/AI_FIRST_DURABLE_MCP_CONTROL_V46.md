# AI-First Durable MCP Control — V46 / 0.0.340

## Product decision

AI Enablement and MCP are first-class product capabilities. A product workflow is not considered AI-enabled merely because an API endpoint exists: authorized AI clients must be able to discover the capability, inspect scoped state, plan/preview where applicable, request the allowed action, follow approvals, observe the durable execution, and inspect result evidence through the same server-side product authority used by UI/API.

## Coverage contract

`MCP_ROUTE_PARITY_AUTHORITY_V1` maps every stable `/api/v1` route to one of four dispositions: `tool-read`, `tool-operate`, `tool-admin`, or explicit `security-excluded`. V46 has no pending route disposition.

AI-callable mutation routes are additionally governed by `MCP_DURABLE_CONTROL_JOB_AUTHORITY_V1`. The route bridge is fixed-family/fixed-action; the model cannot supply an arbitrary route or HTTP method. Every write/admin call requires a caller-provided idempotency key and records a durable control Job before canonical REST mutation dispatch.

## Durable control Job

The Job stores only bounded product-control metadata and a bounded sanitized terminal response. It records request digest rather than persisting arbitrary prompt/body material as a second authority. The authority includes actor, OAuth client, human delegation profile, resource scope, attempt, lease/fence and terminal result digest. The same terminal idempotency key returns the sealed result instead of executing the mutation again.

Persistence parity is implemented for Memory, File and PostgreSQL. PostgreSQL migration `0069_mcp_durable_control_job_authority.sql` owns the database schema and uniqueness boundary.

## Authorization and safety

- OAuth/OIDC human identity remains Keycloak-backed and user-centric.
- Effective permission is the intersection of current product RBAC, active delegation grant, friendly access profile, organization/project/resource scope and domain policy.
- `READ_ONLY`, `OPERATE` and `ADMINISTRATION` remain separate delegation profiles.
- High-impact approval tools remain separate from request tools; self-approval cannot be synthesized by the model.
- Raw passwords, bearer tokens, private keys, kubeconfig, Keycloak admin credentials, SSH, shell, SQL, unrestricted OpenSearch/Git administration and PASS/Physical-PASS authority are forbidden.
- Raw binary/evidence or worker-internal routes remain explicit security exclusions instead of being exposed to satisfy a numeric coverage target.

## Observation

`GET /api/v1/ai/capabilities` is the product truth for current AI enablement and returns route-parity plus durable-mutation coverage. `GET /api/v1/ai/control-jobs` and `GET /api/v1/ai/control-jobs/{id}` provide scoped lifecycle observation. The Operator Console AI Control Plane renders the same authority.

## Remaining external certification

Source/API/MCP coverage is not named-client certification. `lab/mcp-external-client-interop-matrix.json` remains the authority for ChatGPT, Claude, Gemini and Grok external execution. Local black-box conformance is necessary but is not substituted for actual external OAuth/delegation/revocation execution.

## Generated route truth at seal candidate

- Stable routes: **317/317 disposition-covered**.
- AI-callable routes: **280**.
- Read: **146**; Operate: **63**; Administration: **71**.
- Explicit security exclusions: **37**, each with machine-readable rationale.
- AI-callable mutation routes under durable control-job authority: **134/134 = 100%**.
## Release closure security finding

The final black-box MCP pass found and closed a development-only privilege-boundary defect: the loopback authentication middleware intentionally gives the local REST/UI session a `local-development` platform-admin principal, and legacy MCP visibility initially treated that compatibility principal as an MCP administration grant. V46 now makes the local-development principal **read-only on `/mcp`**. Operate/administration visibility requires an explicit API-token permission or active `mcp-human` OAuth delegation. A regression test models the injected development principal and the black-box MCP harness independently verifies that every unauthenticated development tool is `mcp.read`.

Final local conformance markers for the 0.0.340 seal candidate:

- `MCP_EXTERNAL_CLIENT_CERTIFICATION_PASS` for the protocol/read-only black-box harness.
- `AI_CONTROL_PLANE_RUNTIME_SMOKE_PASS` on the rebuilt 0.0.340 binary, including 317/317 route disposition and 134/134 durable mutation assertions.
- `UI_LIVE_AUTHORITY_SMOKE_PASS` on the rebuilt 0.0.340 binary.

These are local product conformance checks only. They do not replace real named-client execution for ChatGPT, Claude, Gemini or Grok.

