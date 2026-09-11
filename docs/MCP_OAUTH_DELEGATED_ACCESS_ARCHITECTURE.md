# MCP Remote OAuth / Human Delegated Access Architecture

**Authority:** `MCP_REMOTE_OAUTH_DELEGATION_ARCHITECTURE_V1`  
**Program authority:** `PROGRAM_PHASE_MODEL_V37`  
**Status:** C7R remote human OAuth delegation is source-implemented in 0.0.318. Trusted-client admission, durable revocable delegation grants, per-request revocation/RBAC enforcement, platform/organization/project scoping and consent APIs are product-owned. C7W full User/Admin operation parity remains mandatory before C9 Feature Freeze.

## Decision

4SO Platform Factory exposes one remote MCP resource server for ChatGPT, Claude, Gemini, Grok and other standards-compatible clients. Keycloak remains the single self-hosted OIDC/OAuth authorization authority. The MCP server is a resource server and delegated product gateway; it is not a second identity provider and never receives a user's password.

The existing service-account/API-token MCP path remains useful for non-human automation, but it is not the primary human integration model. Human MCP clients must use OAuth/OIDC and act as the signed-in user under current product RBAC plus a revocable MCP delegation grant.

## User experience

Normal users should see only this journey:

1. **Sign in with organization account** — redirect to branded Keycloak login.
2. **Select access context** — Platform administration, one Organization, or one/more Projects that the current user can actually access.
3. **Choose friendly access** — e.g. View, Operate, or Administration. OAuth scope strings, revision numbers, internal tool names and token claims are hidden from the normal flow.
4. **Describe the desired change** in ChatGPT/Claude/Gemini/Grok.
5. **Inspect platform-generated preview** — target, impact, risk, approval/window requirements and expected result.
6. **Confirm/request** — the model creates or advances a durable product Job/Operation; it never receives SSH, database or administrator credentials.
7. **Follow result** — job status, audit timeline and evidence are visible both in the AI client and Operator Console.

Advanced operators may inspect protocol/client/grant details in an expandable technical view, but those details are not required for normal use.

## 0.0.318 implementation checkpoint

Source-implemented in this release:

- `GET /.well-known/oauth-protected-resource` advertises the MCP protected resource and Keycloak authorization server.
- unauthorized `/mcp` requests return a Bearer `WWW-Authenticate` challenge carrying the protected-resource metadata location.
- MCP access-token validation uses a dedicated `platform-mcp` audience (configurable with `PLATFORM_FACTORY_MCP_OAUTH_AUDIENCE`) instead of reusing the ordinary API audience.
- the Operator Console renders the human connection journey without enabling a fake Connect action.

C7R is closed at source level. C7W remains fail-closed and mandatory for complete User/Admin read/write parity and external-client interoperability before C9 Feature Freeze.

## Identity and token architecture

`Keycloak -> OAuth access token -> /mcp resource server -> Product RBAC + MCPDelegationGrant -> Tool/action policy -> Domain authority`

Required properties:

- MCP protocol `2026-07-28`, stateless Streamable HTTP.
- `/.well-known/oauth-protected-resource` identifies the Keycloak issuer/authorization server.
- Unauthorized protected requests return OAuth-compliant HTTP `401` plus `WWW-Authenticate`; authorization failure is not hidden only inside a JSON-RPC tool error.
- Access tokens are short lived and audience/resource restricted to the MCP resource server.
- Validate issuer, audience/resource, subject, authorized client, expiry/not-before and signature/JWKS. Token acceptance must not be based only on possession of a generic bearer token.
- Refresh/offline access is allowed only when tenant policy and the external client support it. Refresh tokens are never returned to tools/model context.
- Dynamic client registration is disabled by default. Trusted client metadata or explicit administrator registration is preferred; client metadata and redirect URI changes are reviewable/auditable.
- Raw passwords, Keycloak administrator tokens, client secrets and product secrets never enter model prompts, MCP arguments, durable audit payloads or evidence.

## Product-owned delegation grant

OAuth proves identity; it does **not** become the product authorization database.

`MCPDelegationGrant` is PostgreSQL product authority and binds:

- Keycloak issuer + subject;
- external MCP client identity;
- platform / organization / project resource set;
- friendly access profile and underlying action families;
- creation/consent revision;
- expiry;
- ACTIVE / REVOKED state;
- optional tenant policy constraints.

Effective authorization on every request is the intersection of:

1. authenticated Keycloak human identity;
2. current Organization/Project membership and product RBAC;
3. current active MCP delegation grant;
4. current external-client trust/admission;
5. tool/action policy;
6. resource scope;
7. current domain state/capability/revision/window/approval rules.

A token can therefore never preserve access after membership/grant revocation. Revocation is product-state authoritative and is checked on every protected invocation.

## Tool architecture

Tools remain separate internally even though users do not need to know their names.

### 1. Discover / read

Examples: organizations/projects, clusters, blueprints, workspaces, operations, logs, evidence, health, policy, identity mappings and supported action context.

### 2. Plan / preview

Side-effect-free impact planning. Preview tools return exact target identity, requested change, risk, prerequisites, expected impact, approval/window requirements and recovery path.

### 3. Request change

Write-capable tools **never mutate authoritative resources directly**. They create or advance the same typed durable Job/Operation used by UI/API, with idempotency/request digest and resource identity fences.

### 4. Approval

Approval is a separate action family. It may be exposed through MCP to an independently authorized principal when domain policy permits. High-impact requester self-approval remains fail-closed. Approval is itself durable/audited evidence attached to the Job/Operation.

### 5. Operation / evidence

Read job progress, bounded logs, retries, approvals, result evidence, recovery state and final audit timeline.

### 6. Identity / administration

Admins can perform product-supported identity/administration operations through typed jobs. Server-held Keycloak administration credentials remain server-side and scoped. MCP never exposes raw Keycloak Admin REST credentials or a generic Keycloak administration proxy.

## Meaning of “admin/user can do everything”

“Everything” means **every product-supported action for which that human principal is currently authorized** has an explicit MCP disposition. It does not mean arbitrary infrastructure access.

Explicitly forbidden direct authorities:

- raw SSH/shell;
- arbitrary `kubectl`;
- arbitrary SQL/database access;
- secret/private-key retrieval;
- unrestricted Forgejo/zot/OpenSearch/Keycloak administrator passthrough;
- worker claim/fence mutation internals;
- requester self-approval bypass;
- overriding release or Physical PASS authority.

A coverage validator must fail C7W if a stable API/product action has neither a typed MCP tool nor an explicit security exclusion with rationale.

## Operator Console

Add **Admin -> AI & Integrations -> MCP Connections** with two audiences:

- **My AI connections**: Connect, choose Organization/Project, friendly access profile, expiry, revoke, last use, recent jobs.
- **MCP administration**: admitted clients, metadata/redirect identity, tenant policy, grant inventory, revocation, tool/action coverage, denied-call audit, interoperability results.

The normal connection wizard never asks the user to type OAuth scopes, revision numbers or tool names.

## External interoperability targets

The product has one MCP server, not four provider-specific backends. ChatGPT, Claude, Gemini and Grok are black-box interoperability targets. Client-specific plan/feature availability is treated as external runtime capability and must not change 4SO authority semantics.

Per-client certification checks:

- OAuth discovery and sign-in;
- tool discovery/filtering;
- project/resource isolation;
- read invocation;
- low-risk write job;
- high-risk write stopping at required approval;
- separate-principal approval where policy permits;
- revocation while token is still cryptographically valid;
- tool allow-list/restriction behavior where the client supports it;
- prompt-injection attempt cannot escape the product action registry;
- no secret/password/token appears in returned tool content/evidence.

## Phase ownership

### C7 — Delegated Operation Foundation — source-implemented

Keeps the current MCP 2026-07-28 protocol, service-account path, scoped read tools and existing allow-listed durable request tools.

### C7R — Remote OAuth Human Delegation — mandatory / source-implemented

Owns OAuth protected-resource discovery, Keycloak MCP audience/resource server, client trust, durable revocable grants, token revocation enforcement and connection/consent UX. These source-level requirements are implemented; external-client interoperability remains a C7W certification concern rather than a C7R implementation blocker.

### C7W — User/Admin Write Parity — mandatory / open

Owns complete user/admin parity. `MCP_PRODUCT_ACTION_REGISTRY_V1` now classifies every stable `/api/v1` route family and `MCP_EFFECTIVE_TOOL_FILTERING_V1` keeps `tools/list` and `tools/call` on the same fail-closed tool authorization path. Remaining blockers are all-write-to-job coverage, approval-operation parity, identity/admin job adapters and the external-client interoperability matrix; `pending-parity` registry entries remain explicit and cannot fall back to a generic mutation tool.

Both phases are pre-C9 development work. Exact-SHA physical installation/certification remains deferred until development closure and is **not** a blocker for implementing or testing these phases.
