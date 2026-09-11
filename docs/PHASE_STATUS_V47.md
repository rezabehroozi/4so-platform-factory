# Current Phase Status — PROGRAM_PHASE_MODEL_V47

> Snapshot for release `0.0.341`. The executable roadmap in `internal/targetmodel` is canonical. `source-implemented` is source-level only and never implies Generated Runtime, Integration, Exact-SHA Physical or production PASS.

- Total phases: **34**
- Core Freeze phases: **25**
- Core source-implemented: **19/25 = 76%**
- All source-implemented phases: **19**
- Blocked phases: **11**
- Deferred certification phases: **2**
- Not-evaluated optional phases: **2**

## Open Core Freeze phases

| Phase | Status | Current blockers |
|---|---|---|
| `C7W-mcp-user-admin-write-parity` | blocked | `MCP_EXTERNAL_CLIENT_INTEROP_MATRIX_PENDING` |
| `S1-exact-supply-chain-acquisition-closure` | blocked | `UPSTREAM_ADMISSION_REVIEWS_PENDING`, `COMPONENT_SOURCE_ACQUISITION_PENDING`, `SOURCE_LOCKS_PENDING`, `MANAGEMENT_WORKLOAD_OCI_ARCHIVE_PENDING`, `MANAGEMENT_IMAGE_DIGEST_LOCKS_PENDING`, `RELEASE_BUILD_TOOLCHAIN_LOCK_PENDING` |
| `S2-component-runtime-certification-authorities` | blocked | `COMPONENT_RUNTIME_UPGRADE_MATRIX_PENDING` |
| `H1-baremetal-connected-managed-okd` | blocked | `OKD_CONNECTED_MANAGED_INSTALL_PENDING` |
| `I1-disconnected-okd-core` | blocked | `OKD_OC_MIRROR_V2_ACQUISITION_PENDING` |
| `C9-pre-certification-feature-freeze-exact-bundle` | blocked | `PRE_CERTIFICATION_REQUIRED_FEATURES_OPEN`, `LAB_CANONICAL_BUNDLE_SOURCE_LOCKS_PENDING`, `FEATURE_CERTIFICATION_CONTRACTS_INCOMPLETE` |

## V47 AI-first MCP + Persian product-language quality

### Complete source-surface disposition

- `MCP_ROUTE_PARITY_AUTHORITY_V1` covers **318/318 stable API routes = 100% disposition coverage**.
- **147** routes are AI read, **63** are delegated operate and **71** are delegated administration.
- **37** routes are intentionally `security-excluded`; these are protected raw credential/token issuance, worker/executor internals, raw binary/evidence and MCP self-management authorities. Intentional exclusions are not missing product parity.
- No AI tool accepts an arbitrary URL, HTTP method, shell, SSH, SQL or raw database command.

### Complete durable AI mutation coverage

- `MCP_DURABLE_CONTROL_JOB_AUTHORITY_V1` covers **134/134 AI-callable mutation routes = 100%**.
- Every operate/administration bridge call requires an `idempotencyKey` before canonical mutation dispatch.
- The durable Job records family/action/method/path, request digest, actor, authentication method, OAuth client, delegation profile, organization/project scope, request ID, attempt, lease owner/expiry, fence token and terminal response digest.
- Terminal success/failure is replayable by the same idempotency key; a completed request is not executed a second time after a lost model response.
- Memory, File and PostgreSQL stores persist the same authority. PostgreSQL schema is migration `0069_mcp_durable_control_job_authority.sql`.
- `GET /api/v1/ai/control-jobs` and `GET /api/v1/ai/control-jobs/{id}` expose scoped observation without leaking raw secrets.
- `/api/v1/ai/capabilities`, `/api/v1/ai/persian-writing` and the Operator Console expose route disposition and durable mutation coverage from the same machine-readable authority.
- Repository validation fails if a new `tool-operate`/`tool-admin` route lacks durable-job, idempotency and execution-authority metadata.

### Persian product-language authority

- `persian-writing` 1.3.5 is pinned at upstream commit `118c2167f30cafe18df13c0ba85f98f50dad1894` under `third_party/persian-writing/` as an offline curated core.
- `PERSIAN_WRITING_GATE_V1` applies the formal-but-human register, orthography and anti-AI/anti-bureaucratic rules to real Console and Installer Persian copy while preserving established technical product/protocol names.
- The current gate audits 1,251 unique Persian product strings, executes the vendored upstream `fa_lint.py` engine after masking valid technical identifiers, and reports zero upstream or 4SO findings. The first semantic pass closed 83 mixed-English grammar/adjective findings; the follow-up page-by-page pass rewrote outcome/done-state and high-frequency operational copy to remove additional implementation-first English grammar.
- The runtime/API/MCP surface exposes the pinned language authority read-only through `GET /api/v1/ai/persian-writing` / `api_get_ai_persian_writing`.
- Binary fonts and the large optional upstream lexicon are intentionally not redistributed; runtime has no network dependency on the upstream repository.

### C7W truth

`MCP_WRITE_JOB_COVERAGE_PENDING` is removed. C7W remains blocked only by `MCP_EXTERNAL_CLIENT_INTEROP_MATRIX_PENDING`.

The local black-box MCP harness and source contract do **not** certify named external clients. ChatGPT, Claude, Gemini and Grok remain `externalExecution: pending` until each performs the required OAuth/delegation, tools/list restriction, read, durable mutation, approval/revocation and negative-control matrix against this exact product artifact.

### Security remains fail-closed

- User passwords, raw secrets, private keys, Keycloak admin tokens and unrestricted credentials never enter model context.
- Product RBAC and active delegation grant are intersected on every call.
- Approval remains a distinct authorized action and requester self-approval remains forbidden where domain policy requires independence.
- AI cannot declare Release PASS, Exact-SHA Physical PASS or bypass maintenance/certification gates.

## Other Core truth preserved

- H1 remains blocked on real connected Managed OKD execution evidence.
- I1 remains blocked on exact `oc-mirror v2` acquisition and disconnected certification.
- S1 remains blocked on exact upstream/source/image/toolchain acquisition truth.
- S2 remains blocked until real exact two-version component upgrade edges and runtime evidence are admitted.
- C9 remains blocked by mandatory open branches and exact bundle/certification contract closure.
- Core source closure therefore remains **19/25 = 76%**. No Physical PASS is inferred.

## Required current markers

- `PROGRAM_PHASE_MODEL_V47`
- release `0.0.341`
- `MCP_DURABLE_CONTROL_JOB_AUTHORITY_V1`
- `MCP_EXTERNAL_CLIENT_INTEROP_MATRIX_PENDING`
- `OKD_CONNECTED_MANAGED_INSTALL_PENDING`
- `OKD_OC_MIRROR_V2_ACQUISITION_PENDING`
- `RELEASE_BUILD_TOOLCHAIN_LOCK_PENDING`
- `COMPONENT_RUNTIME_UPGRADE_MATRIX_PENDING`
