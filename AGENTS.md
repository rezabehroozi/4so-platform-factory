# Agent repository instructions

This file is a machine-consumed contributor contract. It intentionally contains stable engineering rules, not release history or project-state mirrors.

- Product behavior is authoritative in implementation, schemas, migrations and tests. Do not create prose source-of-truth layers for runtime state.
- Production control-plane state must be durable; do not introduce an implicit in-memory production fallback.
- Preserve fail-closed handling at authoritative persistence, approval, credential, rollback/recovery and supply-chain boundaries.
- Raw secrets must not be persisted in API resources, audit/event payloads, generated artifacts or Git. Use the existing credential-reference and secret-injection boundaries.
- Agent bootstrap bearer enrollment is one-shot; certificate rotation/re-enrollment must use the certificate authority workflow.
- Resolved catalog sources must remain exact, offline-verifiable and digest-bound. Helm sources must also retain exact render-generation provenance (toolchain, render semantics and values-file digests). Do not convert an unresolved research source into executable state by setting flags or placeholder digests.
- Local/unit/smoke success is not external runtime certification. Never promote a local result into an external/production claim.
- Runtime certification scope must match what the run actually installed and verified from immutable source. Target/cluster capability evidence must not be reused as per-component certification for components that were not installed by that run, and source/offline plan metadata must never become execution-ready without durable control-plane certification authority.
- Add regression coverage to the existing owner package or smoke suite. Do not create release-numbered validators or require validator churn merely because a version/source file changed.
- Operator Console and Bootstrap Installer changes must follow `DESIGN.md`, the canonical product design language. Preserve workflow clarity, runtime truth, accessibility, responsive behavior and the anti-generic enterprise UI constraints documented there.
- Keep documentation minimal and current. Git is history; do not add handoff/state/roadmap/audit Markdown mirrors.
- When a stale validator conflicts with correct product behavior, fix the validator. When a test exposes a real product defect, fix the product owner layer rather than weakening the test.
- GitHub is part of Definition of Done. After every meaningful feature, bugfix, refactor, phase, UI/UX, installer, documentation or release change: validate; review the full working tree; `git add -A`; review staged files; commit; push the canonical `main`; verify the remote SHA matches local HEAD; and for releases/major changes verify a clean clone. Never claim a repository sync from selected-file pushes.
- Canonical repository: `https://github.com/rezabehroozi/4so-platform-factory`, branch `main`. The canonical Git repository must contain every source/config/schema/migration/installer/deployment/test/validator/documentation/agent instruction needed for a new agent to continue from clone alone.
- Do not commit secrets, real `.env`, credentials/private keys, caches, runtime state, logs, generated smoke screenshots, local binaries or release build directories. If an essential large/third-party input is intentionally not ordinary Git source, document whether it is vendored, LFS, a submodule, or digest-locked installer/bootstrap acquisition.

