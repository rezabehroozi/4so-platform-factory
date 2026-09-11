# Managed OKD Production Runtime Hardening — V44 / 0.0.338

## Scope and truth boundary

This release closes a production **source implementation** gap in the Managed OKD Compact-3 journey. It does **not** claim a connected-lab, Exact-SHA Physical, disconnected, upgrade or production certification PASS. `H1-baremetal-connected-managed-okd` remains blocked by `OKD_CONNECTED_MANAGED_INSTALL_PENDING`, and Core Freeze remains **19/25 = 76%**.

The release intentionally requires a pre-staged exact install workspace. The current product request does not contain enough host-networking, pull-secret, SSH and Agent-config authority to generate a correct Agent ISO/workspace autonomously, so V44 does not invent that state. Workspace preparation/acquisition remains part of the open H1/S1 boundary.

## Production execution path

1. Operator or MCP principal creates a canonical Compact-3 request. BMC secret material is never accepted; only scoped credential references are stored.
2. A distinct authorized principal approves the durable operation.
3. `cmd/platform-api` runs the worker only when all Managed OKD runtime inputs validate at startup.
4. The worker renews its lease during long actions and revalidates the current fence/revision before writing evidence.
5. Each BMC credential is resolved from a server-side file authority bound to organization, project, machine and exact Redfish endpoint.
6. The Agent ISO is resolved from a locally staged `sha256/<digest>/agent.iso`, rehashed and exposed to BMC through an expiring HMAC URL bound to the operation.
7. `openshift-install` and `oc` are opened with no-follow semantics, streamed through exact SHA-256 verification and copied from the verified descriptor into a private operation work directory.
8. The install workspace descriptor must bind request digest, organization/project, cluster identity, target version and all three artifact digests.
9. Completion is accepted only when the exact target ClusterVersion is Available/not Failing/not Progressing, at least three Nodes are Ready, and every ClusterOperator is Available/not Degraded/not Progressing.
10. The installed cluster converges into the ordinary ClusterImport/Agent authority using an operation-bound deterministic enrollment; retries reuse the same import and cannot silently claim an import owned by another operation.

## New/strengthened authorities

- `REDFISH_FILE_CREDENTIAL_RESOLVER_V1`
- `MANAGED_OKD_CONTENT_ADDRESSED_MEDIA_V1`
- `MANAGED_OKD_EXACT_WORKSPACE_RUNTIME_V1`
- `MANAGED_OKD_INSTALL_WORKSPACE_V1`
- `MANAGED_OKD_CLUSTER_REGISTRATION_V1`
- `BAREMETAL_MANAGED_INSTALL_EXECUTOR_V1` production wiring
- `GET /api/v1/managed-okd-installs/runtime` runtime-truth surface

## Security and failure semantics

- Credential documents, Agent ISO and exact executables are opened with `O_NOFOLLOW`; unsafe symlinks and unsafe file/directory permissions fail closed.
- Exact binaries are hashed as streams rather than loaded fully into memory.
- `KUBECONFIG`, release-image override and OS-image override values inherited from the parent environment are stripped.
- Command output is bounded and registration/install waits are bounded.
- Media URLs are signed, time-bounded and operation-bound. The locally served bytes are rehashed before response; an after-issuance content swap is rejected.
- Lease heartbeat prevents another worker from reclaiming a legitimate long-running step. The post-heartbeat operation is reloaded so evidence writes do not use a stale revision.
- Nested registration does not add a second redundant human approval: the already-approved top-level critical install operation is the human security boundary. The derived import is system-created, operation-owned, deterministic and audited.
- Claimed imports are not trusted by name alone; ownership must match the exact managed-install operation.

## Operator Console convergence

The Managed OKD form now consumes runtime truth. If the production executor is not configured, the Console explains that execution is unavailable and disables request submission instead of presenting a dead-end action. Request acceptance still never implies installation success; completion/evidence remains in Operations.

## Remaining blockers

H1 remains blocked until all required evidence exists, including:

- exact upstream acquisition and locks for `openshift-install`, FCOS and release payload;
- authoritative preparation/staging of the exact Agent-based install workspace and locally staged Agent ISO;
- connected Compact-3 execution against real BMCs with failure/retry evidence;
- convergence into a connected imported OKD target under the exact release;
- subsequent required Exact-SHA Physical certification.

S1, S2, C7W, I1 and C9 remain independently open. No source test in V44 is a substitute for those authorities.
