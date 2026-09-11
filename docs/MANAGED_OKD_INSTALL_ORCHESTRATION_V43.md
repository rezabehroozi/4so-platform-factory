# Managed OKD Install Orchestration V43

Release 0.0.335 upgrades H1 from a validation foundation to a durable source-level orchestration path.

## Authorities

- `BAREMETAL_MANAGED_INSTALL_AUTHORITY_V2` canonicalizes Compact-3 machine/artifact requests and binds release-payload and Agent ISO versions to the requested OKD target.
- `DURABLE_OPERATION_REQUEST_PAYLOAD_AUTHORITY_V1` atomically seals the canonical request beside a critical Operation in `AWAITING_APPROVAL`; requester self-approval is rejected.
- `BAREMETAL_MANAGED_INSTALL_EXECUTOR_V1` advances validate, Redfish media attach, one-time boot, power cycle, bootstrap observation, connected install, registration and completion.
- Every completed stage is sealed as operation evidence. Expired `RUNNING` operations are rediscoverable and reclaimed with a strictly newer fence.

## Product surfaces

REST: `POST /api/v1/managed-okd-installs`, `GET /api/v1/managed-okd-installs/{id}`, `POST /api/v1/managed-okd-installs/{id}/approve`.

MCP: `managed_okd_install_request`, `managed_okd_install`, `managed_okd_install_approve`. Approval is Administration-only. BMC credential references and raw secrets are not returned through MCP.

## Deliberately still open

`OKD_CONNECTED_MANAGED_INSTALL_PENDING` remains open. The source orchestrator and executor boundary exist, but an exact pinned `openshift-install`/FCOS/release-payload run on real connected bare metal has not been certified. No Physical PASS is inferred.
