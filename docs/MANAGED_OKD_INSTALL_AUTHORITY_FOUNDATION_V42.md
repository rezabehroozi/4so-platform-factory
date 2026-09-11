# Managed OKD Install Authority Foundation — V42

Release 0.0.334 adds `BAREMETAL_MANAGED_INSTALL_AUTHORITY_FOUNDATION_V1` as a source-owned foundation for the still-open H1 managed-install workflow.

The foundation is intentionally **not** an H1 closure. It defines a Compact-3 request contract, exact SHA-256 artifact identity, secret-reference-only machine inputs, independent approval, monotonically increasing fencing for crash/reclaim, deterministic request identity and a restart-safe ordered step model:

`VALIDATE_ARTIFACTS -> ATTACH_MEDIA -> SET_ONE_TIME_BOOT -> POWER_CYCLE -> OBSERVE_BOOTSTRAP -> COMPLETE`.

A higher worker fence can reclaim an interrupted RUNNING operation while stale/equal fences fail closed. Requester self-approval is rejected. Required artifacts are release payload, FCOS and Agent ISO and all are digest-bound.

`BAREMETAL_MANAGED_INSTALL_WORKFLOW_PENDING` remains open until this contract is integrated with durable Memory/File/PostgreSQL operation persistence, product API/MCP admission, the Redfish provider worker and exact connected `openshift-install` execution/recovery evidence. `OKD_CONNECTED_MANAGED_INSTALL_PENDING` remains independently open. No Physical PASS is inferred.
