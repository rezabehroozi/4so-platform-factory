# Target Data Protection Productization V36

`PROGRAM_PHASE_MODEL_V36` closes the **source-level** G4 data-protection productization phase without making any Physical or production-readiness claim. `TARGET_DATA_PROTECTION_AUTHORITY_V1` is the product-owned control-plane authority; Velero remains the target execution provider rather than a second source of truth.

## Product authority

- `BackupPolicy` is durable and project/cluster scoped, with exact schedule, retention, namespace set, BackupStorageLocation and an opaque `k8s-secret://velero/...` credential reference. Secret bytes never enter the product API or MCP surface.
- Policy state is explicitly `ACTIVE` or `DISABLED`. Enable/disable uses optimistic revision fencing and is audited/outboxed; a disabled policy cannot create new BackupRuns and is skipped by the scheduler.
- `BackupRun`, `RestoreRun` and `RestoreDrill` are durable, idempotent, inventory/policy-bound authorities. Direct restore is approval-gated and requester self-approval fails closed.
- Agent task claims use lease + monotonically increasing fence token. Stale/wrong fence results are rejected.
- Successful Backup or Restore Drill evidence can create a verified RecoveryCheckpoint. Restore Drill evidence requires completed Velero progress, `itemsRestored == totalItems > 0`, zero warnings/errors and UID/resourceVersion guarded cleanup of the isolated namespace.

## Scheduler semantics

`TARGET_DATA_PROTECTION_SCHEDULER_V1` evaluates the intentionally small five-field cron grammar in UTC. Each due policy materializes a BackupRun using a policy+minute bucket idempotency key. PostgreSQL uses conflict-safe exact request-digest replay, so concurrent API replicas cannot create duplicate scheduled runs for the same policy/time bucket.

## Restore safety

- Restore Drill V1 requires exactly one protected source namespace and maps it to a generated isolated namespace.
- A fresh drill refuses to adopt a pre-existing target namespace. Retry is allowed only when the already-existing Velero Restore is proven owned by the same run.
- The drill namespace is deleted only with observed UID and resourceVersion preconditions and must be confirmed absent.
- A successful direct Restore requires a different approver from the requester before Agent execution.

## Operator Console

`TARGET_DATA_PROTECTION_OPERATOR_WORKFLOW_V1` is integrated into Fleet/Recovery. Operators can create policies, enable/disable schedules, queue backups, start isolated restore drills, request direct restores, approve eligible restores and inspect evidence/recovery checkpoints. Credential input is reference-only.

## Release-gate truth

G4 is `source-implemented` only. Generated/Installed Runtime, Runtime-Realism, Integration and Exact-SHA Physical certification remain independent levels in `FEATURE_CERTIFICATION_REGISTRY_V1`; source closure must never be interpreted as Physical PASS or `productReleaseReady=true`.
