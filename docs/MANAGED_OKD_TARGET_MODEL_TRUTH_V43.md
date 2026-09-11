# Managed OKD Target-Model Truth — V43

Release `0.0.336` aligns the public target architecture model with the already source-implemented H1 orchestration without weakening runtime or Physical gates.

## Source support

`TARGET_ARCHITECTURE_MODEL_V1` now reports source-level managed-install support only for the pair **OKD + Bare Metal**. The path is backed by `REDFISH_BOOT_MEDIA_PROVIDER_V1`, `BAREMETAL_MANAGED_INSTALL_AUTHORITY_V2`, `BAREMETAL_MANAGED_INSTALL_EXECUTOR_V1`, atomic sealed request persistence, independent approval and monotonic crash-reclaim fencing.

## What remains blocked

`OKD_CONNECTED_MANAGED_INSTALL_PENDING` remains authoritative. `SupportedDistribution(OKD)` deliberately stays false because that helper represents generally admitted runtime support, not source implementation. OpenShift and VMware are not admitted through the OKD Bare Metal path. Exact source bytes, connected install execution, registration convergence, Integration and Exact-SHA Physical certification remain independent evidence gates.

## Why this matters

Before this release the model still described Managed Install as management-plane-only and Bare Metal as a future adapter even though H1 orchestration already existed. The new source predicate removes that contradiction without inflating readiness or phase completion.
