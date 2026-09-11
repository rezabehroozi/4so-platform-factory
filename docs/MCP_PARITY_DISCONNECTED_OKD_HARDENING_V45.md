# MCP Parity + Disconnected OKD Source Workflow Hardening — V45 / 0.0.339

## Scope and truth boundary

V45 advances two independent Core Freeze blockers without converting source implementation into certification claims. C7W gains complete typed coverage for the Workspaces and Projects route families. I1 gains a production-oriented disconnected Managed OKD source workflow. C7W and I1 both remain blocked for the explicitly listed remaining evidence.

## MCP parity closure in this release

### Workspaces

Typed tools now cover the entire stable family:

- `workspaces`
- `workspace`
- `workspace_create`
- `workspace_bindings`
- `workspace_binding_create`
- `workspace_binding_revoke`

The tools consume the same authoritative Workspace store as REST. Binding creation verifies that the referenced cluster belongs to the same project. Revoke uses exact revision fencing. No raw secret or generic mutation surface exists.

### Projects

Typed tools now cover both stable routes:

- `projects`
- `project_create`

Project listing uses the same effective-access filtering as REST. Project creation is administration-only and organization-scoped. A project-scoped API token cannot widen itself into organization administration, while a delegated human administrator is constrained to the granted organization.

The canonical MCP action registry marks both families `typed-tool-complete`.

### Stable read-only family convergence

V45 also closes typed parity for five one-route/read-only families that already had stable REST authority: `version` (`platform_version`), `baselines` (`baselines`), `tenancy` (`tenancy_plans`), `day2-campaign-engine` (`day2_campaign_engine`) and `catalog-governance` (`catalog_signing_identity`). These tools reuse the same source models/loaders as REST. Catalog signing identity returns only public identity/fingerprint; private signing material never becomes MCP output.

The canonical registry therefore has **70 families: 16 typed-tool-complete, 10 typed-tool-partial, 42 pending-parity and 2 security-excluded**. This is real C7W progress but not C7W closure; pending route families and named external-client interoperability remain blockers.

## Disconnected Managed OKD runtime

Disconnected mode reuses the existing durable Managed OKD authority instead of introducing a second orchestrator. Its sealed sequence is:

`VALIDATE → PREPARE_DISCONNECTED_MIRROR → ATTACH_MEDIA → SET_ONE_TIME_BOOT → POWER_CYCLE → OBSERVE_BOOT → DISCONNECTED_INSTALL → REGISTER → COMPLETE`

The mirror preparation boundary requires:

- exact `sha256:` ImageSetConfiguration digest;
- exact `sha256:` mirror inventory digest;
- a canonical inventory covering every archive file;
- no symlinks, special files, unsafe permissions or unsealed extra files;
- exact-SHA product-configured `oc-mirror` executable;
- exact product-managed destination registry, with no credential-bearing request URL;
- `oc-mirror v2` disk-to-mirror mode only;
- stripped inherited proxy/KUBECONFIG/release-image authority;
- operation-isolated HOME/cache;
- durable completion marker bound to the request digest and mirror inputs.

Disconnected install refuses to start without that matching marker. Successful cluster installation continues to require exact ClusterVersion, at least three Ready nodes and healthy ClusterOperators before normal operation-owned Cluster Import convergence.

## Console/API/MCP convergence

The Managed OKD request contract includes `connectivity=connected|disconnected`. REST and MCP both reject disconnected requests when the disconnected runtime is not configured. The runtime-truth endpoint exposes connected and disconnected readiness independently, and the Operator Console enables only the selected mode when that exact runtime exists.

## Remaining I1 boundary

V45 intentionally does not vendor, download or pretend to certify `oc-mirror v2`. Production wiring can enable disconnected execution only when the exact binary path/SHA and product-managed mirror registry are supplied and validate at startup. Consequently:

- removed blocker: `OKD_DISCONNECTED_INSTALL_WORKFLOW_PENDING`
- remaining blocker: `OKD_OC_MIRROR_V2_ACQUISITION_PENDING`

Disconnected/Physical PASS still requires exact acquired upstream bytes plus real disconnected install/upgrade/certification evidence.

## Release-gate interpretation

Passing source/unit/race/UI/artifact gates proves the implementation and packaging boundaries of this release. It cannot prove Connected OKD, Disconnected OKD or Exact-SHA Physical Runtime. Those dimensions remain independently not certified until their real environments and exact acquired artifacts execute successfully.
