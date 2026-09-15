# Current Program Status ? PROGRAM_PHASE_MODEL_V68

`docs/PROGRAM_STATUS.md` is the single current human-readable status summary. Release **0.0.362** is the current repository release identity. Versioned `PHASE_STATUS_V*.md` files are historical release records; executable truth remains `internal/targetmodel/program.go`.

## Progress authority

`PROGRAM_PROGRESS_MODEL_V2` remains the executable progress authority. The current execution wave is `W1-core-closure-blitz`.

| Measure | Current | Meaning |
| --- | ---: | --- |
| Core source/software closure | **25/25 (100%)** | All mandatory Core phases have source/software contracts implemented. |
| Core closure/release ready | **19/25 (76%)** | Six mandatory Core phases still require external/runtime/evidence closure. |
| Pre-physical software closure | **31/35 (88%)** | Core + Expansion source/software closure; Physical certification is excluded. |

V68 exposes independent `sourceStatus` and `closureStatus` for every phase. A phase may be `source-implemented` while its closure remains `blocked`; this is intentional and prevents external bytes, client interoperability, runtime evidence or Physical gates from serializing unrelated software development.

## Source-open software

Only four pre-physical software phases remain source-open:

- `J1-automation-external-integrations` ? real Terraform provider and Crossplane provider.
- `H3-public-cloud-provider-adapters` ? common provider execution framework plus AWS/Azure/GCP adapters.
- `J3-virtual-cluster-profile` ? Virtual Cluster / Developer Mode lifecycle and workspace integration.
- `I2-edge-sovereign-extension` ? bounded edge authority/UI, boot attestation and disconnected local AI profile.

`J6-fleet-reliability-incident-intelligence` is source-implemented. `SERVICE_HEALTH_AUTHORITY_V1`, `INCIDENT_AUTHORITY_V1`, `SLO_ERROR_BUDGET_AUTHORITY_V1`, PostgreSQL persistence, migrations `0074`-`0076`, REST/Console/MCP surfaces and Incident?Operation/Evidence binding are present. Runtime/Physical evidence remains an independent certification concern.

## Execution waves

1. **W0 ? Truth rebaseline:** keep executable roadmap, docs and canonical main synchronized; V68 closes stale J6 roadmap debt.
2. **W1 ? Core closure blitz (current):** S1 exact acquisition and S2 component certification run as a streaming pipeline with up to six independent lanes.
3. **W2 ? Core evidence parallel:** MCP external-client interoperability, Connected Managed OKD and Disconnected OKD evidence advance independently.
4. **W3 ? Expansion mega-wave:** J1 + H3 + J3 + I2 develop in parallel without waiting for Physical certification.
5. **W4 ? Cross-surface convergence:** converge API, SDK, MCP, Console, PostgreSQL, Durable Ops, Evidence and negative controls.
6. **W5 ? Feature freeze:** C9 freezes mandatory scope and emits one exact immutable release before Phase D physical certification.

## Current critical path

The Core bottleneck remains **S1 ? S2**, but it is no longer treated as a whole-phase serial dependency. Exact-locked components should flow immediately from Acquire ? Verify ? Admit ? Runtime Certify ? Negative Controls while other S1 roles continue acquiring.

S1 management-workload diagnostics remain fail-closed until the product-owned OCI archive is fully resolved. No digest, READY state, runtime compatibility, Managed OKD install, disconnected install or Physical PASS may be inferred from source/model progress.

## Current closure blockers

These are closure/evidence blockers, not a reason to reopen completed source work:

- `MANAGEMENT_WORKLOAD_OCI_ARCHIVE_PENDING` ? S1 exact management workload archive/digest closure.
- `COMPONENT_RUNTIME_UPGRADE_MATRIX_PENDING` ? S2 exact historical source/upgrade evidence.
- `MCP_EXTERNAL_CLIENT_INTEROP_MATRIX_PENDING` ? C7W named external-client live interoperability.
- `OKD_CONNECTED_MANAGED_INSTALL_PENDING` ? H1 connected Managed OKD runtime evidence.
- `OKD_OC_MIRROR_V2_ACQUISITION_PENDING` ? I1 exact disconnected mirror acquisition.

## Truth boundary

The release gate remains independent across Source Semantics, Generated/Installed Runtime Semantics, Runtime-Realism Negative Controls and Exact-SHA Physical Runtime. Passing the first three never authorizes a Physical PASS claim. Phase D/M remain deferred until C9 development/feature closure.
