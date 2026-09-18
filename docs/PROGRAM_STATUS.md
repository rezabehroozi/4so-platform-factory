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

## Reporting and handoff contract

Every progress report for 4SO Platform Factory MUST include these fields, even when the value is unchanged:

- **Code progress %**: report overall pre-physical software closure and, separately when useful, mandatory Core source closure.
- **Lab progress %**: derive from explicit Lab closure gates; never inflate it from source/test progress.
- **Last completed stage %**: name the most recently completed stage and show its own completion percentage/evidence.
- **Blockers**: list every current blocker with owner/lane and whether it is software, supply-chain, environment, or physical-runtime related.
- **Actions Reza must do**: always present this section. If nothing requires Reza, say `None` explicitly.
- **Git state**: all real changes MUST land on canonical `main`; keep `main == origin/main`, divergence `0/0`, and remove side branches after any temporary development work. Never claim sync without fresh evidence.
- **Lab per-node state**: when Lab was probed in the current wave, report reachability, time sync, installed/active services, and material blockers per node.
- **Next execution checkpoint**: state the exact next actions so a new chat or AI agent can resume without rediscovery.

`docs/PROGRAM_STATUS.md` is also the canonical human-readable handoff file. It must remain sufficient for a fresh chat/agent to understand what is complete, what is blocked, the current exact Git/release authority, the current Lab state, and the immediate next execution chain. Machine-readable derived knowledge remains in `DERIVED-AGENT-KNOWLEDGE.json`; do not create redundant handoff/worklog files unless an executable consumer genuinely needs one.

## Current handoff checkpoint — 2026-09-17

- Canonical Git: `main == origin/main == 0c2f47519fa32ee4178f6ad294218b438cd0691b`; last fresh divergence `0/0`; remote branch set contains only `main`.
- Exact FULL release for this checkpoint: `4so-platform-factory-0.0.362-0c2f475-FULL.zip`, SHA-256 `553c7f0b4497476cdcca6c8b50e1d79835147eeea7ac4d5f6f3a9ccece6a9933`, 1005 entries.
- Full Verifier for that exact ZIP is currently running; do not claim final Full Verifier PASS until its terminal success marker and exit code `0` are observed.
- Fresh Windows→Lab sweep: vm-lab06..vm-lab12 are 7/7 reachable, chrony 7/7 active with `ntp.ripe.net` selected, KVM 7/7 present, and raw `/dev/sdb` `/dev/sdc` `/dev/sdd` remain untouched.
- vm-lab06: installer service active, but RKE2/containerd inactive. Exact execution remains intentionally blocked until the sealed ApplianceBundle is complete.
- vm-lab07: PostgreSQL active; RKE2/containerd inactive; used as supply-chain/product-certification staging worker.
- RKE2 `v1.34.10+rke2r1` offline artifact set is fully acquired and SHA/size verified on vm-lab06.
- Management external images PostgreSQL/Forgejo/Zot/Keycloak are 4/4 acquired, offline verified, and assembled successfully for the current release lane.
- Product images `platform-api`, `platform-agent`, and `platform-probe` have real exact-release certification evidence; static base uses exact distroless nonroot+CA authority.
- Three locked manifest source files have now been re-acquired from their canonical locked URLs and exact size/SHA verified: Argo CD, CloudNativePG, and Longhorn.
- Manifest inspection currently requires 11 mutable image references to be resolved into exact digests: Argo CD=3, CloudNativePG=1, Longhorn=7.
- Remaining Lab bundle blockers: maintenance-toolchain-base/product maintenance image; exact acquisition/assembly of the 11 manifest images; digest-pinned runtime manifest generation; final management OCI archive; sealed ApplianceBundle; exact installer deployment/execution; RKE2 production-standard-ha bootstrap; runtime health/evidence.
- Physical PASS remains NOT RUN and must never be inferred from the software, supply-chain, or verifier gates above.

## Current handoff checkpoint - 2026-09-18

- Canonical Git before this status update: `main == origin/main == 7b63965aa7ca351708257fb3ce317316c781487c`; fresh divergence `0/0`; remote branch set contains only `main`.
- Major Lab-driven HA network closure is implemented end-to-end. `nodeAddresses` remain the SSH/access authority, while optional `clusterNodeAddresses` plus `clusterInterface` explicitly bind RKE2/etcd east-west traffic to an already configured private/L2 network.
- The installer never invents, assigns or rewrites east-west IP addresses or routes. Planning rejects malformed interfaces, duplicate/non-IP cluster addresses, count mismatches, and an interface without explicit cluster addresses.
- Live HA preflight now verifies the local east-west address is already assigned, peer routes resolve through the declared interface, and every remote peer already owns its declared east-west address before mutation.
- RKE2 configuration uses east-west addresses for `node-ip` and HA join endpoint while preserving access/public addresses in TLS SANs. HA status exposes access nodes, cluster nodes, cluster interface and whether the topology is split.
- Installer Console now provides dedicated HA east-west address/interface fields, submits them through the real request contract, validates obvious count/interface errors client-side, and includes Persian copy for the new workflow.
- Linux exact-toolchain regression PASS with Go `1.27.1 linux/amd64`: `go test ./internal/installation ./internal/bootstrap ./cmd/platform-installer`.
- Repository validation PASS after the change: `REPOSITORY_VALIDATION_PASS 1000`. Persian writing gate PASS with 1352 scanned string occurrences; localization coverage remains zero known text/attribute gaps.
- Canonical Windows control-host supply-chain bug fixed: staged management OCI atomic JSON writes retain POSIX directory-fsync durability on Linux but no longer fail falsely on Windows where directory file descriptors cannot be opened for `fsync`. `tests.test_management_workload_batch` is 8/8 PASS on Windows.
- Release build authority is now fail-closed on exact Go + CGO identity. The Windows host correctly rejects release construction because its active toolchain is `go1.27.0 windows/amd64`; source/test work may continue there, but Exact Release must be built by the admitted Linux/amd64 CGO authority.
- UI browser smoke on Windows is environment-blocked only because Chromium/Playwright browser bytes are absent; Persian UI and localization gates PASS independently. This is not a Physical or product runtime PASS.
- The previous FULL ZIP at commit `0c2f475` is historical and MUST NOT be treated as current-main Exact Release. A new FULL ZIP and Full Verifier remain required for the final current-main SHA after this status commit.
- Physical Lab state from the last verified sweep remains 7/7 reachable with chrony/KVM healthy and raw `/dev/sdb`, `/dev/sdc`, `/dev/sdd` untouched. No newer Physical PASS is claimed by this software wave.
- Immediate Lab continuation: determine the already-configured second-NIC IPs/interfaces from Windows-to-Lab read-only evidence; populate `clusterNodeAddresses`/`clusterInterface` only from that evidence; finish management OCI/manifest resolution and sealed ApplianceBundle; build the Exact Release on the admitted Linux builder; then run production-standard-ha preflight/bootstrap and capture Exact-SHA physical evidence.
