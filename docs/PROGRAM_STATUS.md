# Current Program Status — PROGRAM_PHASE_MODEL_V70

`docs/PROGRAM_STATUS.md` is the single current human-readable status summary. Release **0.0.363** is the current repository release identity. Versioned `PHASE_STATUS_V*.md` files are historical release records; executable truth remains `internal/targetmodel/program.go`.

## Progress authority

`PROGRAM_PROGRESS_MODEL_V2` remains the executable progress authority. The current execution wave is `W1-core-closure-blitz`.

| Measure | Current | Meaning |
| --- | ---: | --- |
| Core source/software closure | **25/25 (100%)** | All mandatory Core phases have source/software contracts implemented. |
| Core closure/release ready | **19/25 (76%)** | Six mandatory Core phases still require external/runtime/evidence closure. |
| Pre-physical software closure | **33/35 (94%)** | Core + Expansion source/software closure; Physical certification is excluded. |

V70 exposes independent `sourceStatus` and `closureStatus` for every phase. A phase may be `source-implemented` while its closure remains `blocked`; this is intentional and prevents external bytes, client interoperability, runtime evidence or Physical gates from serializing unrelated software development.

## Source-open software

Only two pre-physical software phases remain source-open:

- `J3-virtual-cluster-profile` — workspace-bound planning, durable PostgreSQL desired-state persistence, REST/Product API, generated SDK route contract, typed MCP route parity and truthful Operator Console desired-state UI are implemented. The sole remaining source blocker is a real offline-capable runtime executor bound to immutable vCluster OSS chart/image bytes; REQUESTED must not be presented as Running/Ready before that executor converges.
- `I2-edge-sovereign-extension` — bounded edge authority/UI, boot attestation and disconnected local AI profile.

`J1-automation-external-integrations` is source-implemented with real Terraform and Crossplane providers over Product API authority. `H3-public-cloud-provider-adapters` is source-implemented with shared provider descriptors/execution semantics, CAPA/CAPZ/CAPG ClusterClass verification, external-secret-only credential references, and explicit `RECOVERY_REQUIRED` ambiguity handling. Connected cloud runtime/Physical evidence remains independently certification-gated.

`J6-fleet-reliability-incident-intelligence` is source-implemented. `SERVICE_HEALTH_AUTHORITY_V1`, `INCIDENT_AUTHORITY_V1`, `SLO_ERROR_BUDGET_AUTHORITY_V1`, PostgreSQL persistence, migrations `0074`-`0076`, REST/Console/MCP surfaces and Incident?Operation/Evidence binding are present. Runtime/Physical evidence remains an independent certification concern.

## Execution waves

1. **W0 — Truth rebaseline:** keep executable roadmap, docs and canonical main synchronized; V70 records J3 foundation truth without changing physical/runtime claims.
2. **W1 — Core closure blitz (current):** S1 exact acquisition and S2 component certification run as a streaming pipeline with up to six independent lanes.
3. **W2 — Core evidence parallel:** MCP external-client interoperability, Connected Managed OKD and Disconnected OKD evidence advance independently.
4. **W3 — Expansion mega-wave:** J3 + I2 remain source-open; J1 + H3 are source-implemented and move to integration/runtime evidence without waiting for Physical certification.
5. **W4 — Cross-surface convergence:** converge API, SDK, MCP, Console, PostgreSQL, Durable Ops, Evidence and negative controls.
6. **W5 — Feature freeze:** C9 freezes mandatory scope and emits one exact immutable release before Phase D physical certification.

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

## Current handoff checkpoint — 2026-09-18 Lab HA / Exact Release wave

- Release identity: `0.0.363` / `lab-ha-network-storage-exact-release-v68`; roadmap authority remains `PROGRAM_PHASE_MODEL_V68`.
- Lab management topology is evidence-backed: vm-lab06/07/08 use access addresses `213.176.28.136/137/138`, east-west `ens35` addresses `10.77.35.136/137/138/24`, and all nine east-west peer pings PASS.
- Each management node exposes root on `/dev/sda3` plus blank whole-disk `/dev/sdb`, `/dev/sdc`, `/dev/sdd` at 10 GiB each; storage preparation remains gated by explicit ownership claims and installer preflight.
- Exact Linux release builder admission is proven on vm-lab07 with offline Go 1.27.1, GCC 15.2.0, GNU ld 2.46, glibc 2.43, exact libpq header and canonical `libpq.so.5.18` digest.
- Source/runtime-contract gates PASS for HA split-network, storage ownership/reset, Lab schema parity, Installer Console parity, Persian localization and repository validation.
- Remaining closure is supply-chain/runtime evidence: management workload OCI archive, exact manifest-image resolution, sealed ApplianceBundle, exact installer execution, RKE2 three-node bootstrap and Exact-SHA physical certification.
- Autopilot non-PASS/checkpoint state is durable and includes Git SHA/workspace fingerprint/next stage/invocation so a chat/UI timeout can resume rather than replaying green work.

## Current handoff checkpoint - 2026-09-18 Fast Lab functional acceleration

- Canonical Git before this checkpoint update: `main == origin/main == 4aa4b52148066d967345c6b5c34e4ca989bd017d`; fresh local divergence was `0/0`.
- Fast Lab no longer treats Exact-SHA/sealed-bundle completion as a blocker for intermediate functional installation. Final Physical Certification remains strict and separate. Installer source now supports functional milestones `rke2-quorum`, `ha-storage` and resumable `executionStartStep=prepare-storage-devices`; Linux exact regression and repository validation PASS (`REPOSITORY_VALIDATION_PASS 1002`).
- Management HA runtime is physically up on vm-lab06/07/08: RKE2 `v1.34.10+rke2r1`, all three nodes `Ready`, east-west node IPs `10.77.35.136/137/138` on `ens35`, with public/access addresses `213.176.28.136/137/138`.
- Controlled HA service-restart test PASS: `rke2-server` was restarted on vm-lab07; the cluster recovered to 3/3 Ready, CNPG remained 3/3 healthy, Platform API remained 3/3 Running, Zot remained healthy and active Longhorn volumes returned/remained `healthy`.
- Dedicated storage authority is physically proven on all three management nodes. `/dev/sdb`, `/dev/sdc`, `/dev/sdd` are ext4-labelled `4so-lh-00/01/02`, mounted at `/var/lib/longhorn/disks/disk-00/01/02`, and each has a durable system-disk claim under `/var/lib/4so-platform-installer/storage-claims/` containing `MANAGEMENT_PLANE_STORAGE_CLAIM_V1` plus the canonical device path.
- Longhorn is running across vm-lab06/07/08. Product StorageClass `replicated-rwx` is owned by `4so-platform-installer`, uses `driver.longhorn.io`, `numberOfReplicas=3` and `Retain`. All active Platform PostgreSQL/Zot Longhorn volumes are `attached/healthy`.
- CloudNativePG is running and the `platform-postgresql` cluster has 3 instances, 3 Ready, status `Cluster in healthy state`. The Platform API has 3/3 Running replicas distributed across the three management nodes and /healthz + /readyz return 200.
- Zot had a real runtime defect: generated config enabled the Zot UI while search extension was disabled, causing CrashLoopBackOff. Lab config was repaired with UI disabled; Zot is now 1/1 Running. Source owner fix is committed on main (`9afe939`) with regression test (`4aa4b52`), so this failure must not recur.
- Exact release `0.0.363 / lab-ha-network-storage-exact-release-v68` exists on vm-lab07 as `4so-platform-factory-0.0.363-lab-ha-network-storage-exact-release-v68.zip`, SHA-256 `353e6def3342659eacfbf64948ad50cb24db4869434abaa7fb27a01752f0c872`. Backend smoke shards pass; Full Verifier UI lane remains environment-blocked by missing Playwright runtime/browser dependencies on the verifier host and is not required for the Fast Lab functional lane.
- Management external image batch for Forgejo, Keycloak, PostgreSQL and Zot is staged PASS on vm-lab07 and assembled into the current exact-release lane. Exact Forgejo and Keycloak image digests are known and available in acquisition evidence.
- Current Fast Lab gap: Forgejo and Keycloak are not yet running in `platform-system`. The current fast-lab foundation only provisioned the `platform` PostgreSQL role and intentionally disabled OIDC/internal Git bootstrap in Platform API. Production installer source already models distinct Forgejo/Keycloak database roles/secrets; Fast Lab must converge on that contract before declaring appliance-level functional closure.
- Physical PASS remains NOT RUN. Final certification still requires a final immutable current-main release, full bundle/exact image closure, Full Verifier PASS and Exact-SHA Physical Runtime evidence. Fast Lab PASS must never be relabeled as Final Physical PASS.

## Current handoff checkpoint - 2026-09-18 Fast Lab core + GitOps functional closure

- Fast Lab management plane is functionally running on vm-lab06/07/08. RKE2 `v1.34.10+rke2r1` is 3/3 Ready on east-west `10.77.35.136/137/138`; all three management nodes keep public/access SSH on `213.176.28.136/137/138`.
- Dedicated Longhorn storage remains physically bound to claimed `/dev/sdb`, `/dev/sdc`, `/dev/sdd` on each management node. Active Platform volumes are `attached/healthy`, StorageClass `replicated-rwx` remains replica=3/Retain/product-owned, and root disks are not part of Longhorn scheduling.
- CloudNativePG `platform-postgresql` remains 3 instances / 3 Ready / `Cluster in healthy state`. Platform API is 3/3 Running across vm-lab06/07/08.
- Fast Lab managed services are now all running and internally reachable: Platform API, Forgejo 15.0.7, Zot 2.1.20 and Keycloak 26.7.3. Internal functional probes return PASS for API `/healthz`, Forgejo `/api/v1/version`, Zot `/v2/` and Keycloak realm discovery.
- Forgejo exact image could not be pulled directly from Codeberg in this Lab because the network path returned HTTP to an HTTPS client. The already-acquired exact OCI bytes were used from vm-lab07 and Forgejo is 1/1 Running with PostgreSQL-backed persistence.
- Keycloak bootstrap completed, the `platform` realm was imported and the service is 1/1 Ready. A real runtime defect was found: readiness against the hostname-sensitive realm endpoint returned 403. Source now probes Keycloak management health `/health/ready` on port 9000 with regression coverage.
- Zot persistence/restart testing exposed two real runtime defects. First, UI was enabled without search extension and caused CrashLoopBackOff; source now keeps UI disabled. Second, RollingUpdate allowed two Zot processes to contend for the same BoltDB-backed RWO registry volume; source now uses Deployment strategy `Recreate` with regression coverage. After convergence Zot returned to 1/1 Running and its endpoint is healthy.
- Managed-service restart test PASS for Forgejo and Keycloak. Zot initially retried while the prior BoltDB file lock drained, then recovered and is 1/1 Running under the Recreate strategy.
- Argo CD runtime manifest from the acquired/digest-resolved manifest lane is installed in Fast Lab. The manifest is SHA-256 `e4ebd98e3d09496f6f25cd8a90f20c0a44544643aef2270b2b1c450fc2cffd71` and uses exact digests for Argo CD 3.5.0, Dex 2.45.0 and Redis.
- Argo CD required server-side apply for the large ApplicationSet CRD because client-side apply exceeded the Kubernetes annotation-size limit. After server-side reconciliation all 7 Argo CD components are 1/1 Running and the Application, ApplicationSet and AppProject CRDs exist.
- Dex pull from GHCR was avoided by importing the already assembled 11-image manifest OCI archive on vm-lab07. Import returned rc=0; Dex was scheduled to vm-lab07 and Argo CD became fully Ready without acquiring new image bytes.
- Seven-node environment sweep: chrony is active on vm-lab06..vm-lab12; `ens35` is UP with `10.77.35.136..142/24`; RKE2 is active only on the intended management nodes vm-lab06/07/08. vm-lab07 still has a host PostgreSQL staging service active; this is separate from the CNPG appliance database.
- Fast Lab is intentionally non-certifying: Forgejo/Keycloak currently reuse the existing Fast Lab PostgreSQL application credential/database owner rather than the production installer’s separate DB roles/secrets, API OIDC/internal-Git bootstrap remains disabled in the Fast Lab deployment, and public TLS/DNS exposure is not yet the final production path. Production source retains separate role/secret authority.
- Current source regression after the Lab fixes PASSes `go test ./internal/bootstrap ./internal/installation ./cmd/platform-installer` on Linux exact Go and `REPOSITORY_VALIDATION_PASS 1002`.
- Final Physical PASS remains NOT RUN. Exact-SHA/sealed-bundle/full-verifier requirements remain final-certification gates only and must not block ongoing Fast Lab functional development.

## Current handoff checkpoint - 2026-09-19 Fast Lab public GitOps and node-failover closure

- Canonical Git entering this checkpoint: main/origin main clean at `15fa2e0990d0758a967c91f2bcf7017fd0cf6a15` after the Lab-driven availability hardening commits.
- The management plane is 3-node RKE2 `v1.34.10+rke2r1` on vm-lab06/07/08 with east-west `10.77.35.136/137/138`. All three nodes are Ready after two controlled node-maintenance drains and recovery.
- Platform API remains 3-replica with required node spreading. During both one-node drains the external API health endpoint stayed HTTP 200 continuously; the third replica may remain Pending while one of the three required nodes is cordoned, while two replicas continue serving.
- CloudNativePG remained 3/3 healthy during both maintenance campaigns. Longhorn active volumes recovered from expected temporary `degraded` state back to `attached/healthy` with replica count 3 after each node returned.
- Keycloak now runs 2 replicas on distinct management nodes in Fast Lab, matching the production HA manifest. External Auth remained HTTP 200 continuously during node drain. Source and Lab now include `PodDisruptionBudget minAvailable: 1` for production HA Keycloak.
- Forgejo and Zot exact OCI images were preloaded into RKE2 containerd on vm-lab06, vm-lab07 and vm-lab08. Dex exact OCI image was also preloaded across the management nodes so failover does not depend on live registry pulls.
- Second maintenance test drained vm-lab08 after all temporary node selectors were removed. Measured public HTTPS behavior: Platform API and Keycloak remained continuously available; Zot returned 503 for roughly 10 seconds before restart-failover completed; Forgejo returned 503 for roughly 18 seconds before restart-failover completed. Both recovered automatically on vm-lab07 using replicated Longhorn RWO volumes and preloaded exact image bytes.
- These measurements are now represented truthfully in source. `/api/v1/ha/status` exposes authority `MANAGEMENT_HA_AVAILABILITY_V1`: Platform API = `CONTINUOUS_REPLICATED`, PostgreSQL = `QUORUM_REPLICATED`, Keycloak = `CONTINUOUS_REPLICATED`, Forgejo/Zot = `RESTART_FAILOVER` with brief expected maintenance disruption. Production HA plans also disclose this distinction instead of implying universal zero-downtime HA.
- Canonical GitOps is fully functional. Forgejo repository `platform/desired-state` contains signed managed revision `revision-62843b73d58f4f5c` at immutable commit `9f01acf9a4c2fafb795d173930fefb45cd389743`. Argo CD Application `platform-appliance` tracks that exact commit and is `Synced/Healthy`.
- Argo self-heal was physically exercised: `platform-managed-state` was deliberately drifted to `DRIFT-INJECTED`; Argo restored the Git-authoritative value without manual repair while the canonical Application stayed Synced/Healthy. A stale duplicate Fast Lab Application/proxy authority was removed, leaving one canonical reconciler.
- Managed system-service status through Platform API reports Forgejo, Zot, Keycloak and Argo CD all `configured=true, healthy=true`. Internal Git repository bootstrap through Platform API succeeds and reports external clone/html URLs.
- Public Fast Lab ingress is functional through the RKE2 ingress-nginx hostPort 80/443 path using hostnames `platform.fastlab.4so.test`, `git.fastlab.4so.test`, `auth.fastlab.4so.test`, and `registry.fastlab.4so.test`. External functional probes from the Windows canonical control machine pass for API, Forgejo, Keycloak and Zot using explicit host-to-IP resolution.
- OIDC public authority is now HTTPS end-to-end in Fast Lab: issuer `https://auth.fastlab.4so.test/realms/platform`, callback `https://platform.fastlab.4so.test/auth/callback`, PKCE S256, state and nonce are present, the OIDC state cookie is `HttpOnly; Secure; SameSite=Lax`, and HSTS is emitted.
- Fast Lab HTTPS currently uses the ingress-nginx default certificate and is tested with certificate verification disabled. Product source already has the correct managed TLS/CA generator, SAN coverage and `platform-ingress-tls` exposure path. Trusted/product-owned certificate closure remains a final-certification item, not a Fast Lab functional blocker.
- A stale retained Longhorn smoke-test PV/volume from deleted namespace `4so-storage-smoke/data` was proven to be test-owned (`Released`, writer Succeeded, no backup) and safely deleted. Active platform volumes remain intact.
- Temporary Fast Lab completed probe pods/jobs were cleaned up; canonical Argo Application, managed desired-state and Fast Lab ingress were retained for continued testing.
- Source regression after availability changes PASSes `go test ./internal/bootstrap ./internal/installation ./cmd/platform-installer` and `REPOSITORY_VALIDATION_PASS 1002`.
- Final Physical PASS remains NOT RUN. Trusted production TLS, separate production Forgejo/Keycloak DB-role credentials in the deployed Lab instance, Full Verifier UI/browser environment, sealed current-main bundle and final Exact-SHA Physical Runtime remain final-certification work and must not block continued functional Lab development.

## Current handoff checkpoint - 2026-09-19 dual-lane execution model

- Development now runs as two coordinated lanes in parallel:
  - **Remote Commander / Lab lane** owns physical runtime work on the canonical Windows-controlled Lab: installation, HA/runtime validation, failure injection, storage/network checks, service exposure, GitOps reconciliation and physical evidence.
  - **Sandbox / Code lane** owns isolated analysis, CI-failure reproduction, negative controls, regression design and candidate patches. Sandbox is never a second source of truth and never carries an independent release history.
- The only source authority remains Git `main`. Sandbox findings are promoted only after isolated validation, then re-validated from the canonical Windows workspace/Linux environment before push. Lab mutations are never treated as source truth unless the matching source fix also lands on `main`.
- This dual-lane model immediately closed two independent clean-clone CI defects:
  1. acquisition-admission smoke was environment-brittle and expected only `ACQUISITION_TOOLCHAIN_TOOL_MISSING`; it now accepts either exact-tool missing or exact-tool version mismatch while still proving that source admission succeeded first.
  2. remote-installer smoke accidentally used the GitHub runner's non-root UID as the simulated remote target UID. The fixture now simulates only the remote identity probe as Linux/root while production code continues to require root SSH.
- Canonical commit after these CI fixes: `bb4f878ef8bd4c3037a4f71cb73a398fc6a2ff10`. GitHub Actions run `35421417015` completed **SUCCESS**: repository validator, full Go build/tests, all Python tests, Autopilot self-test, installer smoke shard including remote installer, explicit clean-clone verification, and PostgreSQL behavioral integration all passed.
- Fast Lab public exposure is now functionally reachable through RKE2 ingress-nginx on all three management nodes. HTTP and HTTPS endpoints for Platform API, Forgejo, Keycloak and Zot pass from the canonical Windows host. Fast Lab TLS currently uses a temporary seven-day self-signed certificate for `*.fastlab.4so.test`; this is functional evidence only and is not final certificate authority evidence.
- External OIDC flow is functional through HTTPS ingress: Platform API `/auth/login` returns a 302 to `https://auth.fastlab.4so.test/realms/platform` with state, nonce and PKCE S256; redirect URI is `https://platform.fastlab.4so.test/auth/callback`; the state cookie is Secure + HttpOnly; Keycloak accepts the authorization request and returns the login page.
- HA exposure check PASS: Platform API health and Keycloak discovery returned HTTP 200 when the same public hostnames were individually resolved to each of `213.176.28.136`, `213.176.28.137`, and `213.176.28.138`.
- Final certification remains separate: Fast Lab self-signed TLS, functional-lane credentials, and non-final release identity cannot be promoted to Exact-SHA Physical PASS.

## Current handoff checkpoint - 2026-09-19 CNPG recovery and canonical GitOps namespace

- Dual-lane execution continues: Sandbox owns code/CI/negative controls; Remote Commander owns Lab/runtime/failure evidence. Git `main` remains the sole source authority.
- Canonical source before this handoff update: `be119287de17dcbc001a46b04940054729bac924`; repository-integrity run `35422838577` completed SUCCESS. Targeted Linux DR/lifecycle/bootstrap suites PASS and repository validator now reports `REPOSITORY_VALIDATION_PASS 1004`.
- Argo CD has moved to the canonical `platform-gitops` namespace. `platform-appliance` is the only observed canonical Application and is `Synced/Healthy` at desired-state revision `9f01acf9a4c2fafb795d173930fefb45cd389743`.
- CNPG controlled replica-loss recovery PASS: `platform-postgresql-3` on vm-lab08 was deleted while primary `platform-postgresql-1` remained authoritative. Cluster degraded from 3/3 to 2/3 with status `Waiting for the instances to become active`, while external Platform API, Forgejo and Keycloak endpoints all remained HTTP 200 through HTTPS ingress. CNPG recreated the replica on vm-lab08 and returned to 3/3 `Cluster in healthy state` with the same primary.
- Current CNPG distribution after recovery: primary `platform-postgresql-1` on vm-lab07; replica `platform-postgresql-2` on vm-lab06; recreated replica `platform-postgresql-3` on vm-lab08.
- Public Fast Lab exposure remains functional on all three management nodes. HTTPS/OIDC evidence is functional only; the temporary seven-day Fast Lab self-signed certificate is not final certificate authority evidence.
- Whole-appliance DR off-node backup still requires the persisted installer S3-compatible backup authority to be executable. Authenticated installer DR mutation was not bypassed when the tool safety boundary rejected bootstrap-token handling; no backup PASS is claimed from source tests alone.
- Final Exact-SHA Physical Certification remains NOT RUN.

## Current handoff checkpoint - 2026-09-19 resumable parallel execution and Argo HA bundle closure

- Canonical source checkpoint before this handoff-only update: `fb4994c3171f959cc0fc4a30e9da928b7da506e6`.
- GitHub Actions repository-integrity run `35453498785` completed SUCCESS for that exact SHA. PostgreSQL behavioral integration, repository validator, Go build/tests, all Python tests, Codex Autopilot checkpoint/recovery self-test, installer isolated smoke shard, remote installer smoke coverage, and explicit clean-clone verification all passed.
- Large-jump execution is now durable and parallel through `scripts/parallel_wave.py`: DAG dependencies, bounded workers, per-task timeouts, attempt budgets, selective retry, atomic checkpoint state, per-task logs, state-directory lock, heartbeat, exact-spec digest binding, detached execution, and resume without rerunning successful tasks.
- Windows reconnect/disconnect behavior was exercised with detached runner processes under `C:\ProgramData\4so-platform-factory\parallel-waves`. A new Remote Commander session successfully observed and resumed/checkpointed work started by an earlier session. `LATEST.txt` identifies the latest operational wave. Runtime wave state is operational evidence only; Git `main` remains the sole source authority.
- Parallel runner regression tests pass on native Windows and Linux/WSL. The loader accepts both normal UTF-8 JSON and Windows UTF-8 BOM specs so PowerShell-generated wave specs are valid.
- Real detached wave `wave-ha-index-owner-fix-20260919` completed SUCCEEDED. Independent tasks for bundlebuilder tests, runner tests, repository validation, exact-version binary build, installer smoke, and remote-installer smoke converged without rerunning successful tasks.
- Argo CD HA bundle acquisition is profile-aware. Production HA requires the digest-locked HA manifest; single-node retains the standard Argo manifest. The HA manifest is now included in source acquisition authority, bundle manifest, bundle lock/air-gap artifact inventory, runtime selection, and smoke fixtures.
- A real source defect found by remote smoke was closed: the HA GitOps manifest was copied into the bundle manifest but omitted from the air-gap index artifact set. The owner-layer builder now includes it; validators were not weakened. Bundlebuilder regression plus installer and remote-installer smoke all PASS.
- Fast Lab remains healthy after the earlier API session/bootstrap secret split: vm-lab06/vm-lab07/vm-lab08 are RKE2 Ready; CNPG is 3/3 healthy with primary platform-postgresql-1; Platform API is 3/3; Forgejo, Keycloak and zot are Running; Argo Application `platform-appliance` is Synced/Healthy at revision `9f01acf9a4c2fafb795d173930fefb45cd389743`.
- Remaining Fast Lab authority drift is explicit and non-certifying: canonical `platform-internal-services` has not yet fully replaced temporary Fast Lab secret authorities; Forgejo admin, Keycloak admin, and Forgejo/Keycloak database-role separation still require staged migration and rollback-safe runtime evidence.
- Fast Lab TLS remains temporary/self-signed and is not final certificate-authority evidence. Whole-appliance off-node DR still requires the persisted S3-compatible backup authority and authenticated installer mutation path.
- Final sealed current-main release and Exact-SHA Physical Runtime Certification remain NOT RUN.
- Resume rule after connection loss: read `C:\ProgramData\4so-platform-factory\parallel-waves\LATEST.txt`, inspect that wave's `state.json`, and do not start duplicate work. If the detached runner is still active, observe only. If it is no longer active, rerun the exact same spec and state directory; SUCCEEDED tasks are skipped and unfinished/interrupted tasks consume only their remaining attempt budget.

## Current handoff checkpoint - 2026-09-19 detached five-lane resilience wave

- Large-jump execution is now the default operational model for long development/Lab work: independent work is split into bounded parallel tasks under `scripts/parallel_wave.py`, started detached, checkpointed atomically, retried per task, and resumed from the same exact spec/state directory after controller or Remote Commander disconnects.
- Operational latest-wave pointer: `C:\ProgramData\4so-platform-factory\parallel-waves\LATEST.txt`. Before starting new work after reconnect, read this file and inspect the referenced `state.json`. Never start a duplicate wave while its detached runner is active.
- Real detached resilience wave `wave-resilience-20260919-1601` ran with five workers in parallel: repository validator, core Go regression, Lab core health, public HA probes, and Git-main integrity. Every task completed `SUCCEEDED` on attempt 1.
- The wave heartbeat/checkpoint survived independently of the Remote Commander client. Exact wave spec digest: `sha256:b8d47fd44c86d2e1f849faef01ffb5aae52c26b43662e09ec2d6a1cbd605ab82`. Successful tasks are skipped on exact-spec resume; interrupted tasks are marked `INTERRUPTED` and only unfinished work consumes remaining attempt budget.
- Repository validator advanced to `REPOSITORY_VALIDATION_PASS 1007`; test-suite authority gate reports 288. Core Go regression covering bootstrap, disaster recovery, lifecycle, and installer passed.
- Lab health in the detached wave: vm-lab06/07/08 all RKE2 Ready; Platform API 3/3; Forgejo 1/1; Keycloak 2/2; CNPG 3/3 healthy with primary `platform-postgresql-1`; Zot 1/1; Argo Application `platform-appliance` remains `Synced/Healthy` at revision `9f01acf9a4c2fafb795d173930fefb45cd389743`.
- Public HA probes returned HTTP 200 for Platform API, Forgejo, Keycloak and Zot through each management-node public IP `.136`, `.137`, `.138`.
- Connection-timeout operating rule: detached waves continue without the chat/controller connection. On reconnect, inspect `LATEST.txt` + `state.json`; if the runner is still alive, observe only. If it is gone, rerun the same spec/state directory so completed work is not repeated.

## Current handoff checkpoint - 2026-09-19 upgrade migration and immutable parallel resume

- Canonical code checkpoint entering this handoff: `e9078148ae255e96fb35d4ca945a2fee7ae9599e`. GitHub Actions repository-integrity run `35461830253` completed SUCCESS. PostgreSQL behavioral integration, full Go tests/build, all Python tests, Codex Autopilot self-test, installer smoke including remote installer, and explicit clean-clone verification all passed.
- Current repository validator authority is `REPOSITORY_VALIDATION_PASS 1011`; test-suite authority is `TEST_SUITE_AUTHORITY_GATE_PASS 295`.
- Production HA Platform API now consumes the Argo observer token from canonical `platform-internal-services/argocd-observer-token`, matching the non-HA integration contract. The prior HA omission is closed with regression coverage.
- Legacy HA service-database upgrade is now owner-layer and replay-safe. Before desired Forgejo/Keycloak rollout, the installer admits only the exact product-owned database/role/workload pairs, verifies the target login role, refuses unknown owners, quiesces a legacy StatefulSet, uses the local CloudNativePG postgres authority to `REASSIGN OWNED` from the historical `platform` role, transfers database ownership when required, verifies zero remaining legacy ownership, then lets the caller apply desired workload state. Fresh/converged databases are no-op; partial migration is repaired; single-node paths remain untouched.
- Forgejo administrator convergence is hardened for the exact runtime image behavior observed in Lab. The installer refuses root Forgejo admin CLI execution, requires `su-exec`, runs the CLI as the `git` service user, creates `platform-admin` if absent, and rotates an existing administrator to the persisted product credential so Platform API and Forgejo cannot silently diverge.
- A CI concurrency defect was closed. Explicit clean-clone verification no longer assumes `main` remains unchanged for the duration of a workflow run; after clone it checks out the triggering `GITHUB_SHA` detached, then validates that exact source. Run `35461830253` proves this continues to pass while newer commits exist.
- Durable parallel waves now bind more than the JSON spec. Script inputs (including PowerShell `-File`, Python/Bash script files, and explicit `inputFiles`) are SHA-256 bound into state. If a bound input changes between attempts or during execution, the task fails closed and a new state directory is required.
- Detached waves now snapshot the exact `parallel_wave.py` runner into the state directory and bind its digest. Reconnect after repository updates can therefore resume with the state-bound runner semantics instead of applying a newer execution engine to old state. Runner-snapshot tampering fails closed.
- Earlier HA wave `wave-ha-recovery-20260919-1702` physically completed the vm-lab08 drain/recovery path and emitted `NODE_DRAIN_RECOVERY_PASS`, while public availability, installer-resume regression, source regression, and Git-main integrity tasks passed. Its aggregate status remained FAILED only because the Windows-to-Bash wrapper left a CRLF byte after successful execution, producing exit 127. This transport false-negative was not promoted to a product failure.
- A subsequent clean wrapper attempt exposed a PowerShell `.Replace([char]13,'')` overload error before SSH; no Lab mutation occurred in those failed attempts. A corrected detached v2 wave `wave-ha-clean-v2-20260919-1732` was launched with spec digest `sha256:6b8fe9aa89cf0afb5a807dc072c592d8fbaea4036926bec67fc6e83fc42dc917`. Its final state has not been observed because Remote Desktop Commander reached its monthly usage limit. Do not claim this v2 wave PASS until its checkpoint is read.
- Remote Desktop Commander reported its monthly usage exhausted and explicitly instructed not to retry or reconnect; the Windows device remains paired. Interactive Lab work is therefore temporarily tool-blocked, but GitHub/source/CI development continues. On restored access, read `C:\ProgramData\4so-platform-factory\parallel-waves\LATEST.txt` and the referenced `state.json` before doing anything else. Re-running the exact bound state is safe: the state lock prevents overlap, successful tasks stay skipped, and orphaned RUNNING tasks resume as INTERRUPTED; do not create duplicate Lab work blindly.
- Last confirmed Fast Lab health before the Remote tool quota: vm-lab06/vm-lab07/vm-lab08 RKE2 Ready, Platform API 3/3, CNPG 3/3 healthy with primary `platform-postgresql-1`, Forgejo 1/1, Keycloak 2/2, Zot 1/1, and Argo `platform-appliance` Synced/Healthy at revision `9f01acf9a4c2fafb795d173930fefb45cd389743`.
- Fast Lab runtime credential separation is still not claimed complete. Manual secret/password mutation through the controller was blocked by the safety boundary and was not bypassed. The production source now has the formal DB-owner migration and independent authority contracts, but the current manual Fast Lab instance still requires observed runtime convergence after Remote access returns.
- Fast Lab TLS remains temporary/non-certifying, whole-appliance off-node DR still requires the real persisted S3-compatible backup authority and authenticated installer route, and final sealed current-main Exact-SHA Physical Runtime Certification remains NOT RUN.

## Lab-derived defect, hardening and development queue — 2026-09-19

Remote Commander/Lab execution is **paused by explicit user instruction** until the user explicitly re-enables it. This is not a development blocker. While paused, work continues on source, CI, regression/negative-control coverage, upgrade safety, supply-chain logic, API/MCP/Console convergence and other pre-physical software closure. Do not reconnect to or mutate the Lab during this mode.

The queue below is derived from failures and behavior actually observed in Fast Lab plus follow-up source audit. It is the canonical Lab-derived solve/bug-fix/development list; do not create a second competing backlog.

| ID | Priority | Lane | State | Lab-derived problem / next closure |
| --- | --- | --- | --- | --- |
| LAB-BUG-001 | P0 | Bug fix | FIXED + CI PASS | Legacy HA DB migration no longer allows `REASSIGN OWNED BY platform` to silently transfer unrelated shared ownership. `fd310439` inventories product databases/tablespaces, rejects unknown shared ownership and restores non-target database owners in the migration transaction; fixture correction `daeeed8f` is proven by repository-integrity run `35462790354` SUCCESS. |
| LAB-BUG-002 | P0 | Bug fix | FIXED | HA Platform API omitted `PLATFORM_FACTORY_INTERNAL_GITOPS_TOKEN`; HA now consumes canonical `platform-internal-services/argocd-observer-token` with regression coverage. |
| LAB-BUG-003 | P0 | Upgrade | FIXED, runtime evidence pending | Historical Fast Lab used shared PostgreSQL role `platform` for Forgejo/Keycloak. Source now has replay-safe HA role/owner migration, workload quiesce, unexpected-owner rejection and admin convergence; runtime convergence waits for Lab access. |
| LAB-BUG-004 | P1 | Upgrade/replay | SOURCE FIXED + CI PASS; Lab evidence pending | `argocd-observer-token` is now written into authoritative foundation desired state before the live Secret patch. Existing valid live tokens reconcile into desired state without rotation, preservation/idempotency/ambiguity negative controls exist, and both HA inline metadata plus non-HA multiline metadata are supported. Runtime evidence waits for Lab access. |
| LAB-BUG-005 | P1 | GitOps install | FIXED | ApplicationSet CRD exceeded client-side apply annotation limits in Lab. Canonical Argo deployment now uses server-side apply with force-conflicts; keep regression coverage. |
| LAB-BUG-006 | P1 | SSH identity | SOURCE FIXED + CI PASS; Lab evidence pending | `SSH_HOST_KEY_ROTATION_AUTHORITY_V1` now requires an exact current-fingerprint fence, preserves all non-target peer trust, exposes a Console/API rotation journey, records durable evidence and uses a PREPARED/SUCCEEDED/ABORTED digest journal so reconnect can distinguish applied, unapplied and ambiguous outcomes without disabling strict host verification. |
| LAB-BUG-007 | P1 | Execution transport | SOURCE FIXED + CI PASS; Lab evidence pending | Repository-owned `scripts/run_remote_bash.py` replaces ad-hoc PowerShell pipe normalization: UTF-8 BOM/CRLF/bare-CR normalize to LF, NUL/invalid UTF-8 fail closed, SSH keeps strict host-key checking plus bounded keepalive/timeout semantics, and the remote exit code is preserved. Lab re-observation waits for access. |
| LAB-BUG-008 | P1 | Runtime authority | OPEN / LAB EVIDENCE | Manual Fast Lab still uses temporary secret authorities for some service/admin credentials. Production source has independent authorities; when Lab returns, converge runtime only through product-owned migration and verify no DB/admin/session credential reuse. |
| LAB-BUG-009 | P1 | GitOps upgrade | SOURCE FIXED + CI PASS; Lab evidence pending | `GITOPS_LEGACY_NAMESPACE_MIGRATION_V1` identifies only the product-owned legacy `platform-appliance`, deactivates that reconciler after canonical Argo is ready, preserves foreign/unowned Argo, UID-fences cleanup, and deletes a legacy `argocd` namespace only when explicit 4SO ownership is proven after canonical Synced/Healthy handover. |
| LAB-BUG-010 | P1 | Verification | SOURCE FIXED + CI PASS; exact browser bytes pending supply chain | `UI_BROWSER_AUTHORITY_V1` makes Full Verifier certification require an explicit Chromium authority manifest with platform/architecture/version/size/SHA-256/executable identity, rejects symlink/path escapes, and passes the exact admitted executable to every UI lane. Workstation/cache fallback is no longer certification authority. |
| LAB-BUG-011 | P1 | Recovery | SOURCE FIXED + CI PASS; Lab evidence pending | `HA_SERVICE_DATABASE_MIGRATION_V1` persists ADMITTED → QUIESCED → OWNERSHIP_APPLIED → RECONCILED per service DB, reconstructs post-transaction state from PostgreSQL after a crash, rejects journal/database contradiction, and marks RECONCILED only after Forgejo/Keycloak rollout plus admin convergence. |
| LAB-BUG-012 | P2 | Storage cleanup | SOURCE FIXED + CI PASS for future disposable probes; historical volume review pending | `LONGHORN_DISPOSABLE_VOLUME_EVIDENCE_V1` records the exact disposable PVC UID → PV UID → CSI volumeHandle → Longhorn volume UID chain with tamper-bound identity digest. Cleanup requires explicit evidence-ID confirmation plus PVC ownership, Released PV and detached Longhorn state; historical volumes without prior evidence can never be auto-adopted or deleted. |
| LAB-BUG-013 | P0 | Credential lifecycle | SOURCE FIXED + CI PASS; Lab evidence pending | Successful install now persists `INSTALLER_BOOTSTRAP_CREDENTIAL_REVOKED_V1`; a second Start and `prepareHost` fail closed until explicit journaled Reset clears the tombstone. Installer smoke is being updated to use exact source-bound Reset semantics between installation profiles. |
| LAB-FIXED-001 | Closed | Runtime | FIXED | Platform API HA rolling update deadlocked under required anti-affinity; rollout strategy was corrected. |
| LAB-FIXED-002 | Closed | Runtime | FIXED | Zot UI enabled while search extension was disabled, causing CrashLoopBackOff; UI remains disabled by product config. |
| LAB-FIXED-003 | Closed | Runtime | FIXED | Zot RollingUpdate caused single-writer BoltDB/RWO contention; deployment uses Recreate. |
| LAB-FIXED-004 | Closed | Runtime | FIXED | Keycloak readiness used a hostname-sensitive public endpoint and returned 403; readiness uses management `/health/ready` on port 9000. |
| LAB-FIXED-005 | Closed | Cross-platform | FIXED | Windows acquisition failed on POSIX directory fsync assumptions; atomic JSON durability is platform-correct. |
| LAB-FIXED-006 | Closed | CI | FIXED | Acquisition-admission test assumed only missing tools and failed on wrong-version tools; both exact-tool fail-closed outcomes are accepted. |
| LAB-FIXED-007 | Closed | CI | FIXED | Remote installer smoke accidentally used GitHub runner UID 1001 as target identity; fixture simulates only the remote identity probe as Linux/root without weakening production root enforcement. |
| LAB-FIXED-008 | Closed | GitOps | FIXED | Argo duplicate Fast Lab Application/proxy authority was removed and canonical `platform-appliance` remains the single observed reconciler. |
| LAB-FIXED-009 | Closed | Resilience | FIXED | Detached parallel waves now bind exact spec, script inputs and runner snapshot; reconnect skips green work and interrupted work resumes within bounded attempt budgets. |
| LAB-EVIDENCE-001 | P1 | DR | PENDING PHYSICAL | Execute whole-appliance off-node S3 backup, integrity read-back, destructive restore, secret restoration, GitOps recovery and post-restore service verification through the persisted installer authority. Source tests do not count as Physical PASS. |
| LAB-EVIDENCE-002 | P1 | Database HA | PENDING PHYSICAL | Existing replica-loss recovery passed; still force an actual CNPG primary loss/promotion under continuous API/OIDC/Git probes and verify no split authority. |
| LAB-EVIDENCE-003 | P1 | Storage HA | PENDING PHYSICAL | Exercise Longhorn node/disk loss and replica rebuild while PostgreSQL/Forgejo/Zot perform real writes; verify data integrity and recovery time. |
| LAB-EVIDENCE-004 | P1 | TLS | PENDING PHYSICAL | Replace temporary Fast Lab self-signed TLS with the product-owned trusted certificate path and exercise renewal/rotation plus trust propagation. |
| LAB-EVIDENCE-005 | P1 | OIDC | PENDING PHYSICAL | Authorization redirect/PKCE path is proven; complete a real login/callback/token/session flow through public HTTPS and verify logout/expiry/revocation. |
| LAB-EVIDENCE-006 | P1 | Node HA | PENDING OBSERVATION | vm-lab08 drain physically emitted `NODE_DRAIN_RECOVERY_PASS`; final clean detached v2 wave state is unobserved because Remote access stopped. Read the existing checkpoint before any future Lab action. |
| LAB-EVIDENCE-007 | P2 | Service HA | PENDING / PRODUCT DECISION | Forgejo and Zot are documented restart-failover services and showed brief disruption during failover. Keep the truthful HA class unless a future architecture deliberately adds continuous multi-writer/shared-storage semantics. |
| LAB-CLEANUP-001 | P2 | Lab hygiene | DEFERRED | vm-lab07 host PostgreSQL staging service and historical host Zot staging process must be ownership-checked and removed only when Lab access returns; they are not source authority. |
| LAB-SUPPLY-001 | P1 | Supply chain | OPEN | Finish current-main exact management workload OCI archive and immutable bundle authority; never infer READY from source-only progress. |
| LAB-SUPPLY-002 | P1 | Upgrade cert | OPEN | Complete exact historical component/runtime upgrade matrix and negative controls for the supported upgrade edges. |
| DEV-001 | P1 | AI/MCP | OPEN | Complete named external MCP-client interoperability matrix with user delegation, approval, progress, evidence and revocation. |
| DEV-002 | P1 | Providers | OPEN | J1: real Terraform provider + Crossplane provider against Product API authority. |
| DEV-003 | P1 | Providers | OPEN | H3: common provider execution framework plus AWS/Azure/GCP adapters without duplicating product authority. |
| DEV-004 | P1 | Developer platform | OPEN | J3: Virtual Cluster / Developer Mode lifecycle, workspace integration and policy boundaries. |
| DEV-005 | P2 | Edge | OPEN | I2: bounded edge/sovereign authority, boot attestation and disconnected local-AI profile. |
| DEV-006 | P1 | OKD | OPEN EVIDENCE/INTEGRATION | Continue connected Managed OKD, disconnected oc-mirror v2 and upgrade/runtime-certification lanes without moving Factory management plane onto OKD. |
| RELEASE-001 | Final | Certification | PENDING | Build one sealed immutable current-main FULL release, run Full Verifier, then Exact-SHA Physical Runtime certification. Fast Lab evidence must remain distinct. |

Execution order while Remote Commander is paused: **Lab-derived source hardening is now closed through current clean-clone CI → LAB-SUPPLY-001/002 and exact UI-browser acquisition → DEV-002/003/004/005/006 expansion development in parallel; DEV-001 remains external named-client evidence only → final runtime/Physical evidence queue only after Lab access is explicitly restored.**

## Current handoff checkpoint - 2026-09-19 software-only Lab-derived audit

- Remote Desktop Commander and all Lab mutation/probing remain paused by explicit user instruction. Do not reconnect until the user explicitly re-enables the Lab lane.
- Software-only deep audit converted accumulated Fast Lab observations into the canonical Lab-derived defect/hardening/development queue above; no parallel backlog file was created.
- P0 shared PostgreSQL ownership migration hazard is closed and CI-proven. The migration now fences shared database/tablespace ownership instead of letting REASSIGN OWNED transfer unrelated product authority.
- A new P0 credential-lifecycle defect was found during replay audit: successful bootstrap revocation was not durable because a future Start could regenerate the missing bootstrap token. Source now persists a revocation tombstone and requires explicit journaled Reset before another Start.
- Installer smoke was strengthened to follow the same reset semantics: switching from one completed install profile to another now requires Reset, and reset polling binds to exact sourceRunId rather than list position.
- Argo observer authority no longer exists only in the live Secret. Observer token persistence updates the authoritative foundation manifest first, then live state, and recognizes both HA and single-node manifest metadata styles.
- Windows-to-Bash transport has a repository-owned canonicalizer rather than ad-hoc CR stripping. Current source normalizes BOM/CRLF/bare CR, rejects malformed bytes and retains strict SSH verification.
- SSH HostKey audit found that duplicate/pinned trust and fingerprint reporting already exist. Remaining work is narrower: explicit product-owned host-key rotation evidence and a safe pin-update contract, not a second SSH trust subsystem.
- Legacy Argo namespace cleanup remains intentionally open because automatic deletion cannot yet prove ownership of a historical argocd namespace. Future migration must decommission only exactly product-owned legacy reconcilers after canonical platform-gitops is proven healthy; foreign Argo must remain untouched.
- Full Verifier browser self-containment remains open: Playwright is pinned, but browser bytes are still workstation/cache-dependent. Browser acquisition must become explicit immutable/offline-verifiable supply-chain authority rather than an implicit playwright install chromium prerequisite.
- Retained Longhorn smoke-volume cleanup remains open because source currently lacks sufficient ownership-evidence semantics for safe automatic deletion.
- Current Lab percentages and health must not be refreshed while Remote is paused. The last confirmed Fast Lab state remains historical evidence only, not a new probe.


## Current handoff checkpoint - 2026-09-19 Lab-derived source hardening closure

- Remote Commander remains intentionally paused by user instruction. No Lab state or Lab percentage was refreshed in this checkpoint.
- Canonical source checkpoint before this documentation commit: `805e52bed6ebafd73ec97533071bee69e92f6fd4`; repository-integrity run `35470862188` completed **SUCCESS** from a clean clone.
- The Lab-derived software queue now has source-level closure for SSH host-key rotation/recovery, legacy GitOps namespace/reconciler migration, exact Full Verifier browser authority, durable legacy HA database migration phases, and exact-evidence disposable Longhorn smoke cleanup.
- The historical retained Longhorn volume remains deliberately outside automatic cleanup authority because it predates `LONGHORN_DISPOSABLE_VOLUME_EVIDENCE_V1`.
- Full Verifier browser **source authority** is complete, but exact Chromium bytes plus their authority manifest remain a supply-chain input and must not be inferred from CI.
- MCP C7W source implementation remains complete; `MCP_EXTERNAL_CLIENT_INTEROP_MATRIX_PENDING` is external named-client execution evidence, not a reason to invent additional MCP business logic.
- The next genuine source-open expansion priority is J1: a real Terraform provider using the official Terraform provider framework and then a Crossplane provider over the same Product API/SDK authority. Mock/schema-only provider substitutes do not close J1.


## Current handoff checkpoint — 2026-09-20 J3 desired-state convergence

- Canonical source checkpoint before this handoff update: `3750edb3d220437034638435b2461d31651bb9a8`; repository-integrity run `35534385805` proved repository validation, Go/Python suites, Autopilot self-test, installer smoke, Terraform provider, Crossplane provider and PostgreSQL behavioral integration on the J3 API/Console convergence tree.
- J3 now has product-owned workspace-bound desired-state authority across Memory/File/PostgreSQL, migration `0078_virtual_cluster_authority.sql`, project-scoped REST create/list/get routes, generated Product API/SDK route contract, typed MCP parity and Operator Console creation/inspection.
- The PostgreSQL service-container gate proves the virtual-cluster row derives project/workspace/binding/host-cluster/namespace authority from the active WorkspaceBinding and enforces idempotent replay plus request-digest conflict rejection.
- The Console deliberately labels `REQUESTED` as desired state only. It does not expose Suspend/Resume/Delete or claim Running/Ready while the runtime executor is absent.
- `VIRTUAL_CLUSTER_API_MCP_CONSOLE_PENDING` is closed. `VIRTUAL_CLUSTER_DURABLE_RUNTIME_PENDING` remains the only J3 source blocker.
- Runtime direction is vCluster OSS, not vCluster Platform: acquire an exact stable chart and all referenced images through the existing 4SO Helm/Crane + zot supply-chain authority, then execute it through a lease/fence-bound target task with authoritative readback and `RECOVERY_REQUIRED` on ambiguous outcomes. No chart digest or runtime readiness is inferred before real acquisition.
- I2 edge/sovereign remains independently source-open; it can continue in parallel without waiting for J3 physical/runtime certification.
- Remote Commander remains paused. No SSH, Lab mutation or Lab probe was executed in this software wave. Historical Fast Lab state and percentages remain unchanged; Exact-SHA Physical Certification remains NOT RUN.

### چت بعدی / handoff

Refresh `origin/main` first and read this file. Confirm the repository-integrity result for the newest main SHA. Continue J3 at `VIRTUAL_CLUSTER_DURABLE_RUNTIME_PENDING`: add an exact, offline-verifiable vCluster OSS source-selection/acquisition contract without fabricating a digest; reuse the repository's pinned Helm/Crane acquisition and zot authority; then add a durable target-agent task/executor with lease/fence/idempotency, exact WorkspaceBinding revision/desired-digest binding, authoritative readback, and no automatic replay from UNKNOWN outcomes. Keep lifecycle actions hidden until the executor supports them. In parallel, advance I2 bounded edge-local authority/UI, boot-attestation semantics and disconnected local-AI profile. Remote/Lab must remain untouched until Reza explicitly re-enables it.


## Current handoff checkpoint — 2026-09-22 persistent full-Git fast-lane wave

- Canonical upstream base was re-materialized from GitHub at exact `main` SHA `020e21bb107d03877de4a40b9dc47703cb8706a2`, tree `dbe90ca67a597b6e88d07d6c81d8d571ae2d4ea1`. The exact export contains 1083/1083 tracked files and 131,245,260 tracked bytes; `git fsck --full` passed. A full Git bundle and exact source archive were independently checksum-verified before creating the persistent sandbox workspace.
- Development model is now **Persistent Full Git Workspace + Local Commits + Batched Main Push + Async CI**. Git remains the durable development truth, but network push/CI are checkpoint activities rather than synchronous blockers for every edit.
- `scripts/dev-checkpoint.sh` implements the fast-lane checkpoint contract. It runs an optional focused verification command before commit, commits locally, records `.local-dev/SESSION_STATE.json` and `.local-dev/PUSH_QUEUE.json`, bounds network push attempts, and records `PUSH_PENDING` without failing development when push is disabled/unavailable. `.local-dev/` is intentionally Git-ignored runtime state.
- The canonical `main` source contained a real compile blocker in `cmd/platform-agent`: two package-level `workloadImages` functions had incompatible signatures. The virtual-cluster-specific helper is now namespaced as `virtualClusterWorkloadImages`, restoring package compilation without changing the general workload explorer helper.
- The existing J3 negative control `TestVirtualClusterCompletedExecutorRequiresExactWorkloadReadback` exposed a second runtime defect: executor Job completion was promoted directly to Ready without verifying the owned StatefulSet. `inspectVirtualClusterExecutorJob` now requires authoritative virtual-cluster workload readback after Job completion, fails to `RECOVERY_REQUIRED` on readback failure, and only reports Ready after exact ownership/digest/image/readiness checks converge.
- The base tree also contained test-helper drift in `internal/virtualcluster/runtime_source_test.go`: two mirror-map tests referenced removed helper `runtimeSourceFixture`. They now use the canonical `resolvedRuntimeSourceForTest(t)` fixture rather than bypassing runtime-source validation.
- Fresh focused evidence on the merged full-tree workspace: `go test ./cmd/platform-agent -count=1` PASS; `go test ./internal/virtualcluster ./internal/controlplane ./internal/api -count=1` PASS; `python3 -m unittest tests.test_dev_checkpoint -v` 3/3 PASS; repository validator `REPOSITORY_VALIDATION_PASS 1080`, `TEST_SUITE_AUTHORITY_GATE_PASS 323`, Product API contract 350, MCP registry 75, resource-scope registry 75/75.
- One monolithic `go test ./...` attempt exceeded the single-command execution window and is **not** counted as a full-suite PASS. The development model therefore uses bounded owner/package shards during active waves and reserves full-suite/release verification for a checkpoint where the command can complete with fresh evidence.
- Remote Commander/Lab remains paused. No new Lab probe, mutation, Fast-Lab percentage, or Physical PASS was produced. Exact-SHA Physical Runtime certification remains NOT RUN.
- Next owner-layer jump: integrate the already-developed J3 lifecycle journal/runtime-controller contracts into the real Store/PostgreSQL/API/Agent surfaces of this full tree, then regenerate Product API/SDK/MCP/resource-scope/Console parity. Keep `VIRTUAL_CLUSTER_DURABLE_RUNTIME_PENDING` open until Suspend/Resume/Delete have real runtime mutation plus authoritative readback and restart-safe durable recovery in the production owner paths.
