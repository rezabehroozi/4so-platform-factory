# Current Program Status ? PROGRAM_PHASE_MODEL_V68

`docs/PROGRAM_STATUS.md` is the single current human-readable status summary. Release **0.0.363** is the current repository release identity. Versioned `PHASE_STATUS_V*.md` files are historical release records; executable truth remains `internal/targetmodel/program.go`.

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
