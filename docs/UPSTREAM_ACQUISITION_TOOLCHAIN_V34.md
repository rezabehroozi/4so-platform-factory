# Exact Upstream Acquisition Toolchain — V34

`PROGRAM_PHASE_MODEL_V34` hardens S1 by making the build-time Helm/OCI acquisition toolchain exact and machine-readable. This closes ambiguity about which tool binary may resolve source locks; it does **not** mean mandatory upstream sources are acquired or S1 is complete.

## Authority

Machine-readable lock: `catalog/upstream-acquisition-toolchain.json`  
Authority: `UPSTREAM_ACQUISITION_TOOLCHAIN_V2`

Policy is fail-closed:

- no unpinned tools;
- no `latest` resolution;
- upstream asset SHA-256 verification is mandatory for bootstrap;
- bootstrap is build-time only;
- tool binaries are not vendored into the product artifact.

## Exact tool locks

| Tool | Version | Platform | SHA-256 |
|---|---:|---|---|
| Helm | 4.2.4 | linux-amd64 | `c306b46f719b0a4da32d0f78ee21bf90ce8d602f15b22ab753f0674d1670a7f3` |
| Helm | 4.2.4 | linux-arm64 | `564de2191b881e9f71b5606b25345821ea1682f06ab90499d3ab22b530176da1` |
| Crane | 0.22.1 | linux-amd64 | `0ab7a1d6932a213aed964ce97666c3077fe691c8606413674a8b3e0b9ec4cda0` |
| Crane | 0.22.1 | linux-arm64 | `898c0cff975f898a33e8c4580bdafb0e7c02c7faa33374e946762f97c4ab7110` |

`scripts/upstream_acquisition_toolchain.py` validates the lock, resolves exact-version tools from an operator-selected directory or PATH, and optionally downloads/extracts only the pinned archive member after SHA-256 verification. It installs atomically with executable permissions and revalidates the binary version after extraction.

`scripts/acquire_upstream_helm.py` now calls this authority before any chart/repository/OCI acquisition. A missing or mismatched Helm/Crane binary blocks acquisition instead of falling back to another installed version.

## Environment truth

The current development execution environment does not provide the locked Helm/Crane binaries and cannot complete network bootstrap reliably. Therefore actual upstream acquisition remains unexecuted here. This is an execution-environment limitation, not evidence that S1 has passed.

## S1 remains blocked

The mandatory S1 blockers remain:

- `UPSTREAM_ADMISSION_REVIEWS_PENDING`
- `COMPONENT_SOURCE_ACQUISITION_PENDING`
- `SOURCE_LOCKS_PENDING`
- `MANAGEMENT_WORKLOAD_OCI_ARCHIVE_PENDING`
- `MANAGEMENT_IMAGE_DIGEST_LOCKS_PENDING`

The toolchain authority removes tool-version ambiguity only. S1 can close only after admitted source bytes and management workload images are actually acquired, verified, sealed and reproducibly rebuilt from exact locks.

## Disconnected staged-batch handoff — `UPSTREAM_STAGED_BATCH_V1`

The exact Helm/Crane toolchain is needed only on the connected acquisition host. `scripts/acquire_upstream_batch.py --stage-out DIR` runs admitted acquisitions without installing them into the source tree, verifies each produced ExternalCatalogBundle with `platformctl catalog-bundle verify`, and checkpoints a derived `stage-manifest.json` containing exact component/version/source identities and SHA-256 bundle/upstream-artifact digests.

The disconnected build host uses `scripts/acquire_upstream_batch.py --install-staged DIR`. It performs no network fetch and does not trust the manifest as source-of-truth: unresolved entries must still match the live canonical admission row and component release, every bundle file must be a real regular in-directory file with the recorded digest, `platformctl` must independently verify the same identities/digests, and only `catalog-bundle install` may mutate component/runtime/admission authorities. Already-installed entries remain safe to replay through the catalog-bundle idempotent recovery contract.
