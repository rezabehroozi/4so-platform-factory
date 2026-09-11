# Appliance bundle input

Build a local, digest-locked bundle with the canonical CLI:

```bash
platformctl appliance-bundle build \
  --spec examples/appliance-bundle/build-spec.example.json \
  --staging /path/to/prestaged-artifacts \
  --out /path/to/sealed-bundle \
  --release-artifact /path/to/4so-platform-factory-RELEASE.zip
```

The checked-in example is release-neutral (`metadata.version: 0.0.0`); copy it and replace that value with the exact release `VERSION` before building. `metadata.sourceReleaseDigest` in the build specification must equal the SHA-256 of the exact release ZIP supplied by `--release-artifact`. The CLI computes that digest itself and refuses mismatches. The digest is copied into `bundle.json`, `bundle.lock.json`, installer admission, Field Campaign state, and field-evidence inputs so a later Physical PASS can be tied to one exact release artifact.

The bundle must contain the official RKE2 installer, matching installation artifacts, RKE2 image archive, workload image archive, digest-pinned workload images, and the GitOps, CloudNativePG, and replicated-storage manifests. The canonical replicated-storage provider for the **Management Plane production-HA RKE2 appliance** is Longhorn `v1.12.1` using the V1 data engine and three replicas; the source lock pins its official `longhorn.yaml`. This does not make Longhorn a default for OKD or other targets. OCM is an optional integration: omit `workloads.ocmManifest` unless that integration is intentionally enabled. The installer never downloads missing artifacts during execution.

## Lab automatic acquisition

`LabExecution.spec.bundleDirectory` is optional. When it is omitted, `scripts/lab_runner.py run` reads only `lab/appliance-bundle-acquisition-lock.json` from the exact release ZIP. `LAB_APPLIANCE_BUNDLE_ACQUISITION_EXACT_RELEASE_BINDING_V1` makes the runner consume the lock bytes directly from the SHA-bound Exact Release ZIP rather than trusting an extracted copy. A ready `LAB_APPLIANCE_BUNDLE_ACQUISITION_LOCK_V8` points to one immutable input-pack ZIP by public HTTPS URL, exact byte size and SHA-256. The pack carries the build-spec template plus staged artifacts; its build spec must use `sha256:0000000000000000000000000000000000000000000000000000000000000000` as the source-release placeholder. The runner replaces that placeholder with the exact release ZIP digest and uses the release's own `platformctl` to build and verify the sealed bundle.

The current production lock is intentionally `incomplete`, but V8 now has four fully resolved authorities (Longhorn, CloudNativePG, RKE2 and Argo CD), zero partial authorities, one completely missing product-owned source authority (the management workload OCI archive), and one derived authority (the digest-pinned core workload image inventory) computed from that archive. RKE2 `install.sh` is bound to tag commit `d419f09226d50a4777d348e5c53ea1bce3849b77`, Git blob `88c5f55bdfde94f2277465ece2b749c52d86c69b`, SHA-256 `2d24db2184dd6b1a5e281fa45cc9a8234c889394721746f89b5fe953fdaaf40a`, and 25288 bytes. Argo CD `install.yaml` is bound to commit `e95e1be88a2da6c06bff5c2fe1791e4d233ed810`, Git blob `e0ff6c401aa18c2c67ba9dcb5f68f2f15853281f`, SHA-256 `a32bf36a437071a1f563ebf9e81c8a39fba9057c17db7d5d041afb7b6e3f4afe`, and 1917766 bytes. A ready V8 pack is not trusted by its pack digest alone: each resolved source is re-hashed at its unique `stagingPath`, every consumed build-spec source path must match its owner authority exactly, and the eight core workload image references must exactly match the locked image inventory. Unowned automatic inputs such as `ocmManifest` fail closed. Automatic acquisition therefore returns `LAB_CANONICAL_BUNDLE_SOURCE_LOCKS_PENDING` before input-pack acquisition until all production authorities are filled. An operator may still provide an already sealed `bundleDirectory`; that path is verified before installation and does not weaken the acquisition authority.

The legacy-compatible `scripts/build_appliance_bundle.py` path follows the same OCM policy: `--ocm-manifest` is optional. Omitting it produces no `ocmManifest` field and no OCM artifact/image in the air-gap index. Supplying it remains supported for an explicitly operator-prestaged OCM integration, but automatic Lab acquisition still rejects OCM until a canonical source authority is defined for it.
