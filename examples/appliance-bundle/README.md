# Appliance bundle input

Build a local, digest-locked bundle with the canonical CLI:

```bash
platformctl appliance-bundle build \
  --spec examples/appliance-bundle/build-spec.example.json \
  --staging /path/to/prestaged-artifacts \
  --out /path/to/sealed-bundle \
  --release-artifact /path/to/4so-platform-factory-RELEASE.zip
```

`metadata.sourceReleaseDigest` in the build specification must equal the SHA-256 of the exact release ZIP supplied by `--release-artifact`. The CLI computes that digest itself and refuses mismatches. The digest is copied into `bundle.json`, `bundle.lock.json`, installer admission, Field Campaign state, and field-evidence inputs so a later Physical PASS can be tied to one exact release artifact.

The bundle must contain the official RKE2 installer, matching installation artifacts, RKE2 image archive, workload image archive, and digest-pinned workload images. The installer never downloads missing artifacts during execution.
