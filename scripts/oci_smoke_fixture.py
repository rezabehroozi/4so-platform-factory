#!/usr/bin/env python3
"""Deterministic OCI image-layout fixture used by installer/runtime smoke tests.

This is test-only fixture generation. Production release images must come from the
real build pipeline and immutable image digests; this helper never supplies
production authority.
"""
from __future__ import annotations

import hashlib
import io
import json
import tarfile
from pathlib import Path

INVENTORY_AUTHORITY = "MANAGEMENT_WORKLOAD_OCI_ARCHIVE_INVENTORY_V2"
IMPORT_ADDRESSABILITY_AUTHORITY = "MANAGEMENT_WORKLOAD_OCI_IMPORT_ADDRESSABILITY_V2"


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def workload_repositories(prefix: str = "registry.local/") -> list[str]:
    return [prefix + name for name in (
        "postgres", "platform-api", "forgejo", "zot", "keycloak", "maintenance",
        "platform-agent", "platform-probe", "argocd", "cnpg", "storage",
    )]


def write_workload_oci_archive(path: Path, repositories: list[str]) -> dict[str, str]:
    blobs: dict[str, bytes] = {}
    refs: list[str] = []
    descriptors: list[dict[str, object]] = []
    for repo in repositories:
        config = json.dumps({"repository": repo}, separators=(",", ":"), sort_keys=True).encode()
        config_digest = _digest(config)
        config_hex = config_digest.split(":", 1)[1]
        blobs[config_hex] = config
        manifest = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": config_digest,
                "size": len(config),
            },
            "layers": [],
        }
        raw = json.dumps(manifest, separators=(",", ":"), sort_keys=True).encode()
        manifest_digest = _digest(raw)
        manifest_hex = manifest_digest.split(":", 1)[1]
        blobs[manifest_hex] = raw
        ref = f"{repo}@{manifest_digest}"
        refs.append(ref)
        descriptors.append({
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": manifest_digest,
            "size": len(raw),
            "platform": {"architecture": "amd64", "os": "linux"},
            "annotations": {
                "io.containerd.image.name": ref,
                "org.opencontainers.image.ref.name": ref,
            },
        })
    refs.sort()
    descriptors.sort(key=lambda item: str(item["digest"]))
    files: dict[str, bytes] = {
        "oci-layout": json.dumps({"imageLayoutVersion": "1.0.0"}, separators=(",", ":"), sort_keys=True).encode(),
        "index.json": json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "annotations": {"org.opencontainers.image.created.by": "4so-smoke-fixture"}, "manifests": descriptors}, separators=(",", ":"), sort_keys=True).encode(),
        "4so-image-inventory.json": json.dumps({
            "authority": INVENTORY_AUTHORITY,
            "schemaVersion": 2,
            "importAddressabilityAuthority": IMPORT_ADDRESSABILITY_AUTHORITY,
            "images": refs,
        }, separators=(",", ":"), sort_keys=True).encode(),
    }
    for hex_digest, raw in blobs.items():
        files[f"blobs/sha256/{hex_digest}"] = raw
    path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(path, "w", format=tarfile.USTAR_FORMAT) as tf:
        for name in sorted(files):
            raw = files[name]
            info = tarfile.TarInfo(name=name)
            info.mode = 0o644
            info.uid = 0
            info.gid = 0
            info.mtime = 0
            info.size = len(raw)
            tf.addfile(info, io.BytesIO(raw))
    return {ref.split("@", 1)[0]: ref for ref in refs}
