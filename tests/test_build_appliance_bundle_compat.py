from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "build_appliance_bundle.py"


def make_release_archive(root: Path, version: str) -> Path:
    archive = root / "release.zip"
    release_name = "compat-builder-test"
    release_root = f"4so-platform-factory-{version}-{release_name}"
    version_raw = (version + "\n").encode()
    release_name_raw = (release_name + "\n").encode()
    rows = []
    for relative, raw in (("VERSION", version_raw), ("RELEASE-NAME", release_name_raw)):
        rows.append({
            "path": relative,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "size": len(raw),
            "mode": "0o644",
        })
    manifest_raw = (json.dumps({
        "schemaVersion": 2,
        "product": "4SO Platform Factory",
        "version": version,
        "releaseName": release_name,
        "fileCount": len(rows),
        "files": rows,
    }, sort_keys=True) + "\n").encode()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as zf:
        for relative, raw in (("VERSION", version_raw), ("RELEASE-NAME", release_name_raw), ("ARTIFACT-MANIFEST.json", manifest_raw)):
            info = zipfile.ZipInfo(f"{release_root}/{relative}")
            info.create_system = 3
            info.external_attr = ((stat.S_IFREG | 0o644) & 0xFFFF) << 16
            info.compress_type = zipfile.ZIP_STORED
            zf.writestr(info, raw)
    return archive




def make_workload_oci_archive(path: Path, repositories: list[str]) -> dict[str, str]:
    media_manifest = "application/vnd.oci.image.manifest.v1+json"
    media_config = "application/vnd.oci.image.config.v1+json"
    blobs: dict[str, bytes] = {}
    refs: dict[str, str] = {}
    descriptors = []
    for repo in repositories:
        config_raw = json.dumps({"architecture": "amd64", "os": "linux", "rootfs": {"type": "layers", "diff_ids": []}, "config": {"Labels": {"test.repository": repo}}}, sort_keys=True, separators=(",", ":")).encode()
        config_digest = hashlib.sha256(config_raw).hexdigest()
        blobs[config_digest] = config_raw
        manifest_raw = json.dumps({
            "schemaVersion": 2,
            "mediaType": media_manifest,
            "config": {"mediaType": media_config, "digest": f"sha256:{config_digest}", "size": len(config_raw)},
            "layers": [],
        }, sort_keys=True, separators=(",", ":")).encode()
        digest = hashlib.sha256(manifest_raw).hexdigest()
        blobs[digest] = manifest_raw
        ref = f"registry.test/{repo}@sha256:{digest}"
        refs[repo] = ref
        descriptors.append({
            "mediaType": media_manifest,
            "digest": f"sha256:{digest}",
            "size": len(manifest_raw),
            "annotations": {"io.containerd.image.name": ref, "org.opencontainers.image.ref.name": ref},
        })
    inventory_raw = json.dumps({
        "authority": "MANAGEMENT_WORKLOAD_OCI_ARCHIVE_INVENTORY_V2",
        "schemaVersion": 2,
        "importAddressabilityAuthority": "MANAGEMENT_WORKLOAD_OCI_IMPORT_ADDRESSABILITY_V2",
        "images": sorted(refs.values()),
    }, sort_keys=True, separators=(",", ":")).encode()
    index_raw = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": descriptors}, sort_keys=True, separators=(",", ":")).encode()
    layout_raw = b'{"imageLayoutVersion":"1.0.0"}'
    with tarfile.open(path, "w") as tf:
        for name, raw in [("oci-layout", layout_raw), ("index.json", index_raw), ("4so-image-inventory.json", inventory_raw)]:
            info = tarfile.TarInfo(name); info.size = len(raw); info.mode = 0o600; info.mtime = 0
            tf.addfile(info, io.BytesIO(raw))
        for digest, raw in sorted(blobs.items()):
            info = tarfile.TarInfo(f"blobs/sha256/{digest}"); info.size = len(raw); info.mode = 0o600; info.mtime = 0
            tf.addfile(info, io.BytesIO(raw))
    return refs

def image(name: str, digit: str) -> str:
    return f"registry.test/{name}@sha256:{digit * 64}"


def manifest(name: str, digit: str) -> bytes:
    return (
        "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n"
        f"      containers:\n        - name: {name}\n          image: {image(name, digit)}\n"
    ).encode()


class CompatBuilderOCMContractTest(unittest.TestCase):
    def test_compatibility_builder_does_not_require_ocm(self) -> None:
        version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release = make_release_archive(root, version)
            refs = make_workload_oci_archive(root / "workloads.oci.tar", [
                "postgres", "api", "forgejo", "zot", "keycloak", "maintenance", "agent", "probe",
                "argocd", "cnpg", "storage",
            ])
            files = {
                "install.sh": b"#!/bin/sh\nexit 0\n",
                "rke2.tar.gz": b"rke2",
                "rke2-images.tar.zst": b"rke2-images",
                "argocd.yaml": ("apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n        - name: argocd\n          image: " + refs["argocd"] + "\n").encode(),
                "cnpg.yaml": ("apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n        - name: cnpg\n          image: " + refs["cnpg"] + "\n").encode(),
                "storage.yaml": ("apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n        - name: storage\n          image: " + refs["storage"] + "\n").encode(),
            }
            for name, raw in files.items():
                (root / name).write_bytes(raw)
            output = root / "bundle"
            cmd = [
                sys.executable, str(SCRIPT),
                "--output", str(output),
                "--version", version,
                "--release-artifact", str(release),
                "--rke2-version", "v1.34.10+rke2r1",
                "--rke2-installer", str(root / "install.sh"),
                "--rke2-install-artifact", str(root / "rke2.tar.gz"),
                "--rke2-image-archive", str(root / "rke2-images.tar.zst"),
                "--workload-image-archive", str(root / "workloads.oci.tar"),
                "--postgres-image", refs["postgres"],
                "--platform-api-image", refs["api"],
                "--forgejo-image", refs["forgejo"],
                "--zot-image", refs["zot"],
                "--keycloak-image", refs["keycloak"],
                "--maintenance-image", refs["maintenance"],
                "--gitops-manifest", str(root / "argocd.yaml"),
                "--cloudnative-pg-manifest", str(root / "cnpg.yaml"),
                "--storage-manifest", str(root / "storage.yaml"),
                "--fleet-agent-image", refs["agent"],
                "--runtime-probe-image", refs["probe"],
            ]
            completed = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=30)
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            bundle = json.loads((output / "bundle.json").read_text(encoding="utf-8"))
            self.assertNotIn("ocmManifest", bundle["spec"]["workloads"])
            index = json.loads((output / "artifacts" / "airgap-index.json").read_text(encoding="utf-8"))
            self.assertFalse(any("ocm" in value.lower() for value in index["artifacts"]))
            self.assertFalse(any("ocm" in value.lower() for value in index["images"]))

    def test_compatibility_builder_rejects_symlink_source(self) -> None:
        version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release = make_release_archive(root, version)
            real = root / "real-install.sh"
            real.write_text("#!/bin/sh\n", encoding="utf-8")
            link = root / "install.sh"
            try:
                link.symlink_to(real)
            except OSError:
                self.skipTest("symlink unavailable")
            cmd = [
                sys.executable, str(SCRIPT), "--output", str(root / "bundle"), "--version", version,
                "--release-artifact", str(release), "--rke2-version", "test",
                "--rke2-installer", str(link), "--rke2-install-artifact", str(root / "missing-rke2"),
                "--rke2-image-archive", str(root / "missing-images"), "--workload-image-archive", str(root / "missing-workload"),
                "--postgres-image", image("postgres", "1"), "--platform-api-image", image("api", "2"),
                "--forgejo-image", image("forgejo", "3"), "--zot-image", image("zot", "4"),
                "--keycloak-image", image("keycloak", "5"), "--maintenance-image", image("maintenance", "6"),
                "--gitops-manifest", str(root / "missing-gitops"), "--cloudnative-pg-manifest", str(root / "missing-cnpg"),
                "--storage-manifest", str(root / "missing-storage"), "--fleet-agent-image", image("agent", "7"),
                "--runtime-probe-image", image("probe", "8"),
            ]
            completed = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=30)
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("non-empty regular non-symlink", completed.stderr)
            self.assertFalse((root / "bundle" / "bundle.lock.json").exists())

    def test_compatibility_builder_rejects_duplicate_flattened_basename(self) -> None:
        version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release = make_release_archive(root, version)
            first = root / "one" / "same.bin"; second = root / "two" / "same.bin"
            first.parent.mkdir(); second.parent.mkdir(); first.write_bytes(b"one"); second.write_bytes(b"two")
            cmd = [
                sys.executable, str(SCRIPT), "--output", str(root / "bundle"), "--version", version,
                "--release-artifact", str(release), "--rke2-version", "test",
                "--rke2-installer", str(first), "--rke2-install-artifact", str(second),
                "--rke2-image-archive", str(root / "missing-images"), "--workload-image-archive", str(root / "missing-workload"),
                "--postgres-image", image("postgres", "1"), "--platform-api-image", image("api", "2"),
                "--forgejo-image", image("forgejo", "3"), "--zot-image", image("zot", "4"),
                "--keycloak-image", image("keycloak", "5"), "--maintenance-image", image("maintenance", "6"),
                "--gitops-manifest", str(root / "missing-gitops"), "--cloudnative-pg-manifest", str(root / "missing-cnpg"),
                "--storage-manifest", str(root / "missing-storage"), "--fleet-agent-image", image("agent", "7"),
                "--runtime-probe-image", image("probe", "8"),
            ]
            completed = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=30)
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("duplicate artifact basename", completed.stderr)
            self.assertFalse((root / "bundle" / "bundle.lock.json").exists())

    def test_compatibility_builder_rejects_workload_archive_image_mismatch(self) -> None:
        version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release = make_release_archive(root, version)
            refs = make_workload_oci_archive(root / "workloads.oci.tar", [
                "postgres", "api", "forgejo", "zot", "keycloak", "maintenance", "agent", "probe",
                "argocd", "cnpg",  # deliberately omit storage
            ])
            # The storage manifest claims an exact digest that the workload archive does not contain.
            missing_storage = image("storage", "7")
            (root / "install.sh").write_bytes(b"#!/bin/sh\nexit 0\n")
            (root / "rke2.tar.gz").write_bytes(b"rke2")
            (root / "rke2-images.tar.zst").write_bytes(b"rke2-images")
            (root / "argocd.yaml").write_text("image: " + refs["argocd"] + "\n", encoding="utf-8")
            (root / "cnpg.yaml").write_text("image: " + refs["cnpg"] + "\n", encoding="utf-8")
            (root / "storage.yaml").write_text("image: " + missing_storage + "\n", encoding="utf-8")
            cmd = [
                sys.executable, str(SCRIPT), "--output", str(root / "bundle"), "--version", version,
                "--release-artifact", str(release), "--rke2-version", "v1.34.10+rke2r1",
                "--rke2-installer", str(root / "install.sh"), "--rke2-install-artifact", str(root / "rke2.tar.gz"),
                "--rke2-image-archive", str(root / "rke2-images.tar.zst"), "--workload-image-archive", str(root / "workloads.oci.tar"),
                "--postgres-image", refs["postgres"], "--platform-api-image", refs["api"], "--forgejo-image", refs["forgejo"],
                "--zot-image", refs["zot"], "--keycloak-image", refs["keycloak"], "--maintenance-image", refs["maintenance"],
                "--gitops-manifest", str(root / "argocd.yaml"), "--cloudnative-pg-manifest", str(root / "cnpg.yaml"),
                "--storage-manifest", str(root / "storage.yaml"), "--fleet-agent-image", refs["agent"], "--runtime-probe-image", refs["probe"],
            ]
            completed = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=30)
            self.assertNotEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertIn("workload OCI archives must contain exactly all required product and operator/storage images", completed.stderr)
            self.assertFalse((root / "bundle" / "bundle.lock.json").exists())


if __name__ == "__main__":
    unittest.main()
