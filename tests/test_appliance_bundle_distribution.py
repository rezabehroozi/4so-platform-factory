import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import zipfile
import importlib.util

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("seal_dist", ROOT / "scripts" / "seal_appliance_bundle_distribution.py")
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


class ApplianceBundleDistributionSealTests(unittest.TestCase):
    def fixture(self, root: Path):
        payload = b"oci-archive-bytes"
        manifest = b"manifest-bytes"
        receipt = {
            "authority": mod.RECEIPT_AUTHORITY, "archiveBuilt": True,
            "distributionReady": False, "runtimeCertified": False, "physicalCertified": False,
            "releaseVersion": "9.9.9", "archiveBytes": len(payload),
            "archiveSha256": "sha256:" + hashlib.sha256(payload).hexdigest(),
        }
        lock = {
            "authority": mod.LOCK_AUTHORITY, "schemaVersion": 8, "releaseVersion": "9.9.9",
            "status": "incomplete", "inputPack": None, "missingAuthorities": [],
            "derivedAuthorities": ["digest-pinned-core-workload-images"],
            "resolvedAuthorities": [{
                "id": "argocd-install-manifest", "kind": "kubernetes-manifest", "provider": "argocd",
                "version": "v1", "scope": "fixture", "artifacts": [{
                    "name": "install.yaml", "stagingPath": "manifests/install.yaml",
                    "urls": ["https://example.test/install.yaml"], "sha256": hashlib.sha256(manifest).hexdigest(),
                    "sizeBytes": len(manifest),
                }],
            }],
            "partialAuthorities": [{
                "id": mod.ARCHIVE_AUTHORITY, "kind": "oci-archive", "provider": "4so", "version": "9.9.9",
                "scope": "management-plane-workload-images-offline-distribution", "artifacts": [],
                "pendingArtifacts": [{
                    "name": "platform-workloads.oci.tar", "stagingPath": "workloads/platform-workloads.oci.tar",
                    "reason": "distribution pending", "sourceRef": "https://github.com/example/repo/actions/runs/1",
                    "contentAddress": "git-sha1:" + "a" * 40,
                }],
            }],
        }
        build = {"apiVersion": "platform.4so.io/v1alpha1", "kind": "ApplianceBundleBuild",
                 "metadata": {"version": "9.9.9", "sourceReleaseDigest": mod.ZERO_RELEASE_DIGEST}, "spec": {}}
        pack = root / "pack.zip"
        with zipfile.ZipFile(pack, "w", compression=zipfile.ZIP_STORED) as zf:
            zf.writestr("build-spec.json", json.dumps(build))
            zf.writestr("staging/manifests/install.yaml", manifest)
            zf.writestr("staging/workloads/platform-workloads.oci.tar", payload)
        return lock, receipt, pack

    def test_seal_requires_exact_pack_and_preserves_claim_scope(self):
        with tempfile.TemporaryDirectory() as td:
            lock, receipt, pack = self.fixture(Path(td))
            sha, size = mod.inspect_input_pack(pack, lock, receipt)
            out = mod.build_ready_lock(
                lock, receipt,
                archive_url="https://downloads.example.test/platform-workloads.oci.tar",
                input_pack_url="https://downloads.example.test/appliance-input-pack.zip",
                pack_sha=sha, pack_size=size,
            )
            self.assertEqual("ready", out["status"])
            self.assertEqual([], out["partialAuthorities"])
            archive = next(x for x in out["resolvedAuthorities"] if x["id"] == mod.ARCHIVE_AUTHORITY)
            self.assertEqual(receipt["archiveSha256"].removeprefix("sha256:"), archive["artifacts"][0]["sha256"])
            self.assertEqual(sha, out["inputPack"]["sha256"])
            self.assertFalse(receipt["runtimeCertified"])
            self.assertFalse(receipt["physicalCertified"])

    def test_pack_tamper_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            lock, receipt, pack = self.fixture(Path(td))
            with zipfile.ZipFile(pack, "a", compression=zipfile.ZIP_STORED) as zf:
                zf.writestr("staging/manifests/install.yaml", b"tampered")
            with self.assertRaisesRegex(RuntimeError, "DUPLICATE|DIGEST"):
                mod.inspect_input_pack(pack, lock, receipt)

    def test_nonimmutable_urls_are_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "IMMUTABLE_PUBLIC_HTTPS_REQUIRED"):
            mod.immutable_https_url("https://example.test/archive?token=secret", "ARCHIVE_URL")
        with self.assertRaisesRegex(RuntimeError, "IMMUTABLE_PUBLIC_HTTPS_REQUIRED"):
            mod.immutable_https_url("http://example.test/archive", "ARCHIVE_URL")


if __name__ == "__main__":
    unittest.main()
