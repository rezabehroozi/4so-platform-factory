import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import acquire_dapr_runtime as acquire
import mirror_dapr_runtime as mirror
import seal_dapr_runtime as seal


class DaprSupplyChainTests(unittest.TestCase):
    def run_script(self, name: str) -> None:
        proc = subprocess.run(
            [sys.executable, str(SCRIPTS / name), "--self-test"],
            cwd=ROOT, text=True, capture_output=True, timeout=60,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stdout + "\n" + proc.stderr)

    def test_source_only_self_tests(self):
        for name in ("acquire_dapr_runtime.py", "mirror_dapr_runtime.py", "prepare_dapr_executor.py", "build_dapr_executor_image.py", "seal_dapr_runtime.py"):
            with self.subTest(name=name):
                self.run_script(name)

    def test_python_tooling_identity_matches_go_source_plan(self):
        source = (ROOT / "internal" / "targetmodel" / "dapr.go").read_text()
        for token in (
            f'DaprUpstreamRef                = "{acquire.VERSION}"',
            f'DaprUpstreamCommit             = "{acquire.UPSTREAM_COMMIT}"',
            f'DaprRuntimeImageTag            = "{acquire.IMAGE_TAG}"',
            f'DaprUpstreamImageRegistry      = "{acquire.IMAGE_REGISTRY}"',
            'DaprRuntimeSourcePlanAuthority = "DAPR_RUNTIME_SOURCE_PLAN_V1"',
            'DaprRuntimeSupplyChainAuthority = "DAPR_RUNTIME_SUPPLY_CHAIN_LOCK_V1"',
        ):
            self.assertIn(token, source)

    def acquisition(self) -> dict:
        images = []
        for i, (role, repository) in enumerate(sorted(acquire.REQUIRED_IMAGES.items()), 1):
            digest = "sha256:" + str(i) * 64
            images.append({
                "role": role,
                "sourceRepository": repository,
                "sourceTagReference": f"{repository}:{acquire.IMAGE_TAG}",
                "sourceDigest": digest,
                "sourceReference": f"{repository}@{digest}",
            })
        digest = lambda ch: "sha256:" + ch * 64
        return {
            "authority": acquire.AUTHORITY,
            "sourcePlanAuthority": acquire.SOURCE_PLAN_AUTHORITY,
            "version": acquire.VERSION,
            "runtimeImageTag": acquire.IMAGE_TAG,
            "upstreamRepository": acquire.UPSTREAM_REPOSITORY,
            "upstreamRef": acquire.VERSION,
            "upstreamCommit": acquire.UPSTREAM_COMMIT,
            "sourceArchiveUrl": f"{acquire.UPSTREAM_REPOSITORY}/archive/{acquire.UPSTREAM_COMMIT}.tar.gz",
            "sourceArchiveFinalUrl": f"https://codeload.github.com/dapr/dapr/tar.gz/{acquire.UPSTREAM_COMMIT}",
            "sourceArchiveDigest": digest("a"),
            "helmChartPath": acquire.CHART_PATH,
            "helmChartDigest": digest("b"),
            "helmPackageName": f"dapr-{acquire.IMAGE_TAG}.tgz",
            "helmPackageDigest": digest("d"),
            "helmOverrides": [{"path": k, "value": v} for k, v in sorted(acquire.HELM_OVERRIDES.items())],
            "helmRenderDigest": digest("c"),
            "requiredImages": images,
            "resolved": True,
            "mirrorReady": False,
            "runtimeMutationPerformed": False,
            "physicalCertificationInferred": False,
        }

    def write_json(self, path: Path, value: dict) -> str:
        raw = json.dumps(value, indent=2, sort_keys=True).encode() + b"\n"
        path.write_bytes(raw)
        return seal.sha256_bytes(raw)

    def mirror_evidence(self, acquisition: dict, acquisition_digest: str) -> dict:
        registry = "platform-zot:5000"
        rows = []
        for row in acquisition["requiredImages"]:
            role = row["role"]
            digest = row["sourceDigest"]
            rows.append({
                "role": role,
                "sourceRepository": row["sourceRepository"],
                "sourceReference": row["sourceReference"],
                "sourceDigest": digest,
                "mirrorTagReference": f"{registry}/dapr/{role}:{acquire.IMAGE_TAG}",
                "mirrorReference": f"{registry}/dapr/{role}@{digest}",
                "mirrorDigest": digest,
            })
        return {
            "authority": seal.MIRROR_AUTHORITY,
            "registryAuthority": "zot",
            "registryScheme": "http",
            "registryIdentity": registry,
            "version": acquire.VERSION,
            "upstreamCommit": acquire.UPSTREAM_COMMIT,
            "acquisitionReceiptDigest": acquisition_digest,
            "helmPackageDigest": acquisition["helmPackageDigest"],
            "helmMirrorTagReference": f"{registry}/dapr-charts/dapr:{acquire.IMAGE_TAG}",
            "helmMirrorReference": f"{registry}/dapr-charts/dapr@" + ("sha256:" + "e" * 64),
            "helmMirrorManifestDigest": "sha256:" + "e" * 64,
            "helmMirrorContentDigest": acquisition["helmPackageDigest"],
            "images": rows,
            "mirrorReady": True,
            "registryReadback": True,
            "offlineReplayReady": True,
            "credentialsEmbedded": False,
            "runtimeMutationPerformed": False,
            "physicalCertificationInferred": False,
        }

    def executor_evidence(self, acquisition_digest: str, registry: str = "platform-zot:5000") -> dict:
        digest = "sha256:" + "f" * 64
        return {
            "authority": seal.EXECUTOR_AUTHORITY,
            "executorContextAuthority": seal.EXECUTOR_CONTEXT_AUTHORITY,
            "executorContextDigest": "sha256:" + "7" * 64,
            "acquisitionReceiptDigest": acquisition_digest,
            "sourceReleaseDigest": "sha256:" + "8" * 64,
            "buildAuthority": "buildkit",
            "buildctlVersion": "buildctl v0.test",
            "registryAuthority": "zot",
            "registryScheme": "http",
            "registryIdentity": registry,
            "imageReference": f"{registry}/4so/dapr-runtime@{digest}",
            "imageDigest": digest,
            "registryReadback": True,
            "credentialsEmbedded": False,
            "runtimeMutationPerformed": False,
            "physicalCertificationInferred": False,
        }

    def test_seal_accepts_exact_evidence_and_rejects_schema_drift(self):
        with tempfile.TemporaryDirectory(prefix="4so-dapr-seal-") as td:
            root = Path(td)
            acquisition = self.acquisition()
            acquisition_path = root / "acquisition.json"
            acquisition_digest = self.write_json(acquisition_path, acquisition)
            mirror_doc = self.mirror_evidence(acquisition, acquisition_digest)
            mirror_path = root / "mirror.json"
            self.write_json(mirror_path, mirror_doc)
            executor_doc = self.executor_evidence(acquisition_digest)
            executor_path = root / "executor.json"
            self.write_json(executor_path, executor_doc)
            out = root / "runtime-lock.json"

            lock = seal.seal(acquisition_path, mirror_path, executor_path, out)
            self.assertTrue(lock["admitted"])
            self.assertEqual("zot", lock["registryAuthority"])
            self.assertEqual("http", lock["registryScheme"])
            self.assertEqual("platform-zot:5000", lock["mirrorRegistry"])
            self.assertEqual(4, len(lock["imageLocks"]))
            self.assertEqual(acquisition["helmPackageDigest"], lock["helmPackageDigest"])
            self.assertEqual(mirror_doc["helmMirrorReference"], lock["helmMirrorReference"])
            self.assertRegex(lock["acquisitionReceiptDigest"], r"^sha256:[0-9a-f]{64}$")
            self.assertRegex(lock["mirrorEvidenceDigest"], r"^sha256:[0-9a-f]{64}$")
            self.assertEqual(executor_doc["imageReference"], lock["executorImageReference"])
            self.assertEqual(executor_doc["imageDigest"], lock["executorImageDigest"])
            self.assertRegex(lock["executorEvidenceDigest"], r"^sha256:[0-9a-f]{64}$")

            acquisition["untrustedClaim"] = True
            self.write_json(acquisition_path, acquisition)
            with self.assertRaisesRegex(RuntimeError, "DAPR_ACQUISITION_SCHEMA_INVALID"):
                seal.seal(acquisition_path, mirror_path, executor_path, out)

    def test_seal_rejects_mirror_reference_substitution(self):
        with tempfile.TemporaryDirectory(prefix="4so-dapr-mirror-drift-") as td:
            root = Path(td)
            acquisition = self.acquisition()
            acquisition_path = root / "acquisition.json"
            acquisition_digest = self.write_json(acquisition_path, acquisition)
            mirror_doc = self.mirror_evidence(acquisition, acquisition_digest)
            mirror_doc["images"][0]["mirrorReference"] += ".tampered"
            mirror_path = root / "mirror.json"
            self.write_json(mirror_path, mirror_doc)
            executor_path = root / "executor.json"
            self.write_json(executor_path, self.executor_evidence(acquisition_digest))
            with self.assertRaisesRegex(RuntimeError, "DAPR_MIRROR_REFERENCE_INVALID"):
                seal.seal(acquisition_path, mirror_path, executor_path, root / "runtime-lock.json")

    def test_seal_rejects_executor_registry_or_acquisition_drift(self):
        with tempfile.TemporaryDirectory(prefix="4so-dapr-executor-drift-") as td:
            root = Path(td)
            acquisition = self.acquisition()
            acquisition_path = root / "acquisition.json"
            acquisition_digest = self.write_json(acquisition_path, acquisition)
            mirror_path = root / "mirror.json"
            self.write_json(mirror_path, self.mirror_evidence(acquisition, acquisition_digest))
            executor = self.executor_evidence(acquisition_digest)
            executor["registryIdentity"] = "other-zot:5000"
            executor_path = root / "executor.json"
            self.write_json(executor_path, executor)
            with self.assertRaisesRegex(RuntimeError, "DAPR_EXECUTOR_EVIDENCE_AUTHORITY_INVALID"):
                seal.seal(acquisition_path, mirror_path, executor_path, root / "lock.json")

    def test_evidence_inputs_reject_symlinks(self):
        with tempfile.TemporaryDirectory(prefix="4so-dapr-symlink-") as td:
            root = Path(td)
            target = root / "real.json"
            target.write_text("{}")
            link = root / "link.json"
            try:
                link.symlink_to(target)
            except OSError as exc:
                self.skipTest(f"symlink unavailable: {exc}")
            with self.assertRaisesRegex(RuntimeError, "DAPR_ACQUISITION_FILE_INVALID"):
                seal.load_json(link, "DAPR_ACQUISITION")


    def test_registry_transport_parser_is_explicit(self):
        self.assertEqual(("http", "platform-zot:5000"), mirror.validate_registry_url("http://platform-zot:5000"))
        self.assertEqual(("https", "registry.example"), mirror.validate_registry_url("https://registry.example"))
        for invalid in ("platform-zot:5000", "ftp://platform-zot:5000", "http://platform-zot:5000/dapr"):
            with self.assertRaises(RuntimeError):
                mirror.validate_registry_url(invalid)

if __name__ == "__main__":
    unittest.main()
