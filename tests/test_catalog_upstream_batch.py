import importlib.util
import json
import sys
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location("acquire_upstream_batch", ROOT / "scripts" / "acquire_upstream_batch.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class UpstreamBatchTests(unittest.TestCase):
    def test_queue_is_deterministic_and_all_exact_source_candidates_execute(self):
        ready, review = mod.queue(ROOT)
        self.assertEqual(17, len(ready))
        self.assertEqual(0, len(review))
        self.assertEqual(sorted(ready), ready)
        self.assertTrue({"cilium", "kyverno", "metallb"}.issubset(set(ready)))
        self.assertFalse(set(ready) & {name for name, _ in review})

    def test_batch_command_uses_only_canonical_admission_and_atomic_install(self):
        cmd = mod.acquisition_cmd("loki")
        self.assertIn("--from-admission", cmd)
        self.assertIn("--component", cmd)
        self.assertIn("loki", cmd)
        self.assertIn("--install", cmd)
        self.assertNotIn("18.12.1", cmd)
        self.assertNotIn("https://grafana-community.github.io/helm-charts", cmd)

    def test_stage_command_does_not_mutate_repository(self):
        cmd = mod.acquisition_cmd("loki", install=False, out=Path("/stage/loki-18.12.1.zip"))
        self.assertIn("--from-admission", cmd)
        self.assertNotIn("--install", cmd)
        self.assertEqual("/stage/loki-18.12.1.zip", cmd[cmd.index("--out") + 1])

    def test_stage_manifest_is_derived_offline_handoff(self):
        entry = {
            "component": "alloy",
            "version": "1.11.0",
            "source": "https://grafana.github.io/helm-charts",
            "upstreamVersion": "1.11.0",
            "bundleFile": "alloy-1.11.0.zip",
            "bundleDigest": "sha256:" + "a" * 64,
            "upstreamArtifactDigest": "sha256:" + "b" * 64,
            "bundleKey": "alloy/1.11.0",
        }
        manifest = mod.stage_manifest([entry])
        self.assertEqual(mod.STAGE_AUTHORITY, manifest["spec"]["authority"])
        self.assertFalse(manifest["spec"]["networkFetchRequiredForInstall"])
        self.assertIn("upstream-admission.json", manifest["spec"]["canonicalAuthority"])
        self.assertEqual([entry], manifest["spec"]["entries"])

    def test_stage_manifest_rejects_duplicate_entries_before_install(self):
        with tempfile.TemporaryDirectory() as td:
            stage = Path(td)
            payload = b"not-a-real-bundle"
            bundle = stage / "alloy-1.11.0.zip"
            bundle.write_bytes(payload)
            digest = mod.sha256_file(bundle)
            entry = {
                "component": "alloy",
                "version": "1.11.0",
                "source": "https://grafana.github.io/helm-charts",
                "upstreamVersion": "1.11.0",
                "bundleFile": bundle.name,
                "bundleDigest": digest,
                "upstreamArtifactDigest": "sha256:" + "b" * 64,
                "bundleKey": "alloy/1.11.0",
            }
            manifest = mod.stage_manifest([entry, dict(entry)])
            with self.assertRaisesRegex(RuntimeError, "STAGED_BATCH_DUPLICATE"):
                mod.validate_stage_manifest(stage, manifest, root=ROOT)

    def test_stage_manifest_rejects_path_escape(self):
        entry = {
            "component": "alloy",
            "version": "1.11.0",
            "source": "https://grafana.github.io/helm-charts",
            "upstreamVersion": "1.11.0",
            "bundleFile": "../alloy-1.11.0.zip",
            "bundleDigest": "sha256:" + "a" * 64,
            "upstreamArtifactDigest": "sha256:" + "b" * 64,
            "bundleKey": "alloy/1.11.0",
        }
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaisesRegex(RuntimeError, "STAGED_BATCH_ENTRY_IDENTITY_INVALID"):
                mod.validate_stage_manifest(Path(td), mod.stage_manifest([entry]), root=ROOT)


if __name__ == "__main__":
    unittest.main()
