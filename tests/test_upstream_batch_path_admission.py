import importlib.util
import tempfile
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("acquire_upstream_batch", ROOT / "scripts" / "acquire_upstream_batch.py")
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


class UpstreamBatchPathAdmissionTests(unittest.TestCase):
    def test_stage_reuses_verified_orphan_bundle_without_network_reacquisition(self):
        with tempfile.TemporaryDirectory() as td:
            stage = Path(td) / "stage"
            stage.mkdir()
            bundle = stage / "demo-1.2.3.zip"
            bundle.write_bytes(b"bundle")
            row = {
                "component": "demo",
                "status": "ready-for-acquisition",
                "selectedVersion": "1.2.3",
                "source": "https://charts.example.test",
                "upstreamVersion": "1.2.3",
            }
            verified = {
                "valid": True,
                "component": "demo",
                "version": "1.2.3",
                "upstreamUrl": row["source"],
                "bundleDigest": mod.sha256_file(bundle),
                "upstreamArtifactDigest": "sha256:" + "a" * 64,
            }
            with mock.patch.object(mod, "queue", return_value=(["demo"], [])), \
                 mock.patch.object(mod, "admission_map", return_value={"demo": row}), \
                 mock.patch.object(mod, "platformctl_prefix", return_value=["platformctl"]), \
                 mock.patch.object(mod, "_run_json", return_value=verified), \
                 mock.patch.object(mod, "validate_stage_manifest", side_effect=lambda _stage, manifest: manifest["spec"]["entries"]), \
                 mock.patch.object(mod.subprocess, "run") as run:
                rc = mod.stage(0, stage, None)
            self.assertEqual(0, rc)
            run.assert_not_called()
            manifest = (stage / mod.STAGE_MANIFEST).read_text()
            self.assertIn("demo-1.2.3.zip", manifest)

    def test_install_staged_resume_skips_exact_already_resolved_component(self):
        with tempfile.TemporaryDirectory() as td:
            stage = Path(td)
            (stage / mod.STAGE_MANIFEST).write_text("{}")
            entry = {
                "component": "gateway-api",
                "version": "1.5.1",
                "source": "https://github.com/kubernetes-sigs/gateway-api/releases/tag/v1.5.1",
                "upstreamVersion": "v1.5.1",
                "bundleFile": "gateway-api-1.5.1.zip",
                "bundleDigest": "sha256:" + "a" * 64,
                "upstreamArtifactDigest": "sha256:6007c679ec2b427b0c72f0fd724c502c95a341bfbad100ea56ec38c4d6f0d5bb",
                "bundleKey": "gateway-api/1.5.1",
            }
            with mock.patch.object(mod, "validate_stage_manifest", return_value=[entry]), \
                 mock.patch.object(mod, "platformctl_prefix", return_value=["platformctl"]), \
                 mock.patch.object(mod, "_run_json") as run_json, \
                 mock.patch.object(mod, "queue", return_value=([], [])), \
                 mock.patch.object(mod.subprocess, "run") as run:
                rc = mod.install_staged(stage, None)
            self.assertEqual(0, rc)
            run_json.assert_not_called()
            run.assert_not_called()

    def test_stage_and_platformctl_reject_direct_symlinks(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            real_stage = root / "stage"
            real_stage.mkdir()
            stage_link = root / "stage-link"
            real_ctl = root / "platformctl"
            real_ctl.write_text("#!/bin/sh\nexit 0\n")
            real_ctl.chmod(0o755)
            ctl_link = root / "platformctl-link"
            try:
                stage_link.symlink_to(real_stage, target_is_directory=True)
                ctl_link.symlink_to(real_ctl)
            except OSError as exc:
                self.skipTest(f"symlink unavailable: {exc}")
            with self.assertRaisesRegex(RuntimeError, "PLATFORMCTL_NOT_EXECUTABLE"):
                mod.platformctl_prefix(str(ctl_link))
            with self.assertRaisesRegex(RuntimeError, "STAGED_BATCH_DIRECTORY_NOT_REAL_DIRECTORY"):
                mod.stage(0, stage_link, None)


if __name__ == "__main__":
    unittest.main()
