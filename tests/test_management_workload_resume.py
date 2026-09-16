import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "acquire_management_workload_batch",
    ROOT / "scripts" / "acquire_management_workload_batch.py",
)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class ManagementWorkloadResumeTests(unittest.TestCase):
    def test_prepare_role_stage_dir_preserves_canonical_resumable_layout(self):
        with tempfile.TemporaryDirectory() as td:
            role = Path(td) / "forgejo"
            partial = role / ".layout.partial" / "blobs" / "sha256"
            partial.mkdir(parents=True)
            marker = partial / ("a" * 64)
            marker.write_bytes(b"partial")
            mod.prepare_role_stage_dir(role)
            self.assertEqual(b"partial", marker.read_bytes())

    def test_acquire_resumes_only_canonical_partial_layout(self):
        rows = [{
            "role": "forgejo",
            "repository": "codeberg.org/forgejo/forgejo",
            "tag": "15.0.7",
            "version": "15.0.7",
            "selectionChannel": "forgejo-lts",
            "selectionEvidenceURL": "https://forgejo.org/releases/",
        }]
        with tempfile.TemporaryDirectory() as td:
            stage = Path(td) / "stage"
            partial = stage / "forgejo" / ".layout.partial"
            partial.mkdir(parents=True)
            release = Path(td) / "release.zip"; release.write_bytes(b"release")
            ctl = Path(td) / "platformctl"; ctl.write_bytes(b"ctl")
            calls = []
            def fake_run(cmd, timeout=1800):
                calls.append(cmd)
                return {"verified": True, "result": {"exactReference": rows[0]["repository"] + "@sha256:" + "a" * 64}}
            fake_entry = {**rows[0], "manifestDigest": "sha256:" + "a" * 64, "exactReference": rows[0]["repository"] + "@sha256:" + "a" * 64, "layoutPath": "forgejo/layout", "lockPath": "forgejo/acquisition-lock.json", "lockDigest": "sha256:" + "b" * 64, "layoutTreeDigest": "sha256:" + "c" * 64, "layoutFileCount": 1, "layoutBytes": 1}
            with mock.patch.object(mod, "load_plan", return_value=({}, rows)), mock.patch.object(mod, "run_json", side_effect=fake_run), mock.patch.object(mod, "stage_entry", return_value=fake_entry):
                mod.acquire(stage, release, ctl)
            self.assertTrue(any("acquire-external" in cmd for cmd in calls))
            self.assertTrue(partial.is_dir())
