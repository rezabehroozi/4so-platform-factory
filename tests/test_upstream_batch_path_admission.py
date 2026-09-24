import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("acquire_upstream_batch", ROOT / "scripts" / "acquire_upstream_batch.py")
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


class UpstreamBatchPathAdmissionTests(unittest.TestCase):
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
