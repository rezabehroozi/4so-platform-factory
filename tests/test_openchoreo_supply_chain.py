import subprocess
import sys
import unittest
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
import openchoreo_runtime_contract as contract

class OpenChoreoSupplyChainSelfTests(unittest.TestCase):
    def run_script(self, name: str) -> None:
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / name), "--self-test"],
            cwd=ROOT, text=True, capture_output=True, timeout=60,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stdout + "\n" + proc.stderr)

    def test_openchoreo_acquisition(self):
        self.run_script("acquire_openchoreo_runtime.py")

    def test_openchoreo_executor_context(self):
        self.run_script("prepare_openchoreo_executor.py")

    def test_openchoreo_zot_mirror(self):
        self.run_script("mirror_openchoreo_runtime.py")

    def test_openchoreo_executor_image(self):
        self.run_script("build_openchoreo_executor_image.py")

    def test_openchoreo_runtime_seal(self):
        self.run_script("seal_openchoreo_runtime.py")

    def test_openchoreo_exact_identity_is_shared_with_source_selection(self):
        selection = json.loads((ROOT / "runtime" / "openchoreo" / "source-selection.json").read_text())
        spec = selection["spec"]
        self.assertEqual(spec["version"], contract.VERSION)
        self.assertEqual(spec["upstreamRepository"], contract.UPSTREAM_REPOSITORY)
        self.assertEqual(spec["upstreamCommit"], contract.UPSTREAM_COMMIT)
        self.assertEqual(spec["authority"], contract.SOURCE_AUTHORITY)
        legacy = "1aeed89856d088dc5160c0f3eaa39796d4a93611"
        for name in (
            "acquire_openchoreo_runtime.py",
            "prepare_openchoreo_executor.py",
            "seal_openchoreo_runtime.py",
        ):
            self.assertNotIn(legacy, (SCRIPTS / name).read_text(), msg=name)

if __name__ == "__main__":
    unittest.main()
