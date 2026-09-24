import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

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

if __name__ == "__main__":
    unittest.main()
