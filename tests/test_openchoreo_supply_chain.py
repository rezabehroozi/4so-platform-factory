import subprocess
import sys
import tempfile
import unittest
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
import openchoreo_runtime_contract as contract
import build_openchoreo_executor_image as executor_image
import mirror_openchoreo_runtime as mirror_runtime
import prepare_openchoreo_executor as executor_context
import seal_openchoreo_runtime as runtime_seal

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

    def test_openchoreo_evidence_inputs_reject_direct_symlinks(self):
        with tempfile.TemporaryDirectory(prefix="4so-openchoreo-symlink-test-") as td:
            root = Path(td)
            evidence = root / "evidence.json"
            evidence.write_text("{}")
            evidence_link = root / "evidence-link.json"
            context = root / "context"
            context.mkdir()
            context_link = root / "context-link"
            buildctl = root / "buildctl"
            buildctl.write_text("#!/bin/sh\nexit 0\n")
            buildctl.chmod(0o755)
            buildctl_link = root / "buildctl-link"
            try:
                evidence_link.symlink_to(evidence)
                context_link.symlink_to(context, target_is_directory=True)
                buildctl_link.symlink_to(buildctl)
            except OSError as exc:
                self.skipTest(f"symlink unavailable: {exc}")

            with self.assertRaisesRegex(RuntimeError, "OPENCHOREO_MIRROR_EVIDENCE_FILE_INVALID"):
                runtime_seal.load_json(evidence_link, "OPENCHOREO_MIRROR_EVIDENCE")

            # All acquisition consumers must reject the symlink itself before
            # parsing archive bytes or touching network/toolchain state.
            with self.assertRaisesRegex(RuntimeError, "OPENCHOREO_EXECUTOR_ARCHIVE_INVALID"):
                executor_context.prepare(evidence_link, evidence, root / "tools", root / "executor-out")
            with self.assertRaisesRegex(RuntimeError, "OPENCHOREO_EXECUTOR_ARCHIVE_INVALID"):
                mirror_runtime.mirror(evidence_link, "zot.internal/openchoreo", root / "mirror.json")
            with self.assertRaisesRegex(RuntimeError, "OPENCHOREO_EXECUTOR_ARCHIVE_INVALID"):
                runtime_seal.seal(evidence_link, evidence, evidence, root / "runtime-source.json")

            with self.assertRaisesRegex(RuntimeError, "OPENCHOREO_EXECUTOR_CONTEXT_INVALID"):
                executor_image.load_context(context_link)
            with self.assertRaisesRegex(RuntimeError, "OPENCHOREO_BUILDKIT_CLIENT_INVALID"):
                executor_image.build(context, buildctl_link, "", "zot.internal/4so/openchoreo-runtime", root / "executor.json")

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
