import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]

SEAL_SPEC=importlib.util.spec_from_file_location("seal_final_exact_release",ROOT/"scripts"/"seal_final_exact_release.py")
sealer=importlib.util.module_from_spec(SEAL_SPEC); SEAL_SPEC.loader.exec_module(sealer)

PREFLIGHT_SPEC=importlib.util.spec_from_file_location("c9_preflight",ROOT/"scripts"/"c9_preflight.py")
preflight=importlib.util.module_from_spec(PREFLIGHT_SPEC); PREFLIGHT_SPEC.loader.exec_module(preflight)


class C9StableEvidenceSnapshotTests(unittest.TestCase):
    def test_sealer_exposes_single_open_existing_evidence_snapshot(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/"evidence.json"
            expected={"authority":"unit","sourceCommitSHA":"a"*40}
            path.write_text(json.dumps(expected)+"\n",encoding="utf-8")
            self.assertEqual(expected,sealer.load_existing_evidence_snapshot(path))

    def test_preflight_reuses_sealer_snapshot_loader(self):
        source=(ROOT/"scripts"/"c9_preflight.py").read_text(encoding="utf-8")
        start=source.index("def validate_existing_evidence")
        end=source.index("\ndef preflight",start)
        block=source[start:end]
        self.assertIn("sealer.load_existing_evidence_snapshot(evidence)",block)
        self.assertNotIn("evidence.read_text",block)
        self.assertNotIn("evidence.stat()",block)

    def test_snapshot_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            target=root/"target.json"; target.write_text("{}\n",encoding="utf-8")
            link=root/"evidence.json"
            try:
                link.symlink_to(target.name)
            except OSError as exc:
                self.skipTest(f"symlink creation unavailable: {exc}")
            with self.assertRaisesRegex(RuntimeError,"EXISTING_EVIDENCE_INVALID"):
                sealer.load_existing_evidence_snapshot(link)


if __name__=="__main__":
    unittest.main()
