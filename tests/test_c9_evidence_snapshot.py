import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("seal_final_exact_release",ROOT/"scripts"/"seal_final_exact_release.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class C9EvidenceSnapshotTests(unittest.TestCase):
    def test_existing_evidence_resume_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            target=root/"target.json"; target.write_text("{}\n",encoding="utf-8")
            link=root/"evidence.json"
            try:
                link.symlink_to(target.name)
            except OSError as exc:
                self.skipTest(f"symlink creation unavailable: {exc}")
            with self.assertRaisesRegex(RuntimeError,"EXISTING_EVIDENCE_INVALID"):
                mod.resume_existing_evidence(root,link)

    def test_resume_path_keeps_full_release_revalidation(self):
        source=(ROOT/"scripts"/"seal_final_exact_release.py").read_text(encoding="utf-8")
        start=source.index("def resume_existing_evidence")
        end=source.index("\ndef execute",start)
        block=source[start:end]
        self.assertIn("verify_existing_release_full(root,source_sha,release)",block)
        self.assertIn("validate_final_evidence_lineage(root,source_sha,current_sha,out)",block)
        self.assertIn("FINAL_EXACT_RELEASE_SOURCE_CHANGED_DURING_RESUME",block)


if __name__=="__main__":
    unittest.main()
