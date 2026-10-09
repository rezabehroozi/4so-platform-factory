import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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

    def test_resume_path_keeps_full_release_revalidation_and_stable_evidence_bytes(self):
        source=(ROOT/"scripts"/"seal_final_exact_release.py").read_text(encoding="utf-8")
        start=source.index("def resume_existing_evidence")
        end=source.index("\ndef execute",start)
        block=source[start:end]
        self.assertIn("verify_existing_release_full(root,source_sha,release)",block)
        self.assertIn("validate_final_evidence_lineage(root,source_sha,current_sha,out)",block)
        self.assertIn("FINAL_EXACT_RELEASE_SOURCE_CHANGED_DURING_RESUME",block)
        snapshot='admission.mcp_contract.load_with_sha256(out,"FINAL_EXACT_RELEASE_EXISTING_EVIDENCE",max_bytes=1024*1024)'
        self.assertGreaterEqual(block.count(snapshot),2)
        self.assertIn("FINAL_EXACT_RELEASE_EXISTING_EVIDENCE_CHANGED_DURING_RESUME",block)

    def test_git_handoff_rejects_persisted_evidence_drift_before_git_state(self):
        evidence={"sourceCommitSHA":"a"*40,"authority":mod.AUTHORITY}
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); out=root/"evidence.json"; out.write_text("{}\n",encoding="utf-8")
            with mock.patch.object(
                mod.admission.mcp_contract,
                "load_with_sha256",
                return_value=({"sourceCommitSHA":"b"*40,"authority":mod.AUTHORITY},"sha256:"+"c"*64),
            ):
                with self.assertRaisesRegex(RuntimeError,"EVIDENCE_HANDOFF_DRIFT"):
                    mod.final_git_handoff(root,out,evidence)

    def test_git_handoff_rejects_symlinked_evidence_parent_before_read(self):
        evidence={"sourceCommitSHA":"a"*40,"authority":mod.AUTHORITY}
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/"repo"; root.mkdir()
            outside=Path(td)/"outside"; outside.mkdir()
            target=outside/"final-exact-release-evidence.json"
            target.write_text(json.dumps(evidence)+"\n",encoding="utf-8")
            lab=root/"lab"
            try:
                lab.symlink_to(outside,target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"symlink creation unavailable: {exc}")
            with mock.patch.object(
                mod,
                "verify_evidence_publication_binding",
                side_effect=AssertionError("publication verification must not run after an unsafe evidence-parent read"),
            ):
                with self.assertRaisesRegex(RuntimeError,"EVIDENCE_HANDOFF_INVALID"):
                    mod.final_git_handoff(root,lab/target.name,evidence)


if __name__=="__main__":
    unittest.main()
