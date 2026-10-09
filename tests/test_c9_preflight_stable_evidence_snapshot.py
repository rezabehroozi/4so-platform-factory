import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]

PREFLIGHT_SPEC=importlib.util.spec_from_file_location("c9_preflight",ROOT/"scripts"/"c9_preflight.py")
preflight=importlib.util.module_from_spec(PREFLIGHT_SPEC); PREFLIGHT_SPEC.loader.exec_module(preflight)


class C9StableEvidenceSnapshotTests(unittest.TestCase):
    def test_preflight_existing_evidence_snapshot_reads_one_regular_json_file(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/"evidence.json"
            expected={"authority":"unit","sourceCommitSHA":"a"*40}
            path.write_text(json.dumps(expected)+"\n",encoding="utf-8")
            self.assertEqual(expected,preflight.load_existing_evidence_snapshot(path))

    def test_validate_existing_evidence_uses_snapshot_loader_not_path_reopen(self):
        source=(ROOT/"scripts"/"c9_preflight.py").read_text(encoding="utf-8")
        start=source.index("def validate_existing_evidence")
        end=source.index("\ndef preflight",start)
        block=source[start:end]
        self.assertIn("load_existing_evidence_snapshot(evidence)",block)
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
                preflight.load_existing_evidence_snapshot(link)

    def test_snapshot_rejects_symlinked_parent_directory(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/"repo"; root.mkdir()
            outside=Path(td)/"outside"; outside.mkdir()
            evidence=outside/"final-exact-release-evidence.json"
            evidence.write_text('{"authority":"outside"}\n',encoding="utf-8")
            lab=root/"lab"
            try:
                lab.symlink_to(outside,target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"symlink creation unavailable: {exc}")
            with self.assertRaisesRegex(RuntimeError,"EXISTING_EVIDENCE_INVALID"):
                preflight.load_existing_evidence_snapshot(lab/evidence.name)

    def test_preflight_hands_existing_evidence_to_exact_host_when_dir_fd_is_unavailable(self):
        source_sha="e"*40
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); out=root/"lab"/"final-exact-release-evidence.json"; out.parent.mkdir()
            out.write_text('{"authority":"placeholder"}\n',encoding="utf-8")
            with mock.patch.object(preflight.sealer,"git_source_for_resume",return_value=source_sha), \
                 mock.patch.object(preflight.os,"supports_dir_fd",set()), \
                 mock.patch.object(preflight.sealer,"exact_source_admission",side_effect=AssertionError("admission must wait for secure evidence read")):
                result=preflight.preflight(root)
        self.assertFalse(result["ready"])
        self.assertTrue(result["resumeExistingEvidence"])
        self.assertFalse(result["admissionReady"])
        self.assertEqual(source_sha,result["sourceCommitSHA"])
        self.assertEqual("RUN_C9_ON_EXACT_LINUX_HOST",result["nextActionCode"])
        self.assertEqual(preflight.C9_COMMAND_TEMPLATE,result["nextCommandTemplate"])
        self.assertEqual([],result["nextCommand"])


if __name__=="__main__":
    unittest.main()
