import ast
import sys
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
import run_mcp_external_interop as mod


class C7WCanonicalOutputAuthorityTests(unittest.TestCase):
    def test_cli_artifact_guard_accepts_only_canonical_progress_and_evidence_paths(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td).resolve()
            lab=root/"lab"
            lab.mkdir()
            progress=mod.require_canonical_artifact_path(
                root,
                mod.CANONICAL_PROGRESS_REL,
                mod.CANONICAL_PROGRESS_REL,
                "PROGRESS",
            )
            evidence=mod.require_canonical_artifact_path(
                root,
                mod.CANONICAL_EVIDENCE_REL,
                mod.CANONICAL_EVIDENCE_REL,
                "EVIDENCE",
            )
            self.assertEqual(root/mod.CANONICAL_PROGRESS_REL,progress)
            self.assertEqual(root/mod.CANONICAL_EVIDENCE_REL,evidence)
            with self.assertRaisesRegex(RuntimeError,"MCP_EXTERNAL_LOCAL_PROGRESS_PATH_INVALID"):
                mod.require_canonical_artifact_path(root,Path("progress.json"),mod.CANONICAL_PROGRESS_REL,"PROGRESS")
            with self.assertRaisesRegex(RuntimeError,"MCP_EXTERNAL_LOCAL_EVIDENCE_PATH_INVALID"):
                mod.require_canonical_artifact_path(root,root/"other-evidence.json",mod.CANONICAL_EVIDENCE_REL,"EVIDENCE")

    def test_broken_symlink_at_canonical_output_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td).resolve()
            lab=root/"lab"
            lab.mkdir()
            progress=root/mod.CANONICAL_PROGRESS_REL
            try:
                progress.symlink_to(root/"missing-progress-target.json")
            except OSError as exc:
                self.skipTest(f"symlink creation unavailable: {exc}")
            self.assertTrue(progress.is_symlink())
            self.assertFalse(progress.exists())
            with self.assertRaisesRegex(RuntimeError,"MCP_EXTERNAL_LOCAL_PROGRESS_PATH_INVALID"):
                mod.require_canonical_artifact_path(root,progress,mod.CANONICAL_PROGRESS_REL,"PROGRESS")

    def test_cli_main_guards_both_canonical_outputs_before_dispatch(self):
        source=(ROOT/"scripts"/"run_mcp_external_interop.py").read_text(encoding="utf-8")
        tree=ast.parse(source)
        main=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=="main")
        guarded=set()
        for node in ast.walk(main):
            if not isinstance(node,ast.Assign) or not isinstance(node.value,ast.Call):
                continue
            if not isinstance(node.value.func,ast.Name) or node.value.func.id!="require_canonical_artifact_path":
                continue
            for target in node.targets:
                if isinstance(target,ast.Attribute) and isinstance(target.value,ast.Name) and target.value.id=="args":
                    guarded.add(target.attr)
        self.assertEqual({"progress_out","evidence_out"},guarded)


if __name__=="__main__":
    unittest.main()
