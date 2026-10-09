import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("c7w_execution_bindings_source_authority",ROOT/"scripts"/"c7w_execution_bindings.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class C7WExecutionBindingSourceAuthorityTests(unittest.TestCase):
    def init_repo(self,root:Path)->str:
        subprocess.run(["git","init","-b","main"],cwd=root,check=True,capture_output=True)
        subprocess.run(["git","config","user.email","test@example.invalid"],cwd=root,check=True)
        subprocess.run(["git","config","user.name","Test"],cwd=root,check=True)
        (root/"seed.txt").write_text("seed\n")
        subprocess.run(["git","add","seed.txt"],cwd=root,check=True)
        subprocess.run(["git","commit","-m","seed"],cwd=root,check=True,capture_output=True)
        return subprocess.run(["git","rev-parse","HEAD"],cwd=root,check=True,text=True,capture_output=True).stdout.strip()

    def test_explicit_source_commit_must_match_git_head(self):
        head="a"*40
        with mock.patch.object(mod,"git_head",return_value=head):
            self.assertEqual(head,mod.source_commit_sha(Path("/repo"),""))
            self.assertEqual(head,mod.source_commit_sha(Path("/repo"),head))
            with self.assertRaisesRegex(RuntimeError,"MCP_EXTERNAL_EXECUTION_BINDINGS_SOURCE_MISMATCH"):
                mod.source_commit_sha(Path("/repo"),"b"*40)

    def test_invalid_explicit_source_commit_rejects_before_materialization(self):
        with mock.patch.object(mod,"git_head",return_value="a"*40):
            with self.assertRaisesRegex(RuntimeError,"MCP_EXTERNAL_EXECUTION_BINDINGS_SOURCE_UNAVAILABLE"):
                mod.source_commit_sha(Path("/repo"),"not-a-commit")

    def test_git_head_rejects_repository_subdirectory_as_root(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            self.init_repo(root)
            child=root/"child"; child.mkdir()
            with self.assertRaisesRegex(RuntimeError,"MCP_EXTERNAL_EXECUTION_BINDINGS_GIT_ROOT_INVALID"):
                mod.git_head(child)

    def test_required_freeze_allows_only_canonical_c7w_evidence_delta(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); head=self.init_repo(root)
            lab=root/"lab"; lab.mkdir()
            (lab/"mcp-external-client-interop-progress.json").write_text("{}\n")
            self.assertEqual(head,mod.source_commit_sha(root,head,require_freeze=True))
            (root/"unrelated.txt").write_text("drift\n")
            with self.assertRaisesRegex(RuntimeError,"MCP_EXTERNAL_LOCAL_SOURCE_NOT_FROZEN"):
                mod.source_commit_sha(root,head,require_freeze=True)

    def test_required_freeze_rejects_non_main_branch_at_same_head(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); head=self.init_repo(root)
            subprocess.run(["git","checkout","-b","feature"],cwd=root,check=True,capture_output=True)
            with self.assertRaisesRegex(RuntimeError,"MCP_EXTERNAL_LOCAL_BRANCH_NOT_MAIN"):
                mod.source_commit_sha(root,head,require_freeze=True)

    def test_required_freeze_rechecks_head_after_worktree_validation(self):
        head="a"*40
        changed="b"*40
        with (
            mock.patch.object(mod,"git_head",side_effect=[head,changed]) as git_head,
            mock.patch.object(mod,"_require_source_freeze"),
        ):
            with self.assertRaisesRegex(RuntimeError,"MCP_EXTERNAL_EXECUTION_BINDINGS_SOURCE_MISMATCH"):
                mod.source_commit_sha(Path("/repo"),head,require_freeze=True)
        self.assertEqual(2,git_head.call_count)


if __name__=="__main__":
    unittest.main()
