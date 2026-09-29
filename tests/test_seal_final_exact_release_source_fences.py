import importlib.util, json, os, subprocess, tempfile, unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("seal_final_exact_release",ROOT/"scripts"/"seal_final_exact_release.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)

class FinalExactReleaseSourceFenceTests(unittest.TestCase):
    def git(self,root,*args):
        return subprocess.run(["git",*args],cwd=root,text=True,capture_output=True,check=True).stdout.strip()

    def test_git_source_rejects_untracked_bytes_not_bound_to_head(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            self.git(root,"init")
            self.git(root,"config","user.email","test@example.invalid")
            self.git(root,"config","user.name","Test")
            (root/"tracked.txt").write_text("tracked\n")
            self.git(root,"add","tracked.txt"); self.git(root,"commit","-m","initial")
            head=self.git(root,"rev-parse","HEAD")
            self.assertEqual(head,mod.git_source(root.resolve()))
            (root/"untracked.txt").write_text("not in HEAD\n")
            with self.assertRaisesRegex(RuntimeError,"SOURCE_NOT_EXACT_HEAD"):
                mod.git_source(root.resolve())

    def test_git_source_rejects_assume_unchanged_index_masking(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            self.git(root,"init")
            self.git(root,"config","user.email","test@example.invalid")
            self.git(root,"config","user.name","Test")
            tracked=root/"tracked.txt"; tracked.write_text("tracked\n")
            self.git(root,"add","tracked.txt"); self.git(root,"commit","-m","initial")
            self.git(root,"update-index","--assume-unchanged","tracked.txt")
            tracked.write_text("hidden-drift\n")
            with self.assertRaisesRegex(RuntimeError,"GIT_INDEX_FLAGS_FORBIDDEN"):
                mod.git_source(root.resolve())

    def test_detached_worktree_is_pinned_to_exact_head_and_isolated_from_root_drift(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/"repo"; root.mkdir()
            self.git(root,"init")
            self.git(root,"config","user.email","test@example.invalid")
            self.git(root,"config","user.name","Test")
            tracked=root/"tracked.txt"; tracked.write_text("v1\n")
            self.git(root,"add","tracked.txt"); self.git(root,"commit","-m","initial")
            head=self.git(root,"rev-parse","HEAD")
            workspace=Path(td)/"workspace"; workspace.mkdir()
            worktree=mod.prepare_exact_worktree(root.resolve(),head,workspace)
            try:
                self.assertEqual("v1\n",(worktree/"tracked.txt").read_text())
                tracked.write_text("root-drift\n")
                self.assertEqual("v1\n",(worktree/"tracked.txt").read_text())
                mod.verify_worktree_source_unchanged(worktree,head)
                self.git(worktree,"update-index","--assume-unchanged","tracked.txt")
                with self.assertRaisesRegex(RuntimeError,"WORKTREE_SOURCE_CHANGED"):
                    mod.verify_worktree_source_unchanged(worktree,head)
            finally:
                mod.remove_exact_worktree(root.resolve(),worktree)

    def test_exact_release_publication_is_source_sha_scoped(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td).resolve()
            name="4so-platform-factory-0.0.363-test.zip"
            first=mod.exact_release_publication_path(root,"a"*40,name)
            second=mod.exact_release_publication_path(root,"b"*40,name)
            self.assertEqual(root/"release"/"exact-sha"/("a"*40)/name,first)
            self.assertEqual(root/"release"/"exact-sha"/("b"*40)/name,second)
            self.assertNotEqual(first,second)
            with self.assertRaisesRegex(RuntimeError,"SOURCE_SHA_INVALID"):
                mod.exact_release_publication_path(root,"bad",name)

    def test_output_path_preserves_and_rejects_symlink_identity(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td).resolve()
            target=root/"target.json"; target.write_text("{}\n")
            alias=root/"seal.json"; alias.symlink_to(target.name)
            with self.assertRaisesRegex(RuntimeError,"OUTPUT_SYMLINK_FORBIDDEN"):
                mod.admit_output_path(root,alias)
            real=root/"real"; real.mkdir()
            parent_alias=root/"alias"; parent_alias.symlink_to(real.name,target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError,"OUTPUT_PARENT_SYMLINK_FORBIDDEN"):
                mod.admit_output_path(root,parent_alias/"seal.json")

    def test_atomic_seal_publication_never_replaces_existing_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); path=root/"seal.json"
            mod.atomic_write_json(path,{"authority":"test","value":1})
            first=path.read_bytes()
            with self.assertRaisesRegex(RuntimeError,"ALREADY_SEALED"):
                mod.atomic_write_json(path,{"authority":"test","value":2})
            self.assertEqual(first,path.read_bytes())

if __name__=="__main__":
    unittest.main()
