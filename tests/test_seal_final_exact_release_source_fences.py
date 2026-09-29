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
