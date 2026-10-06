import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("seal_final_exact_release_parent_authority",ROOT/"scripts"/"seal_final_exact_release.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


@unittest.skipIf(not hasattr(os,"symlink"),"symlink unavailable")
class C9ParentAuthorityTests(unittest.TestCase):
    def _symlink_or_skip(self,target:Path,link:Path):
        try:
            os.symlink(target,link)
        except OSError as exc:
            self.skipTest(f"symlink unavailable: {exc}")

    def test_stage_toolchain_rejects_broken_parent_before_mkdir(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            archive=root/"go.tgz"; archive.write_bytes(b"trusted-toolchain")
            worktree=root/"worktree"; worktree.mkdir()
            self._symlink_or_skip(root/"missing-vendor",worktree/"vendor")
            exact={
                "localArchivePath":"vendor/toolchains/go.tgz",
                "archiveSize":archive.stat().st_size,
                "archiveSha256":__import__("hashlib").sha256(archive.read_bytes()).hexdigest(),
            }
            with self.assertRaisesRegex(RuntimeError,"FINAL_EXACT_RELEASE_PUBLICATION_PARENT_INVALID"):
                mod.stage_toolchain_archive(archive,exact,worktree)

    def test_output_path_rejects_broken_parent_with_canonical_error(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            self._symlink_or_skip(root/"missing-lab",root/"lab")
            with self.assertRaisesRegex(RuntimeError,"FINAL_EXACT_RELEASE_OUTPUT_PARENT_SYMLINK_FORBIDDEN"):
                mod.admit_output_path(root,Path("lab/final-exact-release-evidence.json"))

    def test_output_path_rejects_broken_final_symlink(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); (root/"lab").mkdir()
            out=root/"lab"/"final-exact-release-evidence.json"
            self._symlink_or_skip(root/"missing-evidence",out)
            with self.assertRaisesRegex(RuntimeError,"FINAL_EXACT_RELEASE_OUTPUT_SYMLINK_FORBIDDEN"):
                mod.admit_output_path(root,out)


if __name__=="__main__":
    unittest.main()
