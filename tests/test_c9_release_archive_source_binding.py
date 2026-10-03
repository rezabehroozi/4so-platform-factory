import importlib.util
import stat
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("seal_final_exact_release_archive_source_test",ROOT/"scripts"/"seal_final_exact_release.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class C9ReleaseArchiveSourceBindingTests(unittest.TestCase):
    def git(self,root:Path,*args:str)->str:
        return subprocess.run(["git",*args],cwd=root,text=True,capture_output=True,check=True).stdout.strip()

    def repo(self,root:Path)->str:
        self.git(root,"init","-b","main")
        self.git(root,"config","user.email","test@example.invalid")
        self.git(root,"config","user.name","Test")
        (root/"VERSION").write_text("0.0.1\n",encoding="utf-8")
        (root/"RELEASE-NAME").write_text("unit\n",encoding="utf-8")
        (root/"tracked.txt").write_text("committed-source\n",encoding="utf-8")
        self.git(root,"add","VERSION","RELEASE-NAME","tracked.txt")
        self.git(root,"commit","-m","source")
        return self.git(root,"rev-parse","HEAD")

    def archive(self,root:Path,tracked:bytes,*,tracked_mode:int=0o644)->Path:
        release=root/"4so-platform-factory-0.0.1-unit.zip"
        prefix=release.stem+"/"
        rows={
            "VERSION":(b"0.0.1\n",0o644),
            "RELEASE-NAME":(b"unit\n",0o644),
            "tracked.txt":(tracked,tracked_mode),
        }
        with zipfile.ZipFile(release,"w",compression=zipfile.ZIP_STORED) as zf:
            for rel,(raw,mode) in rows.items():
                info=zipfile.ZipInfo(prefix+rel)
                info.create_system=3
                info.external_attr=((stat.S_IFREG|mode)&0xFFFF)<<16
                info.compress_type=zipfile.ZIP_STORED
                zf.writestr(info,raw)
        return release

    def test_exact_source_archive_accepts_committed_git_blobs(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            source_sha=self.repo(root)
            release=self.archive(root,b"committed-source\n")
            digest,size=mod.stable_file_fingerprint(release,"TEST_ARCHIVE")
            mod.verify_release_archive_exact_source(
                root.resolve(),release,source_sha,
                expected_digest=digest,expected_size=size,
            )

    def test_exact_source_archive_rejects_internal_archive_with_mutated_tracked_bytes(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            source_sha=self.repo(root)
            release=self.archive(root,b"mutated--source\n")
            digest,size=mod.stable_file_fingerprint(release,"TEST_ARCHIVE")
            with self.assertRaisesRegex(RuntimeError,"SOURCE_BLOB_DRIFT"):
                mod.verify_release_archive_exact_source(
                    root.resolve(),release,source_sha,
                    expected_digest=digest,expected_size=size,
                )

    def test_exact_source_archive_rejects_git_mode_drift(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            source_sha=self.repo(root)
            release=self.archive(root,b"committed-source\n",tracked_mode=0o755)
            digest,size=mod.stable_file_fingerprint(release,"TEST_ARCHIVE")
            with self.assertRaisesRegex(RuntimeError,"SOURCE_MODE_DRIFT"):
                mod.verify_release_archive_exact_source(
                    root.resolve(),release,source_sha,
                    expected_digest=digest,expected_size=size,
                )


if __name__=="__main__":
    unittest.main()
