import hashlib
import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("seal_final_exact_release_handoff_binding_test",ROOT/"scripts"/"seal_final_exact_release.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class C9FinalHandoffPublicationBindingTests(unittest.TestCase):
    def fixture(self,root:Path):
        source_sha="a"*40
        name="4so-platform-factory-0.0.test-unit.zip"
        release=root/"release"/"exact-sha"/source_sha/name
        release.parent.mkdir(parents=True)
        raw=b"sealed-release-bytes"
        release.write_bytes(raw)
        checksum=release.with_name(release.name+".sha256")
        digest=hashlib.sha256(raw).hexdigest()
        checksum.write_text(f"{digest}  {release.name}\n",encoding="utf-8")
        release.chmod(0o444); checksum.chmod(0o444); release.parent.chmod(0o555)
        evidence={
            "sourceCommitSHA":source_sha,
            "releaseArchive":name,
            "releaseArchivePath":release.relative_to(root).as_posix(),
            "releaseArchiveSha256":"sha256:"+digest,
            "releaseArchiveBytes":len(raw),
        }
        return release,checksum,evidence

    def test_evidence_publication_binding_accepts_exact_read_only_snapshot(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            release,_,evidence=self.fixture(root)
            bound=mod.verify_evidence_publication_binding(root,evidence)
            self.assertEqual(release,bound)

    def test_evidence_publication_binding_rejects_archive_drift(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            release,_,evidence=self.fixture(root)
            release.parent.chmod(0o755); release.chmod(0o644)
            release.write_bytes(b"drifted-release-data")
            release.chmod(0o444); release.parent.chmod(0o555)
            with self.assertRaisesRegex(RuntimeError,"EVIDENCE_PUBLICATION_DRIFT"):
                mod.verify_evidence_publication_binding(root,evidence)


if __name__=="__main__":
    unittest.main()
