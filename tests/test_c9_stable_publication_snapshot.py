import hashlib
import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("seal_final_exact_release_stable_publication_test",ROOT/"scripts"/"seal_final_exact_release.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class C9StablePublicationSnapshotTests(unittest.TestCase):
    def test_publication_rejects_same_size_source_drift_from_verified_snapshot(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            source=root/"verified.zip"
            trusted=b"verified-release-A"
            mutated=b"mutated-release-B!"
            self.assertEqual(len(trusted),len(mutated))
            source.write_bytes(trusted)
            expected_digest="sha256:"+hashlib.sha256(trusted).hexdigest()
            expected_size=len(trusted)
            source.write_bytes(mutated)
            target=root/"release"/"exact.zip"
            with self.assertRaisesRegex(RuntimeError,"PUBLICATION_SOURCE_DRIFT"):
                mod.publish_verified_file(
                    source,
                    target,
                    expected_digest=expected_digest,
                    expected_size=expected_size,
                )

    def test_publication_accepts_exact_verified_snapshot_and_remains_independent(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            source=root/"verified.zip"
            trusted=b"verified-release-bytes"
            source.write_bytes(trusted)
            expected_digest="sha256:"+hashlib.sha256(trusted).hexdigest()
            expected_size=len(trusted)
            target=root/"release"/"exact.zip"
            published=mod.publish_verified_file(
                source,
                target,
                expected_digest=expected_digest,
                expected_size=expected_size,
            )
            self.assertEqual(trusted,published.read_bytes())
            self.assertNotEqual(source.stat().st_ino,published.stat().st_ino)
            self.assertEqual(0o444,published.stat().st_mode & 0o777)

    def test_stable_fingerprint_binds_digest_and_size_together(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/"release.zip"
            raw=b"exact-release-snapshot"
            path.write_bytes(raw)
            digest,size=mod.stable_file_fingerprint(path,"TEST_RELEASE")
            self.assertEqual("sha256:"+hashlib.sha256(raw).hexdigest(),digest)
            self.assertEqual(len(raw),size)

    def test_verified_open_reads_from_the_locked_descriptor_snapshot(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/"go.tgz"
            raw=b"locked-toolchain-archive"
            path.write_bytes(raw)
            digest="sha256:"+hashlib.sha256(raw).hexdigest()
            with mod.stable_snapshot.verified_open(
                path,
                "TEST_TOOLCHAIN",
                expected_digest=digest,
                expected_size=len(raw),
            ) as fh:
                self.assertEqual(raw,fh.read())

    def test_verified_open_rejects_digest_drift_before_extraction(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/"go.tgz"
            raw=b"locked-toolchain-archive"
            path.write_bytes(raw)
            with self.assertRaisesRegex(RuntimeError,"SNAPSHOT_MISMATCH"):
                with mod.stable_snapshot.verified_open(
                    path,
                    "TEST_TOOLCHAIN",
                    expected_digest="sha256:"+"0"*64,
                    expected_size=len(raw),
                ):
                    pass


if __name__=="__main__":
    unittest.main()
