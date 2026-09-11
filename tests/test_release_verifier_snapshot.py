import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("verify_release", ROOT / "scripts" / "verify_release.py")
VERIFY = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(VERIFY)


class ReleaseVerifierSnapshotTest(unittest.TestCase):
    def test_snapshot_is_private_and_digest_is_bound_to_copied_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "release.zip"
            original = b"PK\x03\x04" + os.urandom(4096)
            source.write_bytes(original)
            target = root / "snapshot.zip"
            digest = VERIFY.snapshot_archive(source, target)
            source.write_bytes(b"X" * len(original))
            self.assertEqual(target.read_bytes(), original)
            self.assertEqual(digest, hashlib.sha256(original).hexdigest())
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)

    def test_snapshot_rejects_symlink_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real = root / "real.zip"
            real.write_bytes(b"fixture")
            link = root / "release.zip"
            link.symlink_to(real)
            with self.assertRaises(SystemExit):
                VERIFY.snapshot_archive(link, root / "snapshot.zip")

    def test_snapshot_rejects_same_inode_ctime_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "release.zip"
            source.write_bytes(b"PK\x03\x04" + os.urandom(4096))
            target = root / "snapshot.zip"
            original_fstat = VERIFY.os.fstat
            calls = 0

            def drifting_fstat(fd):
                nonlocal calls
                current = original_fstat(fd)
                calls += 1
                if calls == 2:
                    return SimpleNamespace(
                        st_mode=current.st_mode,
                        st_size=current.st_size,
                        st_ino=current.st_ino,
                        st_dev=current.st_dev,
                        st_mtime_ns=current.st_mtime_ns,
                        st_ctime_ns=current.st_ctime_ns + 1,
                    )
                return current

            with mock.patch.object(VERIFY.os, "fstat", side_effect=drifting_fstat):
                with self.assertRaisesRegex(SystemExit, "ARCHIVE_SOURCE_CHANGED_WHILE_SNAPSHOTTING"):
                    VERIFY.snapshot_archive(source, target)


if __name__ == "__main__":
    unittest.main()
