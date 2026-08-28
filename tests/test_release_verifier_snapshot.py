import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

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


if __name__ == "__main__":
    unittest.main()
