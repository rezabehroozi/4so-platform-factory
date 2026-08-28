import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import sys

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("verify_release", ROOT / "scripts" / "verify_release.py")
VERIFY = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = VERIFY
SPEC.loader.exec_module(VERIFY)


class ReleaseIdentityValidation(unittest.TestCase):
    def make_root(self, base: Path, *, version: str = "0.0.129", release_name: str = "test") -> Path:
        root = base / f"4so-platform-factory-{version}-{release_name}"
        root.mkdir()
        (root / "VERSION").write_text(version + "\n", encoding="utf-8")
        (root / "RELEASE-NAME").write_text(release_name + "\n", encoding="utf-8")
        return root

    def manifest(self, *, version: str = "0.0.129", release_name: str = "test") -> dict:
        return {
            "schemaVersion": 2,
            "product": "4SO Platform Factory",
            "version": version,
            "releaseName": release_name,
            "fileCount": 0,
            "files": [],
        }

    def test_manifest_release_name_must_match_packaged_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_root(Path(directory))
            manifest = self.manifest(release_name="forged")
            with self.assertRaisesRegex(SystemExit, "MANIFEST_RELEASE_IDENTITY_MISMATCH"):
                VERIFY.validate_manifest_identity(root, manifest)

    def test_manifest_root_must_be_canonical_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "release"
            root.mkdir()
            (root / "VERSION").write_text("0.0.129\n", encoding="utf-8")
            (root / "RELEASE-NAME").write_text("test\n", encoding="utf-8")
            with self.assertRaisesRegex(SystemExit, "ARCHIVE_ROOT_IDENTITY_MISMATCH"):
                VERIFY.validate_manifest_identity(root, self.manifest())

    def test_duplicate_manifest_json_key_is_rejected(self):
        raw = b'{"schemaVersion":2,"releaseName":"forged","releaseName":"test"}'
        with self.assertRaisesRegex(SystemExit, "MANIFEST_JSON_INVALID"):
            VERIFY.strict_json_loads(raw, label="MANIFEST")

    def test_noncanonical_manifest_path_is_rejected(self):
        with self.assertRaisesRegex(SystemExit, "ARCHIVE_PATH_NON_CANONICAL"):
            VERIFY.canonical_archive_path("meta/../VERSION")

    def test_snapshot_rejects_symlink_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "release.zip"
            source.write_bytes(b"not-empty")
            link = root / "release-link.zip"
            link.symlink_to(source)
            target = root / "snapshot.zip"
            with self.assertRaisesRegex(SystemExit, "ARCHIVE_SOURCE_INVALID"):
                VERIFY.snapshot_archive(link, target)


if __name__ == "__main__":
    unittest.main()
