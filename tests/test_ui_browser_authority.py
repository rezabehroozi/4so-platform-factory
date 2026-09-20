import hashlib
import json
import os
import platform
from pathlib import Path
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import ui_browser_authority as AUTH


class UIBrowserAuthorityTest(unittest.TestCase):
    def make_authority(self, root: Path, *, digest_override: str | None = None):
        executable = root / "browser" / "chromium"
        executable.parent.mkdir(parents=True)
        executable.write_text("#!/bin/sh\necho 'Chromium 152.0.7977.75'\n", encoding="utf-8")
        executable.chmod(0o755)
        digest = hashlib.sha256(executable.read_bytes()).hexdigest()
        manifest = {
            "schemaVersion": 1,
            "authority": AUTH.AUTHORITY,
            "browser": "chromium",
            "platform": AUTH.normalized_platform(),
            "architecture": AUTH.normalized_arch(),
            "version": "152.0.7977.75",
            "executable": "browser/chromium",
            "sha256": digest_override or "sha256:" + digest,
            "size": executable.stat().st_size,
        }
        path = root / "authority.json"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        return path, executable, manifest

    def test_exact_browser_authority_validates_digest_version_and_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            path, executable, manifest = self.make_authority(Path(directory))
            observed, document = AUTH.validate_ui_browser_authority(path)
            self.assertEqual(observed, executable.resolve())
            self.assertEqual(document, manifest)

    def test_digest_mismatch_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path, _, _ = self.make_authority(Path(directory), digest_override="sha256:" + "0" * 64)
            with self.assertRaisesRegex(ValueError, "UI_BROWSER_EXECUTABLE_DIGEST_MISMATCH"):
                AUTH.validate_ui_browser_authority(path)

    def test_symlink_executable_is_rejected(self):
        if os.name == "nt":
            self.skipTest("symlink permissions vary on Windows")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, executable, manifest = self.make_authority(root)
            real = root / "browser" / "real-browser"
            executable.replace(real)
            executable.symlink_to(real.name)
            manifest["size"] = real.stat().st_size
            manifest["sha256"] = "sha256:" + hashlib.sha256(real.read_bytes()).hexdigest()
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "UI_BROWSER_EXECUTABLE_IDENTITY_INVALID"):
                AUTH.validate_ui_browser_authority(path)

    def test_symlink_parent_directory_is_rejected(self):
        if os.name == "nt":
            self.skipTest("symlink permissions vary on Windows")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            external = root / "external"
            external.mkdir()
            real = external / "chromium"
            real.write_text("#!/bin/sh\necho 'Chromium 152.0.7977.75'\n", encoding="utf-8")
            real.chmod(0o755)
            (root / "browser").symlink_to(external, target_is_directory=True)
            manifest = {
                "schemaVersion": 1,
                "authority": AUTH.AUTHORITY,
                "browser": "chromium",
                "platform": AUTH.normalized_platform(),
                "architecture": AUTH.normalized_arch(),
                "version": "152.0.7977.75",
                "executable": "browser/chromium",
                "sha256": "sha256:" + hashlib.sha256(real.read_bytes()).hexdigest(),
                "size": real.stat().st_size,
            }
            path = root / "authority.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "UI_BROWSER_EXECUTABLE_IDENTITY_INVALID"):
                AUTH.validate_ui_browser_authority(path)


    def make_acquisition_lock(self, root: Path, *, url: str = "https://example.test/chrome.zip", digest_override: str | None = None):
        archive = root / "chrome.zip"
        archive.write_bytes(b"exact-browser-archive")
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        lock = {
            "schemaVersion": 1,
            "authority": AUTH.ACQUISITION_AUTHORITY,
            "browser": "chromium",
            "platform": AUTH.normalized_platform(),
            "architecture": AUTH.normalized_arch(),
            "version": "152.0.7977.75",
            "source": {
                "url": url,
                "sha256": digest_override or "sha256:" + digest,
                "size": archive.stat().st_size,
            },
            "executable": "chrome/chrome",
        }
        path = root / "acquisition-lock.json"
        path.write_text(json.dumps(lock), encoding="utf-8")
        return path, archive, lock

    def test_acquisition_lock_verifies_exact_offline_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            lock_path, archive, lock = self.make_acquisition_lock(Path(directory))
            self.assertEqual(AUTH.verify_ui_browser_acquisition_archive(lock_path, archive), lock)

    def test_acquisition_archive_digest_mismatch_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            lock_path, archive, _ = self.make_acquisition_lock(
                Path(directory), digest_override="sha256:" + "0" * 64
            )
            with self.assertRaisesRegex(ValueError, "UI_BROWSER_ACQUISITION_ARCHIVE_DIGEST_MISMATCH"):
                AUTH.verify_ui_browser_acquisition_archive(lock_path, archive)

    def test_acquisition_lock_rejects_non_https_or_mutable_url_shape(self):
        with tempfile.TemporaryDirectory() as directory:
            lock_path, _, _ = self.make_acquisition_lock(
                Path(directory), url="http://example.test/chrome.zip?latest=true"
            )
            with self.assertRaisesRegex(ValueError, "UI_BROWSER_ACQUISITION_LOCK_URL_INVALID"):
                AUTH.validate_ui_browser_acquisition_lock(lock_path)

    def test_full_verifier_requires_explicit_authority(self):
        environment = {}
        with self.assertRaisesRegex(ValueError, "UI_BROWSER_AUTHORITY_MISSING"):
            AUTH.prepare_full_verifier_browser(environment)


if __name__ == "__main__":
    unittest.main()
