import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
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

    def test_bounded_command_times_out_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            rc, stdout, stderr = VERIFY.run_bounded_command(
                [sys.executable, "-c", "import time; time.sleep(2)"],
                cwd=Path(directory),
                env={},
                timeout_seconds=1,
            )
            self.assertEqual(rc, 124)
            self.assertIn("COMMAND_TIMEOUT", stderr)

    def test_full_verifier_binary_identity_requires_exact_source_ldflag(self):
        binary=Path("/tmp/platform-api")
        source="a"*40
        ok=mock.Mock(
            returncode=0,
            stdout=(
                "/tmp/platform-api: go1.27.1\n"
                "\tbuild\t-ldflags=\"-X platform.4so.io/factory/internal/buildinfo.Version=0.0.363 "
                "-X platform.4so.io/factory/internal/buildinfo.SourceCommit="+source+"\"\n"
            ),
            stderr="",
        )
        with mock.patch.object(VERIFY.subprocess,"run",return_value=ok) as run:
            VERIFY.verify_go_binary_build_identity("/exact/go",binary,"0.0.363",source)
        run.assert_called_once_with(["/exact/go","version","-m",str(binary)],capture_output=True,text=True,check=False)

        bad=mock.Mock(returncode=0,stdout=ok.stdout.replace(source,"b"*40),stderr="")
        with mock.patch.object(VERIFY.subprocess,"run",return_value=bad):
            with self.assertRaisesRegex(SystemExit,"BINARY_BUILD_IDENTITY_MISMATCH"):
                VERIFY.verify_go_binary_build_identity("/exact/go",binary,"0.0.363",source)

    def test_full_verifier_declares_checkpoint_safe_v2_authority(self):
        self.assertEqual(VERIFY.FULL_VERIFIER_AUTHORITY, "CHECKPOINT_SAFE_FULL_VERIFIER_V2")
        self.assertEqual(VERIFY.SHARD_AUTHORITY, "AUTOPILOT_STAGE_SHARD_AUTHORITY_V2")

    def test_manual_install_release_payload_requires_all_exact_release_owners(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            required_regular = (
                "VERSION",
                "RELEASE-NAME",
                "scripts/lab_runner.py",
                "scripts/distribution_transport.py",
                "internal/labmodel/certification-matrix.json",
                "lab/appliance-bundle-acquisition-lock.json",
            )
            required_executable = (
                "install.sh",
                "bin/linux-amd64/platformctl",
                "bin/linux-amd64/platform-installer",
            )
            for rel in required_regular + required_executable:
                path = root / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("payload\n", encoding="utf-8")
            for rel in required_executable:
                (root / rel).chmod(0o755)
            VERIFY.validate_manual_install_release_payload(root)
            self.assertEqual(
                VERIFY.MANUAL_INSTALL_RELEASE_PAYLOAD_AUTHORITY,
                "INSTALLER_MANUAL_RELEASE_PAYLOAD_V1",
            )
            (root / "scripts" / "lab_runner.py").unlink()
            with self.assertRaisesRegex(SystemExit, "INSTALLER_MANUAL_RELEASE_PAYLOAD_INVALID"):
                VERIFY.validate_manual_install_release_payload(root)

    def test_manual_install_release_payload_rejects_non_executable_entrypoint(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for rel in (
                "VERSION",
                "RELEASE-NAME",
                "scripts/lab_runner.py",
                "scripts/distribution_transport.py",
                "internal/labmodel/certification-matrix.json",
                "lab/appliance-bundle-acquisition-lock.json",
                "install.sh",
                "bin/linux-amd64/platformctl",
                "bin/linux-amd64/platform-installer",
            ):
                path = root / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("payload\n", encoding="utf-8")
                path.chmod(0o644)
            (root / "bin/linux-amd64/platformctl").chmod(0o755)
            (root / "bin/linux-amd64/platform-installer").chmod(0o755)
            with self.assertRaisesRegex(SystemExit, "INSTALLER_MANUAL_RELEASE_PAYLOAD_INVALID.*install.sh"):
                VERIFY.validate_manual_install_release_payload(root)

    def test_full_verifier_keeps_ui_and_smoke_parity_contract(self):
        source = (ROOT / "scripts" / "verify_release.py").read_text(encoding="utf-8")
        for required in (
            "run_smoke_shard.py",
            "smoke_ui.py",
            "smoke_ui_quality.py",
            "persian_ui_lint.py",
            "smoke_ui_live.py",
            "smoke_ui_workflow_e2e.py",
            "test_lab_runner.py",
            "catalog_upstream_admission.py",
            "acquire_upstream_helm.py",
            "acquire_upstream_tagged_source.py",
            "acquire_historical_upgrade_batch.py",
        ):
            self.assertIn(required, source)


if __name__ == "__main__":
    unittest.main()
