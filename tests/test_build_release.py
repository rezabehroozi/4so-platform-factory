import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("build_release", ROOT / "scripts" / "build_release.py")
BUILD = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = BUILD
SPEC.loader.exec_module(BUILD)


class ReleaseSourceTreeBoundary(unittest.TestCase):
    def test_release_zip_is_byte_stable_without_zlib_dependency(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            stage=root/"stage"; stage.mkdir()
            (stage/"a.txt").write_text("alpha\n",encoding="utf-8")
            sub=stage/"sub"; sub.mkdir()
            binary=sub/"tool"; binary.write_bytes(b"\x00\x01\x02")
            binary.chmod(0o755)
            first=root/"first.zip"; second=root/"second.zip"
            BUILD.write_release_zip(stage,first,"fixture")
            BUILD.write_release_zip(stage,second,"fixture")
            self.assertEqual(first.read_bytes(),second.read_bytes())
            with zipfile.ZipFile(first,"r") as archive:
                self.assertTrue(archive.infolist())
                self.assertTrue(all(row.compress_type==zipfile.ZIP_STORED for row in archive.infolist()))
                self.assertEqual(["fixture/a.txt","fixture/sub/tool"],[row.filename for row in archive.infolist()])

    def test_source_tree_symlink_is_rejected_instead_of_followed(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "repo"
            root.mkdir()
            outside = base / "outside-secret.txt"
            outside.write_text("must-not-be-packaged\n", encoding="utf-8")
            (root / "external-link.txt").symlink_to(outside)
            with self.assertRaisesRegex(SystemExit, "SOURCE_TREE_SYMLINK_FORBIDDEN"):
                BUILD.source_files(root, apply_excludes=True)


    def test_product_owned_durable_temp_is_rejected_from_release_source_tree(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            (root / "catalog" / "components").mkdir(parents=True)
            residue = root / "catalog" / "components" / ".durable-crash-residue"
            residue.write_text("interrupted replacement\n", encoding="utf-8")
            with self.assertRaisesRegex(SystemExit, "SOURCE_TREE_STALE_DURABLE_TEMP_FORBIDDEN"):
                BUILD.source_files(root, apply_excludes=True)

    def test_git_backed_release_source_excludes_ignored_and_untracked_local_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            root.mkdir()
            def git(*args):
                return BUILD.subprocess.run(["git", *args], cwd=root, text=True, capture_output=True, check=True).stdout.strip()
            git("init")
            git("config", "user.email", "test@example.invalid")
            git("config", "user.name", "Test")
            (root / ".gitignore").write_text("*.key\n.local-dev/\n", encoding="utf-8")
            (root / "tracked.txt").write_text("tracked\n", encoding="utf-8")
            git("add", ".gitignore", "tracked.txt")
            git("commit", "-m", "initial")
            (root / "secret.key").write_text("private\n", encoding="utf-8")
            (root / "untracked.txt").write_text("not in HEAD\n", encoding="utf-8")
            local = root / ".local-dev"
            local.mkdir()
            (local / "state.json").write_text("{}\n", encoding="utf-8")
            rels = {str(path.relative_to(root)) for path in BUILD.release_source_files(root)}
            self.assertEqual({".gitignore", "tracked.txt"}, rels)

    def test_git_backed_release_source_rejects_hidden_index_flags(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            root.mkdir()
            def git(*args):
                return BUILD.subprocess.run(["git", *args], cwd=root, text=True, capture_output=True, check=True).stdout.strip()
            git("init")
            git("config", "user.email", "test@example.invalid")
            git("config", "user.name", "Test")
            tracked=root/"tracked.txt"; tracked.write_text("tracked\n",encoding="utf-8")
            git("add","tracked.txt"); git("commit","-m","initial")
            git("update-index","--assume-unchanged","tracked.txt")
            tracked.write_text("hidden-drift\n",encoding="utf-8")
            with self.assertRaisesRegex(SystemExit,"RELEASE_GIT_INDEX_FLAGS_FORBIDDEN"):
                BUILD.release_source_files(root)

    def test_no_git_release_source_uses_only_manifest_sealed_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "bundle"
            root.mkdir()
            tracked = root / "tracked.txt"
            tracked.write_text("sealed\n", encoding="utf-8")
            extra = root / "local-secret.txt"
            extra.write_text("must-not-enter-rebuild\n", encoding="utf-8")
            manifest = {
                "schemaVersion": 2,
                "files": [{
                    "path": "tracked.txt",
                    "sha256": BUILD.sha(tracked),
                    "size": tracked.stat().st_size,
                    "mode": "0o644",
                }],
            }
            (root / "ARTIFACT-MANIFEST.json").write_text(__import__("json").dumps(manifest), encoding="utf-8")
            rels = {str(path.relative_to(root)) for path in BUILD.release_source_files(root)}
            self.assertEqual({"tracked.txt"}, rels)
            tracked.write_text("tampered\n", encoding="utf-8")
            with self.assertRaisesRegex(SystemExit, "RELEASE_MANIFEST_SOURCE_MISMATCH"):
                BUILD.release_source_files(root)

    def test_binary_build_identity_requires_exact_version_and_source_commit_ldflags(self):
        binary=Path("/tmp/platform-api")
        version="0.0.363"; source="a"*40
        ok=mock.Mock(
            returncode=0,
            stdout=(
                "/tmp/platform-api: go1.27.1\n"
                "\tbuild\t-ldflags=\"-s -w -buildid= "
                "-X platform.4so.io/factory/internal/buildinfo.Version=0.0.363 "
                "-X platform.4so.io/factory/internal/buildinfo.SourceCommit="+source+"\"\n"
            ),
            stderr="",
        )
        with mock.patch.dict(BUILD.os.environ,{"GO":"/exact/go"},clear=False), mock.patch.object(BUILD.subprocess,"run",return_value=ok) as run:
            BUILD.verify_binary_build_identity(binary,version,source)
        run.assert_called_once_with(["/exact/go","version","-m",str(binary)],capture_output=True,text=True,check=False)

        bad=mock.Mock(returncode=0,stdout=ok.stdout.replace(source,"b"*40),stderr="")
        with mock.patch.object(BUILD.subprocess,"run",return_value=bad):
            with self.assertRaisesRegex(SystemExit,"BINARY_BUILD_IDENTITY_MISMATCH"):
                BUILD.verify_binary_build_identity(binary,version,source)

    def test_cgo_provenance_rejects_active_toolchain_drift_from_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            stage=Path(directory)
            (stage/"lab").mkdir()
            exact={
                "ccVersion":"gcc exact",
                "ldVersion":"ld exact",
                "libcVersion":"ldd exact",
                "libpqHeaderPath":"/exact/libpq-fe.h",
                "libpqHeaderSha256":"headerhash",
                "libpqLibraryPath":"/exact/libpq.so",
                "libpqLibrarySha256":"libraryhash",
            }
            (stage/"lab/release-build-toolchain-lock.json").write_text(
                __import__("json").dumps({"spec":{"exactCGOToolchain":exact}}),
                encoding="utf-8",
            )
            versions=iter(["gcc exact","ld exact","ldd exact"])
            with mock.patch.object(BUILD,"checked_regular_file"), mock.patch.object(BUILD,"command_first_line",side_effect=lambda _:next(versions)), mock.patch.object(BUILD,"sha",side_effect=lambda p:"headerhash" if str(p).endswith("libpq-fe.h") else "libraryhash"):
                self.assertEqual(exact,BUILD.cgo_toolchain_identity(stage))

            drift=iter(["gcc drift","ld exact","ldd exact"])
            with mock.patch.object(BUILD,"checked_regular_file"), mock.patch.object(BUILD,"command_first_line",side_effect=lambda _:next(drift)), mock.patch.object(BUILD,"sha",side_effect=lambda p:"headerhash" if str(p).endswith("libpq-fe.h") else "libraryhash"):
                with self.assertRaisesRegex(SystemExit,"BUILD_CGO_TOOLCHAIN_IDENTITY_DRIFT ccVersion"):
                    BUILD.cgo_toolchain_identity(stage)

    def test_checked_regular_file_rejects_symlinked_cgo_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); target=root/"libpq.so"; target.write_bytes(b"library")
            link=root/"libpq-link.so"; link.symlink_to(target.name)
            with self.assertRaisesRegex(SystemExit,"CGO_INPUT_NON_REGULAR_FILE"):
                BUILD.checked_regular_file(link,label="CGO_INPUT")

    def test_go_toolchain_version_uses_explicit_go_authority_from_environment(self):
        completed = mock.Mock(stdout="go version go1.27.1 linux/amd64\n")
        with mock.patch.dict(BUILD.os.environ, {"GO": "/opt/4so/go1.27.1/bin/go"}, clear=False):
            with mock.patch.object(BUILD.subprocess, "run", return_value=completed) as run:
                self.assertEqual("go version go1.27.1 linux/amd64", BUILD.go_toolchain_version())
        run.assert_called_once_with(["/opt/4so/go1.27.1/bin/go", "version"], capture_output=True, text=True, check=True)


if __name__ == "__main__":
    unittest.main()
