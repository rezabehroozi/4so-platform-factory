import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("build_release",ROOT/"scripts"/"build_release.py")
build=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(build)


class ReleaseSourceIdentityTests(unittest.TestCase):
    def test_release_source_commit_prefers_valid_explicit_environment(self):
        sha="a"*40
        with mock.patch.dict(os.environ,{"SOURCE_COMMIT":sha},clear=False):
            self.assertEqual(sha,build.release_source_commit(ROOT))

    def test_release_source_commit_rejects_invalid_explicit_environment(self):
        with mock.patch.dict(os.environ,{"SOURCE_COMMIT":"not-a-commit"},clear=False):
            with self.assertRaisesRegex(SystemExit,"RELEASE_SOURCE_COMMIT_ENV_INVALID"):
                build.release_source_commit(ROOT)

    def test_release_source_commit_can_recover_from_existing_provenance_without_git(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); sha="b"*40
            (root/"BUILD-PROVENANCE.json").write_text(json.dumps({"sourceCommitSHA":sha}))
            failed=SimpleNamespace(returncode=1,stdout="",stderr="")
            with mock.patch.dict(os.environ,{"SOURCE_COMMIT":""},clear=False), mock.patch.object(build.subprocess,"run",return_value=failed):
                self.assertEqual(sha,build.release_source_commit(root))

    def test_release_and_container_build_contracts_preserve_source_commit(self):
        make=(ROOT/"Makefile").read_text()
        builder=(ROOT/"scripts/build_release.py").read_text()
        verifier=(ROOT/"scripts/verify_release.py").read_text()
        validator=(ROOT/"scripts/validate_repository.py").read_text()
        self.assertIn("internal/buildinfo.SourceCommit=$(SOURCE_COMMIT)",make)
        self.assertIn('"sourceCommitSHA": source_commit_sha',builder)
        self.assertIn('verify_environment["SOURCE_COMMIT"] = str(provenance["sourceCommitSHA"])',verifier)
        self.assertIn("CONTAINER_BINARY_SOURCE_COMMIT_INJECTION_MISSING",validator)
        for rel in ("Dockerfile","deploy/images/Dockerfile.agent","deploy/images/Dockerfile.probe"):
            recipe=(ROOT/rel).read_text()
            self.assertIn("ARG SOURCE_COMMIT",recipe)
            self.assertIn("internal/buildinfo.SourceCommit=$SOURCE_COMMIT",recipe)
            self.assertIn("^[0-9a-f]{40}$",recipe)


if __name__=="__main__":
    unittest.main()
