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
    def test_release_source_commit_requires_explicit_environment_to_match_git(self):
        git_sha="a"*40
        observed=SimpleNamespace(returncode=0,stdout=git_sha+"\n",stderr="")
        with mock.patch.object(build.subprocess,"run",return_value=observed):
            with mock.patch.dict(os.environ,{"SOURCE_COMMIT":git_sha},clear=False):
                self.assertEqual(git_sha,build.release_source_commit(ROOT))
            with mock.patch.dict(os.environ,{"SOURCE_COMMIT":"b"*40},clear=False):
                with self.assertRaisesRegex(SystemExit,"ENV_GIT_MISMATCH"):
                    build.release_source_commit(ROOT)

    def test_release_source_commit_accepts_valid_explicit_environment_without_git(self):
        sha="a"*40
        failed=SimpleNamespace(returncode=1,stdout="",stderr="")
        with mock.patch.object(build.subprocess,"run",return_value=failed), mock.patch.dict(os.environ,{"SOURCE_COMMIT":sha},clear=False):
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

    def test_release_source_commit_git_probe_ignores_inherited_git_authority(self):
        git_sha="a"*40
        observed=SimpleNamespace(returncode=0,stdout=git_sha+"\n",stderr="")
        with mock.patch.dict(os.environ,{"GIT_DIR":"/tmp/decoy.git","GIT_WORK_TREE":"/tmp/decoy","KEEP_ME":"yes"},clear=False):
            with mock.patch.object(build.subprocess,"run",return_value=observed) as run:
                self.assertEqual(git_sha,build.release_source_commit(ROOT))
        env=run.call_args.kwargs.get("env")
        self.assertIsInstance(env,dict)
        self.assertNotIn("GIT_DIR",env)
        self.assertNotIn("GIT_WORK_TREE",env)
        self.assertEqual("yes",env.get("KEEP_ME"))

    def test_release_source_files_git_probes_ignore_inherited_git_authority(self):
        root=ROOT.resolve()
        top=SimpleNamespace(returncode=0,stdout=str(root)+"\n",stderr="")
        listed=SimpleNamespace(returncode=0,stdout=b"",stderr=b"")
        with mock.patch.dict(os.environ,{"GIT_INDEX_FILE":"/tmp/decoy-index","GIT_WORK_TREE":"/tmp/decoy","KEEP_ME":"yes"},clear=False):
            with mock.patch.object(build.subprocess,"run",side_effect=[top,listed]) as run:
                self.assertEqual([],build.release_source_files(root))
        self.assertEqual(2,run.call_count)
        for call in run.call_args_list:
            env=call.kwargs.get("env")
            self.assertIsInstance(env,dict)
            self.assertNotIn("GIT_INDEX_FILE",env)
            self.assertNotIn("GIT_WORK_TREE",env)
            self.assertEqual("yes",env.get("KEEP_ME"))

    def test_release_and_container_build_contracts_preserve_source_commit(self):
        make=(ROOT/"Makefile").read_text()
        builder=(ROOT/"scripts/build_release.py").read_text()
        verifier=(ROOT/"scripts/verify_release.py").read_text()
        validator=(ROOT/"scripts/validate_repository.py").read_text()
        self.assertIn("override SOURCE_COMMIT := $(GIT_SOURCE_COMMIT)",make)
        self.assertIn("internal/buildinfo.SourceCommit=$(SOURCE_COMMIT)",make)
        self.assertIn('"sourceCommitSHA": source_commit_sha',builder)
        self.assertIn('sys.executable,\n            str(stage / "scripts" / "generate_agent_knowledge.py")',builder)
        self.assertNotIn('            "python3",\n            str(stage / "scripts" / "generate_agent_knowledge.py")',builder)
        self.assertIn('verify_environment["SOURCE_COMMIT"] = str(provenance["sourceCommitSHA"])',verifier)
        self.assertNotIn('["python3", "scripts/',verifier)
        smoke_shard=(ROOT/"scripts/run_smoke_shard.py").read_text()
        self.assertIn('[sys.executable, str(Path("scripts") / script)',smoke_shard)
        self.assertNotIn('["python3", str(Path("scripts") / script)',smoke_shard)
        self.assertIn("CONTAINER_BINARY_SOURCE_COMMIT_INJECTION_MISSING",validator)
        self.assertIn("docker.count(source_regex)!=1",validator)
        self.assertIn("docker.count(source_ldflag)!=1",validator)
        self.assertIn("len(from_rows)!=2",validator)
        self.assertEqual(1,validator.count("def main() -> int:"))
        self.assertEqual(1,validator.count("if __name__ == '__main__':"))
        self.assertNotIn('raise SystemExit(main())\n" not in docker',validator)
        for rel in ("Dockerfile","deploy/images/Dockerfile.agent","deploy/images/Dockerfile.probe"):
            recipe=(ROOT/rel).read_text()
            self.assertIn("ARG SOURCE_COMMIT",recipe)
            self.assertIn("internal/buildinfo.SourceCommit=$SOURCE_COMMIT",recipe)
            self.assertIn("^[0-9a-f]{40}$",recipe)
            self.assertEqual(2,sum(1 for line in recipe.splitlines() if line.startswith("FROM ")),rel)
            self.assertEqual(1,recipe.count("internal/buildinfo.SourceCommit=$SOURCE_COMMIT"),rel)
            self.assertEqual(1,recipe.count("grep -Eq '^[0-9a-f]{40}$'"),rel)


if __name__=="__main__":
    unittest.main()