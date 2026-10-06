import json
import os
import pathlib
import subprocess
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "dev-checkpoint.sh"

class DevCheckpointTests(unittest.TestCase):
    def init_repo(self):
        td = tempfile.TemporaryDirectory()
        root = pathlib.Path(td.name)
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=root, check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=root, check=True)
        (root / "a.txt").write_text("one\n")
        subprocess.run(["git", "add", "a.txt"], cwd=root, check=True)
        subprocess.run(["git", "commit", "-qm", "base"], cwd=root, check=True)
        return td, root

    def run_script(self, root, *args, env=None):
        merged = os.environ.copy()
        merged.pop("DEV_VERIFY_CMD", None)
        merged.pop("DEV_PUSH", None)
        merged.update(env or {})
        return subprocess.run([str(SCRIPT), *args], cwd=root, env=merged, text=True, capture_output=True)

    def test_checkpoint_commits_and_queues_when_push_disabled(self):
        td, root = self.init_repo()
        self.addCleanup(td.cleanup)
        (root / "a.txt").write_text("two\n")
        p = self.run_script(root, "checkpoint", "test: wave", env={"DEV_VERIFY_CMD": "test -f a.txt"})
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(subprocess.check_output(["git", "log", "-1", "--pretty=%s"], cwd=root, text=True).strip(), "test: wave")
        status = json.loads((root / ".local-dev" / "SESSION_STATE.json").read_text())
        queue = json.loads((root / ".local-dev" / "PUSH_QUEUE.json").read_text())
        self.assertEqual(status["pushState"], "PUSH_PENDING")
        self.assertEqual(len(queue["pending"]), 1)

    def test_failed_verify_prevents_commit(self):
        td, root = self.init_repo()
        self.addCleanup(td.cleanup)
        before = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
        (root / "a.txt").write_text("two\n")
        p = self.run_script(root, "checkpoint", "bad", env={"DEV_VERIFY_CMD": "exit 7"})
        self.assertNotEqual(p.returncode, 0)
        after = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
        self.assertEqual(before, after)

    def test_non_network_origin_is_deferred_not_fatal(self):
        td, root = self.init_repo()
        self.addCleanup(td.cleanup)
        bare = pathlib.Path(tempfile.mkdtemp()) / "origin.git"
        self.addCleanup(lambda: __import__('shutil').rmtree(bare.parent, ignore_errors=True))
        subprocess.run(["git", "init", "--bare", "-q", str(bare)], check=True)
        subprocess.run(["git", "remote", "add", "origin", str(bare)], cwd=root, check=True)
        (root / "a.txt").write_text("two\n")
        p = self.run_script(root, "checkpoint", "defer", env={"DEV_PUSH": "1"})
        self.assertEqual(p.returncode, 0, p.stderr)
        status = json.loads((root / ".local-dev" / "SESSION_STATE.json").read_text())
        self.assertEqual(status["pushState"], "PUSH_PENDING")
        self.assertIn("not a network Git remote", status["pushError"])

    def test_status_ignores_inherited_repository_selection_git_environment(self):
        td, root = self.init_repo()
        self.addCleanup(td.cleanup)
        decoy_td, decoy = self.init_repo()
        self.addCleanup(decoy_td.cleanup)
        (decoy / "a.txt").write_text("decoy\n")
        subprocess.run(["git", "add", "a.txt"], cwd=decoy, check=True)
        subprocess.run(["git", "commit", "-qm", "decoy"], cwd=decoy, check=True)
        expected = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
        p = self.run_script(
            root,
            "status",
            env={
                "GIT_DIR": str(decoy / ".git"),
                "GIT_WORK_TREE": str(decoy),
                "GIT_INDEX_FILE": str(decoy / ".git" / "index"),
            },
        )
        self.assertEqual(p.returncode, 0, p.stderr)
        payload = json.loads((root / ".local-dev" / "SESSION_STATE.json").read_text())
        self.assertEqual(expected, payload["head"])

    @unittest.skipUnless(os.name == "posix", "dev-checkpoint shell authority test requires POSIX")
    def test_status_ignores_inherited_git_config_injection(self):
        td, root = self.init_repo()
        self.addCleanup(td.cleanup)
        marker = root / "fsmonitor-ran"
        fsmonitor = root / "fsmonitor.sh"
        fsmonitor.write_text("#!/usr/bin/env sh\nprintf 'ran\\n' >> " + __import__('shlex').quote(str(marker)) + "\nexit 0\n")
        fsmonitor.chmod(0o755)
        expected = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
        p = self.run_script(
            root,
            "status",
            env={
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "core.fsmonitor",
                "GIT_CONFIG_VALUE_0": str(fsmonitor),
                "GIT_CONFIG_PARAMETERS": "'core.worktree=/tmp/decoy'",
            },
        )
        self.assertEqual(p.returncode, 0, p.stderr)
        payload = json.loads((root / ".local-dev" / "SESSION_STATE.json").read_text())
        self.assertEqual(expected, payload["head"])
        self.assertFalse(marker.exists(), "inherited Git config executed an injected fsmonitor")

if __name__ == "__main__":
    unittest.main()
