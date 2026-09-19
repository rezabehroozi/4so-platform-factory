#!/usr/bin/env python3
import importlib.util
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("parallel_wave", ROOT / "scripts" / "parallel_wave.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class ParallelWaveTests(unittest.TestCase):
    def write_spec(self, root, tasks):
        path = Path(root) / "spec.json"
        path.write_text(json.dumps({"schemaVersion": 1, "tasks": tasks}), encoding="utf-8")
        return path

    def test_parallel_execution_and_resume_skip(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            a = root / "a.started"
            b = root / "b.started"
            counter = root / "counter.txt"
            code = (
                "import pathlib,sys,time;"
                "mine=pathlib.Path(sys.argv[1]);peer=pathlib.Path(sys.argv[2]);counter=pathlib.Path(sys.argv[3]);"
                "mine.write_text('1');"
                "deadline=time.time()+3;"
                "\nwhile not peer.exists() and time.time()<deadline: time.sleep(.02)"
                "\nassert peer.exists(), 'peer never started; tasks were not parallel';"
                "\nn=int(counter.read_text()) if counter.exists() else 0;counter.write_text(str(n+1))"
            )
            tasks = [
                {"id": "a", "argv": [sys.executable, "-c", code, str(a), str(b), str(counter)], "maxAttempts": 1, "timeoutSeconds": 5},
                {"id": "b", "argv": [sys.executable, "-c", code, str(b), str(a), str(counter)], "maxAttempts": 1, "timeoutSeconds": 5},
            ]
            spec_path = self.write_spec(root, tasks)
            state_dir = root / "state"
            spec_obj = json.loads(spec_path.read_text())
            self.assertEqual(0, mod.run_wave(spec_obj, state_dir, 2))
            state = json.loads((state_dir / "state.json").read_text())
            self.assertTrue(all(row["state"] == "SUCCEEDED" for row in state["tasks"].values()))
            before = int(counter.read_text())
            self.assertEqual(0, mod.run_wave(spec_obj, state_dir, 2))
            self.assertEqual(before, int(counter.read_text()), "successful tasks reran during resume")

    def test_failed_task_retries_only_itself(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            marker = root / "marker"
            stable_count = root / "stable-count"
            retry_code = (
                "import pathlib,sys;"
                "p=pathlib.Path(sys.argv[1]);"
                "\nif not p.exists(): p.write_text('1'); raise SystemExit(7)"
            )
            stable_code = (
                "import pathlib,sys;"
                "p=pathlib.Path(sys.argv[1]);"
                "n=int(p.read_text()) if p.exists() else 0;p.write_text(str(n+1))"
            )
            tasks = [
                {"id": "retry", "argv": [sys.executable, "-c", retry_code, str(marker)], "maxAttempts": 2, "retryDelaySeconds": 0},
                {"id": "stable", "argv": [sys.executable, "-c", stable_code, str(stable_count)], "maxAttempts": 1},
                {"id": "after", "argv": [sys.executable, "-c", "raise SystemExit(0)"], "dependsOn": ["retry", "stable"], "maxAttempts": 1},
            ]
            state_dir = root / "state"
            obj = {"schemaVersion": 1, "tasks": tasks}
            self.assertEqual(0, mod.run_wave(obj, state_dir, 3))
            state = json.loads((state_dir / "state.json").read_text())
            self.assertEqual(2, state["tasks"]["retry"]["attempts"])
            self.assertEqual(1, state["tasks"]["stable"]["attempts"])
            self.assertEqual("SUCCEEDED", state["tasks"]["after"]["state"])

    def test_load_json_accepts_windows_utf8_bom(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "spec.json"
            path.write_bytes(b"\xef\xbb\xbf" + json.dumps({"schemaVersion": 1, "tasks": []}).encode("utf-8"))
            self.assertEqual(1, mod._load_json(path)["schemaVersion"])

    def test_python_script_content_is_bound_to_wave_state(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            script = root / "task.py"
            script.write_text("raise SystemExit(0)\n", encoding="utf-8")
            obj = {"schemaVersion": 1, "tasks": [{"id": "script", "argv": [sys.executable, str(script)], "maxAttempts": 1}]}
            state_dir = root / "state"
            self.assertEqual(0, mod.run_wave(obj, state_dir, 1))
            state = json.loads((state_dir / "state.json").read_text())
            bindings = state.get("inputBindings", {}).get("script", [])
            self.assertEqual(1, len(bindings))
            self.assertTrue(bindings[0]["digest"].startswith("sha256:"))
            script.write_text("raise SystemExit(7)\n", encoding="utf-8")
            with self.assertRaises(SystemExit):
                mod.run_wave(obj, state_dir, 1)

    def test_explicit_input_file_is_bound_even_for_inline_task(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            config = root / "input.json"
            config.write_text('{"version":1}\n', encoding="utf-8")
            obj = {"schemaVersion": 1, "tasks": [{
                "id": "inline",
                "argv": [sys.executable, "-c", "raise SystemExit(0)"],
                "inputFiles": [str(config)],
                "maxAttempts": 1,
            }]}
            state_dir = root / "state"
            self.assertEqual(0, mod.run_wave(obj, state_dir, 1))
            config.write_text('{"version":2}\n', encoding="utf-8")
            with self.assertRaises(SystemExit):
                mod.run_wave(obj, state_dir, 1)

    def test_script_self_mutation_fails_closed_before_retry(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            script = root / "self_mutate.py"
            script.write_text(
                "from pathlib import Path\n"
                "p=Path(__file__)\n"
                "p.write_text('raise SystemExit(0)\\n', encoding='utf-8')\n"
                "raise SystemExit(7)\n",
                encoding="utf-8",
            )
            obj = {"schemaVersion": 1, "tasks": [{"id": "mutate", "argv": [sys.executable, str(script)], "maxAttempts": 2, "retryDelaySeconds": 0}]}
            state_dir = root / "state"
            self.assertEqual(1, mod.run_wave(obj, state_dir, 1))
            state = json.loads((state_dir / "state.json").read_text())
            row = state["tasks"]["mutate"]
            self.assertEqual("FAILED", row["state"])
            self.assertEqual(1, row["attempts"])
            self.assertIn("input binding changed", row["lastError"])

    def test_runner_snapshot_is_immutable_after_state_binding(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            state_dir = root / "state"
            source = root / "runner-source.py"
            source.write_text("print('v1')\n", encoding="utf-8")
            snapshot = mod._ensure_runner_snapshot(state_dir, source)
            self.assertEqual("print('v1')\n", snapshot.read_text(encoding="utf-8"))
            mod._atomic_json(state_dir / "state.json", {"runnerDigest": mod._file_digest(snapshot)})
            source.write_text("print('v2')\n", encoding="utf-8")
            again = mod._ensure_runner_snapshot(state_dir, source)
            self.assertEqual(snapshot, again)
            self.assertEqual("print('v1')\n", again.read_text(encoding="utf-8"))

    def test_runner_snapshot_tampering_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            state_dir = root / "state"
            source = root / "runner-source.py"
            source.write_text("print('v1')\n", encoding="utf-8")
            snapshot = mod._ensure_runner_snapshot(state_dir, source)
            mod._atomic_json(state_dir / "state.json", {"runnerDigest": mod._file_digest(snapshot)})
            if sys.platform != "win32":
                snapshot.chmod(0o700)
            snapshot.write_text("print('tampered')\n", encoding="utf-8")
            with self.assertRaises(SystemExit):
                mod._ensure_runner_snapshot(state_dir, source)

    def test_state_is_bound_to_exact_spec(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            state_dir = root / "state"
            first = {"schemaVersion": 1, "tasks": [{"id": "one", "argv": [sys.executable, "-c", "raise SystemExit(0)"]}]}
            second = {"schemaVersion": 1, "tasks": [{"id": "one", "argv": [sys.executable, "-c", "print('different')"]}]}
            self.assertEqual(0, mod.run_wave(first, state_dir, 1))
            with self.assertRaises(SystemExit):
                mod.run_wave(second, state_dir, 1)


if __name__ == "__main__":
    unittest.main()
