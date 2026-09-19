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
