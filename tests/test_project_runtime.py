import importlib.util, json, subprocess, sys, tempfile, time, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("project_runtime",ROOT/"scripts"/"project_runtime.py")
R=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(R)

class ProjectRuntimeTests(unittest.TestCase):
    def test_stream_independence_self_test(self):
        self.assertEqual(0,R.self_test())

    def test_atomic_state_and_stale_watchdog_contract(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            s={"status":"RUNNING","runId":"r1","activePid":99999999,"activePidStartTicks":"1","commandPid":None,"commandPidStartTicks":None,"replaySafe":False}
            R.write_state(root,s)
            out=R.reconcile(root,R.read_state(root))
            self.assertEqual("INTERRUPTED",out["status"])
            self.assertTrue(out["recoveryRequired"])
            self.assertEqual("ORPHANED_OR_STALE_RUN",out["latestError"])
            self.assertFalse((root/".project-runtime"/"state.json.tmp").exists())

if __name__=="__main__": unittest.main()
