import importlib.util, json, subprocess, sys, tempfile, time, unittest
from unittest import mock
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


    def test_resume_reuses_run_id_only_for_replay_safe_work(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            runtime=root/".project-runtime"
            log=runtime/"logs"/"resume-1.log"
            info={"repository":"fixture","branch":"main","head":"abc","originMain":"abc"}
            state={
                "status":"INTERRUPTED","runId":"resume-1",**info,
                "phase":"validate","currentTask":"resume-fixture",
                "completedTasks":["prepare"],"failedTasks":[],
                "activePid":None,"activePidStartTicks":None,
                "commandPid":None,"commandPidStartTicks":None,
                "startTime":R.now(),"lastHeartbeat":R.now(),
                "currentStage":"validate","latestCompletedCheckpoint":"prepare",
                "latestError":"ORPHANED_OR_STALE_RUN","latestLogPath":str(log),
                "command":[sys.executable,"-c","from pathlib import Path;Path('resumed').write_text('ok')"],
                "heartbeatSeconds":1,"checkpointFile":"","progress":{"heartbeatCount":1,"stage":"validate"},
                "lastSuccessfulAction":"prepare","replaySafe":True,
                "recoveryRequired":False,"orphaned":True,"attempt":1,
            }
            R.write_state(root,state)
            with mock.patch.object(R,"git",return_value=info):
                result=R.resume(root)
            self.assertEqual("RESUMED",result["action"])
            self.assertEqual("resume-1",result["runId"])
            self.assertEqual(2,result["attempt"])
            deadline=time.monotonic()+5
            while time.monotonic()<deadline:
                current=R.reconcile(root,R.read_state(root))
                if current["status"] in R.TERMINAL: break
                time.sleep(.1)
            final=R.read_state(root)
            self.assertEqual("COMPLETED",final["status"])
            self.assertEqual("resume-1",final["runId"])
            self.assertEqual(2,final["attempt"])
            self.assertEqual("ok",(root/"resumed").read_text())

    def test_non_replay_safe_resume_requires_authoritative_readback(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            state={
                "status":"INTERRUPTED","runId":"physical-1",
                "phase":"physical-install","currentTask":"installer",
                "activePid":None,"activePidStartTicks":None,
                "commandPid":None,"commandPidStartTicks":None,
                "replaySafe":False,"latestError":"ORPHANED_OR_STALE_RUN",
            }
            R.write_state(root,state)
            result=R.resume(root)
            self.assertEqual("RECOVERY_REQUIRED",result["action"])
            final=R.read_state(root)
            self.assertEqual("WAITING",final["status"])
            self.assertTrue(final["recoveryRequired"])
            self.assertEqual("MANUAL_READBACK_REQUIRED_BEFORE_REPLAY",final["latestError"])
            self.assertFalse(R.lock_file(root).exists())

if __name__=="__main__": unittest.main()
