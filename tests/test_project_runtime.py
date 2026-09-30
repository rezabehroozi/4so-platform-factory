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


    def test_live_observer_cannot_overwrite_newer_terminal_state(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            pid=R.os.getpid()
            start=R.ticks(pid)
            stale={"status":"RUNNING","runId":"observer-race","activePid":pid,"activePidStartTicks":start,
                   "commandPid":None,"commandPidStartTicks":None,"replaySafe":True}
            R.write_state(root,stale)
            stale_snapshot=R.read_state(root)
            terminal=dict(stale_snapshot)
            terminal.update(status="COMPLETED",activePid=None,activePidStartTicks=None,
                            latestCompletedCheckpoint="validate",latestError="")
            R.write_state(root,terminal)
            observed=R.reconcile(root,stale_snapshot)
            self.assertTrue(observed["workerAlive"])
            self.assertEqual("COMPLETED",R.read_state(root)["status"])
            self.assertEqual("validate",R.read_state(root)["latestCompletedCheckpoint"])

    def test_worker_handoff_persists_identity_before_transfer_without_clobbering_worker_state(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            state={"status":"REQUESTED","runId":"handoff-race","commandPid":None,"commandPidStartTicks":None}
            def transfer_observer(_root,_run_id,_pid,_ticks,_override=None):
                persisted=R.read_state(root)
                self.assertEqual("RUNNING",persisted["status"])
                self.assertEqual(12345,persisted["activePid"])
                self.assertEqual("67890",str(persisted["activePidStartTicks"]))
                persisted["commandPid"]=22222
                persisted["commandPidStartTicks"]="33333"
                R.write_state(root,persisted)
            with mock.patch.object(R,"transfer",side_effect=transfer_observer):
                out=R.activate_worker(root,state,"handoff-race",12345,"67890")
            self.assertEqual(12345,out["activePid"])
            final=R.read_state(root)
            self.assertEqual(22222,final["commandPid"])
            self.assertEqual("33333",str(final["commandPidStartTicks"]))

    def test_resume_reuses_run_id_only_for_replay_safe_work(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            runtime=root/".project-runtime"
            log=runtime/"logs"/"resume-1.log"
            info={"repository":"fixture","branch":"main","head":"abc","originMain":"remote-advanced","gitSyncStatus":"DIFFERENT"}
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

    def test_local_git_authority_does_not_require_remote_or_fetch(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            subprocess.run(["git","init","-q","-b","main"],cwd=root,check=True)
            subprocess.run(["git","config","user.email","test@example.invalid"],cwd=root,check=True)
            subprocess.run(["git","config","user.name","Test"],cwd=root,check=True)
            (root/"tracked").write_text("x\n")
            subprocess.run(["git","add","tracked"],cwd=root,check=True)
            subprocess.run(["git","commit","-qm","initial"],cwd=root,check=True)
            info=R.git(root)
            self.assertEqual("main",info["branch"])
            self.assertEqual("",info["originMain"])
            self.assertEqual("UNAVAILABLE",info["gitSyncStatus"])
            self.assertFalse(info["originRefreshAttempted"])
            self.assertEqual("",info["originRefreshError"])

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
