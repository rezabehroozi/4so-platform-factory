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
            persisted_info={"repository":"fixture","branch":"main","head":"abc","originMain":"abc"}
            current_info={"repository":"fixture","branch":"main","head":"abc","originMain":"remote-advanced","gitSyncStatus":"DIFFERENT"}
            state={
                "status":"INTERRUPTED","runId":"resume-1",**persisted_info,
                "phase":"validate","currentTask":"resume-fixture",
                "completedTasks":["prepare"],"failedTasks":["resume-fixture"],
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
            with mock.patch.object(R,"git",return_value=current_info):
                result=R.resume(root)
            self.assertEqual("RESUMED",result["action"])
            self.assertEqual("resume-1",result["runId"])
            self.assertEqual(2,result["attempt"])
            self.assertEqual("DIFFERENT",result["state"]["gitSyncStatus"])
            self.assertEqual("remote-advanced",result["state"]["currentOriginMain"])
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
            self.assertNotIn("resume-fixture",final["failedTasks"])

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

    def test_manual_waiting_state_is_stable_under_observation(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            state={
                "status":"WAITING","runId":"manual-1",
                "activePid":None,"activePidStartTicks":None,"commandPid":None,"commandPidStartTicks":None,
                "replaySafe":False,"recoveryRequired":True,"orphaned":True,
                "latestError":"MANUAL_READBACK_REQUIRED_BEFORE_REPLAY",
                "latestCompletedCheckpoint":"install-dispatched",
            }
            R.write_state(root,state)
            observed=R.reconcile(root,R.read_state(root))
            self.assertEqual("WAITING",observed["status"])
            self.assertEqual("MANUAL_READBACK_REQUIRED_BEFORE_REPLAY",observed["latestError"])
            self.assertEqual("install-dispatched",observed["latestCompletedCheckpoint"])

    def test_orphaned_child_exit_transitions_by_replay_safety(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            base={
                "status":"WAITING","runId":"orphan-1",
                "activePid":99999991,"activePidStartTicks":"1",
                "commandPid":99999992,"commandPidStartTicks":"1",
                "recoveryRequired":True,"orphaned":True,
                "latestError":"ORPHANED_SUPERVISOR_CHILD_STILL_ACTIVE",
            }
            replay=dict(base,replaySafe=True)
            R.write_state(root,replay)
            out=R.reconcile(root,R.read_state(root))
            self.assertEqual("INTERRUPTED",out["status"])
            self.assertFalse(out["recoveryRequired"])
            self.assertEqual("ORPHANED_CHILD_EXITED_OUTCOME_UNKNOWN_REPLAY_SAFE",out["latestError"])

            manual=dict(base,runId="orphan-2",replaySafe=False)
            R.write_state(root,manual)
            out=R.reconcile(root,R.read_state(root))
            self.assertEqual("WAITING",out["status"])
            self.assertTrue(out["recoveryRequired"])
            self.assertEqual("ORPHANED_CHILD_EXITED_OUTCOME_UNKNOWN_MANUAL_READBACK",out["latestError"])

    def test_start_cannot_bypass_non_replay_safe_recovery(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            info={"repository":"fixture","branch":"main","head":"abc","originMain":"","gitSyncStatus":"UNAVAILABLE"}
            command=[sys.executable,"-c","print('must-not-run')"]
            state={
                "status":"WAITING","runId":"unsafe-1",**info,
                "phase":"physical-install","currentTask":"installer","command":command,
                "activePid":None,"activePidStartTicks":None,"commandPid":None,"commandPidStartTicks":None,
                "replaySafe":False,"recoveryRequired":True,"latestError":"MANUAL_READBACK_REQUIRED_BEFORE_REPLAY",
            }
            R.write_state(root,state)
            with mock.patch.object(R,"git",return_value=info), mock.patch.object(R,"acquire") as acquire:
                result=R.start(root,"other-phase","other-task",[sys.executable,"-c","print('new')"])
            self.assertEqual("RECOVERY_REQUIRED",result["action"])
            acquire.assert_not_called()
            self.assertEqual("unsafe-1",R.read_state(root)["runId"])

    def test_unresolved_replay_safe_run_blocks_even_a_different_new_job(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            info={"repository":"fixture","branch":"main","head":"abc","originMain":"","gitSyncStatus":"UNAVAILABLE"}
            command=[sys.executable,"-c","print('replay-safe')"]
            state={
                "status":"FAILED","runId":"replay-1",**info,
                "phase":"validate","currentTask":"owner-tests","command":command,
                "activePid":None,"activePidStartTicks":None,"commandPid":None,"commandPidStartTicks":None,
                "replaySafe":True,"recoveryRequired":False,"latestError":"COMMAND_EXIT_1",
            }
            R.write_state(root,state)
            with mock.patch.object(R,"git",return_value=info), mock.patch.object(R,"acquire") as acquire:
                result=R.start(root,"different-phase","different-task",[sys.executable,"-c","print('new-job')"],replay_safe=True)
            self.assertEqual("RESUME_REQUIRED",result["action"])
            acquire.assert_not_called()
            self.assertEqual("replay-1",R.read_state(root)["runId"])
            self.assertEqual("owner-tests",R.read_state(root)["currentTask"])

    def test_worker_launch_failure_before_execution_is_safe_to_resume_and_releases_lock(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            with mock.patch.object(R.subprocess,"Popen",side_effect=OSError("spawn failed")):
                with self.assertRaisesRegex(RuntimeError,"WORKER_LAUNCH_FAILED_BEFORE_EXECUTION"):
                    R.start(root,"validate","owner-tests",[sys.executable,"-c","print('x')"],replay_safe=False,skip_git=True)
            state=R.read_state(root)
            self.assertEqual("INTERRUPTED",state["status"])
            self.assertTrue(state["safeToRetry"])
            self.assertFalse(state["executionStarted"])
            self.assertFalse(state["recoveryRequired"])
            self.assertEqual("WORKER_LAUNCH_FAILED_BEFORE_EXECUTION",state["latestError"])
            self.assertFalse(R.lock_file(root).exists())
            follow=R.start(root,"different","different-task",[sys.executable,"-c","print('new')"],replay_safe=False,skip_git=True)
            self.assertEqual("RESUME_REQUIRED",follow["action"])
            self.assertEqual(state["runId"],follow["state"]["runId"])

    def test_manual_resolution_can_authorize_one_non_replay_safe_resume(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            state={
                "status":"WAITING","runId":"manual-replay-1",
                "repository":"fixture","branch":"main","head":"abc","originMain":"",
                "phase":"installer","currentTask":"apply","command":[sys.executable,"-c","print('apply')"],
                "completedTasks":[],"failedTasks":["apply"],
                "activePid":None,"activePidStartTicks":None,"commandPid":None,"commandPidStartTicks":None,
                "replaySafe":False,"recoveryRequired":True,"orphaned":True,
                "latestError":"MANUAL_READBACK_REQUIRED_BEFORE_REPLAY","attempt":1,
                "latestLogPath":str(root/".project-runtime/logs/manual-replay-1.log"),
                "heartbeatSeconds":1,"checkpointFile":"",
            }
            R.write_state(root,state)
            resolved=R.resolve_recovery(root,"manual-replay-1","allow-replay","authoritative readback confirms side effect did not occur")
            self.assertEqual("RECOVERY_RESOLVED",resolved["action"])
            self.assertTrue(resolved["state"]["manualReplayAuthorized"])
            self.assertFalse(resolved["state"]["recoveryRequired"])
            evidence=R.recovery_file(root,"manual-replay-1")
            self.assertTrue(evidence.is_file())
            self.assertEqual(R.RESOLUTION_AUTHORITY,json.loads(evidence.read_text())["authority"])
            current_info={"repository":"fixture","branch":"main","head":"abc","originMain":"","gitSyncStatus":"UNAVAILABLE"}
            fake_worker=mock.Mock(pid=12345)
            with mock.patch.object(R,"git",return_value=current_info), \
                 mock.patch.object(R,"acquire"), \
                 mock.patch.object(R.subprocess,"Popen",return_value=fake_worker), \
                 mock.patch.object(R,"ticks",return_value="777"), \
                 mock.patch.object(R,"activate_worker",side_effect=lambda _root,s,*_args,**_kwargs:s):
                resumed=R.resume(root)
            self.assertEqual("RESUMED",resumed["action"])
            consumed=R.read_state(root)
            self.assertFalse(consumed["manualReplayAuthorized"])
            self.assertEqual("REQUESTED",consumed["status"])

    def test_recovery_abandon_unblocks_a_new_job_without_losing_resolution_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            state={
                "status":"WAITING","runId":"old-run",
                "repository":"fixture","branch":"main","head":"abc","originMain":"",
                "phase":"old","currentTask":"old-task","command":["old"],
                "activePid":None,"activePidStartTicks":None,"commandPid":None,"commandPidStartTicks":None,
                "replaySafe":True,"recoveryRequired":True,"orphaned":True,"latestError":"LOCAL_GIT_AUTHORITY_CHANGED_REPLAN_REQUIRED",
            }
            R.write_state(root,state)
            out=R.resolve_recovery(root,"old-run","abandon","source authority changed; old attempt intentionally superseded")
            self.assertEqual("ABANDONED",out["state"]["status"])
            evidence=R.recovery_file(root,"old-run")
            self.assertEqual("abandon",json.loads(evidence.read_text())["decision"])
            info={"repository":"fixture","branch":"main","head":"def","originMain":"","gitSyncStatus":"UNAVAILABLE"}
            with mock.patch.object(R,"git",return_value=info), mock.patch.object(R,"acquire",side_effect=RuntimeError("new-start-reached")):
                with self.assertRaisesRegex(RuntimeError,"new-start-reached"):
                    R.start(root,"new","new-task",["new"],replay_safe=True)
            self.assertTrue(evidence.is_file())

    def test_recovery_resolution_is_run_id_fenced_and_immutable(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            state={
                "status":"WAITING","runId":"fenced-run",
                "activePid":None,"activePidStartTicks":None,"commandPid":None,"commandPidStartTicks":None,
                "replaySafe":False,"recoveryRequired":True,"latestError":"MANUAL_READBACK_REQUIRED_BEFORE_REPLAY",
                "phase":"install","currentTask":"apply",
            }
            R.write_state(root,state)
            with self.assertRaisesRegex(RuntimeError,"RUN_ID_MISMATCH"):
                R.resolve_recovery(root,"wrong-run","abandon","operator selected a new plan")
            first=R.resolve_recovery(root,"fenced-run","abandon","operator selected a new plan")
            second=R.resolve_recovery(root,"fenced-run","abandon","operator selected a new plan")
            self.assertEqual("RECOVERY_RESOLVED",first["action"])
            self.assertEqual("ALREADY_RESOLVED",second["action"])
            with self.assertRaisesRegex(RuntimeError,"RESOLUTION_CONFLICT"):
                R.resolve_recovery(root,"fenced-run","mark-completed","different outcome after sealed resolution")

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
