#!/usr/bin/env python3
from __future__ import annotations
import argparse, datetime, fcntl, hashlib, json, os, secrets, signal, socket, stat, subprocess, sys, tempfile, time
from contextlib import contextmanager
from pathlib import Path

AUTHORITY="PROJECT_RUNTIME_STATE_V1"
LOCK_AUTHORITY="PROJECT_RUNTIME_SINGLE_WRITER_LOCK_V1"
SCHEMA=1
ACTIVE={"REQUESTED","RUNNING","WAITING"}
TERMINAL={"FAILED","INTERRUPTED","COMPLETED","ABANDONED"}
RESOLUTION_AUTHORITY="PROJECT_RUNTIME_RECOVERY_RESOLUTION_V1"
COMMAND_EXEC_FAILURE_AUTHORITY="PROJECT_RUNTIME_COMMAND_EXEC_FAILURE_V1"
RESOLUTION_DECISIONS={"allow-replay","mark-completed","abandon"}

def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00","Z")

def ticks(pid):
    try:
        raw=Path(f"/proc/{int(pid)}/stat").read_text()
        return raw[raw.rfind(")")+2:].split()[19]
    except (OSError,TypeError,ValueError,IndexError):
        return None

def alive(pid,start):
    cur=ticks(pid)
    return bool(cur and str(cur)==str(start or ""))

def fsync_dir(path):
    if os.name!="posix": return
    fd=os.open(path.parent,os.O_RDONLY)
    try: os.fsync(fd)
    finally: os.close(fd)

def atomic_json(path,data):
    path.parent.mkdir(parents=True,exist_ok=True)
    fd,tmp=tempfile.mkstemp(prefix=path.name+".",suffix=".tmp",dir=path.parent)
    tmp=Path(tmp)
    try:
        with os.fdopen(fd,"w",encoding="utf-8") as f:
            json.dump(data,f,sort_keys=True,indent=2); f.write("\n"); f.flush(); os.fsync(f.fileno())
        os.replace(tmp,path); fsync_dir(path)
    finally:
        tmp.unlink(missing_ok=True)

def immutable_json(path,data,label):
    raw=(json.dumps(data,sort_keys=True,indent=2)+"\n").encode("utf-8")
    path.parent.mkdir(parents=True,exist_ok=True)
    if path.exists() or path.is_symlink():
        if path.is_symlink() or not path.is_file():
            raise RuntimeError(f"{label}_PATH_INVALID")
        if path.read_bytes()!=raw:
            raise RuntimeError(f"{label}_REPLACEMENT_FORBIDDEN")
        return
    fd,tmp=tempfile.mkstemp(prefix=path.name+".",suffix=".tmp",dir=path.parent)
    tmp=Path(tmp)
    try:
        with os.fdopen(fd,"wb") as f:
            f.write(raw); f.flush(); os.fsync(f.fileno())
        try:
            os.link(tmp,path,follow_symlinks=False)
        except FileExistsError:
            if path.is_symlink() or not path.is_file() or path.read_bytes()!=raw:
                raise RuntimeError(f"{label}_REPLACEMENT_FORBIDDEN")
        fsync_dir(path)
    finally:
        tmp.unlink(missing_ok=True)

def canonical_run_id(value):
    run_id=str(value or "").strip()
    if not run_id or len(run_id)>160 or any(not (ch.isalnum() or ch in "._:-") for ch in run_id):
        raise RuntimeError("PROJECT_RUNTIME_RUN_ID_INVALID")
    return run_id

def runtime_dir(root,override=None):
    root=Path(root).resolve()
    value=override or os.getenv("PLATFORM_FACTORY_RUNTIME_ROOT") or ".project-runtime"
    raw=Path(str(value))
    if not str(value).strip() or ".." in raw.parts:
        raise RuntimeError("PROJECT_RUNTIME_ROOT_INVALID")
    target=Path(os.path.abspath(raw if raw.is_absolute() else root/raw))
    if not raw.is_absolute():
        try: target.relative_to(root)
        except ValueError as exc: raise RuntimeError("PROJECT_RUNTIME_ROOT_OUTSIDE_PROJECT") from exc
    if target==root:
        raise RuntimeError("PROJECT_RUNTIME_ROOT_PROJECT_ALIAS_FORBIDDEN")
    for candidate in (target,*target.parents):
        if candidate.is_symlink():
            raise RuntimeError(f"PROJECT_RUNTIME_ROOT_SYMLINK_FORBIDDEN {candidate}")
        if candidate.exists() and not candidate.is_dir():
            raise RuntimeError(f"PROJECT_RUNTIME_ROOT_COMPONENT_INVALID {candidate}")
        if candidate==Path(candidate.anchor):
            break
    return target

def ensure_runtime_dir(root,override=None):
    target=runtime_dir(root,override)
    target.mkdir(parents=True,exist_ok=True)
    checked=runtime_dir(root,override)
    if checked!=target or target.is_symlink() or not target.is_dir():
        raise RuntimeError("PROJECT_RUNTIME_ROOT_INVALID")
    return target

def runtime_subdir(root,name,override=None):
    if not name or "/" in name or "\\" in name or name in {".",".."}:
        raise RuntimeError("PROJECT_RUNTIME_SUBDIR_INVALID")
    base=ensure_runtime_dir(root,override)
    target=base/name
    if target.exists() or target.is_symlink():
        if target.is_symlink() or not target.is_dir():
            raise RuntimeError(f"PROJECT_RUNTIME_SUBDIR_INVALID {target}")
    else:
        target.mkdir(mode=0o700)
    if target.is_symlink() or not target.is_dir():
        raise RuntimeError(f"PROJECT_RUNTIME_SUBDIR_INVALID {target}")
    return target

def state_file(root,override=None): return runtime_dir(root,override)/"state.json"
def state_mutex_file(root,override=None): return runtime_dir(root,override)/"state.mutex"
def lock_file(root,override=None): return runtime_dir(root,override)/"mutation.lock"
def log_file(root,run_id,override=None): return runtime_subdir(root,"logs",override)/f"{canonical_run_id(run_id)}.log"
def recovery_file(root,run_id,override=None):
    run_id=canonical_run_id(run_id)
    digest=hashlib.sha256(run_id.encode("utf-8")).hexdigest()
    return runtime_subdir(root,"recovery",override)/f"{digest}.json"
def command_exec_failure_file(root,run_id,attempt,override=None):
    run_id=canonical_run_id(run_id)
    identity=f"{run_id}:{int(attempt or 0)}"
    digest=hashlib.sha256(identity.encode("utf-8")).hexdigest()
    return runtime_subdir(root,"command-exec-failures",override)/f"{digest}.json"

def state_log_file(root,state,override=None):
    run_id=canonical_run_id(state.get("runId"))
    expected=log_file(root,run_id,override)
    stored=str(state.get("latestLogPath") or "").strip()
    if not stored or Path(os.path.abspath(stored))!=expected:
        raise RuntimeError("PROJECT_RUNTIME_LOG_PATH_DRIFT")
    return expected

def load(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size<=0 or path.stat().st_size>4*1024*1024:
        raise RuntimeError(f"INVALID_RUNTIME_FILE {path}")
    data=json.loads(path.read_text())
    if not isinstance(data,dict): raise RuntimeError(f"INVALID_RUNTIME_OBJECT {path}")
    return data

def read_state(root,override=None):
    p=state_file(root,override)
    if not p.exists(): return None
    data=load(p)
    if data.get("authority")!=AUTHORITY or data.get("schemaVersion")!=SCHEMA:
        raise RuntimeError("PROJECT_RUNTIME_STATE_AUTHORITY_INVALID")
    revision=data.get("stateRevision",0)
    if type(revision) is not int or revision<0:
        raise RuntimeError("PROJECT_RUNTIME_STATE_REVISION_INVALID")
    if data.get("runId") not in (None,""):
        canonical_run_id(data.get("runId"))
    data["stateRevision"]=revision
    return data

@contextmanager
def state_guard(root,override=None):
    ensure_runtime_dir(root,override)
    p=state_mutex_file(root,override)
    flags=os.O_CREAT|os.O_RDWR|os.O_CLOEXEC
    if hasattr(os,"O_NOFOLLOW"): flags|=os.O_NOFOLLOW
    fd=os.open(p,flags,0o600)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise RuntimeError("PROJECT_RUNTIME_STATE_MUTEX_INVALID")
        fcntl.flock(fd,fcntl.LOCK_EX)
        yield
    finally:
        try: fcntl.flock(fd,fcntl.LOCK_UN)
        finally: os.close(fd)

def write_state(root,state,override=None,expected_revision=None):
    with state_guard(root,override):
        current=read_state(root,override)
        current_revision=int((current or {}).get("stateRevision") or 0)
        if expected_revision is not None and current_revision!=int(expected_revision):
            return False,current
        body=dict(state); body["authority"]=AUTHORITY; body["schemaVersion"]=SCHEMA
        body["stateRevision"]=current_revision+1; body["updatedAt"]=now()
        atomic_json(state_file(root,override),body)
        return True,body

def git_worktree_fingerprint(root,head):
    indexed=subprocess.run(["git","ls-files","-v","-z"],cwd=root,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False)
    status=subprocess.run(["git","status","--porcelain=v1","-z","--untracked-files=all"],cwd=root,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False)
    unstaged=subprocess.run(["git","diff","--binary","--no-ext-diff","HEAD","--"],cwd=root,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False)
    staged=subprocess.run(["git","diff","--binary","--cached","--no-ext-diff","HEAD","--"],cwd=root,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False)
    untracked=subprocess.run(["git","ls-files","--others","--exclude-standard","-z"],cwd=root,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False)
    if any(p.returncode!=0 for p in (indexed,status,unstaged,staged,untracked)):
        raise RuntimeError("GIT_WORKTREE_FINGERPRINT_FAILED")
    for raw in indexed.stdout.split(b"\x00"):
        if raw and not raw.startswith(b"H "):
            raise RuntimeError("GIT_INDEX_FLAGS_FORBIDDEN")
    digest=hashlib.sha256()
    digest.update(b"PROJECT_RUNTIME_GIT_WORKTREE_V1\x00")
    digest.update(str(head).encode("ascii","strict")+b"\x00")
    for label,payload in ((b"status",status.stdout),(b"unstaged",unstaged.stdout),(b"staged",staged.stdout)):
        digest.update(label+b"\x00"+len(payload).to_bytes(8,"big")+payload)
    untracked_rows=[raw for raw in untracked.stdout.split(b"\x00") if raw]
    for raw in sorted(untracked_rows):
        path=root/Path(os.fsdecode(raw))
        try: info=path.lstat()
        except OSError as exc: raise RuntimeError("GIT_UNTRACKED_SOURCE_UNREADABLE") from exc
        digest.update(b"untracked\x00"+len(raw).to_bytes(8,"big")+raw)
        digest.update(str(stat.S_IFMT(info.st_mode)).encode()+b":"+str(stat.S_IMODE(info.st_mode)).encode()+b"\x00")
        if path.is_symlink():
            target=os.readlink(path).encode(sys.getfilesystemencoding(),"surrogateescape")
            digest.update(len(target).to_bytes(8,"big")+target)
        elif path.is_file():
            digest.update(info.st_size.to_bytes(8,"big"))
            with path.open("rb") as fh:
                for block in iter(lambda:fh.read(1024*1024),b""): digest.update(block)
        else:
            raise RuntimeError("GIT_UNTRACKED_SOURCE_TYPE_INVALID")
    return "sha256:"+digest.hexdigest(),bool(status.stdout)

def git(root,refresh=False,allow_detached=False,require_origin_sync=False):
    def run(*args,check=True,timeout=30):
        p=subprocess.run(["git",*args],cwd=root,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=timeout)
        if check and p.returncode: raise RuntimeError("GIT_COMMAND_FAILED "+" ".join(args)+" "+p.stdout.strip())
        return p
    refresh_error=""
    if refresh:
        fetched=run("fetch","--quiet","origin","main",check=False,timeout=120)
        if fetched.returncode:
            refresh_error=(fetched.stdout or "").strip() or f"exit-{fetched.returncode}"
    head_proc=run("rev-parse","HEAD"); head=head_proc.stdout.strip()
    branch_proc=run("branch","--show-current"); branch=branch_proc.stdout.strip() or "(detached)"
    if branch!="main" and not allow_detached: raise RuntimeError(f"GIT_BRANCH_NOT_MAIN {branch}")
    origin_proc=run("rev-parse","--verify","origin/main",check=False)
    origin=origin_proc.stdout.strip() if origin_proc.returncode==0 else ""
    sync="UNAVAILABLE" if not origin else ("MATCHED" if origin==head else "DIFFERENT")
    if require_origin_sync and sync!="MATCHED":
        raise RuntimeError(f"GIT_ORIGIN_SYNC_REQUIRED head={head} originMain={origin or 'unavailable'}")
    remote=run("config","--get","remote.origin.url",check=False)
    worktree_fingerprint,worktree_dirty=git_worktree_fingerprint(root,head)
    return {"repository":remote.stdout.strip(),"branch":branch,"head":head,"originMain":origin,
            "gitSyncStatus":sync,"originRefreshAttempted":bool(refresh),"originRefreshError":refresh_error,
            "worktreeFingerprint":worktree_fingerprint,"worktreeDirty":worktree_dirty}

def lock_owner_live(lock):
    return alive(lock.get("pid"),lock.get("startTicks"))

def read_lock(root,override=None):
    p=lock_file(root,override)
    if not p.exists(): return None
    d=load(p)
    if d.get("authority")!=LOCK_AUTHORITY: raise RuntimeError("PROJECT_RUNTIME_LOCK_AUTHORITY_INVALID")
    run_id=str(d.get("runId") or "").strip(); pid=d.get("pid"); start=str(d.get("startTicks") or "").strip()
    if not run_id or type(pid) is not int or pid<=0 or not start.isdigit():
        raise RuntimeError("PROJECT_RUNTIME_LOCK_IDENTITY_INVALID")
    return d

def reconcile(root,state,override=None,write=True):
    # Observation must never overwrite newer worker-owned state.  In
    # particular, a status/watchdog poll may hold a stale RUNNING snapshot
    # while the detached worker commits COMPLETED.  Only a proven orphan/stale
    # transition is persisted; liveness fields are derived for the observer.
    s=dict(state)
    worker=alive(s.get("activePid"),s.get("activePidStartTicks"))
    child=alive(s.get("commandPid"),s.get("commandPidStartTicks"))
    lock=read_lock(root,override)
    lock_live=bool(lock and lock_owner_live(lock))
    s["workerAlive"]=worker; s["commandAlive"]=child
    s["lockAlive"]=lock_live; s["lockRunId"]=str((lock or {}).get("runId") or "")
    s["activeRun"]=worker or child or lock_live
    transition=False
    status=s.get("status")
    if status=="WAITING" and s.get("orphaned") is True and s.get("latestError")=="ORPHANED_SUPERVISOR_CHILD_STILL_ACTIVE":
        if child or lock_live:
            pass
        elif s.get("replaySafe") is True:
            s.update(status="INTERRUPTED",recoveryRequired=False,latestError="ORPHANED_CHILD_EXITED_OUTCOME_UNKNOWN_REPLAY_SAFE",
                     activePid=None,activePidStartTicks=None,commandPid=None,commandPidStartTicks=None)
            transition=True
        else:
            s.update(status="WAITING",recoveryRequired=True,latestError="ORPHANED_CHILD_EXITED_OUTCOME_UNKNOWN_MANUAL_READBACK",
                     activePid=None,activePidStartTicks=None,commandPid=None,commandPidStartTicks=None)
            transition=True
    elif status=="WAITING" and not worker and not child:
        # Durable WAITING is an intentional recovery/readback state, not proof
        # of a stale execution.  Preserve the reason and checkpoint until an
        # operator explicitly resolves or resumes it.
        pass
    elif status in ACTIVE:
        if worker or lock_live:
            pass
        elif child:
            s.update(status="WAITING",orphaned=True,recoveryRequired=True,latestError="ORPHANED_SUPERVISOR_CHILD_STILL_ACTIVE")
            transition=True
        else:
            s.update(status="INTERRUPTED",orphaned=True,recoveryRequired=not bool(s.get("replaySafe")),latestError="ORPHANED_OR_STALE_RUN",
                     activePid=None,activePidStartTicks=None,commandPid=None,commandPidStartTicks=None)
            transition=True
    if write and transition:
        # Compare-and-swap under the local state mutex.  A worker can complete
        # between liveness observation and this mutation; revision fencing
        # prevents an observer from overwriting that newer terminal state.
        expected=int(state.get("stateRevision") or 0)
        written,current=write_state(root,s,override,expected_revision=expected)
        if not written:
            if current and current.get("runId")==state.get("runId"):
                return reconcile(root,current,override,write=False)
            return current or s
        return read_state(root,override) or s
    return s

def _reclaim_stale_lock_unlocked(root,state,override=None):
    p=lock_file(root,override); lk=read_lock(root,override)
    if not lk: return True
    if lock_owner_live(lk): return False
    if state:
        worker_live=alive(state.get("activePid"),state.get("activePidStartTicks"))
        child_live=alive(state.get("commandPid"),state.get("commandPidStartTicks"))
        if worker_live or child_live:
            return False
        if state.get("runId")!=lk.get("runId") and state.get("status") in ACTIVE:
            return False
    p.unlink(missing_ok=True); fsync_dir(p); return True

def reclaim_stale_lock(root,state,override=None):
    with state_guard(root,override):
        return _reclaim_stale_lock_unlocked(root,state,override)

def acquire(root,run_id,override=None):
    run_id=str(run_id or "").strip()
    if not run_id: raise RuntimeError("PROJECT_RUNTIME_LOCK_RUN_ID_INVALID")
    owner_pid=os.getpid(); owner_ticks=ticks(owner_pid)
    if not owner_ticks: raise RuntimeError("PROJECT_RUNTIME_LOCK_OWNER_IDENTITY_UNAVAILABLE")
    p=lock_file(root,override); p.parent.mkdir(parents=True,exist_ok=True)
    # Serialize stale-lock observation, unlink and replacement. Without this
    # mutex two reclaimers can both observe the same stale inode and one can
    # unlink the other's freshly-created live lock.
    with state_guard(root,override):
        for _ in range(2):
            payload={"authority":LOCK_AUTHORITY,"runId":run_id,"pid":owner_pid,"startTicks":owner_ticks,"hostname":socket.gethostname(),"acquiredAt":now()}
            try: fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            except FileExistsError:
                lk=read_lock(root,override)
                if lk and lock_owner_live(lk): raise RuntimeError(f"PROJECT_RUNTIME_ALREADY_ACTIVE runId={lk.get('runId')} pid={lk.get('pid')}")
                if not _reclaim_stale_lock_unlocked(root,read_state(root,override),override): raise RuntimeError("PROJECT_RUNTIME_STALE_LOCK_REQUIRES_OBSERVATION")
                continue
            with os.fdopen(fd,"w") as f:
                json.dump(payload,f,sort_keys=True,indent=2); f.write("\n"); f.flush(); os.fsync(f.fileno())
            fsync_dir(p); return payload
    raise RuntimeError("PROJECT_RUNTIME_LOCK_ACQUIRE_FAILED")

def transfer(root,run_id,to_pid,to_ticks,override=None):
    p=lock_file(root,override); lk=read_lock(root,override)
    if not lk or lk.get("runId")!=run_id or lk.get("pid")!=os.getpid() or str(lk.get("startTicks"))!=str(ticks(os.getpid())):
        raise RuntimeError("PROJECT_RUNTIME_LOCK_TRANSFER_OWNER_MISMATCH")
    lk.update(pid=to_pid,startTicks=to_ticks,transferredAt=now()); atomic_json(p,lk)

def activate_worker(root,state,run_id,worker_pid,worker_ticks,override=None):
    # Persist worker identity before transferring the execution lock.  The
    # worker cannot leave its handoff wait until transfer() succeeds, so this
    # ordering prevents the parent from overwriting a newer commandPid written
    # by the worker after it starts the child process.
    s=dict(state)
    s.update(status="RUNNING",activePid=worker_pid,activePidStartTicks=worker_ticks,lastHeartbeat=now(),safeToRetry=False)
    write_state(root,s,override)
    try:
        transfer(root,run_id,worker_pid,worker_ticks,override)
    except Exception as exc:
        try: os.kill(worker_pid,signal.SIGTERM)
        except (ProcessLookupError,PermissionError): pass
        current=read_state(root,override) or s
        preexecution_failure(root,current,"WORKER_LOCK_TRANSFER_FAILED_BEFORE_EXECUTION",override)
        release(root,run_id,os.getpid(),ticks(os.getpid()),override)
        raise RuntimeError("PROJECT_RUNTIME_WORKER_LOCK_TRANSFER_FAILED_BEFORE_EXECUTION") from exc
    return s

def preexecution_failure(root,state,error,override=None):
    s=dict(state)
    s.update(status="INTERRUPTED",recoveryRequired=False,safeToRetry=True,executionStarted=False,
             activePid=None,activePidStartTicks=None,commandPid=None,commandPidStartTicks=None,
             lastHeartbeat=now(),latestError=error)
    write_state(root,s,override)
    return s

def spawn_waiting_worker(root,run_id,state,log_path,override=None,resume_attempt=None):
    args=[sys.executable,str(Path(__file__).resolve()),"_worker","--root",str(root),"--run-id",run_id]
    if override: args+=["--runtime-root",override]
    worker=None
    try:
        with log_path.open("a",buffering=1) as log:
            if resume_attempt is not None:
                log.write(json.dumps({"event":"run-resume-launch","runId":run_id,"attempt":resume_attempt,"at":now()},sort_keys=True)+"\n")
            worker=subprocess.Popen(args,cwd=root,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,start_new_session=True,close_fds=True)
        wt=None
        for _ in range(50):
            wt=ticks(worker.pid)
            if wt: break
            time.sleep(.01)
        if not wt:
            try: worker.terminate()
            except Exception: pass
            raise RuntimeError("PROJECT_RUNTIME_WORKER_IDENTITY_UNAVAILABLE")
        return worker,wt
    except Exception as exc:
        owner=read_lock(root,override)
        if owner and owner.get("runId")==run_id and owner.get("pid")==os.getpid() and str(owner.get("startTicks"))==str(ticks(os.getpid())):
            if worker is not None:
                try: worker.terminate()
                except Exception: pass
            preexecution_failure(root,state,"WORKER_LAUNCH_FAILED_BEFORE_EXECUTION",override)
            release(root,run_id,os.getpid(),ticks(os.getpid()),override)
            raise RuntimeError("PROJECT_RUNTIME_WORKER_LAUNCH_FAILED_BEFORE_EXECUTION") from exc
        raise

def release(root,run_id,pid,start,override=None):
    p=lock_file(root,override)
    if not p.exists(): return
    lk=read_lock(root,override)
    if lk and lk.get("runId")==run_id and lk.get("pid")==pid and str(lk.get("startTicks"))==str(start):
        p.unlink(missing_ok=True); fsync_dir(p)

def command_gate_state(root,run_id,pid,start,override=None):
    s=read_state(root,override)
    if not s or s.get("runId")!=run_id:
        return None
    if s.get("status")!="RUNNING" or s.get("commandPid")!=pid or str(s.get("commandPidStartTicks"))!=str(start):
        return None
    if s.get("executionStarted") is not True:
        return None
    return s

def record_command_exec_failure(root,state,error,override=None):
    attempt=int(state.get("attempt") or 0)
    evidence={
        "authority":COMMAND_EXEC_FAILURE_AUTHORITY,"runId":state.get("runId"),"attempt":attempt,
        "commandPid":os.getpid(),"commandPidStartTicks":ticks(os.getpid()),
        "error":str(error or "COMMAND_EXEC_FAILED"),"recordedAt":now(),
    }
    immutable_json(command_exec_failure_file(root,state.get("runId"),attempt,override),evidence,"PROJECT_RUNTIME_COMMAND_EXEC_FAILURE")
    return evidence

def command_wrapper(root,run_id,override=None):
    pid=os.getpid(); pt=ticks(pid); last_state=None
    for _ in range(400):
        last_state=read_state(root,override)
        gated=command_gate_state(root,run_id,pid,pt,override)
        if gated is not None:
            command=list(gated.get("command") or [])
            if not command:
                record_command_exec_failure(root,gated,"COMMAND_EMPTY",override); return 125
            try:
                os.execvpe(command[0],command,os.environ.copy())
            except OSError as exc:
                record_command_exec_failure(root,gated,f"COMMAND_EXEC_ERROR {exc}",override); return 125
            raise RuntimeError("PROJECT_RUNTIME_COMMAND_EXEC_RETURNED")
        time.sleep(.025)
    if last_state and last_state.get("runId")==run_id:
        record_command_exec_failure(root,last_state,"COMMAND_GATE_TIMEOUT",override)
    return 125

def checkpoint(root,path):
    if not path: return {}
    p=Path(path); p=p if p.is_absolute() else root/p
    if p.is_symlink() or not p.is_file(): return {}
    try: d=json.loads(p.read_text())
    except (OSError,json.JSONDecodeError): return {}
    if not isinstance(d,dict): return {}
    return {"path":str(p),"currentStage":str(d.get("currentStage") or d.get("stage") or d.get("phase") or ""),
            "latestCompletedCheckpoint":str(d.get("latestCompletedCheckpoint") or ""),"nextIndex":d.get("nextIndex") if isinstance(d.get("nextIndex"),int) else None}

def start(root,phase,task,command,heartbeat=30,checkpoint_file="",replay_safe=False,override=None,skip_git=False,allow_detached=False):
    prev=read_state(root,override)
    if prev:
        prev=reconcile(root,prev,override)
        if prev.get("status") in {"RUNNING","WAITING"} and prev.get("activeRun"):
            return {"action":"REJOIN","state":prev}
        if prev.get("recoveryRequired") is True and not prev.get("activeRun"):
            return {"action":"RECOVERY_REQUIRED","state":prev}
        if prev.get("status") in {"FAILED","INTERRUPTED","WAITING"} and not prev.get("activeRun"):
            if prev.get("replaySafe") is True or prev.get("manualReplayAuthorized") is True or prev.get("safeToRetry") is True:
                return {"action":"RESUME_REQUIRED","state":prev}
            prev.update(status="WAITING",recoveryRequired=True,latestError=prev.get("latestError") or "MANUAL_READBACK_REQUIRED_BEFORE_REPLAY")
            write_state(root,prev,override)
            return {"action":"RECOVERY_REQUIRED","state":prev}
    info={"repository":"self-test","branch":"main","head":"self-test","originMain":"self-test","gitSyncStatus":"UNAVAILABLE"} if skip_git else git(root,allow_detached=allow_detached)
    if prev:
        same_job=(prev.get("head")==info["head"] and prev.get("branch")==info["branch"] and prev.get("worktreeFingerprint")==info.get("worktreeFingerprint") and prev.get("phase")==phase and prev.get("currentTask")==task and prev.get("command")==command)
        if prev.get("status")=="COMPLETED" and same_job:
            return {"action":"CACHED_COMPLETED","state":prev}
    run_id="run-"+datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")+"-"+secrets.token_hex(4)
    acquire(root,run_id,override)
    lp=log_file(root,run_id,override); lp.parent.mkdir(parents=True,exist_ok=True)
    s={"status":"REQUESTED","runId":run_id,**info,"phase":phase,"currentTask":task,"completedTasks":[],"failedTasks":[],
       "activePid":None,"activePidStartTicks":None,"commandPid":None,"commandPidStartTicks":None,"startTime":now(),"lastHeartbeat":now(),
       "currentStage":"prepare","latestCompletedCheckpoint":"","latestError":"","latestLogPath":str(lp),"command":command,
       "heartbeatSeconds":max(1,min(60,int(heartbeat))),"checkpointFile":checkpoint_file,"progress":{"heartbeatCount":0,"stage":"prepare"},
       "lastSuccessfulAction":"git-authority-verified","replaySafe":bool(replay_safe),"recoveryRequired":False,"orphaned":False,
       "safeToRetry":False,"executionStarted":False,
       "attempt":1,"backend":"detached-process-supervisor","observerAuthority":False,"executionAuthority":AUTHORITY}
    write_state(root,s,override)
    worker,wt=spawn_waiting_worker(root,run_id,s,lp,override)
    s=activate_worker(root,s,run_id,worker.pid,wt,override)
    return {"action":"STARTED","runId":run_id,"pid":worker.pid,"log":str(lp),"state":s}

def resolve_recovery(root,run_id,decision,reason,override=None):
    s=read_state(root,override)
    if not s: raise RuntimeError("PROJECT_RUNTIME_NO_STATE")
    s=reconcile(root,s,override)
    if s.get("activeRun"):
        raise RuntimeError("PROJECT_RUNTIME_RECOVERY_ACTIVE_RUN")
    run_id=str(run_id or "").strip()
    if not run_id or s.get("runId")!=run_id:
        raise RuntimeError("PROJECT_RUNTIME_RECOVERY_RUN_ID_MISMATCH")
    decision=str(decision or "").strip()
    if decision not in RESOLUTION_DECISIONS:
        raise RuntimeError("PROJECT_RUNTIME_RECOVERY_DECISION_INVALID")
    reason=str(reason or "").strip()
    if len(reason)<4 or len(reason)>1000:
        raise RuntimeError("PROJECT_RUNTIME_RECOVERY_REASON_INVALID")
    if s.get("status")=="COMPLETED" and decision!="mark-completed":
        raise RuntimeError("PROJECT_RUNTIME_RECOVERY_ALREADY_COMPLETED")
    if s.get("status")=="ABANDONED" and decision!="abandon":
        raise RuntimeError("PROJECT_RUNTIME_RECOVERY_ALREADY_ABANDONED")
    existing=s.get("recoveryResolution")
    if isinstance(existing,dict):
        if existing.get("decision")!=decision or existing.get("reason")!=reason:
            raise RuntimeError("PROJECT_RUNTIME_RECOVERY_RESOLUTION_CONFLICT")
        immutable_json(recovery_file(root,run_id,override),existing,"PROJECT_RUNTIME_RECOVERY_EVIDENCE")
        return {"action":"ALREADY_RESOLVED","state":s,"resolution":existing}
    resolution={
        "authority":RESOLUTION_AUTHORITY,"runId":run_id,"decision":decision,"reason":reason,
        "resolvedAt":now(),"previousStatus":s.get("status"),"previousError":s.get("latestError",""),
        "phase":s.get("phase",""),"task":s.get("currentTask",""),
        "latestCompletedCheckpoint":s.get("latestCompletedCheckpoint",""),
    }
    if decision=="allow-replay":
        s.update(status="INTERRUPTED",recoveryRequired=False,manualReplayAuthorized=True,
                 latestError="MANUAL_READBACK_AUTHORIZED_REPLAY")
    elif decision=="mark-completed":
        task=str(s.get("currentTask") or "")
        done=list(s.get("completedTasks") or [])
        if task and task not in done: done.append(task)
        failed=[item for item in list(s.get("failedTasks") or []) if item!=task]
        s.update(status="COMPLETED",recoveryRequired=False,manualReplayAuthorized=False,orphaned=False,
                 latestError="",completedTasks=done,failedTasks=failed,
                 lastSuccessfulAction="manual-readback-completed",
                 latestCompletedCheckpoint=s.get("latestCompletedCheckpoint") or "manual-readback-completed")
    else:
        s.update(status="ABANDONED",recoveryRequired=False,manualReplayAuthorized=False,orphaned=False,
                 latestError="",lastSuccessfulAction="manual-recovery-abandoned")
    s.update(activePid=None,activePidStartTicks=None,commandPid=None,commandPidStartTicks=None,
             recoveryResolution=resolution)
    expected=int(s.get("stateRevision") or 0)
    written,current=write_state(root,s,override,expected_revision=expected)
    if not written:
        current=current or read_state(root,override)
        if not current or current.get("runId")!=run_id:
            raise RuntimeError("PROJECT_RUNTIME_RECOVERY_STATE_CHANGED")
        concurrent=current.get("recoveryResolution")
        if isinstance(concurrent,dict):
            if concurrent.get("decision")==decision and concurrent.get("reason")==reason:
                immutable_json(recovery_file(root,run_id,override),concurrent,"PROJECT_RUNTIME_RECOVERY_EVIDENCE")
                return {"action":"ALREADY_RESOLVED","state":current,"resolution":concurrent}
            raise RuntimeError("PROJECT_RUNTIME_RECOVERY_RESOLUTION_CONFLICT")
        raise RuntimeError("PROJECT_RUNTIME_RECOVERY_STATE_CHANGED")
    immutable_json(recovery_file(root,run_id,override),resolution,"PROJECT_RUNTIME_RECOVERY_EVIDENCE")
    return {"action":"RECOVERY_RESOLVED","state":current,"resolution":resolution}

def resume(root,override=None,allow_detached=False):
    s=read_state(root,override)
    if not s: raise RuntimeError("PROJECT_RUNTIME_NO_STATE")
    s=reconcile(root,s,override)
    if s.get("status") in {"RUNNING","WAITING"} and s.get("activeRun"):
        return {"action":"REJOIN","state":s}
    if s.get("status")=="COMPLETED":
        return {"action":"ALREADY_COMPLETED","state":s}
    if not s.get("replaySafe") and s.get("manualReplayAuthorized") is not True and s.get("safeToRetry") is not True:
        s.update(status="WAITING",recoveryRequired=True,latestError="MANUAL_READBACK_REQUIRED_BEFORE_REPLAY")
        write_state(root,s,override)
        return {"action":"RECOVERY_REQUIRED","state":s}
    info=git(root,refresh=False,allow_detached=allow_detached)
    if s.get("head")!=info["head"] or s.get("branch")!=info["branch"] or s.get("worktreeFingerprint")!=info.get("worktreeFingerprint"):
        s.update(status="WAITING",recoveryRequired=True,latestError="LOCAL_GIT_AUTHORITY_CHANGED_REPLAN_REQUIRED",
                 currentOriginMain=info.get("originMain",""),gitSyncStatus=info.get("gitSyncStatus","UNAVAILABLE"),
                 currentWorktreeFingerprint=info.get("worktreeFingerprint",""),currentWorktreeDirty=info.get("worktreeDirty"))
        write_state(root,s,override)
        return {"action":"REPLAN_REQUIRED","state":s}
    s["currentOriginMain"]=info.get("originMain","")
    s["gitSyncStatus"]=info.get("gitSyncStatus","UNAVAILABLE")
    s["currentWorktreeFingerprint"]=info.get("worktreeFingerprint","")
    s["currentWorktreeDirty"]=info.get("worktreeDirty")
    run_id=str(s.get("runId") or "")
    if not run_id: raise RuntimeError("PROJECT_RUNTIME_RUN_ID_MISSING")
    acquire(root,run_id,override)
    s.update(status="REQUESTED",attempt=int(s.get("attempt") or 1)+1,latestError="",orphaned=False,recoveryRequired=False,
             manualReplayAuthorized=False,safeToRetry=False,executionStarted=False,
             activePid=None,activePidStartTicks=None,commandPid=None,commandPidStartTicks=None,lastHeartbeat=now())
    write_state(root,s,override)
    lp=state_log_file(root,s,override)
    worker,wt=spawn_waiting_worker(root,run_id,s,lp,override,resume_attempt=s["attempt"])
    s=activate_worker(root,s,run_id,worker.pid,wt,override)
    return {"action":"RESUMED","runId":run_id,"pid":worker.pid,"attempt":s["attempt"],"state":s}

def worker(root,run_id,override=None):
    pid=os.getpid(); pt=ticks(pid)
    for _ in range(200):
        lk=read_lock(root,override)
        if lk and lk.get("runId")==run_id and lk.get("pid")==pid and str(lk.get("startTicks"))==str(pt): break
        time.sleep(.025)
    else: raise RuntimeError("PROJECT_RUNTIME_WORKER_LOCK_HANDOFF_TIMEOUT")
    s=read_state(root,override)
    if not s or s.get("runId")!=run_id: raise RuntimeError("PROJECT_RUNTIME_WORKER_STATE_MISMATCH")
    command=list(s.get("command") or [])
    log=state_log_file(root,s,override); hb=max(1,min(60,int(s.get("heartbeatSeconds") or 30)))
    interrupted=False; child=None
    def stop(_sig,_frame):
        nonlocal interrupted
        interrupted=True
        if child and child.poll() is None:
            try: os.killpg(child.pid,signal.SIGTERM)
            except ProcessLookupError: pass
    signal.signal(signal.SIGTERM,stop); signal.signal(signal.SIGINT,stop)
    with log.open("a",buffering=1) as out:
        out.write(json.dumps({"event":"run-start","runId":run_id,"at":now(),"command":command},sort_keys=True)+"\n")
        wrapper=[sys.executable,str(Path(__file__).resolve()),"_command","--root",str(root),"--run-id",run_id]
        if override: wrapper+=["--runtime-root",override]
        try:
            child=subprocess.Popen(wrapper,cwd=root,stdin=subprocess.DEVNULL,stdout=out,stderr=subprocess.STDOUT,start_new_session=True,close_fds=True)
        except Exception:
            s=read_state(root,override) or s
            s=preexecution_failure(root,s,"COMMAND_WRAPPER_LAUNCH_FAILED_BEFORE_EXECUTION",override)
            out.write(json.dumps({"event":"run-terminal","runId":run_id,"status":s["status"],"exitCode":None,"at":now()},sort_keys=True)+"\n"); out.flush()
            release(root,run_id,pid,pt,override)
            return 1
        ct=None
        for _ in range(50):
            ct=ticks(child.pid)
            if ct: break
            time.sleep(.01)
        s.update(status="RUNNING",activePid=pid,activePidStartTicks=pt,commandPid=child.pid,commandPidStartTicks=ct,
                 safeToRetry=False,executionStarted=True,lastSuccessfulAction="command-started")
        write_state(root,s,override)
        count=0; next_hb=0.0
        while child.poll() is None and not interrupted:
            if time.monotonic()>=next_hb:
                s=read_state(root,override) or s; cp=checkpoint(root,s.get("checkpointFile")); count+=1
                s["lastHeartbeat"]=now(); s["checkpoint"]=cp
                if cp.get("currentStage"): s["currentStage"]=cp["currentStage"]
                if cp.get("latestCompletedCheckpoint"): s["latestCompletedCheckpoint"]=cp["latestCompletedCheckpoint"]
                s["progress"]={"heartbeatCount":count,"stage":s.get("currentStage"),"nextIndex":cp.get("nextIndex")}
                s["lastSuccessfulAction"]=s.get("latestCompletedCheckpoint") or "heartbeat"; write_state(root,s,override)
                out.write(json.dumps({"event":"heartbeat","runId":run_id,"count":count,"stage":s.get("currentStage"),"at":s["lastHeartbeat"]},sort_keys=True)+"\n"); out.flush()
                next_hb=time.monotonic()+hb
            time.sleep(min(1.0,hb/4))
        if interrupted and child.poll() is None:
            try: child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                try: os.killpg(child.pid,signal.SIGKILL)
                except ProcessLookupError: pass
        rc=child.wait(); s=read_state(root,override) or s; cp=checkpoint(root,s.get("checkpointFile"))
        preexec_path=command_exec_failure_file(root,run_id,s.get("attempt"),override)
        if preexec_path.exists():
            marker=load(preexec_path)
            if marker.get("authority")!=COMMAND_EXEC_FAILURE_AUTHORITY or marker.get("runId")!=run_id or marker.get("attempt")!=int(s.get("attempt") or 0):
                raise RuntimeError("PROJECT_RUNTIME_COMMAND_EXEC_FAILURE_EVIDENCE_INVALID")
            s=preexecution_failure(root,s,str(marker.get("error") or "COMMAND_EXEC_FAILED_BEFORE_EXECUTION"),override)
            s["exitCode"]=rc; s["checkpoint"]=cp
            out.write(json.dumps({"event":"run-terminal","runId":run_id,"status":s["status"],"exitCode":rc,"preExecutionFailure":True,"at":now()},sort_keys=True)+"\n"); out.flush()
            release(root,run_id,pid,pt,override)
            return 1
        if cp.get("currentStage"): s["currentStage"]=cp["currentStage"]
        if cp.get("latestCompletedCheckpoint"): s["latestCompletedCheckpoint"]=cp["latestCompletedCheckpoint"]
        s.update(activePid=None,activePidStartTicks=None,commandPid=None,commandPidStartTicks=None,lastHeartbeat=now(),checkpoint=cp,exitCode=rc)
        task=str(s.get("currentTask") or "")
        if interrupted: s.update(status="INTERRUPTED",latestError="SUPERVISOR_INTERRUPTED",recoveryRequired=not bool(s.get("replaySafe")))
        elif rc==0:
            done=list(s.get("completedTasks") or [])
            if task and task not in done: done.append(task)
            failed=[item for item in list(s.get("failedTasks") or []) if item!=task]
            s.update(status="COMPLETED",latestError="",completedTasks=done,failedTasks=failed,recoveryRequired=False,lastSuccessfulAction=task or "command-completed",
                     latestCompletedCheckpoint=s.get("latestCompletedCheckpoint") or s.get("currentStage") or task)
        else:
            failed=list(s.get("failedTasks") or [])
            if task and task not in failed: failed.append(task)
            s.update(status="FAILED",latestError=f"COMMAND_EXIT_{rc}",failedTasks=failed,recoveryRequired=not bool(s.get("replaySafe")))
        write_state(root,s,override); out.write(json.dumps({"event":"run-terminal","runId":run_id,"status":s["status"],"exitCode":rc,"at":now()},sort_keys=True)+"\n"); out.flush()
    release(root,run_id,pid,pt,override); return 0 if s["status"]=="COMPLETED" else 1

def self_test():
    with tempfile.TemporaryDirectory() as td:
        root=Path(td); (root/".state").mkdir()
        payload=("import json,time;from pathlib import Path;"
                 "p=Path('count');p.write_text(str(int(p.read_text())+1) if p.exists() else '1');"
                 "c=Path('.state/checkpoint.json');c.write_text(json.dumps({'currentStage':'build','latestCompletedCheckpoint':'prepare','nextIndex':1}));"
                 "time.sleep(2);c.write_text(json.dumps({'currentStage':'validate','latestCompletedCheckpoint':'build','nextIndex':2}));time.sleep(1)")
        cmd=[sys.executable,"-c",payload]
        first=start(root,"fixture","long-job",cmd,1,".state/checkpoint.json",True,skip_git=True)
        if first["action"]!="STARTED": raise AssertionError(first)
        run_id=first["runId"]; pid=first["pid"]; time.sleep(1.2)
        second=start(root,"fixture","long-job",cmd,1,".state/checkpoint.json",True,skip_git=True)
        if second["action"]!="REJOIN" or second["state"]["runId"]!=run_id or second["state"]["activePid"]!=pid: raise AssertionError((first,second))
        if (root/"count").read_text()!="1": raise AssertionError("duplicate command")
        deadline=time.monotonic()+10
        while time.monotonic()<deadline:
            s=reconcile(root,read_state(root) or {})
            if s.get("status") in TERMINAL: break
            time.sleep(.2)
        s=read_state(root)
        if not s or s.get("status")!="COMPLETED" or (root/"count").read_text()!="1" or s.get("latestCompletedCheckpoint")!="build": raise AssertionError(s)
        if not Path(s["latestLogPath"]).is_file() or lock_file(root).exists(): raise AssertionError("log/lock invariant")
        stale=dict(s); stale.update(status="RUNNING",activePid=99999999,activePidStartTicks="1",latestError="")
        write_state(root,stale); stale=reconcile(root,read_state(root) or {})
        if stale.get("status")!="INTERRUPTED" or stale.get("latestError")!="ORPHANED_OR_STALE_RUN": raise AssertionError(stale)
        print(json.dumps({"authority":"PROJECT_RUNTIME_STREAM_INDEPENDENCE_TEST_V1","observerDetached":True,"workerSurvived":True,"duplicatePrevented":True,"checkpointPreserved":True,"completed":True,"staleDetection":True,"runId":run_id,"workerPid":pid},sort_keys=True))
    return 0

def main():
    ap=argparse.ArgumentParser(); sub=ap.add_subparsers(dest="cmd",required=True)
    for name in ("status","watchdog","resume","self-test"):
        p=sub.add_parser(name); p.add_argument("--root",default=str(Path(__file__).resolve().parents[1])); p.add_argument("--runtime-root")
        if name=="resume": p.add_argument("--allow-detached",action="store_true")
    p=sub.add_parser("resolve"); p.add_argument("--root",default=str(Path(__file__).resolve().parents[1])); p.add_argument("--runtime-root")
    p.add_argument("--run-id",required=True); p.add_argument("--decision",choices=sorted(RESOLUTION_DECISIONS),required=True); p.add_argument("--reason",required=True)
    p=sub.add_parser("start"); p.add_argument("--root",default=str(Path(__file__).resolve().parents[1])); p.add_argument("--runtime-root"); p.add_argument("--phase",required=True); p.add_argument("--task",required=True); p.add_argument("--heartbeat-seconds",type=int,default=30); p.add_argument("--checkpoint-file"); p.add_argument("--replay-safe",action="store_true"); p.add_argument("--allow-detached",action="store_true"); p.add_argument("command",nargs=argparse.REMAINDER)
    p=sub.add_parser("_worker"); p.add_argument("--root",required=True); p.add_argument("--runtime-root"); p.add_argument("--run-id",required=True)
    p=sub.add_parser("_command"); p.add_argument("--root",required=True); p.add_argument("--runtime-root"); p.add_argument("--run-id",required=True)
    a=ap.parse_args(); root=Path(a.root).resolve()
    try:
        if a.cmd=="self-test": return self_test()
        if a.cmd=="status":
            s=read_state(root,a.runtime_root)
            if not s: print(json.dumps({"status":"IDLE","activeRun":False,"authority":AUTHORITY,"schemaVersion":SCHEMA},sort_keys=True)); return 0
            print(json.dumps(reconcile(root,s,a.runtime_root),sort_keys=True)); return 0
        if a.cmd=="resume":
            result=resume(root,a.runtime_root,getattr(a,"allow_detached",False)); print(json.dumps(result,sort_keys=True))
            return 4 if result["action"] in {"RECOVERY_REQUIRED","REPLAN_REQUIRED"} else 0
        if a.cmd=="resolve":
            result=resolve_recovery(root,a.run_id,a.decision,a.reason,a.runtime_root); print(json.dumps(result,sort_keys=True)); return 0
        if a.cmd=="watchdog":
            s=read_state(root,a.runtime_root)
            if not s: print(json.dumps({"status":"IDLE","action":"NO_STATE"},sort_keys=True)); return 0
            before=s.get("status"); s=reconcile(root,s,a.runtime_root); reclaimed=False
            if s.get("status") in TERMINAL and not s.get("activeRun"): reclaimed=reclaim_stale_lock(root,s,a.runtime_root)
            print(json.dumps({"action":"WATCHDOG","before":before,"after":s.get("status"),"lockReclaimed":reclaimed,"state":s},sort_keys=True)); return 0
        if a.cmd=="_worker": return worker(root,a.run_id,a.runtime_root)
        if a.cmd=="_command": return command_wrapper(root,a.run_id,a.runtime_root)
        command=list(a.command); command=command[1:] if command and command[0]=="--" else command
        if not command: raise RuntimeError("PROJECT_RUNTIME_COMMAND_REQUIRED")
        result=start(root,a.phase,a.task,command,a.heartbeat_seconds,a.checkpoint_file or "",a.replay_safe,a.runtime_root,allow_detached=a.allow_detached)
        print(json.dumps(result,sort_keys=True))
        return 4 if result["action"] in {"RECOVERY_REQUIRED","RESUME_REQUIRED"} else 0
    except Exception as e:
        print(f"PROJECT_RUNTIME_ERROR {e}",file=sys.stderr); return 2
if __name__=="__main__": raise SystemExit(main())
