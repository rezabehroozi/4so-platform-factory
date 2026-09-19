#!/usr/bin/env python3
"""Durable parallel task-wave runner.

Designed for long-running development/Lab waves that must survive controller
disconnects. Tasks are argv-only (no shell), checkpointed atomically, retried
individually, and skipped after success on resume.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

if os.name == "nt":
    import msvcrt
else:
    import fcntl

SCHEMA_VERSION = 1
_STATES = {"PENDING", "RUNNING", "SUCCEEDED", "FAILED", "BLOCKED", "INTERRUPTED"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _canonical_digest(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=path.name + ".tmp.", dir=path.parent)
    tmp = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, sort_keys=True, indent=2, ensure_ascii=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
        if os.name != "nt":
            dfd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
    finally:
        with contextlib.suppress(FileNotFoundError):
            tmp.unlink()


def _load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8-sig") as stream:
        return json.load(stream)


def _validate_spec(spec: dict[str, Any]) -> list[dict[str, Any]]:
    if spec.get("schemaVersion") != SCHEMA_VERSION:
        raise SystemExit(f"wave spec schemaVersion must be {SCHEMA_VERSION}")
    tasks = spec.get("tasks")
    if not isinstance(tasks, list) or not tasks:
        raise SystemExit("wave spec tasks must be a non-empty array")
    ids: set[str] = set()
    normalized: list[dict[str, Any]] = []
    for raw in tasks:
        if not isinstance(raw, dict):
            raise SystemExit("each wave task must be an object")
        task_id = raw.get("id")
        argv = raw.get("argv")
        if not isinstance(task_id, str) or not task_id or task_id.strip() != task_id:
            raise SystemExit("each wave task requires a canonical non-empty id")
        if task_id in ids:
            raise SystemExit(f"duplicate wave task id: {task_id}")
        ids.add(task_id)
        if not isinstance(argv, list) or not argv or not all(isinstance(x, str) and x for x in argv):
            raise SystemExit(f"task {task_id} argv must be a non-empty string array")
        timeout = int(raw.get("timeoutSeconds", 1800))
        attempts = int(raw.get("maxAttempts", 2))
        delay = float(raw.get("retryDelaySeconds", 2))
        if timeout <= 0 or attempts <= 0 or delay < 0:
            raise SystemExit(f"task {task_id} has invalid timeout/retry policy")
        deps = raw.get("dependsOn", [])
        if not isinstance(deps, list) or not all(isinstance(x, str) and x for x in deps):
            raise SystemExit(f"task {task_id} dependsOn must be a string array")
        cwd = raw.get("cwd")
        if cwd is not None and (not isinstance(cwd, str) or not cwd):
            raise SystemExit(f"task {task_id} cwd must be a non-empty string")
        input_files = raw.get("inputFiles", [])
        if not isinstance(input_files, list) or not all(isinstance(x, str) and x for x in input_files):
            raise SystemExit(f"task {task_id} inputFiles must be a string array")
        normalized.append({
            "id": task_id,
            "argv": argv,
            "cwd": cwd,
            "dependsOn": deps,
            "inputFiles": input_files,
            "timeoutSeconds": timeout,
            "maxAttempts": attempts,
            "retryDelaySeconds": delay,
        })
    by_id = {t["id"]: t for t in normalized}
    for task in normalized:
        missing = [dep for dep in task["dependsOn"] if dep not in by_id]
        if missing:
            raise SystemExit(f"task {task['id']} has unknown dependencies: {missing}")
        if task["id"] in task["dependsOn"]:
            raise SystemExit(f"task {task['id']} cannot depend on itself")

    visiting: set[str] = set()
    visited: set[str] = set()
    def visit(task_id: str) -> None:
        if task_id in visited:
            return
        if task_id in visiting:
            raise SystemExit("wave task dependency graph contains a cycle")
        visiting.add(task_id)
        for dep in by_id[task_id]["dependsOn"]:
            visit(dep)
        visiting.remove(task_id)
        visited.add(task_id)
    for task_id in by_id:
        visit(task_id)
    return normalized


def _task_input_paths(task: dict[str, Any]) -> list[Path]:
    candidates: list[str] = list(task.get("inputFiles") or [])
    argv = task["argv"]
    executable = Path(argv[0]).name.lower()

    if len(argv) >= 3:
        for index, arg in enumerate(argv[:-1]):
            if arg.lower() in {"-file", "--file"}:
                candidates.append(argv[index + 1])

    if len(argv) >= 2:
        script = argv[1]
        suffix = Path(script).suffix.lower()
        if executable.startswith("python") and suffix == ".py":
            candidates.append(script)
        elif executable in {"bash", "bash.exe", "sh", "sh.exe"} and suffix in {".sh", ".bash"}:
            candidates.append(script)

    first_suffix = Path(argv[0]).suffix.lower()
    if first_suffix in {".py", ".ps1", ".sh", ".bash"}:
        candidates.append(argv[0])

    base = Path(task["cwd"]).expanduser() if task["cwd"] else Path.cwd()
    resolved: dict[str, Path] = {}
    explicit = set(task.get("inputFiles") or [])
    for raw in candidates:
        path = Path(raw).expanduser()
        if not path.is_absolute():
            path = base / path
        path = path.absolute()
        if not path.is_file():
            if raw in explicit or raw == argv[0] or raw in argv[1:2] or any(
                flag.lower() in {"-file", "--file"} and i + 1 < len(argv) and argv[i + 1] == raw
                for i, flag in enumerate(argv)
            ):
                raise SystemExit(f"task {task['id']} bound input file is missing: {path}")
            continue
        resolved[str(path)] = path
    return [resolved[key] for key in sorted(resolved)]


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _task_input_binding(task: dict[str, Any]) -> list[dict[str, str]]:
    return [{"path": str(path), "digest": _file_digest(path)} for path in _task_input_paths(task)]


def _input_bindings(tasks: list[dict[str, Any]]) -> dict[str, list[dict[str, str]]]:
    return {task["id"]: _task_input_binding(task) for task in tasks}


def _task_input_binding_error(task: dict[str, Any], expected: list[dict[str, str]]) -> str:
    try:
        observed = _task_input_binding(task)
    except (OSError, SystemExit) as exc:
        return f"task input binding unavailable: {exc}"
    if observed != expected:
        return "task input binding changed after wave acceptance; use a new state directory"
    return ""


def _lock_fd(fd: int) -> None:
    if os.name == "nt":
        if os.fstat(fd).st_size == 0:
            os.write(fd, b"\0")
            os.fsync(fd)
        os.lseek(fd, 0, os.SEEK_SET)
        try:
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        except OSError as exc:
            raise SystemExit("another parallel wave is active for this state directory") from exc
    else:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise SystemExit("another parallel wave is active for this state directory") from exc


@contextlib.contextmanager
def _exclusive_state(state_dir: Path):
    state_dir.mkdir(parents=True, exist_ok=True)
    lock = state_dir / ".parallel-wave.lock"
    fd = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise SystemExit("parallel wave lock is not a regular file")
        _lock_fd(fd)
        yield
    finally:
        if os.name == "nt":
            os.lseek(fd, 0, os.SEEK_SET)
            with contextlib.suppress(OSError):
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        else:
            with contextlib.suppress(OSError):
                fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _initial_state(spec_digest: str, tasks: list[dict[str, Any]], input_bindings: dict[str, list[dict[str, str]]]) -> dict[str, Any]:
    return {
        "schemaVersion": SCHEMA_VERSION,
        "specDigest": spec_digest,
        "inputBindings": input_bindings,
        "createdAt": _now(),
        "updatedAt": _now(),
        "heartbeatAt": _now(),
        "status": "RUNNING",
        "tasks": {
            t["id"]: {
                "state": "PENDING", "attempts": 0, "lastExitCode": None,
                "lastError": "", "startedAt": "", "finishedAt": "", "log": "",
            } for t in tasks
        },
    }


def _load_or_init_state(path: Path, spec_digest: str, tasks: list[dict[str, Any]], input_bindings: dict[str, list[dict[str, str]]]) -> dict[str, Any]:
    if not path.exists():
        return _initial_state(spec_digest, tasks, input_bindings)
    state = _load_json(path)
    if state.get("schemaVersion") != SCHEMA_VERSION or state.get("specDigest") != spec_digest:
        raise SystemExit("parallel wave state is bound to a different spec; use a new state directory")
    if state.get("inputBindings") != input_bindings:
        raise SystemExit("parallel wave task inputs changed after acceptance; use a new state directory")
    known = {t["id"] for t in tasks}
    if set((state.get("tasks") or {}).keys()) != known:
        raise SystemExit("parallel wave state task set differs from the bound spec")
    for task in state["tasks"].values():
        if task.get("state") not in _STATES:
            raise SystemExit("parallel wave state contains an invalid task state")
        if task["state"] == "RUNNING":
            task["state"] = "INTERRUPTED"
            task["lastError"] = "previous runner stopped before recording task completion"
            task["finishedAt"] = _now()
    state["status"] = "RUNNING"
    state["heartbeatAt"] = _now()
    state["updatedAt"] = _now()
    return state


def _execute(task: dict[str, Any], log_path: Path) -> tuple[int, str]:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    cwd = task["cwd"] or None
    try:
        with log_path.open("ab", buffering=0) as log:
            banner = f"\n=== attempt started {_now()} ===\nargv={json.dumps(task['argv'])}\n".encode()
            log.write(banner)
            process = subprocess.Popen(
                task["argv"], cwd=cwd, stdin=subprocess.DEVNULL,
                stdout=log, stderr=subprocess.STDOUT, close_fds=True,
            )
            try:
                rc = process.wait(timeout=task["timeoutSeconds"])
                return rc, "" if rc == 0 else f"exit code {rc}"
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
                return 124, f"timeout after {task['timeoutSeconds']} seconds"
    except Exception as exc:
        return 125, f"{type(exc).__name__}: {exc}"


def run_wave(spec: dict[str, Any], state_dir: Path, max_workers: int) -> int:
    tasks = _validate_spec(spec)
    if max_workers <= 0:
        raise SystemExit("max-workers must be positive")
    digest = _canonical_digest(spec)
    state_path = state_dir / "state.json"
    logs_dir = state_dir / "logs"
    by_id = {t["id"]: t for t in tasks}
    input_bindings = _input_bindings(tasks)
    stop_heartbeat = threading.Event()

    with _exclusive_state(state_dir):
        state = _load_or_init_state(state_path, digest, tasks, input_bindings)
        _atomic_json(state_path, state)

        def heartbeat() -> None:
            while not stop_heartbeat.wait(2):
                state["heartbeatAt"] = _now()
                state["updatedAt"] = _now()
                _atomic_json(state_path, state)

        hb = threading.Thread(target=heartbeat, name="parallel-wave-heartbeat", daemon=True)
        hb.start()
        futures: dict[Any, str] = {}
        executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="wave")
        try:
            while True:
                # Failed dependency permanently blocks dependents.
                for task in tasks:
                    row = state["tasks"][task["id"]]
                    if row["state"] in {"SUCCEEDED", "RUNNING", "FAILED", "BLOCKED"}:
                        continue
                    deps = [state["tasks"][dep]["state"] for dep in task["dependsOn"]]
                    if any(dep in {"FAILED", "BLOCKED"} for dep in deps):
                        row["state"] = "BLOCKED"
                        row["lastError"] = "dependency failed or was blocked"
                        row["finishedAt"] = _now()

                running_ids = set(futures.values())
                capacity = max_workers - len(futures)
                if capacity > 0:
                    for task in tasks:
                        if capacity <= 0:
                            break
                        task_id = task["id"]
                        row = state["tasks"][task_id]
                        if task_id in running_ids or row["state"] in {"SUCCEEDED", "FAILED", "BLOCKED", "RUNNING"}:
                            continue
                        if any(state["tasks"][dep]["state"] != "SUCCEEDED" for dep in task["dependsOn"]):
                            continue
                        if row["attempts"] >= task["maxAttempts"]:
                            row["state"] = "FAILED"
                            row["lastError"] = row["lastError"] or "attempt budget exhausted"
                            row["finishedAt"] = _now()
                            continue
                        binding_error = _task_input_binding_error(task, state["inputBindings"][task_id])
                        if binding_error:
                            row["state"] = "FAILED"
                            row["lastError"] = binding_error
                            row["finishedAt"] = _now()
                            continue
                        if row["state"] in {"INTERRUPTED", "PENDING"} and row["attempts"] > 0:
                            time.sleep(task["retryDelaySeconds"])
                        row["attempts"] += 1
                        row["state"] = "RUNNING"
                        row["startedAt"] = _now()
                        row["finishedAt"] = ""
                        log_path = logs_dir / f"{task_id}.attempt-{row['attempts']}.log"
                        row["log"] = str(log_path)
                        fut = executor.submit(_execute, task, log_path)
                        futures[fut] = task_id
                        capacity -= 1
                        state["updatedAt"] = _now()
                        _atomic_json(state_path, state)

                if not futures:
                    remaining = [r for r in state["tasks"].values() if r["state"] not in {"SUCCEEDED", "FAILED", "BLOCKED"}]
                    if not remaining:
                        break
                    # A pending graph with no runnable tasks is invalid/fail-closed.
                    for row in remaining:
                        row["state"] = "BLOCKED"
                        row["lastError"] = "no runnable dependency path remains"
                        row["finishedAt"] = _now()
                    break

                done, _ = wait(tuple(futures), timeout=1, return_when=FIRST_COMPLETED)
                for fut in done:
                    task_id = futures.pop(fut)
                    task = by_id[task_id]
                    row = state["tasks"][task_id]
                    rc, error = fut.result()
                    binding_error = _task_input_binding_error(task, state["inputBindings"][task_id])
                    row["lastExitCode"] = rc
                    row["lastError"] = binding_error or error
                    row["finishedAt"] = _now()
                    if binding_error:
                        row["state"] = "FAILED"
                    elif rc == 0:
                        row["state"] = "SUCCEEDED"
                    elif row["attempts"] < task["maxAttempts"]:
                        row["state"] = "PENDING"
                    else:
                        row["state"] = "FAILED"
                    state["updatedAt"] = _now()
                    _atomic_json(state_path, state)

            failed = [tid for tid, row in state["tasks"].items() if row["state"] != "SUCCEEDED"]
            state["status"] = "SUCCEEDED" if not failed else "FAILED"
            state["heartbeatAt"] = _now()
            state["updatedAt"] = _now()
            _atomic_json(state_path, state)
            return 0 if not failed else 1
        finally:
            stop_heartbeat.set()
            executor.shutdown(wait=True, cancel_futures=False)
            hb.join(timeout=3)


def _detach(argv: list[str], state_dir: Path) -> int:
    state_dir.mkdir(parents=True, exist_ok=True)
    log_path = state_dir / "runner.log"
    child = [sys.executable, str(Path(__file__).resolve())] + argv
    with log_path.open("ab", buffering=0) as log:
        kwargs: dict[str, Any] = {
            "stdin": subprocess.DEVNULL, "stdout": log, "stderr": subprocess.STDOUT,
            "close_fds": True,
        }
        if os.name == "nt":
            kwargs["creationflags"] = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            kwargs["start_new_session"] = True
        process = subprocess.Popen(child, **kwargs)
    print(json.dumps({"status": "DETACHED", "pid": process.pid, "stateDir": str(state_dir), "log": str(log_path)}))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec", required=True)
    parser.add_argument("--state-dir", required=True)
    parser.add_argument("--max-workers", type=int, default=4)
    parser.add_argument("--detach", action="store_true")
    parser.add_argument("--status", action="store_true")
    args = parser.parse_args(argv)
    state_dir = Path(args.state_dir).expanduser().absolute()
    if args.status:
        path = state_dir / "state.json"
        if not path.exists():
            print(json.dumps({"status": "NOT_STARTED", "stateDir": str(state_dir)}))
            return 2
        print(json.dumps(_load_json(path), sort_keys=True))
        return 0
    spec_path = Path(args.spec).expanduser().absolute()
    spec = _load_json(spec_path)
    if not isinstance(spec, dict):
        raise SystemExit("wave spec must be a JSON object")
    if args.detach:
        child_args = ["--spec", str(spec_path), "--state-dir", str(state_dir), "--max-workers", str(args.max_workers)]
        return _detach(child_args, state_dir)
    return run_wave(spec, state_dir, args.max_workers)


if __name__ == "__main__":
    raise SystemExit(main())
