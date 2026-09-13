#!/usr/bin/env python3
from __future__ import annotations

import argparse
import dataclasses
import datetime
import hashlib
import json
import os
import posixpath
from pathlib import Path
import re
import signal
import shlex
import shutil
import subprocess
import stat
import sys
import tempfile
import textwrap
import time
import zipfile


@dataclasses.dataclass(frozen=True)
class Stage:
    name: str
    command: tuple[str, ...]
    timeout: int


@dataclasses.dataclass
class StageResult:
    name: str
    status: str
    returncode: int
    elapsed_seconds: float
    fingerprint: str
    output_tail: str


ROOT = Path(__file__).resolve().parents[1]


def _absolute_path_no_symlink_resolution(raw: str) -> Path:
    return Path(os.path.abspath(os.path.expanduser(raw)))


def _terminate_process_tree(process: subprocess.Popen[str], *, grace_seconds: float = 2.0) -> str:
    """Terminate a timed-out stage and all descendants, then return captured output.

    `make`, Go tests and browser smoke stages all create descendants. Killing only
    the immediate parent can leave API servers or test workers alive and poison a
    retry. POSIX stages therefore run in their own session/process group.
    """
    if process.poll() is not None:
        stdout, _ = process.communicate()
        return stdout or ""
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    else:
        # Windows has no POSIX process groups. Terminating only the direct
        # parent leaves Go/Python/browser descendants alive, contaminating a
        # checkpoint retry. taskkill /T is the native bounded tree operation.
        taskkill = shutil.which("taskkill")
        if taskkill:
            subprocess.run(
                [taskkill, "/PID", str(process.pid), "/T", "/F"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, check=False,
            )
        else:
            process.terminate()
    try:
        stdout, _ = process.communicate(timeout=grace_seconds)
        return stdout or ""
    except subprocess.TimeoutExpired:
        if os.name == "posix":
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        else:
            process.kill()
        stdout, _ = process.communicate()
        return stdout or ""


def _run(command: tuple[str, ...] | list[str], *, cwd: Path, timeout: int, env: dict[str, str] | None = None, track_state_root: Path | None = None, active_label: str | None = None) -> subprocess.CompletedProcess[str]:
    merged = os.environ.copy()
    if env:
        merged.update(env)
    command_list = list(command)
    process = subprocess.Popen(
        command_list, cwd=cwd, env=merged, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL, start_new_session=(os.name == "posix"),
    )
    if track_state_root is not None:
        _mark_active_process(track_state_root, process.pid, active_label or command_list[0])
    try:
        try:
            stdout, _ = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            stdout = _terminate_process_tree(process)
            raise subprocess.TimeoutExpired(command_list, timeout, output=stdout)
        return subprocess.CompletedProcess(command_list, process.returncode, stdout, None)
    finally:
        if track_state_root is not None:
            _clear_active_process(track_state_root, process.pid)


def _fingerprint(returncode: int, output: str) -> str:
    tail = "\n".join(output.splitlines()[-120:])
    normalized = "\n".join(line.strip() for line in tail.splitlines() if line.strip())
    return hashlib.sha256(f"{returncode}\n{normalized}".encode()).hexdigest()[:20]


def _tail(output: str, lines: int = 100) -> str:
    return "\n".join(output.splitlines()[-lines:])


def canonical_stages(root: Path) -> list[Stage]:
    version = (root / "VERSION").read_text().strip()
    return [
        Stage("repository-validation", ("python3", "scripts/validate_repository.py", "."), 180),
Stage("go-unit-1", ("python3", "scripts/run_go_package_shard.py", "--shard", "1"), 900),
        Stage("go-unit-2", ("python3", "scripts/run_go_package_shard.py", "--shard", "2"), 900),
        Stage("go-unit-3", ("python3", "scripts/run_go_package_shard.py", "--shard", "3"), 900),
        Stage("go-unit-4", ("python3", "scripts/run_go_package_shard.py", "--shard", "4"), 900),
        Stage("python-tests", ("python3", "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py", "-v"), 300),
        Stage("lab-runner-tests", ("python3", "scripts/test_lab_runner.py"), 300),
        Stage("lab-runner-self-test", ("python3", "scripts/lab_runner.py", "self-test"), 300),
        Stage("derived-agent-knowledge", ("python3", "scripts/generate_agent_knowledge.py", "--check"), 180),
        Stage("browser-triage-profile", ("python3", "scripts/browser_triage_profile.py", "--check"), 60),
        Stage("browser-triage-prerequisites-policy", ("python3", "scripts/browser_triage_bootstrap.py", "--self-test"), 60),
        Stage("upstream-acquisition-self-test", ("python3", "scripts/acquire_upstream_helm.py", "--self-test"), 120),
Stage("go-vet-1", ("python3", "scripts/run_go_package_shard.py", "--vet", "--shard", "1"), 600),
        Stage("go-vet-2", ("python3", "scripts/run_go_package_shard.py", "--vet", "--shard", "2"), 600),
        Stage("go-vet-3", ("python3", "scripts/run_go_package_shard.py", "--vet", "--shard", "3"), 600),
        Stage("go-vet-4", ("python3", "scripts/run_go_package_shard.py", "--vet", "--shard", "4"), 600),
        Stage("go-race-1", ("python3", "scripts/run_go_package_shard.py", "--race", "--shard", "1"), 900),
        Stage("go-race-2", ("python3", "scripts/run_go_package_shard.py", "--race", "--shard", "2"), 900),
        Stage("go-race-3", ("python3", "scripts/run_go_package_shard.py", "--race", "--shard", "3"), 900),
        Stage("go-race-4", ("python3", "scripts/run_go_package_shard.py", "--race", "--shard", "4"), 900),
        Stage("build-for-smoke", ("make", "build"), 900),
        Stage("smoke-1", ("python3", "scripts/run_smoke_shard.py", "--shard", "1"), 900),
        Stage("smoke-2", ("python3", "scripts/run_smoke_shard.py", "--shard", "2"), 900),
        Stage("smoke-3", ("python3", "scripts/run_smoke_shard.py", "--shard", "3"), 900),
        Stage("smoke-4", ("python3", "scripts/run_smoke_shard.py", "--shard", "4"), 900),
        Stage("binary-version", ("python3", "-c", _version_check_program(version)), 120),
        Stage("smoke-ui-rendered", ("python3", "scripts/smoke_ui.py", "."), 900),
        Stage("smoke-ui-quality", ("python3", "scripts/smoke_ui_quality.py"), 900),
        Stage("persian-ui-lint", ("python3", "scripts/persian_ui_lint.py", "--root", "."), 120),
        Stage("smoke-ui-live", ("python3", "scripts/smoke_ui_live.py", "./bin/platform-api", "."), 900),
        Stage("smoke-ui-workflow-e2e", ("python3", "scripts/smoke_ui_workflow_e2e.py", "./bin/platform-api", "./bin/platform-installer"), 900),
        Stage("build-release", ("make", "build-release"), 900),
        Stage("package", ("python3", "scripts/build_release.py", "."), 900),
        Stage("artifact-quick-verify", ("python3", "-c", _artifact_verify_program(version, full=False)), 600),
    ]


def _version_check_program(version: str) -> str:
    bins = ["platform-api", "platformctl", "platform-installer", "platform-agent", "platform-probe"]
    return textwrap.dedent(f"""
        import subprocess
        expected={version!r}
        bins={bins!r}
        for name in bins:
            p=subprocess.run([f'./bin/{{name}}','--version'],text=True,capture_output=True)
            if p.returncode!=0 or expected not in (p.stdout+p.stderr):
                raise SystemExit(f'BINARY_VERSION_MISMATCH {{name}} expected={{expected}} got={{p.stdout}}{{p.stderr}}')
        print('AUTOPILOT_BINARY_VERSION_PASS',expected,len(bins))
    """).strip()


def _exact_artifact_full_stage(release_path: Path) -> Stage:
    return Stage("artifact-full-verify", ("python3", "scripts/verify_release.py", str(_absolute_path_no_symlink_resolution(str(release_path))), "--full"), 7200)


def _artifact_verify_program(version: str, *, full: bool) -> str:
    full_arg = ", '--full'" if full else ""
    return textwrap.dedent(f"""
        from pathlib import Path
        import subprocess
        root=Path('.')
        release_name=(root/'RELEASE-NAME').read_text().strip()
        artifact=root/'release'/f'4so-platform-factory-{version}-{{release_name}}.zip'
        if not artifact.is_file():
            raise SystemExit(f'ARTIFACT_MISSING {{artifact}}')
        command=['python3','scripts/verify_release.py',str(artifact){full_arg}]
        p=subprocess.run(command,text=True,capture_output=True)
        print(p.stdout,end=''); print(p.stderr,end='')
        raise SystemExit(p.returncode)
    """).strip()


def unresolved_components(root: Path) -> list[str]:
    unresolved: list[str] = []
    for path in sorted((root / "catalog" / "components").glob("*.json")):
        doc = json.loads(path.read_text())
        if not bool(doc.get("spec", {}).get("source", {}).get("resolved")):
            unresolved.append(doc.get("metadata", {}).get("name", path.stem))
    return unresolved


def _release_readiness(root: Path) -> tuple[dict | None, str | None]:
    blueprint = root / "blueprints" / "enterprise-private-cloud.json"
    if not blueprint.is_file():
        return None, f"release blueprint missing: {blueprint}"
    binary = root / "bin" / "platformctl"
    if binary.is_file() and os.access(binary, os.X_OK):
        command = [str(binary), "release-readiness", "-f", str(blueprint)]
    else:
        command = ["go", "run", "./cmd/platformctl", "release-readiness", "-f", str(blueprint)]
    try:
        result = _run(command, cwd=root, timeout=300)
    except (subprocess.TimeoutExpired, OSError) as exc:
        return None, f"release readiness execution failed: {exc}"
    if result.returncode != 0:
        return None, f"release readiness command failed rc={result.returncode}: {_tail(result.stdout, 40)}"
    try:
        document = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        return None, f"release readiness returned invalid JSON: {exc}"
    required = {
        "planId", "deploymentExecutable", "productReleaseReady",
        "productReleaseBlockers", "roadmapFeatureBlockers", "deploymentContextBlockers",
        "productBlockerCodes", "roadmapFeatureBlockerCodes", "deploymentContextBlockerCodes",
        "physicalRuntimeStatus", "programRoadmap", "phases",
    }
    if not isinstance(document, dict) or not required.issubset(document):
        return None, "release readiness response is missing canonical authority fields"
    if document.get("physicalRuntimeStatus") != "not-evaluated":
        return None, "release readiness command must not manufacture physical runtime certification"
    return document, None


def _readiness_code_names(document: dict, field: str) -> list[str]:
    value = document.get(field, {})
    if not isinstance(value, dict):
        return []
    return sorted(str(code) for code, count in value.items() if isinstance(count, int) and count > 0)


def _codex_command(*, sandbox: str = "workspace-write") -> list[str] | None:
    override = os.environ.get("PLATFORM_FACTORY_CODEX_COMMAND", "").strip()
    if override:
        # Test/custom wrappers own their sandbox contract. Native Codex is
        # explicitly constrained below.
        return shlex.split(override)
    if shutil.which("codex"):
        # `codex exec` is the documented non-interactive entry point. Triage is
        # always read-only; only the single repair worker gets workspace-write.
        return ["codex", "exec", "--ephemeral", "--skip-git-repo-check", "--sandbox", sandbox]
    return None


def _stage_specialist(stage: Stage) -> str:
    name = stage.name
    if name.startswith("smoke-ui") or name == "persian-ui-lint":
        return "operator-console"
    if name in {"derived-agent-knowledge", "browser-triage-profile", "browser-triage-prerequisites-policy"}:
        return "developer-agent-experience"
    if name == "smoke-4" or "installer" in name:
        return "installer-runtime"
    if name.startswith(("artifact-", "package", "build-release", "upstream-")):
        return "supply-chain-release"
    if name.startswith("lab-"):
        return "lab-certification"
    if name.startswith("smoke-"):
        return "product-runtime"
    return "backend-correctness"


_SECRET_PATTERNS = [
    re.compile(r"(?i)(authorization\s*[:=]\s*bearer\s+)[^\s]+"),
    re.compile(r"(?i)((?:password|passwd|token|secret|api[_-]?key|dsn)\s*[:=]\s*)[^\s,;]+"),
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----", re.S),
]


def _redact_failure_text(text: str) -> str:
    redacted = text
    for pattern in _SECRET_PATTERNS:
        redacted = pattern.sub(lambda match: (match.group(1) if match.lastindex else "") + "[REDACTED]", redacted)
    return redacted


def _triage_prompt(stage: Stage, result: StageResult, iteration: int) -> str:
    return textwrap.dedent(f"""
        You are the read-only 4SO Platform Factory triage agent for specialist
        `{_stage_specialist(stage)}`. Do not edit files and do not run destructive
        commands. Classify this failure as one of CODE_DEFECT, TEST_DEFECT,
        ENVIRONMENT, SUPPLY_CHAIN, or UNKNOWN. Identify the narrowest likely owner
        and the smallest proof command. Never recommend weakening a correct gate.

        Stage: {stage.name}
        Iteration: {iteration}
        Fingerprint: {result.fingerprint}
        Command: {' '.join(stage.command)}
        Redacted output tail:
        {_redact_failure_text(result.output_tail)}
    """).strip()


def _python_module_available(name: str) -> bool:
    try:
        __import__(name)
        return True
    except Exception:
        return False




def _playwright_browser_executable() -> str | None:
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as playwright:
            candidate = Path(playwright.chromium.executable_path)
            if candidate.is_file():
                return str(candidate)
    except Exception:
        return None
    return None


def _browser_executable() -> str | None:
    return (
        shutil.which("chromium")
        or shutil.which("chromium-browser")
        or shutil.which("google-chrome")
        or _playwright_browser_executable()
    )

def environment_preflight(*, require_codex: bool) -> tuple[list[str], dict[str, str]]:
    missing: list[str] = []
    details: dict[str, str] = {}
    for tool in ("go", "make"):
        path = shutil.which(tool)
        if path:
            details[tool] = path
        else:
            missing.append(tool)
    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if compiler:
        details["c-compiler"] = compiler
    else:
        missing.append("c-compiler")
    pg_config = shutil.which("pg_config")
    pkg_config = shutil.which("pkg-config")
    libpq_ok = bool(pg_config)
    if not libpq_ok and pkg_config:
        probe = subprocess.run([pkg_config, "--exists", "libpq"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        libpq_ok = probe.returncode == 0
    if libpq_ok:
        details["libpq"] = pg_config or "pkg-config:libpq"
    else:
        missing.append("libpq-dev")
    browser = _browser_executable()
    if browser:
        details["browser"] = browser
    else:
        missing.append("chromium-or-chrome")
    for optional_tool in ("node", "npx"):
        optional_path = shutil.which(optional_tool)
        details["optional:" + optional_tool] = optional_path or "unavailable"
    for module in ("yaml", "playwright"):
        if _python_module_available(module):
            details["python:" + module] = "available"
        else:
            missing.append("python-module:" + module)
    codex = _codex_command()
    if codex:
        executable = codex[0]
        executable_path = shutil.which(executable)
        if not executable_path and ("/" in executable or "\\" in executable):
            candidate = Path(executable).expanduser()
            executable_path = str(candidate) if candidate.is_file() and os.access(candidate, os.X_OK) else None
        if executable_path:
            details["codex-command"] = shlex.join(codex)
            details["codex-executable"] = executable_path
        elif require_codex:
            missing.append("codex-command-executable")
    elif require_codex:
        missing.append("codex-cli-or-PLATFORM_FACTORY_CODEX_COMMAND")
    return missing, details


def print_environment_preflight(*, require_codex: bool) -> int:
    missing, details = environment_preflight(require_codex=require_codex)
    print("AUTOPILOT_PREFLIGHT_DETAILS=" + json.dumps(details, sort_keys=True), flush=True)
    if missing:
        print("AUTOPILOT_PREFLIGHT=BLOCKED missing=" + ",".join(missing), flush=True)
        return 3
    print("AUTOPILOT_PREFLIGHT=PASS requireCodex=" + str(require_codex).lower(), flush=True)
    return 0


def _repair_prompt(stage: Stage, result: StageResult, iteration: int, triage: str = "") -> str:
    return textwrap.dedent(f"""
        You are the single-writer 4SO Platform Factory correctness repair worker
        for specialist `{_stage_specialist(stage)}`.

        The canonical local validation stage `{stage.name}` failed on iteration {iteration}.
        Fix only a confirmed defect that explains this failure. Do not add product features,
        do not create documentation/handoff/roadmap files, do not create a new validator when
        an existing owner suite is the correct place, and do not weaken a correct test merely
        to make it pass. Prefer the product owner layer for product defects and the test owner
        layer for stale/broken tests.

        After editing, run the smallest owner test that proves the fix. Do not run an endless
        repair loop; return when the defect is fixed or when the failure is environmental.

        Failure fingerprint: {result.fingerprint}
        Command: {' '.join(stage.command)}
        Redacted output tail:
        {_redact_failure_text(result.output_tail)}

        Read-only triage result:
        {_redact_failure_text(triage)}
    """).strip()


def run_stage(root: Path, stage: Stage) -> StageResult:
    started = time.monotonic()
    env = {"CGO_ENABLED": "1"} if stage.name.startswith(("go-unit-", "go-vet-", "go-race-")) else None
    try:
        p = _run(stage.command, cwd=root, timeout=stage.timeout, env=env, track_state_root=root, active_label="stage:" + stage.name)
        elapsed = time.monotonic() - started
        fp = _fingerprint(p.returncode, p.stdout)
        return StageResult(stage.name, "PASS" if p.returncode == 0 else "FAIL", p.returncode, elapsed, fp, _tail(p.stdout))
    except subprocess.TimeoutExpired as exc:
        elapsed = time.monotonic() - started
        raw = (exc.stdout or "") + "\n" + (exc.stderr or "")
        if isinstance(raw, bytes):
            raw = raw.decode(errors="replace")
        fp = _fingerprint(124, str(raw))
        return StageResult(stage.name, "TIMEOUT", 124, elapsed, fp, _tail(str(raw)))


def _ensure_browser_triage_for_stage(root: Path, stage: Stage) -> tuple[bool, str]:
    if _stage_specialist(stage) != "operator-console":
        return True, ""
    script = root / "scripts" / "browser_triage_bootstrap.py"
    try:
        result = _run((sys.executable, str(script), "--ensure", "--json"), cwd=root, timeout=600, track_state_root=root, active_label="browser-triage-prerequisites:" + stage.name)
    except subprocess.TimeoutExpired:
        return False, "BROWSER_TRIAGE_PREREQUISITE_INSTALL_TIMEOUT"
    if result.returncode != 0:
        return False, "BROWSER_TRIAGE_PREREQUISITE_INSTALL_FAILED\n" + _redact_failure_text(_tail(result.stdout, 80))
    return True, _tail(result.stdout, 20)


def invoke_codex(root: Path, stage: Stage, result: StageResult, iteration: int, timeout: int) -> tuple[bool, str]:
    browser_ready, browser_detail = _ensure_browser_triage_for_stage(root, stage)
    if not browser_ready:
        return False, browser_detail
    triage_base = _codex_command(sandbox="read-only")
    repair_base = _codex_command(sandbox="workspace-write")
    if not triage_base or not repair_base:
        return False, "CODEX_CLI_UNAVAILABLE"
    try:
        triage_run = _run(tuple([*triage_base, _triage_prompt(stage, result, iteration)]), cwd=root, timeout=min(timeout, 300), track_state_root=root, active_label="codex-triage:" + stage.name)
    except subprocess.TimeoutExpired:
        return False, "CODEX_TRIAGE_TIMEOUT"
    triage_tail = _tail(triage_run.stdout, 120)
    if triage_run.returncode != 0:
        return False, f"CODEX_TRIAGE_FAILED rc={triage_run.returncode}\n{_redact_failure_text(triage_tail)}"
    prompt = _repair_prompt(stage, result, iteration, triage_tail)
    cmd = [*repair_base, prompt]
    try:
        p = _run(tuple(cmd), cwd=root, timeout=timeout, track_state_root=root, active_label="codex-repair:" + stage.name)
    except subprocess.TimeoutExpired:
        return False, "CODEX_REPAIR_TIMEOUT"
    tail = _tail(p.stdout, 120)
    if p.returncode != 0:
        return False, f"CODEX_REPAIR_FAILED rc={p.returncode}\n{_redact_failure_text(tail)}"
    return True, _redact_failure_text(tail)


_AUTOPILOT_STATE_SCHEMA = 1
_AUTOPILOT_REPORT_SCHEMA = 1
_AUTOPILOT_EVENT_SCHEMA = 1
_AUTOPILOT_STATE_RELATIVE = Path(".state") / "codex-autopilot-run.json"
_AUTOPILOT_REPORT_RELATIVE = Path(".state") / "codex-autopilot-report.json"
_AUTOPILOT_EVENTS_RELATIVE = Path(".state") / "codex-autopilot-events"
_FINGERPRINT_EXCLUDED_DIRS = {".git", ".state", "bin", "release", "__pycache__", ".pytest_cache"}


def _workspace_fingerprint(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        if not path.is_file():
            continue
        rel = path.relative_to(root)
        if any(part in _FINGERPRINT_EXCLUDED_DIRS for part in rel.parts):
            continue
        # Editor/patch backups are not product inputs and must not invalidate an
        # interrupted-run checkpoint.
        if path.name.endswith((".pyc", ".pyo", "~", ".bak")):
            continue
        digest.update(rel.as_posix().encode())
        digest.update(b"\0")
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        digest.update(b"\0")
    return digest.hexdigest()


def _stage_graph_signature(stages: list[Stage], *, repair: bool) -> str:
    payload = {
        "repair": repair,
        "stages": [dataclasses.asdict(stage) for stage in stages],
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _checkpoint_path(root: Path) -> Path:
    return root / _AUTOPILOT_STATE_RELATIVE


def _report_path(root: Path) -> Path:
    return root / _AUTOPILOT_REPORT_RELATIVE


def _event_log_path(root: Path, run_id: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", str(run_id).strip()) or "unknown"
    return root / _AUTOPILOT_EVENTS_RELATIVE / f"{safe}.jsonl"


def _new_run_id() -> str:
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"ap-{stamp}-{os.urandom(4).hex()}"


class _AutopilotEventLog:
    def __init__(self, root: Path, run_id: str) -> None:
        self.root = root
        self.run_id = str(run_id).strip()
        if not self.run_id:
            raise ValueError("autopilot run id is required")
        self.path = _event_log_path(root, self.run_id)

    def append(self, event: str, **fields: object) -> None:
        body: dict[str, object] = {
            "schemaVersion": _AUTOPILOT_EVENT_SCHEMA,
            "authority": "AUTOPILOT_EVENT_LOG_V1",
            "runId": self.run_id,
            "event": str(event),
            "at": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
        }
        for key, value in fields.items():
            if value is None or isinstance(value, (str, int, float, bool)):
                body[str(key)] = value
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(body, sort_keys=True, separators=(",", ":")) + "\n")
            handle.flush()
            os.fsync(handle.fileno())

def _summarize_event_log(root: Path) -> dict:
    directory = root / _AUTOPILOT_EVENTS_RELATIVE
    if not directory.is_dir():
        return {}
    candidates = [p for p in directory.glob("*.jsonl") if p.is_file() and not p.is_symlink()]
    if not candidates:
        return {}
    path = max(candidates, key=lambda p: p.stat().st_mtime_ns)
    events: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            events.append(row)
    if not events:
        return {}
    passed: list[str] = []
    last_failure: dict = {}
    next_index = 0
    status = str(events[-1].get("status") or "RUNNING")
    for row in events:
        if "nextIndex" in row:
            try:
                next_index = int(row["nextIndex"])
            except (TypeError, ValueError):
                pass
        if row.get("event") == "stage-result" and row.get("status") == "PASS":
            stage = str(row.get("stage") or "")
            if stage and stage not in passed:
                passed.append(stage)
        if row.get("status") not in (None, "", "PASS", "RUNNING") and row.get("stage"):
            last_failure = {key: row.get(key) for key in ("stage", "specialist", "status", "fingerprint", "reason") if row.get(key) not in (None, "")}
    return {
        "runId": str(events[-1].get("runId") or ""),
        "eventCount": len(events),
        "status": status,
        "nextIndex": next_index,
        "passedStages": passed,
        "lastFailure": last_failure,
        "path": str(path),
    }


def _report_result(stage: Stage, result: StageResult) -> dict:
    # Deliberately exclude output_tail. Failure packets may contain environment
    # detail even after redaction and are not needed by the Operator Console.
    return {
        "name": result.name,
        "specialist": _stage_specialist(stage),
        "status": result.status,
        "returncode": result.returncode,
        "elapsedSeconds": round(float(result.elapsed_seconds), 3),
        "fingerprint": result.fingerprint,
    }


def _read_report_results(root: Path, graph_signature: str) -> list[dict]:
    path = _report_path(root)
    if not path.is_file() or path.is_symlink():
        return []
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return []
    if data.get("schemaVersion") != _AUTOPILOT_REPORT_SCHEMA or data.get("graphSignature") != graph_signature:
        return []
    rows = data.get("stageResults")
    if not isinstance(rows, list):
        return []
    safe: list[dict] = []
    for row in rows[-100:]:
        if not isinstance(row, dict):
            continue
        safe.append({key: row.get(key) for key in ("name", "specialist", "status", "returncode", "elapsedSeconds", "fingerprint")})
    return safe


def _write_autopilot_report(root: Path, *, stages: list[Stage], graph_signature: str, repair: bool, phase: str, next_index: int, repair_count: int, status: str, current_stage: str | None, stage_results: list[dict], last_failure: dict | None = None) -> None:
    stage = next((item for item in stages if item.name == current_stage), None)
    body = {
        "schemaVersion": _AUTOPILOT_REPORT_SCHEMA,
        "authority": "AUTOPILOT_CAMPAIGN_REPORT_V1",
        "derived": True,
        "notProductAuthority": True,
        "graphSignature": graph_signature,
        "repair": repair,
        "status": status,
        "phase": phase,
        "stageCount": len(stages),
        "nextIndex": next_index,
        "currentStage": current_stage or "",
        "currentSpecialist": _stage_specialist(stage) if stage else "",
        "repairCount": repair_count,
        "resumeEligible": _checkpoint_path(root).is_file(),
        "updatedAt": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
        "stageResults": stage_results[-100:],
    }
    if last_failure:
        body["lastFailure"] = {key: last_failure.get(key) for key in ("stage", "specialist", "status", "fingerprint", "reason") if last_failure.get(key) not in (None, "")}
    _write_state_raw(_report_path(root), body)


def _process_start_ticks(pid: int) -> str | None:
    if os.name == "nt":
        try:
            import ctypes
            from ctypes import wintypes
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            kernel32.OpenProcess.restype = wintypes.HANDLE
            kernel32.GetProcessTimes.argtypes = [
                wintypes.HANDLE,
                ctypes.POINTER(wintypes.FILETIME), ctypes.POINTER(wintypes.FILETIME),
                ctypes.POINTER(wintypes.FILETIME), ctypes.POINTER(wintypes.FILETIME),
            ]
            kernel32.GetProcessTimes.restype = wintypes.BOOL
            kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
            kernel32.CloseHandle.restype = wintypes.BOOL
            handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
            if not handle:
                return None
            try:
                creation = wintypes.FILETIME()
                exit_time = wintypes.FILETIME()
                kernel_time = wintypes.FILETIME()
                user_time = wintypes.FILETIME()
                if not kernel32.GetProcessTimes(handle, ctypes.byref(creation), ctypes.byref(exit_time), ctypes.byref(kernel_time), ctypes.byref(user_time)):
                    return None
                value = (int(creation.dwHighDateTime) << 32) | int(creation.dwLowDateTime)
                return str(value)
            finally:
                kernel32.CloseHandle(handle)
        except (OSError, AttributeError, ValueError):
            return None
    if os.name != "posix":
        return None
    try:
        # /proc/<pid>/stat field 22 is process start time in clock ticks. The
        # command name may contain spaces inside parentheses, so split only the
        # suffix after the final ')'.
        raw = Path(f"/proc/{pid}/stat").read_text()
        suffix = raw[raw.rfind(")") + 2:].split()
        return suffix[19]
    except (OSError, IndexError):
        return None


def _write_state_raw(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(state, sort_keys=True, indent=2) + "\n")
    os.replace(tmp, path)


def _mark_active_process(root: Path, pid: int, label: str) -> None:
    path = _checkpoint_path(root)
    if not path.is_file():
        return
    try:
        state = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return
    state["activeProcess"] = {
        "pid": pid,
        "startTicks": _process_start_ticks(pid),
        "label": label,
    }
    _write_state_raw(path, state)


def _clear_active_process(root: Path, pid: int | None = None) -> None:
    path = _checkpoint_path(root)
    if not path.is_file():
        return
    try:
        state = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return
    active = state.get("activeProcess")
    if not active:
        return
    if pid is not None and active.get("pid") != pid:
        return
    state.pop("activeProcess", None)
    _write_state_raw(path, state)


def _cleanup_checkpoint_process(root: Path, state: dict) -> None:
    active = state.get("activeProcess")
    if not isinstance(active, dict):
        return
    try:
        pid = int(active.get("pid", 0))
    except (TypeError, ValueError):
        pid = 0
    expected_ticks = active.get("startTicks")
    label = str(active.get("label", "unknown"))
    if pid <= 1:
        state.pop("activeProcess", None)
        return
    current_ticks = _process_start_ticks(pid)
    if current_ticks is None or (expected_ticks is not None and current_ticks != expected_ticks):
        print(f"AUTOPILOT_RESUME_PROCESS=STALE pid={pid} label={label}", flush=True)
        state.pop("activeProcess", None)
        return
    print(f"AUTOPILOT_RESUME_PROCESS=TERMINATE pid={pid} label={label}", flush=True)
    if os.name == "posix":
        try:
            os.killpg(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline and _process_start_ticks(pid) == current_ticks:
            time.sleep(0.05)
        if _process_start_ticks(pid) == current_ticks:
            try:
                os.killpg(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    elif os.name == "nt":
        taskkill = shutil.which("taskkill")
        if taskkill:
            subprocess.run(
                [taskkill, "/PID", str(pid), "/T", "/F"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, check=False,
            )
        elif _process_start_ticks(pid) == current_ticks:
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
    state.pop("activeProcess", None)


def _write_checkpoint(root: Path, payload: dict) -> None:
    path = _checkpoint_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    body = dict(payload)
    body["schemaVersion"] = _AUTOPILOT_STATE_SCHEMA
    body["workspaceFingerprint"] = _workspace_fingerprint(root)
    _write_state_raw(path, body)


def _clear_checkpoint(root: Path) -> None:
    path = _checkpoint_path(root)
    path.unlink(missing_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.unlink(missing_ok=True)


def _load_checkpoint(root: Path, *, graph_signature: str, repair: bool) -> dict | None:
    path = _checkpoint_path(root)
    if not path.is_file():
        return None
    try:
        state = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        print("AUTOPILOT_RESUME=RESET reason=STATE_INVALID", flush=True)
        _clear_checkpoint(root)
        return None
    _cleanup_checkpoint_process(root, state)
    _write_state_raw(path, state)
    expected = {
        "schemaVersion": _AUTOPILOT_STATE_SCHEMA,
        "graphSignature": graph_signature,
        "repair": repair,
    }
    for key, value in expected.items():
        if state.get(key) != value:
            print(f"AUTOPILOT_RESUME=RESET reason=STATE_MISMATCH field={key}", flush=True)
            _clear_checkpoint(root)
            return None
    current = _workspace_fingerprint(root)
    if state.get("workspaceFingerprint") != current:
        print("AUTOPILOT_RESUME=RESET reason=WORKSPACE_CHANGED", flush=True)
        _clear_checkpoint(root)
        return None
    return state


def _checkpoint_forward(root: Path, *, graph_signature: str, repair: bool, next_index: int, repair_count: int, seen_failures: dict[tuple[str, str], int], current_stage: str | None = None, run_id: str | None = None) -> None:
    _write_checkpoint(root, {
        "graphSignature": graph_signature,
        "repair": repair,
        "phase": "forward",
        "nextIndex": next_index,
        "currentStage": current_stage,
        "runId": run_id or "",
        "repairCount": repair_count,
        "seenFailures": [{"stage": key[0], "fingerprint": key[1], "count": value} for key, value in sorted(seen_failures.items())],
    })


def _checkpoint_convergence(root: Path, *, graph_signature: str, repair: bool, next_index: int, repair_count: int, seen_failures: dict[tuple[str, str], int], run_id: str | None = None) -> None:
    _write_checkpoint(root, {
        "graphSignature": graph_signature,
        "repair": repair,
        "phase": "convergence",
        "nextIndex": next_index,
        "runId": run_id or "",
        "repairCount": repair_count,
        "seenFailures": [{"stage": key[0], "fingerprint": key[1], "count": value} for key, value in sorted(seen_failures.items())],
    })


def _decode_seen_failures(state: dict) -> dict[tuple[str, str], int]:
    result: dict[tuple[str, str], int] = {}
    for item in state.get("seenFailures", []):
        try:
            result[(str(item["stage"]), str(item["fingerprint"]))] = int(item["count"])
        except (KeyError, TypeError, ValueError):
            continue
    return result


def _execute_stages(root: Path, stages: list[Stage], *, repair: bool, max_repairs: int, codex_timeout: int, enforce_supply_chain: bool = True, emit_ready_result: bool = True) -> int:
    results: list[StageResult] = []
    graph_signature = _stage_graph_signature(stages, repair=repair)
    state = _load_checkpoint(root, graph_signature=graph_signature, repair=repair)
    seen_failures: dict[tuple[str, str], int] = _decode_seen_failures(state or {})
    repair_count = int((state or {}).get("repairCount", 0))
    phase = str((state or {}).get("phase", "forward"))
    next_index = int((state or {}).get("nextIndex", 0))
    if next_index < 0 or next_index > len(stages):
        print("AUTOPILOT_RESUME=RESET reason=INDEX_INVALID", flush=True)
        _clear_checkpoint(root)
        phase = "forward"
        next_index = 0
        repair_count = 0
        seen_failures = {}
        state = None
    if state:
        print(f"AUTOPILOT_RESUME=PASS phase={phase} nextIndex={next_index} repairs={repair_count}", flush=True)

    run_id = str((state or {}).get("runId") or _new_run_id())
    event_log = _AutopilotEventLog(root, run_id)
    event_log.append("run-resume" if state else "run-start", phase=phase, status="RUNNING", nextIndex=next_index, repairCount=repair_count, graphSignature=graph_signature)

    report_rows = _read_report_results(root, graph_signature)
    _write_autopilot_report(root, stages=stages, graph_signature=graph_signature, repair=repair, phase=phase, next_index=next_index, repair_count=repair_count, status="RUNNING", current_stage=(state or {}).get("currentStage"), stage_results=report_rows)

    def terminal(code: int, status: str, *, current_stage: str | None = None, last_failure: dict | None = None) -> int:
        failure = last_failure or {}
        event_log.append("terminal", phase=phase, stage=current_stage or failure.get("stage"), specialist=failure.get("specialist"), status=status, code=code, fingerprint=failure.get("fingerprint"), reason=failure.get("reason"), nextIndex=next_index, repairCount=repair_count)
        if code == 0 and status == "PASS":
            _clear_checkpoint(root)
        _write_autopilot_report(root, stages=stages, graph_signature=graph_signature, repair=repair, phase=phase, next_index=next_index, repair_count=repair_count, status=status, current_stage=current_stage, stage_results=report_rows, last_failure=last_failure)
        return code

    if phase == "forward":
        for index in range(next_index, len(stages)):
            stage = stages[index]
            while True:
                _checkpoint_forward(root, graph_signature=graph_signature, repair=repair, next_index=index, repair_count=repair_count, seen_failures=seen_failures, current_stage=stage.name, run_id=run_id)
                _write_autopilot_report(root, stages=stages, graph_signature=graph_signature, repair=repair, phase="forward", next_index=index, repair_count=repair_count, status="RUNNING", current_stage=stage.name, stage_results=report_rows)
                event_log.append("stage-start", phase="forward", stage=stage.name, specialist=_stage_specialist(stage), status="RUNNING", nextIndex=index, repairCount=repair_count)
                print(f"AUTOPILOT_STAGE_START name={stage.name} timeout={stage.timeout}", flush=True)
                result = run_stage(root, stage)
                results.append(result)
                report_rows.append(_report_result(stage, result))
                event_log.append("stage-result", phase="forward", stage=stage.name, specialist=_stage_specialist(stage), status=result.status, returncode=result.returncode, fingerprint=result.fingerprint, nextIndex=index + (1 if result.status == "PASS" else 0), repairCount=repair_count)
                _write_autopilot_report(root, stages=stages, graph_signature=graph_signature, repair=repair, phase="forward", next_index=index + (1 if result.status == "PASS" else 0), repair_count=repair_count, status="RUNNING" if result.status == "PASS" else result.status, current_stage=stage.name, stage_results=report_rows, last_failure=None if result.status == "PASS" else {"stage": stage.name, "specialist": _stage_specialist(stage), "status": result.status, "fingerprint": result.fingerprint})
                print(json.dumps(dataclasses.asdict(result), sort_keys=True), flush=True)
                if result.status == "PASS":
                    _checkpoint_forward(root, graph_signature=graph_signature, repair=repair, next_index=index + 1, repair_count=repair_count, seen_failures=seen_failures, run_id=run_id)
                    break

                key = (stage.name, result.fingerprint)
                seen_failures[key] = seen_failures.get(key, 0) + 1
                _checkpoint_forward(root, graph_signature=graph_signature, repair=repair, next_index=index, repair_count=repair_count, seen_failures=seen_failures, current_stage=stage.name, run_id=run_id)
                if result.status == "TIMEOUT":
                    print(f"AUTOPILOT_RESULT=ENVIRONMENT_BLOCKED stage={stage.name} reason=TIMEOUT fingerprint={result.fingerprint}", flush=True)
                    return terminal(3, "ENVIRONMENT_BLOCKED", current_stage=stage.name, last_failure={"stage": stage.name, "specialist": _stage_specialist(stage), "status": result.status, "fingerprint": result.fingerprint, "reason": "TIMEOUT"})
                if not repair:
                    print(f"AUTOPILOT_RESULT=CODE_DEFECT stage={stage.name} fingerprint={result.fingerprint}", flush=True)
                    return terminal(2, "CODE_DEFECT", current_stage=stage.name, last_failure={"stage": stage.name, "specialist": _stage_specialist(stage), "status": result.status, "fingerprint": result.fingerprint})
                if seen_failures[key] >= 2:
                    print(f"AUTOPILOT_RESULT=CODE_DEFECT stage={stage.name} reason=NO_PROGRESS fingerprint={result.fingerprint}", flush=True)
                    return terminal(2, "CODE_DEFECT", current_stage=stage.name, last_failure={"stage": stage.name, "specialist": _stage_specialist(stage), "status": result.status, "fingerprint": result.fingerprint, "reason": "NO_PROGRESS"})
                if repair_count >= max_repairs:
                    print(f"AUTOPILOT_RESULT=CODE_DEFECT stage={stage.name} reason=REPAIR_LIMIT fingerprint={result.fingerprint}", flush=True)
                    return terminal(2, "CODE_DEFECT", current_stage=stage.name, last_failure={"stage": stage.name, "specialist": _stage_specialist(stage), "status": result.status, "fingerprint": result.fingerprint, "reason": "REPAIR_LIMIT"})

                repair_count += 1
                event_log.append("repair-start", phase="forward", stage=stage.name, specialist=_stage_specialist(stage), status="REPAIRING", fingerprint=result.fingerprint, nextIndex=index, repairCount=repair_count)
                _write_autopilot_report(root, stages=stages, graph_signature=graph_signature, repair=repair, phase="forward", next_index=index, repair_count=repair_count, status="REPAIRING", current_stage=stage.name, stage_results=report_rows, last_failure={"stage": stage.name, "specialist": _stage_specialist(stage), "status": result.status, "fingerprint": result.fingerprint})
                ok, detail = invoke_codex(root, stage, result, repair_count, codex_timeout)
                print(f"AUTOPILOT_CODEX_REPAIR iteration={repair_count} status={'PASS' if ok else 'BLOCKED'}", flush=True)
                if detail:
                    print(detail, flush=True)
                if not ok:
                    print(f"AUTOPILOT_RESULT=ENVIRONMENT_BLOCKED stage={stage.name} reason=CODEX_UNAVAILABLE_OR_FAILED", flush=True)
                    return terminal(3, "ENVIRONMENT_BLOCKED", current_stage=stage.name, last_failure={"stage": stage.name, "specialist": _stage_specialist(stage), "status": result.status, "fingerprint": result.fingerprint, "reason": "CODEX_UNAVAILABLE_OR_FAILED"})
                # Codex intentionally changed the workspace. Persist the new
                # fingerprint while keeping the same failing-stage boundary so
                # a runner crash immediately after repair resumes by proving the
                # repaired owner stage rather than replaying earlier green work.
                _checkpoint_forward(root, graph_signature=graph_signature, repair=repair, next_index=index, repair_count=repair_count, seen_failures=seen_failures, current_stage=stage.name, run_id=run_id)

        # Repairs are incremental: rerun only the failing owner stage while
        # fixing, then execute one final no-repair convergence pass. Persist the
        # convergence cursor so a runner/process interruption does not replay
        # already-converged expensive stages.
        if repair and repair_count > 0:
            phase = "convergence"
            next_index = 0
            event_log.append("phase-transition", phase="convergence", status="RUNNING", nextIndex=0, repairCount=repair_count)
            _checkpoint_convergence(root, graph_signature=graph_signature, repair=repair, next_index=0, repair_count=repair_count, seen_failures=seen_failures, run_id=run_id)
        else:
            phase = "done"

    if phase == "convergence":
        print(f"AUTOPILOT_CONVERGENCE_START stages={len(stages)} repairs={repair_count}", flush=True)
        _write_autopilot_report(root, stages=stages, graph_signature=graph_signature, repair=repair, phase="convergence", next_index=next_index, repair_count=repair_count, status="RUNNING", current_stage=None, stage_results=report_rows)
        convergence_state = _load_checkpoint(root, graph_signature=graph_signature, repair=repair) or {}
        convergence_index = int(convergence_state.get("nextIndex", next_index))
        for index in range(convergence_index, len(stages)):
            stage = stages[index]
            _checkpoint_convergence(root, graph_signature=graph_signature, repair=repair, next_index=index, repair_count=repair_count, seen_failures=seen_failures, run_id=run_id)
            _write_autopilot_report(root, stages=stages, graph_signature=graph_signature, repair=repair, phase="convergence", next_index=index, repair_count=repair_count, status="RUNNING", current_stage=stage.name, stage_results=report_rows)
            event_log.append("stage-start", phase="convergence", stage=stage.name, specialist=_stage_specialist(stage), status="RUNNING", nextIndex=index, repairCount=repair_count)
            print(f"AUTOPILOT_CONVERGENCE_STAGE_START name={stage.name} timeout={stage.timeout}", flush=True)
            result = run_stage(root, stage)
            results.append(result)
            report_rows.append(_report_result(stage, result))
            event_log.append("stage-result", phase="convergence", stage=stage.name, specialist=_stage_specialist(stage), status=result.status, returncode=result.returncode, fingerprint=result.fingerprint, nextIndex=index + (1 if result.status == "PASS" else 0), repairCount=repair_count)
            _write_autopilot_report(root, stages=stages, graph_signature=graph_signature, repair=repair, phase="convergence", next_index=index + (1 if result.status == "PASS" else 0), repair_count=repair_count, status="RUNNING" if result.status == "PASS" else result.status, current_stage=stage.name, stage_results=report_rows, last_failure=None if result.status == "PASS" else {"stage": stage.name, "specialist": _stage_specialist(stage), "status": result.status, "fingerprint": result.fingerprint})
            print(json.dumps(dataclasses.asdict(result), sort_keys=True), flush=True)
            if result.status == "TIMEOUT":
                print(f"AUTOPILOT_RESULT=ENVIRONMENT_BLOCKED stage={stage.name} reason=CONVERGENCE_TIMEOUT fingerprint={result.fingerprint}", flush=True)
                return terminal(3, "ENVIRONMENT_BLOCKED", current_stage=stage.name, last_failure={"stage": stage.name, "specialist": _stage_specialist(stage), "status": result.status, "fingerprint": result.fingerprint, "reason": "CONVERGENCE_TIMEOUT"})
            if result.status != "PASS":
                print(f"AUTOPILOT_RESULT=CODE_DEFECT stage={stage.name} reason=CONVERGENCE_REGRESSION fingerprint={result.fingerprint}", flush=True)
                return terminal(2, "CODE_DEFECT", current_stage=stage.name, last_failure={"stage": stage.name, "specialist": _stage_specialist(stage), "status": result.status, "fingerprint": result.fingerprint, "reason": "CONVERGENCE_REGRESSION"})
            _checkpoint_convergence(root, graph_signature=graph_signature, repair=repair, next_index=index + 1, repair_count=repair_count, seen_failures=seen_failures, run_id=run_id)
        print(f"AUTOPILOT_CONVERGENCE_PASS stages={len(stages)} repairs={repair_count}", flush=True)

    if enforce_supply_chain:
        unresolved = unresolved_components(root)
        if unresolved:
            print("AUTOPILOT_RESULT=ENVIRONMENT_BLOCKED reason=SUPPLY_CHAIN_UNRESOLVED count=%d components=%s" % (len(unresolved), ",".join(unresolved)), flush=True)
            return terminal(3, "ENVIRONMENT_BLOCKED", last_failure={"stage": "supply-chain", "specialist": "supply-chain-release", "status": "BLOCKED", "reason": "SUPPLY_CHAIN_UNRESOLVED"})

    if emit_ready_result:
        print(f"AUTOPILOT_RESULT=READY_FOR_REAL_TEST stages={len(stages)} repairs={repair_count}", flush=True)
    else:
        print(f"AUTOPILOT_LOCAL_GATES_PASS stages={len(stages)} repairs={repair_count}", flush=True)
    return terminal(0, "PASS")

def _field_campaign_args() -> list[str]:
    args: list[str] = []
    token_file = os.environ.get("PLATFORM_FACTORY_AUTOPILOT_FIELD_TOKEN_FILE", "").strip()
    ca_file = os.environ.get("PLATFORM_FACTORY_AUTOPILOT_FIELD_CA_FILE", "").strip()
    if token_file:
        args += ["--token-file", token_file]
    if ca_file:
        args += ["--ca-file", ca_file]
    return args


def _load_field_campaign(path: Path) -> dict:
    try:
        doc = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"FIELD_CAMPAIGN_STATE_INVALID {path}: {exc}") from exc
    if doc.get("apiVersion") != "platform.4so.io/v1alpha1" or doc.get("kind") != "FieldExecutionCampaign":
        raise RuntimeError("FIELD_CAMPAIGN_CONTRACT_INVALID")
    return doc


def _run_logged(command: list[str], *, root: Path, timeout: int) -> tuple[int, str]:
    try:
        p = _run(command, cwd=root, timeout=timeout)
        return p.returncode, p.stdout
    except subprocess.TimeoutExpired as exc:
        raw = (exc.stdout or "") + "\n" + (exc.stderr or "")
        if isinstance(raw, bytes):
            raw = raw.decode(errors="replace")
        return 124, str(raw)


def _run_field_campaign_real(root: Path, state_path: Path, evidence_dir: Path, timeout: int) -> StageResult:
    started = time.monotonic()
    ctl = root / "bin" / "platformctl"
    if not ctl.is_file():
        detail = f"PLATFORMCTL_MISSING {ctl}"
        return StageResult("field-campaign-real", "FAIL", 1, time.monotonic()-started, _fingerprint(1, detail), detail)
    extra = _field_campaign_args()
    try:
        doc = _load_field_campaign(state_path)
    except RuntimeError as exc:
        detail = str(exc)
        return StageResult("field-campaign-real", "FAIL", 1, time.monotonic()-started, _fingerprint(1, detail), detail)

    release_raw = os.environ.get("PLATFORM_FACTORY_AUTOPILOT_RELEASE_ARTIFACT", "").strip()
    release_path = _absolute_path_no_symlink_resolution(release_raw) if release_raw else None
    try:
        release_digest, installer_digest, release_version = _inspect_exact_release(release_path) if release_path and release_path.is_file() else ("", "", "")
    except (OSError, ValueError, zipfile.BadZipFile, KeyError, json.JSONDecodeError) as exc:
        detail = f"FIELD_CAMPAIGN_EXACT_SHA_BINDING_INVALID {exc}"
        return StageResult("field-campaign-real", "FAIL", 1, time.monotonic()-started, _fingerprint(1, detail), detail)
    expected_version = (root / "VERSION").read_text(encoding="utf-8").strip()
    if release_path is None or not release_path.is_file() or release_version != expected_version or int(doc.get("schemaVersion") or 0) < 3 or doc.get("releaseArtifactDigest") != release_digest or doc.get("installerBinaryDigest") != installer_digest:
        detail = "FIELD_CAMPAIGN_EXACT_SHA_BINDING_INVALID"
        return StageResult("field-campaign-real", "FAIL", 1, time.monotonic()-started, _fingerprint(1, detail), detail)

    output: list[str] = []
    state = str(doc.get("state") or "")
    if state == "PREPARED":
        rc, raw = _run_logged([str(ctl), "field-campaign", "start", "--state", str(state_path), "--confirmation", "INSTALL", *extra], root=root, timeout=120)
        output.append(raw)
        if rc != 0:
            joined = "\n".join(output)
            return StageResult("field-campaign-real", "FAIL", rc, time.monotonic()-started, _fingerprint(rc, joined), _tail(joined))
        doc = _load_field_campaign(state_path)
        state = str(doc.get("state") or "")

    evidence_dir.mkdir(parents=True, exist_ok=True)
    resume_confirmation = os.environ.get("PLATFORM_FACTORY_AUTOPILOT_FIELD_RESUME_CONFIRMATION", "").strip()
    if state == "FAILED":
        diagnostic = evidence_dir / "field-diagnostic.json"
        rc, raw = _run_logged([str(ctl), "field-campaign", "diagnose", "--state", str(state_path), "--out", str(diagnostic), *extra], root=root, timeout=180)
        output.append(raw)
        if rc != 0:
            joined = "\n".join(output + [f"FIELD_DIAGNOSTIC_COLLECTION_FAILED rc={rc}"])
            status = "TIMEOUT" if rc == 124 else "FAIL"
            return StageResult("field-campaign-real", status, rc, time.monotonic()-started, _fingerprint(rc, joined), _tail(joined))
        output.append(f"FIELD_DIAGNOSTIC={diagnostic}")

    if state in {"FAILED", "INTERRUPTED"}:
        if resume_confirmation != "RESUME":
            joined = "\n".join(output + [f"FIELD_CAMPAIGN_RESUME_CONFIRMATION_REQUIRED state={state} required=RESUME"])
            return StageResult("field-campaign-real", "FAIL", 1, time.monotonic()-started, _fingerprint(1, joined), _tail(joined))
        rc, raw = _run_logged([str(ctl), "field-campaign", "resume", "--state", str(state_path), "--confirmation", "RESUME", *extra], root=root, timeout=120)
        output.append(raw)
        if rc != 0:
            joined = "\n".join(output)
            status = "TIMEOUT" if rc == 124 else "FAIL"
            return StageResult("field-campaign-real", status, rc, time.monotonic()-started, _fingerprint(rc, joined), _tail(joined))
        doc = _load_field_campaign(state_path)
        state = str(doc.get("state") or "")

    if state in {"START_REQUESTED", "RUNNING"}:
        watch_timeout = max(60, timeout - int(time.monotonic()-started))
        rc, raw = _run_logged([str(ctl), "field-campaign", "watch", "--state", str(state_path), "--poll-interval", "5s", "--timeout", f"{watch_timeout}s", *extra], root=root, timeout=watch_timeout + 30)
        output.append(raw)
        if rc != 0:
            joined = "\n".join(output)
            status = "TIMEOUT" if rc == 124 else "FAIL"
            return StageResult("field-campaign-real", status, rc, time.monotonic()-started, _fingerprint(rc, joined), _tail(joined))
        doc = _load_field_campaign(state_path)
        state = str(doc.get("state") or "")

    if state != "SUCCEEDED":
        joined = "\n".join(output + [f"FIELD_CAMPAIGN_NON_TERMINAL state={state}"])
        return StageResult("field-campaign-real", "FAIL", 1, time.monotonic()-started, _fingerprint(1, joined), _tail(joined))

    if doc.get("simulation") is not False:
        joined = "\n".join(output + [f"FIELD_CAMPAIGN_NOT_LIVE simulation={doc.get('simulation')!r}"])
        return StageResult("field-campaign-real", "FAIL", 1, time.monotonic()-started, _fingerprint(1, joined), _tail(joined))

    # A Physical PASS must be based on a freshly downloaded report from the live
    # Installer. Never trust evidenceVerified from mutable local campaign state.
    evidence = evidence_dir / "field-evidence.json"
    rc, raw = _run_logged([
        str(ctl), "field-campaign", "collect", "--state", str(state_path), "--out", str(evidence),
        "--release-artifact", str(release_path), *extra,
    ], root=root, timeout=300)
    output.append(raw)
    if rc != 0:
        joined = "\n".join(output)
        return StageResult("field-campaign-real", "FAIL", rc, time.monotonic()-started, _fingerprint(rc, joined), _tail(joined))

    # Re-verify the materialized report independently against the same exact ZIP,
    # including the running installer binary digest recorded by schema v3.
    rc, raw = _run_logged([
        str(ctl), "field-evidence", "verify-report", "-f", str(evidence),
        "--release-artifact", str(release_path),
    ], root=root, timeout=120)
    output.append(raw)
    if rc != 0:
        joined = "\n".join(output)
        return StageResult("field-campaign-real", "FAIL", rc, time.monotonic()-started, _fingerprint(rc, joined), _tail(joined))
    doc = _load_field_campaign(state_path)

    if not bool(doc.get("evidenceVerified")) or str(doc.get("runState") or "") != "SUCCEEDED":
        joined = "\n".join(output + ["FIELD_EVIDENCE_NOT_VERIFIED"])
        return StageResult("field-campaign-real", "FAIL", 1, time.monotonic()-started, _fingerprint(1, joined), _tail(joined))
    if int(doc.get("schemaVersion") or 0) < 3 or doc.get("releaseArtifactDigest") != release_digest or doc.get("installerBinaryDigest") != installer_digest:
        joined = "\n".join(output + ["FIELD_CAMPAIGN_EXACT_SHA_BINDING_INVALID"])
        return StageResult("field-campaign-real", "FAIL", 1, time.monotonic()-started, _fingerprint(1, joined), _tail(joined))
    joined = "\n".join(output + [f"FIELD_CAMPAIGN_REAL_PASS id={doc.get('id')} releaseArtifactDigest={doc.get('releaseArtifactDigest')} installerBinaryDigest={doc.get('installerBinaryDigest')} evidenceDigest={doc.get('evidenceDigest')}"])
    return StageResult("field-campaign-real", "PASS", 0, time.monotonic()-started, _fingerprint(0, joined), _tail(joined))




def _strict_release_json_loads(raw: str | bytes) -> object:
    def no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"release artifact manifest contains duplicate JSON key {key!r}")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=no_duplicates)


def _canonical_release_archive_path(raw: object) -> str:
    if (
        not isinstance(raw, str)
        or not raw
        or raw.strip() != raw
        or "\\" in raw
        or "\x00" in raw
        or raw.startswith("/")
        or raw.endswith("/")
        or posixpath.normpath(raw) != raw
        or any(part in {"", ".", ".."} for part in raw.split("/"))
    ):
        raise ValueError(f"release artifact path is not canonical: {raw!r}")
    return raw


def _release_manifest_rows(manifest: object) -> list[dict[str, object]]:
    keys = {"schemaVersion", "product", "version", "releaseName", "fileCount", "files"}
    file_keys = {"path", "sha256", "size", "mode"}
    if not isinstance(manifest, dict) or set(manifest) != keys:
        raise ValueError("release artifact manifest schema is invalid")
    rows = manifest.get("files")
    if not isinstance(rows, list) or manifest.get("fileCount") != len(rows):
        raise ValueError("release artifact manifest fileCount is invalid")
    seen: set[str] = set()
    validated: list[dict[str, object]] = []
    for row in rows:
        if not isinstance(row, dict) or set(row) != file_keys:
            raise ValueError("release artifact manifest file record is invalid")
        path = _canonical_release_archive_path(row.get("path"))
        sha256 = row.get("sha256")
        size = row.get("size")
        mode = row.get("mode")
        if path == "ARTIFACT-MANIFEST.json" or path in seen:
            raise ValueError("release artifact manifest path is duplicated or invalid")
        if not isinstance(sha256, str) or re.fullmatch(r"[0-9a-f]{64}", sha256) is None:
            raise ValueError("release artifact manifest sha256 is invalid")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise ValueError("release artifact manifest size is invalid")
        if not isinstance(mode, str) or re.fullmatch(r"0o[0-7]{3}", mode) is None:
            raise ValueError("release artifact manifest mode is invalid")
        seen.add(path)
        validated.append(row)
    return validated


def _inspect_exact_release(path: Path) -> tuple[str, str, str]:
    info = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_size <= 0:
        raise ValueError("release artifact must be a non-empty regular non-symlink file")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        if not os.path.samestat(info, opened) or not stat.S_ISREG(opened.st_mode) or opened.st_size <= 0:
            raise ValueError("release artifact changed while opening")
        h = hashlib.sha256()
        with tempfile.TemporaryFile("w+b") as snapshot, os.fdopen(os.dup(fd), "rb", closefd=True) as source:
            written = 0
            while True:
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                snapshot.write(chunk)
                h.update(chunk)
                written += len(chunk)
            if written != opened.st_size:
                raise ValueError("release artifact changed size while snapshotting")
            snapshot.flush()
            snapshot.seek(0)
            with zipfile.ZipFile(snapshot) as archive:
                infos = archive.infolist()
                names: list[str] = []
                for item in infos:
                    if item.is_dir():
                        raise ValueError("release artifact contains non-canonical directory entries")
                    names.append(_canonical_release_archive_path(item.filename))
                if len(names) != len(set(names)):
                    raise ValueError("release artifact contains duplicate archive paths")
                manifest_names = [name for name in names if name.endswith("/ARTIFACT-MANIFEST.json") and name.count("/") == 1]
                if len(manifest_names) != 1:
                    raise ValueError("release artifact manifest is missing or ambiguous")
                root = manifest_names[0].split("/", 1)[0]
                version_name = root + "/VERSION"
                release_name_name = root + "/RELEASE-NAME"
                if version_name not in names or release_name_name not in names:
                    raise ValueError("release artifact VERSION or RELEASE-NAME is missing")
                version_raw = archive.read(version_name)
                release_name_raw = archive.read(release_name_name)
                version = version_raw.decode("utf-8", errors="strict").strip()
                release_name = release_name_raw.decode("utf-8", errors="strict").strip()
                if version_raw != (version + "\n").encode("utf-8") or release_name_raw != (release_name + "\n").encode("utf-8"):
                    raise ValueError("release artifact identity files are not canonical")
                manifest = _strict_release_json_loads(archive.read(manifest_names[0]))
                rows = _release_manifest_rows(manifest)
                if (
                    not version
                    or re.fullmatch(r"\d+\.\d+\.\d+", version) is None
                    or re.fullmatch(r"[a-z0-9][a-z0-9-]*", release_name) is None
                    or manifest.get("version") != version
                    or manifest.get("releaseName") != release_name
                    or manifest.get("schemaVersion") != 2
                    or manifest.get("product") != "4SO Platform Factory"
                    or root != f"4so-platform-factory-{version}-{release_name}"
                ):
                    raise ValueError("release artifact identity contract is invalid")
                if any(not name.startswith(root + "/") for name in names):
                    raise ValueError("release artifact contains entries outside the canonical root")
                row_by_path = {str(item["path"]): item for item in rows}
                actual_relatives = {name[len(root) + 1:] for name in names if name != manifest_names[0]}
                if set(row_by_path) != actual_relatives:
                    raise ValueError("release artifact manifest does not cover archive contents")
                for relative, raw in (("VERSION", version_raw), ("RELEASE-NAME", release_name_raw)):
                    row = row_by_path.get(relative)
                    if row is None or hashlib.sha256(raw).hexdigest() != row.get("sha256") or len(raw) != row.get("size"):
                        raise ValueError(f"release artifact {relative} manifest binding is invalid")
                installer_row = row_by_path.get("bin/linux-amd64/platform-installer")
                if installer_row is None:
                    raise ValueError("release artifact installer binary digest is missing or ambiguous")
                claimed = str(installer_row.get("sha256") or "").strip()
                installer_name = root + "/bin/linux-amd64/platform-installer"
                if installer_name not in names:
                    raise ValueError("release artifact installer binary is missing")
                actual = hashlib.sha256(archive.read(installer_name)).hexdigest()
                if actual != claimed:
                    raise ValueError("release artifact installer manifest digest does not match archive bytes")
        return "sha256:" + h.hexdigest(), "sha256:" + claimed, version
    finally:
        os.close(fd)


def _exact_release_digest(path: Path) -> str:
    return _inspect_exact_release(path)[0]


def _release_installer_binary_digest(path: Path) -> str:
    return _inspect_exact_release(path)[1]


def _real_test_preflight(root: Path) -> tuple[list[str], Path | None]:
    missing: list[str] = []
    if unresolved_components(root):
        missing.append("SUPPLY_CHAIN_UNRESOLVED")
    for key in ("POSTGRES_CERT_DSN", "POSTGRES_CERT_ADMIN_DSN", "POSTGRES_CERT_RESTART_COMMAND"):
        if not os.environ.get(key, "").strip():
            missing.append(key)
    if os.environ.get("ALLOW_DESTRUCTIVE_POSTGRES_CERTIFICATION") != "1":
        missing.append("ALLOW_DESTRUCTIVE_POSTGRES_CERTIFICATION=1")
    state_raw = os.environ.get("PLATFORM_FACTORY_AUTOPILOT_FIELD_CAMPAIGN_STATE", "").strip()
    state_path = Path(state_raw).resolve() if state_raw else None
    if state_path is None or not state_path.is_file():
        missing.append("PLATFORM_FACTORY_AUTOPILOT_FIELD_CAMPAIGN_STATE")
    token_file = os.environ.get("PLATFORM_FACTORY_AUTOPILOT_FIELD_TOKEN_FILE", "").strip()
    if token_file and not Path(token_file).is_file():
        missing.append("PLATFORM_FACTORY_AUTOPILOT_FIELD_TOKEN_FILE")
    if not token_file and not os.environ.get("PLATFORM_INSTALLER_TOKEN", "").strip():
        missing.append("PLATFORM_INSTALLER_TOKEN_OR_TOKEN_FILE")
    ca_file = os.environ.get("PLATFORM_FACTORY_AUTOPILOT_FIELD_CA_FILE", "").strip()
    if ca_file and not Path(ca_file).is_file():
        missing.append("PLATFORM_FACTORY_AUTOPILOT_FIELD_CA_FILE")
    release_raw = os.environ.get("PLATFORM_FACTORY_AUTOPILOT_RELEASE_ARTIFACT", "").strip()
    release_path = _absolute_path_no_symlink_resolution(release_raw) if release_raw else None
    if release_path is None or not release_path.is_file():
        missing.append("PLATFORM_FACTORY_AUTOPILOT_RELEASE_ARTIFACT")
    if state_path is not None and state_path.is_file() and release_path is not None and release_path.is_file():
        try:
            campaign = _load_field_campaign(state_path)
            release_digest, installer_digest, release_version = _inspect_exact_release(release_path)
            expected_version = (root / "VERSION").read_text(encoding="utf-8").strip()
            if release_version != expected_version or int(campaign.get("schemaVersion") or 0) < 3 or campaign.get("releaseArtifactDigest") != release_digest or campaign.get("installerBinaryDigest") != installer_digest:
                missing.append("FIELD_CAMPAIGN_EXACT_SHA_BINDING")
        except (RuntimeError, OSError, ValueError, zipfile.BadZipFile, KeyError, json.JSONDecodeError):
            missing.append("FIELD_CAMPAIGN_EXACT_SHA_BINDING")
    return missing, state_path


def run_real_test(root: Path, *, timeout: int) -> int:
    missing, state_path = _real_test_preflight(root)
    if missing:
        print("AUTOPILOT_RESULT=ENVIRONMENT_BLOCKED reason=REAL_TEST_PREREQUISITES missing=" + ",".join(missing), flush=True)
        return 3
    assert state_path is not None
    evidence_dir = Path(os.environ.get("PLATFORM_FACTORY_AUTOPILOT_EVIDENCE_DIR", str(root / ".state" / "autopilot-evidence"))).resolve()
    evidence_dir.mkdir(parents=True, exist_ok=True)

    postgres = Stage(
        "postgresql-runtime-certification",
        ("python3", "scripts/postgresql_runtime_certify.py", "--evidence", str(evidence_dir / "postgresql-runtime-certification.json")),
        min(timeout, 3600),
    )
    print(f"AUTOPILOT_STAGE_START name={postgres.name} timeout={postgres.timeout}", flush=True)
    pg_result = run_stage(root, postgres)
    print(json.dumps(dataclasses.asdict(pg_result), sort_keys=True), flush=True)
    if pg_result.status != "PASS":
        reason = "TIMEOUT" if pg_result.status == "TIMEOUT" else "POSTGRESQL_RUNTIME_CERTIFICATION_FAILED"
        if pg_result.status == "TIMEOUT":
            print(f"AUTOPILOT_RESULT=ENVIRONMENT_BLOCKED stage={postgres.name} reason={reason} evidence={evidence_dir / 'postgresql-runtime-certification.json'}", flush=True)
            return 3
        # A live certification failure is evidence, not an owner diagnosis. It
        # can belong to product code, the target environment, compatibility,
        # storage/networking, or configuration. Never reopen development until
        # the evidence is diagnosed.
        print(f"AUTOPILOT_RESULT=REAL_TEST_FAILED stage={postgres.name} reason={reason} requiresDiagnosis=true autoRepair=false evidence={evidence_dir / 'postgresql-runtime-certification.json'}", flush=True)
        return 2

    print(f"AUTOPILOT_STAGE_START name=field-campaign-real timeout={timeout}", flush=True)
    field_result = _run_field_campaign_real(root, state_path, evidence_dir, timeout)
    print(json.dumps(dataclasses.asdict(field_result), sort_keys=True), flush=True)
    if field_result.status != "PASS":
        if field_result.status == "TIMEOUT":
            print("AUTOPILOT_RESULT=ENVIRONMENT_BLOCKED stage=field-campaign-real reason=TIMEOUT", flush=True)
            return 3
        # Do not mutate source or resume a live destructive run automatically. A
        # failed live campaign is evidence requiring owner diagnosis; it is not
        # automatically a code defect.
        print("AUTOPILOT_RESULT=REAL_TEST_FAILED stage=field-campaign-real reason=LIVE_FAILURE_REQUIRES_DIAGNOSIS requiresDiagnosis=true autoRepair=false", flush=True)
        return 2

    print(f"AUTOPILOT_RESULT=REAL_TEST_PASS evidenceDir={evidence_dir}", flush=True)
    return 0


def _feature_freeze_closed(readiness: dict) -> bool:
    phases = readiness.get("phases", [])
    if not isinstance(phases, list):
        return False
    for phase in phases:
        if not isinstance(phase, dict):
            continue
        if phase.get("id") == "C9-pre-certification-feature-freeze-exact-bundle":
            return phase.get("status") in {"source-implemented", "certified", "complete"}
    return False


def run_autopilot(root: Path, *, repair: bool, max_repairs: int, codex_timeout: int, start_stage: str | None = None, stop_stage: str | None = None, real_test: bool = False, real_test_timeout: int = 7200, release_ready: bool = False) -> int:
    # A repair run must discover a missing Codex CLI before spending time on
    # expensive repository stages. Read-only validation does not require Codex.
    if print_environment_preflight(require_codex=repair) != 0:
        return 3

    stages = canonical_stages(root)
    names = [s.name for s in stages]
    if start_stage:
        if start_stage not in names:
            raise SystemExit(f"unknown start stage {start_stage}")
        stages = stages[names.index(start_stage):]
    if stop_stage:
        current_names = [s.name for s in stages]
        if stop_stage not in current_names:
            raise SystemExit(f"unknown stop stage {stop_stage}")
        stages = stages[:current_names.index(stop_stage)+1]

    # Local correctness and external supply-chain closure are distinct states.
    # Codex repair owns deterministic repository defects; unresolved third-party
    # acquisition must not turn a clean codebase into a fake CODE_DEFECT result.
    rc = _execute_stages(root, stages, repair=repair, max_repairs=max_repairs, codex_timeout=codex_timeout, enforce_supply_chain=False, emit_ready_result=False)
    if rc != 0:
        return rc

    readiness, readiness_error = _release_readiness(root)
    if readiness_error is not None or readiness is None:
        print("AUTOPILOT_RESULT=CODE_DEFECT reason=RELEASE_READINESS_EVALUATION_FAILED detail=" + json.dumps(readiness_error), flush=True)
        return 2
    product_blocker_count = int(readiness.get("productReleaseBlockers", 0))
    deployment_context_blocker_count = int(readiness.get("deploymentContextBlockers", 0))
    product_codes = _readiness_code_names(readiness, "productBlockerCodes")
    deployment_codes = _readiness_code_names(readiness, "deploymentContextBlockerCodes")
    unresolved = unresolved_components(root)
    if real_test and not _feature_freeze_closed(readiness):
        print("AUTOPILOT_RESULT=ENVIRONMENT_BLOCKED reason=FEATURE_FREEZE_NOT_CLOSED requiredPhase=C9-pre-certification-feature-freeze-exact-bundle", flush=True)
        return 3
    if product_blocker_count:
        print(
            "AUTOPILOT_RELEASE_READINESS=BLOCKED reason=PRODUCT_RELEASE_BLOCKED "
            f"count={product_blocker_count} codes={','.join(product_codes)} "
            f"deploymentContextBlockers={deployment_context_blocker_count} "
            f"deploymentContextCodes={','.join(deployment_codes)} "
            f"sourceUnresolved={len(unresolved)} planId={readiness.get('planId','')}",
            flush=True,
        )
        if release_ready or real_test:
            print("AUTOPILOT_RESULT=ENVIRONMENT_BLOCKED reason=PRODUCT_RELEASE_BLOCKED", flush=True)
            return 3
        print(f"AUTOPILOT_RESULT=LOCAL_CODE_PASS stages={len(stages)} releaseReady=false blockers={product_blocker_count} deploymentContextBlockers={deployment_context_blocker_count}", flush=True)
        return 0

    if deployment_context_blocker_count:
        print(
            "AUTOPILOT_DEPLOYMENT_CONTEXT=BLOCKED "
            f"count={deployment_context_blocker_count} codes={','.join(deployment_codes)} "
            "resolution=publish-and-observe-runtime-git-commit", flush=True,
        )
    if not real_test:
        result = "RELEASE_READY" if release_ready else "LOCAL_CODE_PASS"
        print(f"AUTOPILOT_RESULT={result} stages={len(stages)} releaseReady=true deploymentContextBlockers={deployment_context_blocker_count}", flush=True)
        return 0

    # Layer 1-3 artifact verification and Layer 4 physical execution MUST use
    # the same exact release ZIP. Validate the campaign binding before spending
    # time on the full extracted-artifact graph, then verify the exact path that
    # the physical campaign will consume. Never substitute root/release/*.zip.
    physical_missing, _ = _real_test_preflight(root)
    if physical_missing:
        print("AUTOPILOT_RESULT=ENVIRONMENT_BLOCKED reason=REAL_TEST_PREREQUISITES missing=" + ",".join(physical_missing), flush=True)
        return 3
    release_path = _absolute_path_no_symlink_resolution(os.environ["PLATFORM_FACTORY_AUTOPILOT_RELEASE_ARTIFACT"])
    artifact_full = _exact_artifact_full_stage(release_path)
    rc = _execute_stages(root, [artifact_full], repair=False, max_repairs=0, codex_timeout=codex_timeout, enforce_supply_chain=False, emit_ready_result=False)
    if rc != 0:
        return rc
    return run_real_test(root, timeout=real_test_timeout)

def self_test() -> int:
    old_override = os.environ.get("PLATFORM_FACTORY_CODEX_COMMAND")
    try:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            marker = root / "fixed"
            stage = Stage("fixture", (sys.executable, "-c", "import pathlib,sys;sys.exit(0 if pathlib.Path('fixed').exists() else 7)"), 10)
            first = run_stage(root, stage)
            if first.status != "FAIL" or first.returncode != 7:
                raise AssertionError(first)

            fake = root / "fake_codex.py"
            fake.write_text("from pathlib import Path\nPath('fixed').write_text('ok\\n')\nprint('FAKE_CODEX_FIX_PASS')\n")
            os.environ["PLATFORM_FACTORY_CODEX_COMMAND"] = f"{shlex.quote(sys.executable)} {shlex.quote(str(fake))}"
            rc = _execute_stages(root, [stage], repair=True, max_repairs=2, codex_timeout=10, enforce_supply_chain=False)
            if rc != 0 or not marker.is_file():
                raise AssertionError(f"repair loop failed rc={rc}")

            # A repair to a later stage may regress an earlier stage. The loop
            # must detect that once, at final convergence, instead of re-running
            # the entire suite after every patch.
            early = root / "early-ok"
            early.write_text("ok\n")
            late = root / "late-ok"
            early_stage = Stage("early", (sys.executable, "-c", "import pathlib,sys;sys.exit(0 if pathlib.Path('early-ok').exists() else 9)"), 10)
            late_stage = Stage("late", (sys.executable, "-c", "import pathlib,sys;sys.exit(0 if pathlib.Path('late-ok').exists() else 8)"), 10)
            regression = root / "regression_codex.py"
            regression.write_text("from pathlib import Path\nPath('late-ok').write_text('fixed\\n')\nPath('early-ok').unlink(missing_ok=True)\nprint('FAKE_CODEX_LATE_FIX_WITH_REGRESSION')\n")
            os.environ["PLATFORM_FACTORY_CODEX_COMMAND"] = f"{shlex.quote(sys.executable)} {shlex.quote(str(regression))}"
            rc = _execute_stages(root, [early_stage, late_stage], repair=True, max_repairs=2, codex_timeout=10, enforce_supply_chain=False)
            if rc != 2:
                raise AssertionError(f"final convergence did not detect an earlier-stage regression rc={rc}")
            early.write_text("ok\n")
            late.unlink(missing_ok=True)

            marker.unlink()
            noop = root / "noop_codex.py"
            noop.write_text("print('FAKE_CODEX_NOOP')\n")
            os.environ["PLATFORM_FACTORY_CODEX_COMMAND"] = f"{shlex.quote(sys.executable)} {shlex.quote(str(noop))}"
            rc = _execute_stages(root, [stage], repair=True, max_repairs=3, codex_timeout=10, enforce_supply_chain=False)
            if rc != 2:
                raise AssertionError(f"no-progress loop was not bounded rc={rc}")

            timeout_stage = Stage("timeout", (sys.executable, "-c", "import time;time.sleep(2)"), 1)
            timed = run_stage(root, timeout_stage)
            if timed.status != "TIMEOUT":
                raise AssertionError(timed)

            # A timed-out parent must not leave descendants alive. This mirrors
            # `make smoke`/browser stages, which spawn API servers and workers.
            orphan = root / ".state" / "timeout-orphan"
            orphan.parent.mkdir(exist_ok=True)
            child_program = "import pathlib,time;time.sleep(1.5);pathlib.Path('.state/timeout-orphan').write_text('alive')"
            parent_program = "import subprocess,sys,time;subprocess.Popen([sys.executable,'-c',%r]);time.sleep(10)" % child_program
            tree_stage = Stage("timeout-tree", (sys.executable, "-c", parent_program), 1)
            tree_result = run_stage(root, tree_stage)
            if tree_result.status != "TIMEOUT":
                raise AssertionError(tree_result)
            time.sleep(1.0)
            if orphan.exists():
                raise AssertionError("timed-out stage left a descendant process alive")

            # Interrupted deterministic runs may resume a proven prefix only
            # while both the stage graph and workspace fingerprint are unchanged.
            source_marker = root / "source.txt"
            source_marker.write_text("v1\n")
            count = root / ".state" / "resume-count"
            count_program = "from pathlib import Path;p=Path('.state/resume-count');p.write_text(str(int(p.read_text())+1) if p.exists() else '1')"
            resume_stages = [
                Stage("resume-early", (sys.executable, "-c", count_program), 10),
                Stage("resume-late", (sys.executable, "-c", "pass"), 10),
            ]
            graph = _stage_graph_signature(resume_stages, repair=False)
            first_resume = run_stage(root, resume_stages[0])
            if first_resume.status != "PASS":
                raise AssertionError(first_resume)
            _checkpoint_forward(root, graph_signature=graph, repair=False, next_index=1, repair_count=0, seen_failures={})
            rc = _execute_stages(root, resume_stages, repair=False, max_repairs=0, codex_timeout=10, enforce_supply_chain=False)
            if rc != 0 or count.read_text() != "1":
                raise AssertionError(f"valid checkpoint replayed an already-passed stage rc={rc} count={count.read_text()}")

            # If the runner itself dies mid-stage, the checkpoint retains the
            # active process group. The next invocation must terminate that exact
            # PID/start-time identity before resuming, preventing an orphaned
            # `go test`, API server or browser from contaminating the retry.
            graph = _stage_graph_signature(resume_stages, repair=False)
            _checkpoint_forward(root, graph_signature=graph, repair=False, next_index=1, repair_count=0, seen_failures={})
            stranded = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(30)"], cwd=root, start_new_session=True)
            try:
                _mark_active_process(root, stranded.pid, "self-test-stranded-stage")
                loaded = _load_checkpoint(root, graph_signature=graph, repair=False)
                if loaded is None:
                    raise AssertionError("checkpoint with stranded process did not load")
                try:
                    stranded.wait(timeout=3)
                except subprocess.TimeoutExpired as exc:
                    raise AssertionError("resume did not terminate the stranded stage process group") from exc
            finally:
                if stranded.poll() is None:
                    stranded.kill()
                    stranded.wait()
            _clear_checkpoint(root)

            # The same checkpoint must be discarded after a source mutation.
            first_resume = run_stage(root, resume_stages[0])
            if first_resume.status != "PASS":
                raise AssertionError(first_resume)
            _checkpoint_forward(root, graph_signature=graph, repair=False, next_index=1, repair_count=0, seen_failures={})
            source_marker.write_text("v2\n")
            rc = _execute_stages(root, resume_stages, repair=False, max_repairs=0, codex_timeout=10, enforce_supply_chain=False)
            if rc != 0 or count.read_text() != "3":
                raise AssertionError(f"stale checkpoint was not invalidated rc={rc} count={count.read_text()}")

            fp1 = _fingerprint(1, "stable failure\n")
            fp2 = _fingerprint(1, "stable failure\n")
            if fp1 != fp2:
                raise AssertionError("failure fingerprint is not deterministic")
            redacted = _redact_failure_text("password=hunter2 Authorization: Bearer abc123 token=qwerty")
            if "hunter2" in redacted or "abc123" in redacted or "qwerty" in redacted:
                raise AssertionError(f"failure redaction leaked a secret: {redacted}")
            if _feature_freeze_closed({"phases": [{"id": "C9-pre-certification-feature-freeze-exact-bundle", "status": "blocked"}]}):
                raise AssertionError("blocked C9 must not authorize physical testing")
            if not _feature_freeze_closed({"phases": [{"id": "C9-pre-certification-feature-freeze-exact-bundle", "status": "source-implemented"}]}):
                raise AssertionError("closed C9 must authorize physical testing")

            # Canonical correctness passes must not replay an entire extracted
            # artifact verification or compile twice before smoke. Full artifact
            # execution is reserved for the one-shot Real-Test boundary.
            release_root = root / "release-fixture"
            release_root.mkdir()
            (release_root / "VERSION").write_text("9.9.9\n")
            names = [item.name for item in canonical_stages(release_root)]
            if "build" in names or "artifact-full-verify" in names:
                raise AssertionError(f"duplicate canonical stage regression: {names}")
            if names.index("smoke-1") > names.index("binary-version"):
                raise AssertionError(f"binary version must verify the binaries built by smoke: {names}")

            # Release readiness must be delegated to the canonical CLI phase
            # authority. Autopilot must not maintain a second blocker classifier
            # that can drift from platformctl or manufacture physical PASS.
            release_fixture = root / "release-readiness-authority"
            (release_fixture / "blueprints").mkdir(parents=True)
            (release_fixture / "bin").mkdir()
            (release_fixture / "blueprints" / "enterprise-private-cloud.json").write_text("{}\n")
            readiness_output = (
                '{"planId":"plan-test","deploymentExecutable":false,'
                '"productReleaseReady":false,"productReleaseBlockers":2,"roadmapFeatureBlockers":1,'
                '"deploymentContextBlockers":1,"productBlockerCodes":{"SOURCE_LOCK_MISSING":1,"TARGET_NODE_LIFECYCLE_PENDING":1},'
                '"roadmapFeatureBlockerCodes":{"TARGET_NODE_LIFECYCLE_PENDING":1},'
                '"deploymentContextBlockerCodes":{"GIT_REVISION_NOT_IMMUTABLE":1},'
                '"physicalRuntimeStatus":"not-evaluated","programRoadmap":{"authority":"PROGRAM_PHASE_MODEL_V26","goalReady":false,"phases":[]},"phases":[]}\n'
            )
            if os.name == "nt":
                original_run = globals()["_run"]
                globals()["_run"] = lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, readiness_output, None)
                try:
                    readiness_doc, readiness_error = _release_readiness(release_fixture)
                finally:
                    globals()["_run"] = original_run
            else:
                fake_ctl = release_fixture / "bin" / "platformctl"
                fake_ctl.write_text("#!/bin/sh\nprintf '%s' " + shlex.quote(readiness_output) + "\n")
                fake_ctl.chmod(0o755)
                readiness_doc, readiness_error = _release_readiness(release_fixture)
            if readiness_error is not None or readiness_doc is None or bool(readiness_doc.get("productReleaseReady")):
                raise AssertionError((readiness_doc, readiness_error))
            if _readiness_code_names(readiness_doc, "productBlockerCodes") != ["SOURCE_LOCK_MISSING", "TARGET_NODE_LIFECYCLE_PENDING"]:
                raise AssertionError(readiness_doc)
            if _readiness_code_names(readiness_doc, "roadmapFeatureBlockerCodes") != ["TARGET_NODE_LIFECYCLE_PENDING"]:
                raise AssertionError(readiness_doc)
            if _readiness_code_names(readiness_doc, "deploymentContextBlockerCodes") != ["GIT_REVISION_NOT_IMMUTABLE"]:
                raise AssertionError(readiness_doc)

            # Default Codex repair invocations must be writable without relying
            # on a user's global config. Official non-interactive Codex defaults
            # to read-only unless workspace-write is explicit.
            old_path = os.environ.get("PATH", "")
            old_cmd = os.environ.pop("PLATFORM_FACTORY_CODEX_COMMAND", None)
            fake_bin = root / "fake-bin"
            fake_bin.mkdir(exist_ok=True)
            fake_codex = fake_bin / ("codex.cmd" if os.name == "nt" else "codex")
            fake_codex.write_text("@exit /b 0\n" if os.name == "nt" else "#!/bin/sh\nexit 0\n")
            fake_codex.chmod(0o755)
            os.environ["PATH"] = str(fake_bin) + os.pathsep + old_path
            default_cmd = _codex_command()
            if default_cmd is None or default_cmd[:2] != ["codex", "exec"] or "--sandbox" not in default_cmd or "workspace-write" not in default_cmd:
                raise AssertionError(f"Codex repair sandbox is not explicit workspace-write: {default_cmd}")
            os.environ["PATH"] = old_path
            if old_cmd is not None:
                os.environ["PLATFORM_FACTORY_CODEX_COMMAND"] = old_cmd

            # Real-test preflight must fail closed when destructive/live inputs
            # are absent; local success must never be promoted into a live PASS.
            missing, state = _real_test_preflight(root)
            if not missing or state is not None:
                raise AssertionError((missing, state))
    finally:
        if old_override is None:
            os.environ.pop("PLATFORM_FACTORY_CODEX_COMMAND", None)
        else:
            os.environ["PLATFORM_FACTORY_CODEX_COMMAND"] = old_override
    print("CODEX_AUTOPILOT_SELF_TEST_PASS")
    return 0

def main() -> int:
    ap = argparse.ArgumentParser(description="4SO Platform Factory bounded Codex correctness autopilot")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--preflight", action="store_true", help="check deterministic test/repair host prerequisites without running the suite")
    ap.add_argument("--repair", action="store_true", help="invoke Codex on deterministic failures")
    ap.add_argument("--max-repairs", type=int, default=3)
    ap.add_argument("--codex-timeout", type=int, default=1800)
    ap.add_argument("--start-stage")
    ap.add_argument("--stop-stage")
    ap.add_argument("--release-ready", action="store_true", help="require third-party supply-chain closure after local deterministic gates")
    ap.add_argument("--real-test", action="store_true", help="after deterministic gates and supply-chain closure, run destructive PostgreSQL certification and a prepared live Field Campaign")
    ap.add_argument("--real-test-timeout", type=int, default=7200, help="maximum Field Campaign watch duration in seconds")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    if args.preflight:
        return print_environment_preflight(require_codex=args.repair)
    if args.max_repairs < 0 or args.max_repairs > 10:
        raise SystemExit("--max-repairs must be between 0 and 10")
    if args.real_test_timeout < 300 or args.real_test_timeout > 86400:
        raise SystemExit("--real-test-timeout must be between 300 and 86400 seconds")
    return run_autopilot(ROOT, repair=args.repair, max_repairs=args.max_repairs, codex_timeout=args.codex_timeout, start_stage=args.start_stage, stop_stage=args.stop_stage, real_test=args.real_test, real_test_timeout=args.real_test_timeout, release_ready=args.release_ready)


if __name__ == "__main__":
    raise SystemExit(main())
