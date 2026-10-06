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
_GIT_REPOSITORY_SELECTION_ENV = frozenset({
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_CEILING_DIRECTORIES",
    "GIT_DISCOVERY_ACROSS_FILESYSTEM",
})


def _repository_git_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    merged = os.environ.copy()
    if extra:
        merged.update(extra)
    for key in list(merged):
        if key in _GIT_REPOSITORY_SELECTION_ENV or key.startswith("GIT_CONFIG"):
            merged.pop(key, None)
    return merged


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
    merged = _repository_git_env(env)
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


_FAILURE_SIGNAL = re.compile(r"(?i)(error|fail(?:ed|ure)?|panic|fatal|traceback|exception|expected|actual|mismatch|timeout|blocked|undefined|not found|permission denied)")
_FAILURE_CAPSULE_MAX_LINES = 36
_FAILURE_CAPSULE_MAX_CHARS = 6000


def _failure_capsule(text: str, *, max_lines: int = _FAILURE_CAPSULE_MAX_LINES, max_chars: int = _FAILURE_CAPSULE_MAX_CHARS) -> str:
    redacted = _redact_failure_text(text)
    lines = [line.rstrip() for line in redacted.splitlines() if line.strip()]
    signals: list[str] = []
    seen: set[str] = set()
    for line in lines:
        normalized = line.strip()
        if _FAILURE_SIGNAL.search(normalized) and normalized not in seen:
            seen.add(normalized)
            signals.append(normalized)
    terminal = lines[-12:]
    selected: list[str] = []
    for line in [*signals[-24:], *terminal]:
        if line not in selected:
            selected.append(line)
    selected = selected[-max_lines:]
    capsule = "\n".join(selected)
    if len(capsule) > max_chars:
        capsule = capsule[-max_chars:]
        capsule = "[...failure capsule truncated...]\n" + capsule
    return capsule


def canonical_stages(root: Path) -> list[Stage]:
    version = (root / "VERSION").read_text().strip()
    return [
        Stage("repository-validation", ("python3", "scripts/validate_repository.py", "."), 180),
        Stage("installer-entrypoint-contracts", ("python3", "-m", "unittest", "tests.test_install_entrypoint", "-v"), 120),
        Stage("installer-go-owner-tests", ("go", "test", "./cmd/platformctl", "./cmd/platform-installer", "./internal/bootstrap", "./internal/hostdeployment", "./internal/remotebootstrap", "-count=1"), 600),
        Stage("autopilot-owner-tests", ("python3", "-m", "unittest", "tests.test_codex_autopilot", "-v"), 240),
        Stage("go-unit-1", ("python3", "scripts/run_go_package_shard.py", "--shard", "1", "--exclude-installer-owner"), 900),
        Stage("go-unit-2", ("python3", "scripts/run_go_package_shard.py", "--shard", "2", "--exclude-installer-owner"), 900),
        Stage("go-unit-3", ("python3", "scripts/run_go_package_shard.py", "--shard", "3", "--exclude-installer-owner"), 900),
        Stage("go-unit-4", ("python3", "scripts/run_go_package_shard.py", "--shard", "4", "--exclude-installer-owner"), 900),
        Stage("python-tests", ("python3", "-c", _broad_python_test_program()), 300),
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
        Stage("installer-core-smoke", ("python3", "scripts/smoke_installer.py", "./bin/platform-installer", "./bin/platformctl"), 900),
        Stage("installer-host-smoke", ("python3", "scripts/smoke_installer_host.py", "./bin/platformctl", "./bin/platform-installer"), 900),
        Stage("installer-remote-smoke", ("python3", "scripts/smoke_installer_remote.py", "./bin/platformctl", "./bin/platform-installer"), 900),
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


def _broad_python_test_program() -> str:
    return textwrap.dedent("""
        import unittest
        excluded = (
            "test_install_entrypoint.",
            "tests.test_install_entrypoint.",
            "test_codex_autopilot.",
            "tests.test_codex_autopilot.",
        )
        def flatten(suite):
            for item in suite:
                if isinstance(item, unittest.TestSuite):
                    yield from flatten(item)
                else:
                    yield item
        loader = unittest.TestLoader()
        discovered = loader.discover("tests", pattern="test_*.py")
        selected = unittest.TestSuite(
            test for test in flatten(discovered)
            if not test.id().startswith(excluded)
        )
        print("PYTHON_OWNER_DEDUP authority=AUTOPILOT_OWNER_PYTHON_DEDUP_V1 excluded=test_install_entrypoint,test_codex_autopilot")
        result = unittest.TextTestRunner(verbosity=2).run(selected)
        raise SystemExit(0 if result.wasSuccessful() else 1)
    """).strip()


def _version_check_program(version: str) -> str:
    bins = ["platform-api", "platformctl", "platform-installer", "platform-agent", "platform-probe", "virtual-cluster-renderer", "openchoreo-runtime"]
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
        return shlex.split(override)
    if shutil.which("codex"):
        return ["codex", "exec", "--ephemeral", "--skip-git-repo-check", "--sandbox", sandbox]
    return None


def _stage_specialist(stage: Stage) -> str:
    name = stage.name
    if name == "smoke-ui-workflow-e2e":
        return "operator-installer-e2e"
    if name.startswith("smoke-ui") or name == "persian-ui-lint":
        return "operator-console"
    if name in {"autopilot-owner-tests", "derived-agent-knowledge", "browser-triage-profile", "browser-triage-prerequisites-policy"}:
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


def _select_convergence_stages(stages: list[Stage], repaired_stage_names: set[str]) -> list[Stage]:
    if not repaired_stage_names:
        return list(stages)
    by_name = {stage.name: stage for stage in stages}
    if any(name not in by_name for name in repaired_stage_names):
        return list(stages)
    specialists = {_stage_specialist(by_name[name]) for name in repaired_stage_names}
    wanted: set[str] = {"repository-validation", *repaired_stage_names}
    for specialist in specialists:
        if specialist == "operator-console":
            wanted.update({"build-for-smoke", "smoke-ui-rendered", "smoke-ui-quality", "persian-ui-lint", "smoke-ui-live", "smoke-ui-workflow-e2e", "build-release", "package", "artifact-quick-verify"})
        elif specialist == "operator-installer-e2e":
            wanted.update({"installer-entrypoint-contracts", "installer-go-owner-tests", "build-for-smoke", "installer-core-smoke", "installer-host-smoke", "installer-remote-smoke", "smoke-ui-rendered", "smoke-ui-quality", "persian-ui-lint", "smoke-ui-live", "smoke-ui-workflow-e2e", "build-release", "package", "artifact-quick-verify"})
        elif specialist == "installer-runtime":
            wanted.update({"installer-entrypoint-contracts", "installer-go-owner-tests", "build-for-smoke", "installer-core-smoke", "installer-host-smoke", "installer-remote-smoke", "smoke-ui-workflow-e2e", "build-release", "package", "artifact-quick-verify"})
        elif specialist == "developer-agent-experience":
            wanted.update({"autopilot-owner-tests", "derived-agent-knowledge", "browser-triage-profile", "browser-triage-prerequisites-policy"})
        elif specialist == "lab-certification":
            wanted.update({"python-tests", "lab-runner-tests", "lab-runner-self-test"})
        elif specialist == "supply-chain-release":
            wanted.update({"upstream-acquisition-self-test", "build-release", "package", "artifact-quick-verify"})
        elif specialist == "product-runtime":
            wanted.update({"build-for-smoke", "smoke-1", "smoke-2", "smoke-3", "installer-core-smoke", "installer-host-smoke", "installer-remote-smoke", "binary-version", "smoke-ui-live", "smoke-ui-workflow-e2e", "build-release", "package", "artifact-quick-verify"})
        elif specialist == "backend-correctness":
            wanted.update({stage.name for stage in stages if stage.name.startswith(("go-unit-", "go-vet-", "go-race-"))})
            wanted.update({"python-tests", "build-for-smoke", "smoke-1", "smoke-2", "smoke-3", "installer-core-smoke", "installer-host-smoke", "installer-remote-smoke", "binary-version", "build-release", "package", "artifact-quick-verify"})
        else:
            return list(stages)
    selected = [stage for stage in stages if stage.name in wanted]
    return selected or list(stages)


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


def _triage_prompt(stage: Stage, result: StageResult, iteration: int, root: Path | None = None) -> str:
    failure_hints = _failure_path_hints(root, stage, result.output_tail) if root is not None else []
    return textwrap.dedent(f"""
        You are the read-only 4SO Platform Factory triage agent for specialist
        `{_stage_specialist(stage)}`. Do not edit files and do not run destructive
        commands. Classify this failure as one of CODE_DEFECT, TEST_DEFECT,
        ENVIRONMENT, SUPPLY_CHAIN, or UNKNOWN. Your first non-empty output line
        MUST be exactly `CLASSIFICATION=<VALUE>`. Then identify the narrowest
        likely owner and the smallest proof command. Never recommend weakening a
        correct gate and never request source mutation for ENVIRONMENT or SUPPLY_CHAIN.

        Stage: {stage.name}
        Iteration: {iteration}
        Fingerprint: {result.fingerprint}
        Command: {' '.join(stage.command)}
        Start with these owner paths before broad repository search:
        {', '.join(_owner_context_paths(stage)) or '(owner mapping unavailable; stay on the failing command and its direct imports)'}
        Exact failure path hints, when present:
        {', '.join(failure_hints) or '(none extracted; do not broaden search unless the owner proof requires it)'}

        Compact redacted failure capsule:
        {_failure_capsule(result.output_tail, max_chars=TRIAGE_FAILURE_CAPSULE_MAX_CHARS)}
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

FAILURE_CAPSULE_AUTHORITY = "AUTOPILOT_FAILURE_CAPSULE_V1"
SELECTIVE_CONVERGENCE_AUTHORITY = "AUTOPILOT_OWNER_SCOPED_CONVERGENCE_V1"
REPAIR_SCOPE_FENCE_AUTHORITY = "AUTOPILOT_REPAIR_SCOPE_FENCE_V1"
STRUCTURED_TRIAGE_AUTHORITY = "AUTOPILOT_STRUCTURED_TRIAGE_V1"
REPAIR_GIT_BOUNDARY_AUTHORITY = "AUTOPILOT_REPAIR_GIT_BOUNDARY_V1"
DIRTY_DELTA_AUTHORITY = "AUTOPILOT_DIRTY_DELTA_V1"
WORKSPACE_FINGERPRINT_AUTHORITY = "AUTOPILOT_GIT_WORKSPACE_FINGERPRINT_V1"
AGENT_CONTEXT_AUTHORITY = "AUTOPILOT_AGENT_CONTEXT_V1"
AGENT_CONTEXT_COMPACT_AUTHORITY = "AUTOPILOT_AGENT_CONTEXT_COMPACT_V1"
AGENT_CONTEXT_BUDGET_FALLBACK_AUTHORITY = "AUTOPILOT_CONTEXT_BUDGET_FALLBACK_V1"
AGENT_CONTEXT_COMMAND_DEDUP_AUTHORITY = "AUTOPILOT_COMPACT_COMMAND_DEDUP_V1"
LOW_TOKEN_CONTEXT_AUTHORITY = "AUTOPILOT_LOW_TOKEN_CONTEXT_V2"
DETERMINISTIC_ENV_TRIAGE_AUTHORITY = "AUTOPILOT_DETERMINISTIC_ENV_TRIAGE_V1"
REPAIR_PROOF_DEDUP_AUTHORITY = "AUTOPILOT_REPAIR_PROOF_DEDUP_V1"
AGENT_CONTEXT_COMPACT_MAX_CHARS = 4800
AGENT_CONTEXT_COMPACT_FAILURE_MAX_CHARS = 1000
AGENT_CONTEXT_COMPACT_OWNER_PATH_LIMIT = 4
AGENT_FAILURE_CAPSULE_AUTHORITY = "AUTOPILOT_AGENT_FAILURE_CAPSULE_V2"
INSTALLER_OWNER_STAGE_AUTHORITY = "AUTOPILOT_INSTALLER_OWNER_STAGE_V1"
INSTALLER_OWNER_CONTRACT_STAGE_AUTHORITY = "AUTOPILOT_INSTALLER_OWNER_CONTRACT_STAGE_V1"
AGENT_OWNER_PROOF_AUTHORITY = "AUTOPILOT_AGENT_OWNER_PROOF_V1"
ENVIRONMENT_PREFLIGHT_HANDOFF_AUTHORITY = "AUTOPILOT_ENVIRONMENT_PREFLIGHT_HANDOFF_V1"
ENVIRONMENT_REMEDIATION_HINTS_AUTHORITY = "AUTOPILOT_ENVIRONMENT_REMEDIATION_HINTS_V1"
OWNER_CONTEXT_AUTHORITY = "AUTOPILOT_OWNER_CONTEXT_PATHS_V1"
PROMPT_BUDGET_AUTHORITY = "AUTOPILOT_PROMPT_BUDGET_V1"
AGENT_REPAIR_BUDGET_AUTHORITY = "AUTOPILOT_AGENT_REPAIR_BUDGET_V1"
FAILURE_PATH_HINTS_AUTHORITY = "AUTOPILOT_FAILURE_PATH_HINTS_V1"
EXTERNAL_OWNER_FIX_ADOPTION_AUTHORITY = "AUTOPILOT_EXTERNAL_OWNER_FIX_ADOPTION_V1"
DURABLE_TRIAGE_CLASSIFICATION_AUTHORITY = "AUTOPILOT_DURABLE_TRIAGE_CLASSIFICATION_V1"
TRIAGE_CACHE_AUTHORITY = "AUTOPILOT_TRIAGE_CACHE_V1"
AGENT_NEXT_ACTION_AUTHORITY = "AUTOPILOT_AGENT_NEXT_ACTION_V1"
OWNER_FIRST_STAGE_ORDER_AUTHORITY = "AUTOPILOT_OWNER_FIRST_STAGE_ORDER_V1"
OWNER_UNIT_DEDUP_AUTHORITY = "AUTOPILOT_OWNER_UNIT_DEDUP_V1"
OWNER_PYTHON_DEDUP_AUTHORITY = "AUTOPILOT_OWNER_PYTHON_DEDUP_V1"
LIVE_RUN_REJOIN_FENCE_AUTHORITY = "AUTOPILOT_LIVE_RUN_REJOIN_FENCE_V1"
CROSS_SURFACE_OWNER_CONTEXT_AUTHORITY = "AUTOPILOT_CROSS_SURFACE_OWNER_CONTEXT_V1"
AUTOPILOT_OWNER_TEST_STAGE_AUTHORITY = "AUTOPILOT_OWNER_TEST_STAGE_V1"
CONVERGENCE_REPAIR_AUTHORITY = "AUTOPILOT_CONVERGENCE_REPAIR_V1"
OUTER_RUNTIME_CONTEXT_AUTHORITY = "AUTOPILOT_OUTER_RUNTIME_CONTEXT_V1"
RESUME_PREFLIGHT_CURSOR_AUTHORITY = "AUTOPILOT_RESUME_PREFLIGHT_CURSOR_V1"
LAZY_REPAIR_CAPABILITY_AUTHORITY = "AUTOPILOT_LAZY_REPAIR_CAPABILITY_V1"
REPAIR_BUDGET_ACTUAL_WRITER_AUTHORITY = "AUTOPILOT_REPAIR_BUDGET_ACTUAL_WRITER_V1"
PROGRESSIVE_STAGE_PREFLIGHT_AUTHORITY = "AUTOPILOT_PROGRESSIVE_STAGE_PREFLIGHT_V1"
OUTER_RUNTIME_ENVIRONMENT_HANDOFF_AUTHORITY = "AUTOPILOT_OUTER_RUNTIME_ENVIRONMENT_HANDOFF_V1"
DEFAULT_REPAIR_BUDGET = 3
DEFAULT_AGENT_REPAIR_BUDGET = 8
TRIAGE_FAILURE_CAPSULE_MAX_CHARS = 1800
TRIAGE_RESULT_MAX_CHARS = 1200
REPAIR_FAILURE_CAPSULE_MAX_CHARS = 1800
REPAIR_TRIAGE_MAX_CHARS = 1200
AGENT_FAILURE_CAPSULE_MAX_CHARS = 1800

_OWNER_CONTEXT_PATHS: dict[str, tuple[str, ...]] = {
    "operator-console": ("webconsole/", "scripts/smoke_ui", "scripts/persian_", "tests/test_smoke_ui"),
    "operator-installer-e2e": ("webconsole/", "cmd/platform-installer/", "cmd/platformctl/installer_", "install.sh", "scripts/smoke_ui", "scripts/smoke_installer", "tests/test_smoke_ui", "tests/test_install", "tests/test_installer"),
    "installer-runtime": ("install.sh", "cmd/platform-installer/", "cmd/platformctl/installer_", "internal/bootstrap/", "internal/hostdeployment/", "internal/remotebootstrap/", "scripts/smoke_installer", "tests/test_install", "tests/test_installer"),
    "developer-agent-experience": ("AGENTS.md", "DERIVED-AGENT-KNOWLEDGE.json", "scripts/codex_autopilot.py", "tests/test_codex_autopilot.py", "scripts/generate_agent_knowledge.py", "scripts/browser_triage_", "tests/test_browser_"),
    "lab-certification": ("lab/", "scripts/lab_runner.py", "scripts/test_lab_runner.py", "scripts/postgresql_runtime_certify.py", "internal/fieldcampaign/"),
    "supply-chain-release": ("catalog/", "scripts/build_release.py", "scripts/verify_release", "scripts/acquire_upstream_", "internal/bundlebuilder/", "internal/releaseartifact/", "ARTIFACT-MANIFEST.json", "SBOM.spdx.json"),
    "product-runtime": ("internal/api/", "internal/domain/", "internal/persistence/", "cmd/platform-api/", "cmd/platform-agent/", "scripts/smoke_"),
    "backend-correctness": ("internal/", "cmd/", "sdk/", "tests/", "scripts/run_go_", "scripts/run_smoke_shard.py"),
}

def _owner_context_paths(stage: Stage) -> tuple[str, ...]:
    return _OWNER_CONTEXT_PATHS.get(_stage_specialist(stage), ())

_FULL_ENVIRONMENT_REQUIREMENTS = frozenset({"go", "make", "bash", "c-compiler", "libpq", "browser", "yaml", "playwright"})

def _environment_requirements(stages: list[Stage] | None) -> set[str]:
    if stages is None:
        return set(_FULL_ENVIRONMENT_REQUIREMENTS)
    required: set[str] = set()
    for stage in stages:
        name = stage.name
        if name.startswith(("go-unit-", "go-vet-")) or name == "installer-go-owner-tests":
            required.update({"go", "c-compiler", "libpq"})
        if name == "installer-entrypoint-contracts":
            required.add("bash")
        if name.startswith("go-race-"):
            required.update({"go", "c-compiler", "libpq"})
        if name in {"build-for-smoke", "build-release"}:
            required.update({"go", "make", "c-compiler", "libpq"})
        if name == "upstream-acquisition-self-test":
            required.add("yaml")
        if name.startswith("smoke-ui-"):
            required.update({"browser", "playwright"})
    return required

def environment_preflight(*, require_codex: bool, stages: list[Stage] | None = None) -> tuple[list[str], dict[str, str]]:
    requirements = _environment_requirements(stages)
    missing: list[str] = []
    details: dict[str, str] = {}
    for tool in ("go", "make", "bash"):
        if tool not in requirements:
            continue
        path = shutil.which(tool)
        if path:
            details[tool] = path
        else:
            missing.append(tool)
    if "c-compiler" in requirements:
        compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
        if compiler:
            details["c-compiler"] = compiler
        else:
            missing.append("c-compiler")
    if "libpq" in requirements:
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
    if "browser" in requirements:
        browser = _browser_executable()
        if browser:
            details["browser"] = browser
        else:
            missing.append("chromium-or-chrome")
    for optional_tool in ("node", "npx"):
        optional_path = shutil.which(optional_tool)
        details["optional:" + optional_tool] = optional_path or "unavailable"
    for module in ("yaml", "playwright"):
        if module not in requirements:
            continue
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
            details["codex-command-source"] = "override" if os.environ.get("PLATFORM_FACTORY_CODEX_COMMAND") else "default"
            details["codex-command-argv-count"] = str(len(codex))
            details["codex-executable"] = executable_path
        elif require_codex:
            missing.append("codex-command-executable")
    elif require_codex:
        missing.append("codex-cli-or-PLATFORM_FACTORY_CODEX_COMMAND")
    return missing, details

_ENVIRONMENT_REMEDIATION_HINTS = {
    "bash": "install or expose a Bash executable, then rerun the same Autopilot invocation",
    "go": "install or expose the repository-supported Go toolchain and confirm go version before rerunning",
    "make": "install or expose GNU Make before rerunning",
    "c-compiler": "install or expose a C compiler toolchain required by CGO/race stages",
    "libpq-dev": "install PostgreSQL/libpq development headers so pg_config or pkg-config libpq succeeds",
    "chromium-or-chrome": "install Chromium/Chrome or provision the Playwright Chromium browser used by UI stages",
    "python-module:yaml": "install the repository test requirements so the yaml module is importable",
    "python-module:playwright": "install the repository test requirements and provision Playwright Chromium",
    "codex-cli-or-PLATFORM_FACTORY_CODEX_COMMAND": "install/connect Codex CLI or set PLATFORM_FACTORY_CODEX_COMMAND to an executable wrapper",
    "codex-command-executable": "fix the executable referenced by PLATFORM_FACTORY_CODEX_COMMAND or restore the default Codex CLI",
}

def _environment_preflight_handoff(missing: list[str], stages: list[Stage] | None) -> dict:
    requirements = sorted(_environment_requirements(stages))
    normalized_missing = sorted({str(item) for item in missing if str(item).strip()})
    remediation = {item: _ENVIRONMENT_REMEDIATION_HINTS.get(item, "provide this prerequisite, then rerun the same Autopilot invocation") for item in normalized_missing}
    payload = {"missing": normalized_missing, "requirements": requirements, "remediationHints": remediation}
    fingerprint = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {**payload, "remediationAuthority": ENVIRONMENT_REMEDIATION_HINTS_AUTHORITY, "fingerprint": fingerprint}


def print_environment_preflight(*, require_codex: bool, stages: list[Stage] | None = None) -> int:
    missing, details = environment_preflight(require_codex=require_codex, stages=stages)
    print("AUTOPILOT_PREFLIGHT_DETAILS=" + json.dumps(details, sort_keys=True), flush=True)
    if missing:
        print("AUTOPILOT_PREFLIGHT=BLOCKED missing=" + ",".join(missing), flush=True)
        return 3
    print("AUTOPILOT_PREFLIGHT=PASS requireCodex=" + str(require_codex).lower(), flush=True)
    return 0


def _repair_prompt(stage: Stage, result: StageResult, iteration: int, triage: str = "", root: Path | None = None) -> str:
    failure_hints = _failure_path_hints(root, stage, result.output_tail) if root is not None else []
    return textwrap.dedent(f"""
        You are the single-writer 4SO Platform Factory correctness repair worker
        for specialist `{_stage_specialist(stage)}`.

        The canonical local validation stage `{stage.name}` failed on iteration {iteration}.
        Fix only a confirmed defect that explains this failure. Do not add product features,
        do not create documentation/handoff/roadmap files, do not create a new validator when
        an existing owner suite is the correct place, and do not weaken a correct test merely
        to make it pass. Prefer the product owner layer for product defects and the test owner
        layer for stale/broken tests. Do not commit, amend, reset, checkout, switch, stash,
        rebase, merge, clean, or otherwise mutate Git refs/index/history; edit only the working
        tree files needed for this defect.

        Do not rerun the failing stage, broad test suite, build, or release verifier yourself.
        The Autopilot controller owns the exact post-repair owner proof and final convergence
        under AUTOPILOT_REPAIR_PROOF_DEDUP_V1. You may use only a tiny local syntax/format/read
        check when needed to avoid returning malformed source. Return immediately after the
        narrow edit, or without editing when the failure is environmental.

        Failure fingerprint: {result.fingerprint}
        Command: {' '.join(stage.command)}
        Start with these owner paths before broad repository search:
        {', '.join(_owner_context_paths(stage)) or '(owner mapping unavailable; stay on the failing command and its direct imports)'}
        Exact failure path hints, when present:
        {', '.join(failure_hints) or '(none extracted; do not broaden search unless the owner proof requires it)'}

        Compact redacted failure capsule:
        {_failure_capsule(result.output_tail, max_chars=REPAIR_FAILURE_CAPSULE_MAX_CHARS)}

        Read-only triage result:
        {_failure_capsule(triage, max_lines=20, max_chars=REPAIR_TRIAGE_MAX_CHARS)}
    """).strip()


def run_stage(root: Path, stage: Stage) -> StageResult:
    started = time.monotonic()
    env = {"CGO_ENABLED": "1"} if stage.name.startswith(("go-unit-", "go-vet-", "go-race-")) or stage.name == "installer-go-owner-tests" else None
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
    if _stage_specialist(stage) not in {"operator-console", "operator-installer-e2e"}:
        return True, ""
    script = root / "scripts" / "browser_triage_bootstrap.py"
    try:
        result = _run((sys.executable, str(script), "--ensure", "--json"), cwd=root, timeout=600, track_state_root=root, active_label="browser-triage-prerequisites:" + stage.name)
    except subprocess.TimeoutExpired:
        return False, "BROWSER_TRIAGE_PREREQUISITE_INSTALL_TIMEOUT"
    if result.returncode != 0:
        return False, "BROWSER_TRIAGE_PREREQUISITE_INSTALL_FAILED\n" + _redact_failure_text(_tail(result.stdout, 80))
    return True, _tail(result.stdout, 20)


_TRIAGE_CLASSIFICATIONS = frozenset({"CODE_DEFECT", "TEST_DEFECT", "ENVIRONMENT", "SUPPLY_CHAIN", "UNKNOWN"})


def _deterministic_failure_classification(stage: Stage, result: StageResult) -> tuple[str, str] | None:
    text = _redact_failure_text(result.output_tail or "")
    lowered = text.lower()
    if result.returncode in {126, 127} and (
        "command not found" in lowered
        or "not found" in lowered
        or "permission denied" in lowered
        or "cannot execute" in lowered
    ):
        detail = _failure_capsule(text, max_lines=8, max_chars=900)
        return "ENVIRONMENT", f"{DETERMINISTIC_ENV_TRIAGE_AUTHORITY}\n{detail}"
    required = _environment_requirements([stage])
    missing_module = re.search(r"ModuleNotFoundError:\s+No module named ['\"]([^'\"]+)['\"]", text)
    if missing_module:
        module = missing_module.group(1).split(".", 1)[0]
        requirement = {"yaml": "yaml", "playwright": "playwright"}.get(module)
        if requirement and requirement in required:
            detail = _failure_capsule(text, max_lines=8, max_chars=900)
            return "ENVIRONMENT", f"{DETERMINISTIC_ENV_TRIAGE_AUTHORITY}\n{detail}"
    return None


def _parse_triage_classification(text: str) -> str:
    matches = re.findall(
        r"(?m)^\s*CLASSIFICATION=(CODE_DEFECT|TEST_DEFECT|ENVIRONMENT|SUPPLY_CHAIN|UNKNOWN)\s*$",
        text,
    )
    unique = set(matches)
    if len(unique) != 1:
        return "UNKNOWN"
    return next(iter(unique))


def _record_triage_classification(root: Path, stage: Stage, result: StageResult, classification: str, triage_capsule: str = "") -> None:
    if classification not in _TRIAGE_CLASSIFICATIONS:
        classification = "UNKNOWN"
    checkpoint = _checkpoint_path(root)
    if not checkpoint.is_file() or checkpoint.is_symlink():
        return
    try:
        state = json.loads(checkpoint.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    if str(state.get("currentStage") or "") != stage.name:
        return
    state["lastFailureClassification"] = classification
    state["lastFailureStage"] = stage.name
    state["lastFailureFingerprint"] = result.fingerprint
    state["lastTriageCapsule"] = _failure_capsule(triage_capsule, max_lines=20, max_chars=TRIAGE_RESULT_MAX_CHARS)
    state["lastTriageAuthority"] = TRIAGE_CACHE_AUTHORITY
    state["updatedAt"] = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    _write_state_raw(checkpoint, state)


def _cached_triage(root: Path, stage: Stage, result: StageResult) -> tuple[str, str] | None:
    checkpoint = _checkpoint_path(root)
    if not checkpoint.is_file() or checkpoint.is_symlink():
        return None
    try:
        state = json.loads(checkpoint.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    classification = str(state.get("lastFailureClassification") or "")
    if (
        state.get("lastTriageAuthority") != TRIAGE_CACHE_AUTHORITY
        or str(state.get("lastFailureStage") or "") != stage.name
        or str(state.get("lastFailureFingerprint") or "") != result.fingerprint
        or classification not in _TRIAGE_CLASSIFICATIONS
    ):
        return None
    capsule = str(state.get("lastTriageCapsule") or "")[:TRIAGE_RESULT_MAX_CHARS]
    return classification, capsule


def invoke_codex_triage(root: Path, stage: Stage, result: StageResult, iteration: int, timeout: int) -> tuple[bool, str, str]:
    deterministic = _deterministic_failure_classification(stage, result)
    if deterministic is not None:
        classification, detail = deterministic
        _record_triage_classification(root, stage, result, classification, detail)
        print(
            f"AUTOPILOT_TRIAGE=DETERMINISTIC authority={DETERMINISTIC_ENV_TRIAGE_AUTHORITY} "
            f"stage={stage.name} classification={classification}",
            flush=True,
        )
        return True, classification, detail
    browser_ready, browser_detail = _ensure_browser_triage_for_stage(root, stage)
    if not browser_ready:
        return False, "ENVIRONMENT", browser_detail
    triage_base = _codex_command(sandbox="read-only")
    if not triage_base:
        return False, "ENVIRONMENT", "CODEX_CLI_UNAVAILABLE"
    try:
        triage_run = _run(tuple([*triage_base, _triage_prompt(stage, result, iteration, root)]), cwd=root, timeout=min(timeout, 300), track_state_root=root, active_label="codex-triage:" + stage.name)
    except subprocess.TimeoutExpired:
        return False, "ENVIRONMENT", "CODEX_TRIAGE_TIMEOUT"
    triage_tail = _failure_capsule(triage_run.stdout, max_lines=20, max_chars=TRIAGE_RESULT_MAX_CHARS)
    if triage_run.returncode != 0:
        return False, "ENVIRONMENT", f"CODEX_TRIAGE_FAILED rc={triage_run.returncode}\n{triage_tail}"
    classification = _parse_triage_classification(triage_run.stdout)
    _record_triage_classification(root, stage, result, classification, triage_tail)
    return True, classification, triage_tail


def invoke_codex(root: Path, stage: Stage, result: StageResult, iteration: int, timeout: int) -> tuple[bool, str]:
    cached = _cached_triage(root, stage, result)
    if cached is not None:
        classification, triage_tail = cached
        triage_ok = True
        print(f"AUTOPILOT_TRIAGE=CACHED authority={TRIAGE_CACHE_AUTHORITY} stage={stage.name} fingerprint={result.fingerprint}", flush=True)
    else:
        triage_ok, classification, triage_tail = invoke_codex_triage(root, stage, result, iteration, timeout)
    if not triage_ok:
        return False, triage_tail
    if classification not in {"CODE_DEFECT", "TEST_DEFECT"}:
        return False, f"AUTOPILOT_TRIAGE_BLOCKED classification={classification}\n{triage_tail}"
    repair_base = _codex_command(sandbox="workspace-write")
    if not repair_base:
        return False, "CODEX_CLI_UNAVAILABLE"
    prompt = _repair_prompt(stage, result, iteration, triage_tail, root)
    cmd = [*repair_base, prompt]
    try:
        p = _run(tuple(cmd), cwd=root, timeout=timeout, track_state_root=root, active_label="codex-repair:" + stage.name)
    except subprocess.TimeoutExpired:
        return False, "CODEX_REPAIR_TIMEOUT"
    tail = _failure_capsule(p.stdout, max_lines=20, max_chars=TRIAGE_RESULT_MAX_CHARS)
    if p.returncode != 0:
        return False, f"CODEX_REPAIR_FAILED rc={p.returncode}\n{tail}"
    return True, tail


def _repair_writer_attempted(ok: bool, detail: str) -> bool:
    return bool(ok or str(detail).startswith("CODEX_REPAIR_"))


_AUTOPILOT_STATE_SCHEMA = 1
_AUTOPILOT_REPORT_SCHEMA = 1
_AUTOPILOT_EVENT_SCHEMA = 1
_AUTOPILOT_STATE_RELATIVE = Path(".state") / "codex-autopilot-run.json"
_AUTOPILOT_REPORT_RELATIVE = Path(".state") / "codex-autopilot-report.json"
_AUTOPILOT_EVENTS_RELATIVE = Path(".state") / "codex-autopilot-events"
_FINGERPRINT_EXCLUDED_DIRS = {".git", ".state", "bin", "release", "__pycache__", ".pytest_cache"}


def _full_workspace_fingerprint(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        if not path.is_file():
            continue
        rel = path.relative_to(root)
        if any(part in _FINGERPRINT_EXCLUDED_DIRS for part in rel.parts):
            continue
        if path.name.endswith((".pyc", ".pyo", "~", ".bak")):
            continue
        digest.update(rel.as_posix().encode())
        digest.update(b"\0")
        try:
            digest.update(f"mode:{path.stat().st_mode & 0o7777:o}".encode())
        except OSError:
            digest.update(b"mode:UNREADABLE")
        digest.update(b"\0")
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        digest.update(b"\0")
    return digest.hexdigest()


def _workspace_fingerprint(root: Path) -> str:
    head = _git_head(root)
    dirty = _git_dirty_paths(root)
    if not head or dirty is None:
        return _full_workspace_fingerprint(root)
    manifest = _hash_workspace_paths(root, dirty)
    digest = hashlib.sha256()
    digest.update(b"AUTOPILOT_GIT_WORKSPACE_FINGERPRINT_V1\0")
    digest.update(head.encode())
    digest.update(b"\0")
    for relative in sorted(manifest):
        digest.update(relative.encode(errors="surrogateescape"))
        digest.update(b"\0")
        digest.update(manifest[relative].encode())
        digest.update(b"\0")
    return digest.hexdigest()


def _git_dirty_paths(root: Path) -> list[str] | None:
    git_env = _repository_git_env()
    try:
        tracked = subprocess.run(
            ["git", "diff", "--name-only", "-z", "HEAD", "--"],
            cwd=root, env=git_env, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            check=False, timeout=10,
        )
        untracked = subprocess.run(
            ["git", "ls-files", "--others", "--exclude-standard", "-z"],
            cwd=root, env=git_env, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            check=False, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if tracked.returncode != 0 or untracked.returncode != 0:
        return None
    paths: set[str] = set()
    for raw in (tracked.stdout, untracked.stdout):
        for item in raw.decode(errors="surrogateescape").split("\0"):
            if not item:
                continue
            normalized = item.replace("\\", "/")
            parts = Path(normalized).parts
            if any(part in _FINGERPRINT_EXCLUDED_DIRS for part in parts):
                continue
            if Path(normalized).name.endswith((".pyc", ".pyo", "~", ".bak")):
                continue
            paths.add(normalized)
    return sorted(paths)


def _hash_workspace_paths(root: Path, paths: list[str]) -> dict[str, str]:
    manifest: dict[str, str] = {}
    for relative in sorted(set(paths)):
        path = root / relative
        try:
            if not path.is_file() or path.is_symlink():
                manifest[relative] = "MISSING_OR_NONREGULAR"
                continue
            digest = hashlib.sha256()
            mode = path.stat().st_mode & 0o7777
            digest.update(f"mode:{mode:o}\0".encode())
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            manifest[relative] = digest.hexdigest()
        except OSError:
            manifest[relative] = "UNREADABLE"
    return manifest


def _git_dirty_manifest(root: Path) -> dict[str, str] | None:
    dirty = _git_dirty_paths(root)
    if dirty is None:
        return None
    return _hash_workspace_paths(root, dirty)


def _workspace_manifest(root: Path) -> dict[str, str]:
    dirty = _git_dirty_paths(root)
    if dirty is not None:
        return _hash_workspace_paths(root, dirty)
    manifest: dict[str, str] = {}
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        if not path.is_file():
            continue
        rel = path.relative_to(root)
        if any(part in _FINGERPRINT_EXCLUDED_DIRS for part in rel.parts):
            continue
        if path.name.endswith((".pyc", ".pyo", "~", ".bak")):
            continue
        digest = hashlib.sha256()
        try:
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
        except OSError:
            manifest[rel.as_posix()] = "UNREADABLE"
            continue
        manifest[rel.as_posix()] = digest.hexdigest()
    return manifest


def _workspace_manifest_delta(before: dict[str, str], after: dict[str, str]) -> list[str]:
    return sorted(path for path in set(before) | set(after) if before.get(path) != after.get(path))


_AUTOPILOT_ORCHESTRATION_PATHS = frozenset({
    "scripts/codex_autopilot.py",
    "tests/test_codex_autopilot.py",
    "scripts/validate_repository.py",
})


def _repair_path_in_owner_scope(stage: Stage, relative_path: str) -> bool:
    path = relative_path.replace("\\", "/").lstrip("./")
    specialist = _stage_specialist(stage)
    if path in _AUTOPILOT_ORCHESTRATION_PATHS:
        return True
    return any(path.startswith(prefix) for prefix in _OWNER_CONTEXT_PATHS.get(specialist, ()))


def _repair_requires_full_convergence(stage: Stage, changed_paths: list[str]) -> bool:
    if not changed_paths:
        return True
    normalized = [path.replace("\\", "/").lstrip("./") for path in changed_paths]
    if any(path in _AUTOPILOT_ORCHESTRATION_PATHS for path in normalized):
        return True
    return any(not _repair_path_in_owner_scope(stage, path) for path in normalized)


def _external_adoption_path_in_owner_scope(stage: Stage, relative_path: str) -> bool:
    path = relative_path.replace("\\", "/").lstrip("./")
    if path in _AUTOPILOT_ORCHESTRATION_PATHS:
        return False
    return any(path.startswith(prefix) for prefix in _OWNER_CONTEXT_PATHS.get(_stage_specialist(stage), ()))


_FAILURE_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_.-])((?:/)?(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+\.(?:go|py|js|css|html|json|sh|yaml|yml))(?:[:(]\d+)?"
)

def _failure_path_hints(root: Path, stage: Stage, text: str, limit: int = 8) -> list[str]:
    root_resolved = root.resolve()
    hints: list[str] = []
    seen: set[str] = set()
    for raw in _FAILURE_PATH_RE.findall(str(text or "")):
        candidate = Path(raw)
        try:
            if candidate.is_absolute():
                relative = candidate.resolve().relative_to(root_resolved).as_posix()
            else:
                relative = candidate.as_posix().lstrip("./")
        except (OSError, ValueError):
            continue
        if not relative or relative in seen or ".." in Path(relative).parts:
            continue
        path = root / relative
        try:
            if not path.is_file() or path.is_symlink():
                continue
        except OSError:
            continue
        if not _repair_path_in_owner_scope(stage, relative):
            continue
        seen.add(relative)
        hints.append(relative)
        if len(hints) >= max(1, min(int(limit), 8)):
            break
    return hints


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

# Remaining implementation continues unchanged from the exact source snapshot.
# This file is intentionally preserved as the canonical Autopilot owner.
