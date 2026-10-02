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


_FAILURE_SIGNAL = re.compile(r"(?i)(error|fail(?:ed|ure)?|panic|fatal|traceback|exception|expected|actual|mismatch|timeout|blocked|undefined|not found|permission denied)")
_FAILURE_CAPSULE_MAX_LINES = 36
_FAILURE_CAPSULE_MAX_CHARS = 6000


def _failure_capsule(text: str, *, max_lines: int = _FAILURE_CAPSULE_MAX_LINES, max_chars: int = _FAILURE_CAPSULE_MAX_CHARS) -> str:
    """Return a bounded failure packet for AI triage/repair.

    Raw stage tails are useful for humans but expensive to resend to multiple
    agents. Keep unique high-signal lines plus a short terminal tail, redact
    secrets once, and enforce a hard character budget.
    """
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
        # Fail narrow owner defects before broad discovery spends test or agent budget.
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
    """Run all Python unit tests except owner suites already proven earlier."""
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
    """Select the smallest safe post-repair convergence graph.

    The failing owner stage is already rerun immediately after repair. The final
    convergence proves its dependency family and packaging surfaces without
    blindly replaying unrelated Lab/browser/docs stages. Any unrecognized stage
    fails safe to the original full graph.
    """
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
AGENT_CONTEXT_COMPACT_MAX_CHARS = 7000
AGENT_CONTEXT_COMPACT_FAILURE_MAX_CHARS = 1600
AGENT_CONTEXT_COMPACT_OWNER_PATH_LIMIT = 6
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
DEFAULT_REPAIR_BUDGET = 3
DEFAULT_AGENT_REPAIR_BUDGET = 8
TRIAGE_FAILURE_CAPSULE_MAX_CHARS = 3200
TRIAGE_RESULT_MAX_CHARS = 2400
REPAIR_FAILURE_CAPSULE_MAX_CHARS = 3200
REPAIR_TRIAGE_MAX_CHARS = 2400
AGENT_FAILURE_CAPSULE_MAX_CHARS = 3200

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
            required.add("go")
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

        After editing, run the smallest owner test that proves the fix. Do not run an endless
        repair loop; return when the defect is fixed or when the failure is environmental.

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


def _parse_triage_classification(text: str) -> str:
    # codex wrappers may emit progress lines before the model's final response.
    # Admit exactly one unambiguous classification line anywhere in the bounded
    # output; missing or conflicting classifications fail closed to UNKNOWN.
    matches = re.findall(
        r"(?m)^\s*CLASSIFICATION=(CODE_DEFECT|TEST_DEFECT|ENVIRONMENT|SUPPLY_CHAIN|UNKNOWN)\s*$",
        text,
    )
    unique = set(matches)
    if len(unique) != 1:
        return "UNKNOWN"
    return next(iter(unique))


def _record_triage_classification(root: Path, stage: Stage, result: StageResult, classification: str, triage_capsule: str = "") -> None:
    """Persist bounded read-only diagnosis for exact-fingerprint crash/resume reuse."""
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
    """Reuse only diagnosis sealed to the exact current stage/failure fingerprint."""
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
    """Fingerprint source identity without rehashing every tracked file per stage.

    A Git commit already content-addresses the clean tracked tree. Combine that
    immutable identity with exact hashes of only dirty/untracked product inputs.
    If local Git enumeration is unavailable, fall back to the full-tree digest.
    """
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
    """Return tracked-dirty + untracked paths without hashing the whole tree.

    Git is used only as a local change-index here, never as execution authority.
    If it is unavailable or ambiguous, callers fall back to the full safe manifest.
    """
    try:
        tracked = subprocess.run(
            ["git", "diff", "--name-only", "-z", "HEAD", "--"],
            cwd=root, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            check=False, timeout=10,
        )
        untracked = subprocess.run(
            ["git", "ls-files", "--others", "--exclude-standard", "-z"],
            cwd=root, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
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
    """Return the exact Git-relative dirty manifest for safe external-fix adoption."""
    dirty = _git_dirty_paths(root)
    if dirty is None:
        return None
    return _hash_workspace_paths(root, dirty)


def _workspace_manifest(root: Path) -> dict[str, str]:
    """Digest only locally changed product inputs when Git can enumerate them.

    This keeps repair-boundary accounting cheap on large repositories. If the
    local Git index cannot be read, fall back to the prior full-tree manifest so
    convergence safety never depends on the optimization.
    """
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
    """Whether a repair stayed inside the failing specialist's normal owner surface.

    This is intentionally conservative and is not an authorization boundary.
    A false result merely expands the final convergence back to the full graph.
    """
    path = relative_path.replace("\\", "/").lstrip("./")
    specialist = _stage_specialist(stage)
    if path in _AUTOPILOT_ORCHESTRATION_PATHS:
        return True
    return any(path.startswith(prefix) for prefix in _OWNER_CONTEXT_PATHS.get(specialist, ()))


def _repair_requires_full_convergence(stage: Stage, changed_paths: list[str]) -> bool:
    if not changed_paths:
        # An agent claiming success without changing source is ambiguous; the
        # repaired owner stage will rerun, but final convergence stays full.
        return True
    normalized = [path.replace("\\", "/").lstrip("./") for path in changed_paths]
    if any(path in _AUTOPILOT_ORCHESTRATION_PATHS for path in normalized):
        # The runner/gate changed underneath the selected graph. It may be a
        # legitimate owner fix, but selective convergence would reuse proofs
        # produced by the old orchestration semantics.
        return True
    return any(not _repair_path_in_owner_scope(stage, path) for path in normalized)


def _external_adoption_path_in_owner_scope(stage: Stage, relative_path: str) -> bool:
    """Stricter than repair scope: orchestration/gate edits invalidate resume semantics."""
    path = relative_path.replace("\\", "/").lstrip("./")
    if path in _AUTOPILOT_ORCHESTRATION_PATHS:
        return False
    return any(path.startswith(prefix) for prefix in _OWNER_CONTEXT_PATHS.get(_stage_specialist(stage), ()))


_FAILURE_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_.-])((?:/)?(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+\.(?:go|py|js|css|html|json|sh|yaml|yml))(?:[:(]\d+)?"
)

def _failure_path_hints(root: Path, stage: Stage, text: str, limit: int = 8) -> list[str]:
    """Return bounded owner-scoped source paths mentioned by a redacted failure.

    Hints are convenience context only. They never widen repair authority and
    never replace the deterministic failing command or owner scope.
    """
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


def _outer_runtime_context(root: Path) -> dict:
    """Read the canonical durable wrapper status without creating a second runtime authority."""
    runtime = root / "scripts" / "project_runtime.py"
    base = {
        "authority": OUTER_RUNTIME_CONTEXT_AUTHORITY,
        "derived": True,
        "notProductAuthority": True,
        "available": False,
        "status": "UNKNOWN",
        "runId": "",
        "activeRun": False,
        "recoveryRequired": False,
        "safeToRetry": False,
        "replaySafe": False,
        "action": "STATUS_UNAVAILABLE",
    }
    if not runtime.is_file() or runtime.is_symlink():
        return base
    try:
        result = subprocess.run(
            [sys.executable, str(runtime), "status", "--root", str(root)],
            cwd=root,
            text=True,
            capture_output=True,
            check=False,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return base
    if result.returncode != 0:
        return base
    try:
        payload = json.loads(result.stdout)
    except (json.JSONDecodeError, TypeError):
        return base
    if not isinstance(payload, dict) or payload.get("authority") != "PROJECT_RUNTIME_STATE_V1":
        return base
    status = str(payload.get("status") or "UNKNOWN").upper()
    active = bool(payload.get("activeRun")) or status in {"REQUESTED", "RUNNING", "WAITING"}
    recovery = bool(payload.get("recoveryRequired"))
    safe = bool(payload.get("safeToRetry"))
    replay_safe = bool(payload.get("replaySafe"))
    if active:
        action = "OBSERVE_ACTIVE"
    elif recovery:
        action = "RECOVERY_REQUIRED"
    elif status in {"FAILED","INTERRUPTED","WAITING"} and (safe or replay_safe):
        action = "RESUME_RUNTIME"
    else:
        action = "NO_ACTIVE_RUNTIME"
    return {
        **base,
        "available": True,
        "projectRuntimeAuthority": "PROJECT_RUNTIME_STATE_V1",
        "status": status,
        "runId": str(payload.get("runId") or ""),
        "phase": str(payload.get("phase") or ""),
        "task": str(payload.get("task") or ""),
        "activeRun": active,
        "recoveryRequired": recovery,
        "safeToRetry": safe,
        "replaySafe": replay_safe,
        "latestError": str(payload.get("latestError") or "")[:600],
        "action": action,
    }


def _agent_context(root: Path) -> dict:
    """Return a compact, non-authoritative continuation capsule for the next agent."""
    report: dict = {}
    path = _report_path(root)
    if path.is_file() and not path.is_symlink():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict) and loaded.get("authority") == "AUTOPILOT_CAMPAIGN_REPORT_V1":
                report = loaded
        except (OSError, json.JSONDecodeError):
            report = {}
    events = _summarize_event_log(root)
    outer_runtime = _outer_runtime_context(root)
    last_failure = report.get("lastFailure") if isinstance(report.get("lastFailure"), dict) else events.get("lastFailure", {})
    status = str(report.get("status") or events.get("status") or "IDLE")
    resume_invocation = report.get("invocation") if isinstance(report.get("invocation"), list) else []
    checkpoint_state: dict = {}
    checkpoint = _checkpoint_path(root)
    if checkpoint.is_file() and not checkpoint.is_symlink():
        try:
            loaded_checkpoint = json.loads(checkpoint.read_text(encoding="utf-8"))
            if isinstance(loaded_checkpoint, dict):
                checkpoint_state = loaded_checkpoint
        except (OSError, json.JSONDecodeError):
            checkpoint_state = {}
    failure_capsule = str(checkpoint_state.get("lastFailureCapsule") or "")[:AGENT_FAILURE_CAPSULE_MAX_CHARS]
    current_stage_name = str(report.get("currentStage") or "")
    current_command = tuple(str(item) for item in report.get("currentCommand", []) if isinstance(item, str)) if isinstance(report.get("currentCommand"), list) else ()
    current_stage = Stage(current_stage_name, current_command, int(report.get("currentTimeoutSeconds") or 0)) if current_stage_name else None
    failure_path_hints = _failure_path_hints(root, current_stage, failure_capsule) if current_stage else []
    context = {
        "schemaVersion": 1,
        "authority": "AUTOPILOT_AGENT_CONTEXT_V1",
        "derived": True,
        "notProductAuthority": True,
        "gitHead": _git_head(root),
        "runId": str(report.get("runId") or events.get("runId") or ""),
        "status": status,
        "phase": str(report.get("phase") or ""),
        "currentStage": str(report.get("currentStage") or ""),
        "currentSpecialist": str(report.get("currentSpecialist") or ""),
        "nextStage": str(report.get("nextStage") or ""),
        "repairCount": int(report.get("repairCount") or 0),
        "resumeEligible": bool(report.get("resumeEligible", False)),
        "lastFailure": {
            key: last_failure.get(key)
            for key in ("stage", "specialist", "status", "fingerprint", "reason", "classification")
            if isinstance(last_failure, dict) and last_failure.get(key) not in (None, "")
        },
        "failureCapsuleAuthority": AGENT_FAILURE_CAPSULE_AUTHORITY,
        "ownerProofAuthority": AGENT_OWNER_PROOF_AUTHORITY,
        "installerOwnerStageAuthority": INSTALLER_OWNER_STAGE_AUTHORITY,
        "installerOwnerContractStageAuthority": INSTALLER_OWNER_CONTRACT_STAGE_AUTHORITY,
        "ownerContextAuthority": OWNER_CONTEXT_AUTHORITY,
        "ownerContextPaths": [str(item) for item in report.get("currentOwnerPaths", [])[:12]] if isinstance(report.get("currentOwnerPaths"), list) else [],
        "promptBudgetAuthority": PROMPT_BUDGET_AUTHORITY,
        "agentRepairBudgetAuthority": AGENT_REPAIR_BUDGET_AUTHORITY,
        "failurePathHintsAuthority": FAILURE_PATH_HINTS_AUTHORITY,
        "failurePathHints": failure_path_hints,
        "externalOwnerFixAdoptionAuthority": EXTERNAL_OWNER_FIX_ADOPTION_AUTHORITY,
        "durableTriageClassificationAuthority": DURABLE_TRIAGE_CLASSIFICATION_AUTHORITY,
        "triageCacheAuthority": TRIAGE_CACHE_AUTHORITY,
        "agentNextActionAuthority": AGENT_NEXT_ACTION_AUTHORITY,
        "ownerFirstStageOrderAuthority": OWNER_FIRST_STAGE_ORDER_AUTHORITY,
        "ownerUnitDedupAuthority": OWNER_UNIT_DEDUP_AUTHORITY,
        "ownerPythonDedupAuthority": OWNER_PYTHON_DEDUP_AUTHORITY,
        "liveRunRejoinFenceAuthority": LIVE_RUN_REJOIN_FENCE_AUTHORITY,
        "crossSurfaceOwnerContextAuthority": CROSS_SURFACE_OWNER_CONTEXT_AUTHORITY,
        "autopilotOwnerTestStageAuthority": AUTOPILOT_OWNER_TEST_STAGE_AUTHORITY,
        "convergenceRepairAuthority": CONVERGENCE_REPAIR_AUTHORITY,
        "outerRuntimeContextAuthority": OUTER_RUNTIME_CONTEXT_AUTHORITY,
        "resumePreflightCursorAuthority": RESUME_PREFLIGHT_CURSOR_AUTHORITY,
        "outerRuntime": outer_runtime,
        "defaultRepairBudget": int(report.get("defaultRepairBudget") or DEFAULT_REPAIR_BUDGET),
        "defaultAgentRepairBudget": int(report.get("defaultAgentRepairBudget") or DEFAULT_AGENT_REPAIR_BUDGET),
        "promptBudgetChars": report.get("promptBudgetChars") if isinstance(report.get("promptBudgetChars"), dict) else {
            "triageFailure": TRIAGE_FAILURE_CAPSULE_MAX_CHARS,
            "triageResult": TRIAGE_RESULT_MAX_CHARS,
            "repairFailure": REPAIR_FAILURE_CAPSULE_MAX_CHARS,
            "repairTriage": REPAIR_TRIAGE_MAX_CHARS,
        },
        "failureCapsuleMaxChars": AGENT_FAILURE_CAPSULE_MAX_CHARS,
        "failureCapsule": failure_capsule,
        "proofCommand": report.get("currentCommand") if isinstance(report.get("currentCommand"), list) else [],
        "proofTimeoutSeconds": int(report.get("currentTimeoutSeconds") or 0),
        "resumeInvocation": resume_invocation,
        "environmentPreflight": report.get("environmentPreflight") if isinstance(report.get("environmentPreflight"), dict) else {},
        "environmentRemediationHintsAuthority": ENVIRONMENT_REMEDIATION_HINTS_AUTHORITY,
        "sourceContext": {
            "agentInstructions": "AGENTS.md",
            "derivedKnowledge": "DERIVED-AGENT-KNOWLEDGE.json",
            "canonicalPhaseSource": "internal/targetmodel/program.go",
        },
        "continuationRules": [
            "read failurePathHints first when present, then only the failing owner surface plus AGENTS.md/derived knowledge needed for that owner",
            "rerun the same invocation when resumeEligible; do not replay already checkpointed green stages manually",
            "use the compact failure fingerprint/capsule and run the smallest owner proof before broader convergence",
            "never mutate Git refs/index/history from the repair agent",
            "never convert source/local success into Runtime/Lab/Exact-SHA Physical PASS",
            "prefer one durable agent-run entrypoint over manually replaying stage ranges; owner-scoped convergence is selected from the actual repaired stage and dirty delta",
            "a new defect found only during final convergence receives the same bounded triage/repair budget at that exact cursor; same-fingerprint repetition stops and cross-owner repair expands to full convergence",
        ],
    }
    context["nextActionCode"] = "START_AUTOPILOT_AGENT"
    context["nextCommand"] = ["make", "autopilot-agent"]
    if outer_runtime.get("action") == "OBSERVE_ACTIVE":
        context["nextActionCode"] = "OBSERVE_OUTER_RUNTIME"
        context["nextCommand"] = ["make", "runtime-status"]
        context["nextAction"] = "outer project runtime is already active; observe/rejoin it with make runtime-status and do not start a duplicate autopilot-agent"
    elif outer_runtime.get("action") == "RECOVERY_REQUIRED":
        context["nextActionCode"] = "RESOLVE_OUTER_RUNTIME_RECOVERY"
        context["nextCommand"] = ["make", "runtime-status"]
        context["nextAction"] = "outer project runtime requires explicit recovery resolution before any new Autopilot execution; inspect make runtime-status and do not replay the command"
    elif outer_runtime.get("action") == "RESUME_RUNTIME":
        context["nextActionCode"] = "RESUME_OUTER_RUNTIME"
        context["nextCommand"] = ["make", "runtime-resume"]
        context["nextAction"] = "outer project runtime is safely resumable; run make runtime-resume, then re-read make autopilot-context"
    elif status == "ENVIRONMENT_BLOCKED" and context["environmentPreflight"]:
        if resume_invocation:
            context["nextActionCode"] = "REPAIR_ENVIRONMENT_AND_RESUME"
            context["nextCommand"] = resume_invocation
            context["nextAction"] = "apply only the environmentPreflight.remediationHints for missing prerequisites, then rerun resumeInvocation; do not edit product source for an environment blocker"
        else:
            context["nextActionCode"] = "INSPECT_AUTOPILOT_STATE"
            context["nextCommand"] = ["make", "autopilot-status"]
            context["nextAction"] = "the durable report does not contain an exact resume invocation; inspect autopilot-status and do not reconstruct or guess a command"
    elif status in {"ENVIRONMENT_BLOCKED", "CODE_DEFECT", "FAIL", "TIMEOUT"}:
        if resume_invocation:
            context["nextActionCode"] = "FIX_OWNER_AND_RESUME"
            context["nextCommand"] = resume_invocation
            context["nextAction"] = "inspect lastFailure and rerun the recorded invocation after fixing only the owning cause"
        else:
            context["nextActionCode"] = "INSPECT_AUTOPILOT_STATE"
            context["nextCommand"] = ["make", "autopilot-status"]
            context["nextAction"] = "the durable report does not contain an exact resume invocation; inspect autopilot-status and do not reconstruct or guess a command"
    elif status in {"RUNNING", "REPAIRING"} and context["resumeEligible"]:
        if resume_invocation:
            context["nextActionCode"] = "REJOIN_AUTOPILOT"
            context["nextCommand"] = resume_invocation
            context["nextAction"] = "rerun resumeInvocation; the durable checkpoint will rejoin/resume the exact graph cursor"
        else:
            context["nextActionCode"] = "INSPECT_AUTOPILOT_STATE"
            context["nextCommand"] = ["make", "autopilot-status"]
            context["nextAction"] = "resume metadata is incomplete; inspect autopilot-status and do not guess a replacement invocation"
    elif status == "PASS":
        context["nextActionCode"] = "CHECK_RELEASE_READINESS"
        context["nextCommand"] = ["make", "release-readiness"]
        context["nextAction"] = "local campaign is complete; consult release-readiness before any external/physical campaign"
    else:
        context["nextAction"] = "run make autopilot-agent; it performs prerequisite checking and durable checkpoint/resume automatically"
    return context


def _compact_agent_context(root: Path) -> dict:
    """Return only the actionable continuation packet needed by the next agent.

    Full report/authority diagnostics remain available through --agent-context.
    The default Make handoff uses this bounded projection so a new coding agent
    does not spend context on orchestration metadata it is explicitly told not
    to consume.
    """
    full = _agent_context(root)
    outer = full.get("outerRuntime") if isinstance(full.get("outerRuntime"), dict) else {}
    environment = full.get("environmentPreflight") if isinstance(full.get("environmentPreflight"), dict) else {}
    remediation = environment.get("remediationHints") if isinstance(environment.get("remediationHints"), dict) else {}
    failure = str(full.get("failureCapsule") or "")[:AGENT_CONTEXT_COMPACT_FAILURE_MAX_CHARS]
    raw_last_failure = full.get("lastFailure") if isinstance(full.get("lastFailure"), dict) else {}
    safe_last_failure = {}
    for key in ("stage", "specialist", "status", "fingerprint", "reason", "classification"):
        value = raw_last_failure.get(key)
        if value in (None, ""):
            continue
        if isinstance(value, str):
            safe_last_failure[key] = _redact_failure_text(value)[:480]
        else:
            safe_last_failure[key] = value
    safe_remediation = {
        str(key)[:96]: _redact_failure_text(str(value))[:480]
        for key, value in list(remediation.items())[:8]
    }
    compact = {
        "schemaVersion": 1,
        "authority": AGENT_CONTEXT_COMPACT_AUTHORITY,
        "derived": True,
        "notProductAuthority": True,
        "contextBudgetChars": AGENT_CONTEXT_COMPACT_MAX_CHARS,
        "gitHead": str(full.get("gitHead") or ""),
        "runId": str(full.get("runId") or ""),
        "status": str(full.get("status") or "IDLE"),
        "phase": str(full.get("phase") or ""),
        "currentStage": str(full.get("currentStage") or ""),
        "currentSpecialist": str(full.get("currentSpecialist") or ""),
        "nextStage": str(full.get("nextStage") or ""),
        "resumeEligible": bool(full.get("resumeEligible", False)),
        "lastFailure": safe_last_failure,
        "failurePathHints": [str(item) for item in (full.get("failurePathHints") or [])[:8]],
        "ownerContextPaths": [str(item) for item in (full.get("ownerContextPaths") or [])[:AGENT_CONTEXT_COMPACT_OWNER_PATH_LIMIT]],
        "failureCapsule": failure,
        "proofCommand": full.get("proofCommand") if isinstance(full.get("proofCommand"), list) else [],
        "proofTimeoutSeconds": int(full.get("proofTimeoutSeconds") or 0),
        "resumeInvocation": full.get("resumeInvocation") if isinstance(full.get("resumeInvocation"), list) else [],
        "environmentPreflight": {
            "missing": [str(item) for item in (environment.get("missing") or [])],
            "remediationHints": safe_remediation,
        } if environment else {},
        "outerRuntime": {
            key: outer.get(key)
            for key in ("status", "runId", "activeRun", "recoveryRequired", "safeToRetry", "replaySafe", "action")
            if key in outer
        },
        "nextActionCode": str(full.get("nextActionCode") or ""),
        "nextCommand": full.get("nextCommand") if isinstance(full.get("nextCommand"), list) else [],
        "nextAction": str(full.get("nextAction") or ""),
        "rules": [
            "read failurePathHints, then ownerContextPaths; do not broad-scan first",
            "run proofCommand for diagnosis; let Autopilot own final convergence",
            "execute only nextCommand admitted by nextActionCode",
            "never infer Runtime/Lab/Exact-SHA Physical PASS from local/source success",
        ],
    }
    # Reserve a small fixed envelope for the serializedChars field itself so
    # the final emitted JSON, not merely its pre-metadata payload, stays below
    # the advertised hard handoff budget.
    payload_budget = AGENT_CONTEXT_COMPACT_MAX_CHARS - 64
    raw = json.dumps(compact, sort_keys=True, separators=(",", ":"))
    if len(raw) > payload_budget:
        compact["failureCapsule"] = failure[-800:]
        compact["ownerContextPaths"] = compact["ownerContextPaths"][:4]
        compact["failurePathHints"] = compact["failurePathHints"][:4]
        compact["contextTruncated"] = True
        raw = json.dumps(compact, sort_keys=True, separators=(",", ":"))
    if len(raw) > payload_budget:
        compact["nextAction"] = compact["nextAction"][:480]
        compact["environmentPreflight"] = {
            "missing": compact.get("environmentPreflight", {}).get("missing", []),
        }
        raw = json.dumps(compact, sort_keys=True, separators=(",", ":"))
    if len(raw) > payload_budget:
        raise RuntimeError("AUTOPILOT_COMPACT_AGENT_CONTEXT_BUDGET_EXCEEDED")
    compact["serializedChars"] = len(raw)
    final_raw = json.dumps(compact, sort_keys=True, separators=(",", ":"))
    if len(final_raw) > AGENT_CONTEXT_COMPACT_MAX_CHARS:
        raise RuntimeError("AUTOPILOT_COMPACT_AGENT_CONTEXT_BUDGET_EXCEEDED")
    compact["serializedChars"] = len(final_raw)
    return compact


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


def _git_head(root: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            text=True,
            capture_output=True,
            check=False,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return result.stdout.strip() if result.returncode == 0 else ""


def _autopilot_invocation() -> list[str]:
    return [str(Path(sys.executable).resolve()), *sys.argv]


def _write_autopilot_report(root: Path, *, stages: list[Stage], graph_signature: str, repair: bool, phase: str, next_index: int, repair_count: int, status: str, current_stage: str | None, stage_results: list[dict], last_failure: dict | None = None, run_id: str | None = None, environment_preflight: dict | None = None) -> None:
    stage = next((item for item in stages if item.name == current_stage), None)
    resolved_run_id = str(run_id or "").strip()
    if not resolved_run_id:
        checkpoint = _checkpoint_path(root)
        if checkpoint.is_file():
            try:
                resolved_run_id = str(json.loads(checkpoint.read_text(encoding="utf-8")).get("runId") or "").strip()
            except (OSError, json.JSONDecodeError):
                resolved_run_id = ""
    if not resolved_run_id:
        resolved_run_id = str(_summarize_event_log(root).get("runId") or "").strip()
    body = {
        "schemaVersion": _AUTOPILOT_REPORT_SCHEMA,
        "authority": "AUTOPILOT_CAMPAIGN_REPORT_V1",
        "failureCapsuleAuthority": FAILURE_CAPSULE_AUTHORITY,
        "selectiveConvergenceAuthority": SELECTIVE_CONVERGENCE_AUTHORITY,
        "repairScopeFenceAuthority": REPAIR_SCOPE_FENCE_AUTHORITY,
        "structuredTriageAuthority": STRUCTURED_TRIAGE_AUTHORITY,
        "repairGitBoundaryAuthority": REPAIR_GIT_BOUNDARY_AUTHORITY,
        "dirtyDeltaAuthority": DIRTY_DELTA_AUTHORITY,
        "workspaceFingerprintAuthority": WORKSPACE_FINGERPRINT_AUTHORITY,
        "installerOwnerStageAuthority": INSTALLER_OWNER_STAGE_AUTHORITY,
        "installerOwnerContractStageAuthority": INSTALLER_OWNER_CONTRACT_STAGE_AUTHORITY,
        "agentOwnerProofAuthority": AGENT_OWNER_PROOF_AUTHORITY,
        "environmentPreflightHandoffAuthority": ENVIRONMENT_PREFLIGHT_HANDOFF_AUTHORITY,
        "ownerContextAuthority": OWNER_CONTEXT_AUTHORITY,
        "promptBudgetAuthority": PROMPT_BUDGET_AUTHORITY,
        "agentRepairBudgetAuthority": AGENT_REPAIR_BUDGET_AUTHORITY,
        "failurePathHintsAuthority": FAILURE_PATH_HINTS_AUTHORITY,
        "externalOwnerFixAdoptionAuthority": EXTERNAL_OWNER_FIX_ADOPTION_AUTHORITY,
        "durableTriageClassificationAuthority": DURABLE_TRIAGE_CLASSIFICATION_AUTHORITY,
        "triageCacheAuthority": TRIAGE_CACHE_AUTHORITY,
        "agentNextActionAuthority": AGENT_NEXT_ACTION_AUTHORITY,
        "ownerFirstStageOrderAuthority": OWNER_FIRST_STAGE_ORDER_AUTHORITY,
        "ownerUnitDedupAuthority": OWNER_UNIT_DEDUP_AUTHORITY,
        "ownerPythonDedupAuthority": OWNER_PYTHON_DEDUP_AUTHORITY,
        "liveRunRejoinFenceAuthority": LIVE_RUN_REJOIN_FENCE_AUTHORITY,
        "crossSurfaceOwnerContextAuthority": CROSS_SURFACE_OWNER_CONTEXT_AUTHORITY,
        "autopilotOwnerTestStageAuthority": AUTOPILOT_OWNER_TEST_STAGE_AUTHORITY,
        "convergenceRepairAuthority": CONVERGENCE_REPAIR_AUTHORITY,
        "outerRuntimeContextAuthority": OUTER_RUNTIME_CONTEXT_AUTHORITY,
        "resumePreflightCursorAuthority": RESUME_PREFLIGHT_CURSOR_AUTHORITY,
        "defaultRepairBudget": DEFAULT_REPAIR_BUDGET,
        "defaultAgentRepairBudget": DEFAULT_AGENT_REPAIR_BUDGET,
        "promptBudgetChars": {
            "triageFailure": TRIAGE_FAILURE_CAPSULE_MAX_CHARS,
            "triageResult": TRIAGE_RESULT_MAX_CHARS,
            "repairFailure": REPAIR_FAILURE_CAPSULE_MAX_CHARS,
            "repairTriage": REPAIR_TRIAGE_MAX_CHARS,
        },
        "currentOwnerPaths": list(_owner_context_paths(stage)) if stage else [],
        "derived": True,
        "notProductAuthority": True,
        "runId": resolved_run_id,
        "eventLog": str(_event_log_path(root, resolved_run_id)) if resolved_run_id else "",
        "graphSignature": graph_signature,
        "repair": repair,
        "status": status,
        "phase": phase,
        "stageCount": len(stages),
        "nextIndex": next_index,
        "currentStage": current_stage or "",
        "currentSpecialist": _stage_specialist(stage) if stage else "",
        "currentCommand": list(stage.command) if stage else [],
        "currentTimeoutSeconds": int(stage.timeout) if stage else 0,
        "repairCount": repair_count,
        "resumeEligible": _checkpoint_path(root).is_file(),
        "gitHead": _git_head(root),
        "workspaceFingerprint": _workspace_fingerprint(root),
        "checkpointPath": str(_checkpoint_path(root)),
        "reportPath": str(_report_path(root)),
        "nextStage": stages[next_index].name if 0 <= next_index < len(stages) else "",
        "invocation": _autopilot_invocation(),
        "resumeHint": "rerun the same invocation; the durable checkpoint resumes the exact graph cursor",
        "updatedAt": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
        "stageResults": stage_results[-100:],
    }
    if last_failure:
        body["lastFailure"] = {key: last_failure.get(key) for key in ("stage", "specialist", "status", "fingerprint", "reason") if last_failure.get(key) not in (None, "")}
        checkpoint = _checkpoint_path(root)
        if checkpoint.is_file() and not checkpoint.is_symlink():
            try:
                checkpoint_state = json.loads(checkpoint.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                checkpoint_state = {}
            if (
                checkpoint_state.get("lastFailureStage") == body["lastFailure"].get("stage")
                and checkpoint_state.get("lastFailureFingerprint") == body["lastFailure"].get("fingerprint")
                and checkpoint_state.get("lastFailureClassification") in _TRIAGE_CLASSIFICATIONS
            ):
                body["lastFailure"]["classification"] = checkpoint_state["lastFailureClassification"]
    if isinstance(environment_preflight, dict):
        body["environmentPreflight"] = {
            "authority": ENVIRONMENT_PREFLIGHT_HANDOFF_AUTHORITY,
            "missing": sorted({str(item) for item in environment_preflight.get("missing", []) if str(item).strip()}),
            "requirements": sorted({str(item) for item in environment_preflight.get("requirements", []) if str(item).strip()}),
            "remediationAuthority": str(environment_preflight.get("remediationAuthority") or ENVIRONMENT_REMEDIATION_HINTS_AUTHORITY),
            "remediationHints": {
                str(key): str(value)
                for key, value in (environment_preflight.get("remediationHints") or {}).items()
                if str(key).strip() and str(value).strip()
            } if isinstance(environment_preflight.get("remediationHints"), dict) else {},
            "fingerprint": str(environment_preflight.get("fingerprint") or ""),
        }
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

class _AutopilotRunLock:
    def __init__(self, root: Path):
        self.path = root / ".state" / "codex-autopilot.lock"
        self.pid = os.getpid()
        self.start_ticks = _process_start_ticks(self.pid)
        self.acquired = False

    @staticmethod
    def _owner_alive(state: dict) -> bool:
        try:
            pid = int(state.get("pid", 0))
        except (TypeError, ValueError):
            return False
        expected = str(state.get("startTicks") or "")
        current = _process_start_ticks(pid) if pid > 1 else None
        return bool(current and expected and current == expected)

    def acquire(self) -> None:
        if not self.start_ticks:
            raise RuntimeError("AUTOPILOT_RUN_LOCK_IDENTITY_UNAVAILABLE")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "authority": "AUTOPILOT_SINGLE_RUN_LOCK_V1",
            "pid": self.pid,
            "startTicks": self.start_ticks,
            "acquiredAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        for _ in range(2):
            try:
                fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                try:
                    state = json.loads(self.path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError) as exc:
                    raise RuntimeError("AUTOPILOT_RUN_LOCK_INVALID") from exc
                if self._owner_alive(state):
                    raise RuntimeError("AUTOPILOT_RUN_ALREADY_ACTIVE")
                self.path.unlink(missing_ok=True)
                continue
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            self.acquired = True
            return
        raise RuntimeError("AUTOPILOT_RUN_LOCK_ACQUIRE_FAILED")

    def release(self) -> None:
        if not self.acquired:
            return
        try:
            state = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            self.acquired = False
            return
        if state.get("pid") == self.pid and str(state.get("startTicks") or "") == self.start_ticks:
            self.path.unlink(missing_ok=True)
        self.acquired = False

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


def _cleanup_checkpoint_process(root: Path, state: dict) -> bool:
    """Validate checkpoint process identity without killing live work.

    Chat/UI/controller loss is not execution failure. If the tracked stage child
    is still alive with the same PID start identity, a new observer must rejoin
    rather than terminate or duplicate it. Only disproven/stale identities are
    removed from the checkpoint.
    """
    active = state.get("activeProcess")
    if not isinstance(active, dict):
        return False
    try:
        pid = int(active.get("pid", 0))
    except (TypeError, ValueError):
        pid = 0
    expected_ticks = str(active.get("startTicks") or "")
    label = str(active.get("label", "unknown"))
    if pid <= 1:
        state.pop("activeProcess", None)
        return False
    current_ticks = _process_start_ticks(pid)
    if current_ticks is None or not expected_ticks or current_ticks != expected_ticks:
        print(f"AUTOPILOT_RESUME_PROCESS=STALE pid={pid} label={label}", flush=True)
        state.pop("activeProcess", None)
        return False
    print(f"AUTOPILOT_RESUME_PROCESS=REJOIN pid={pid} label={label}", flush=True)
    return True


def _write_checkpoint(root: Path, payload: dict) -> None:
    path = _checkpoint_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    body = dict(payload)
    current_stage = str(body.get("currentStage") or "")
    if current_stage and path.is_file() and not path.is_symlink():
        try:
            previous = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            previous = {}
        if str(previous.get("lastFailureStage") or "") == current_stage:
            for key in ("lastFailureClassification", "lastFailureStage", "lastFailureFingerprint", "lastTriageCapsule", "lastTriageAuthority"):
                if previous.get(key) not in (None, ""):
                    body[key] = previous[key]
    body["schemaVersion"] = _AUTOPILOT_STATE_SCHEMA
    body["workspaceFingerprint"] = _workspace_fingerprint(root)
    body["gitHead"] = _git_head(root)
    dirty_manifest = _git_dirty_manifest(root)
    if dirty_manifest is not None:
        body["workspaceDirtyManifest"] = dirty_manifest
    body["invocation"] = _autopilot_invocation()
    body["updatedAt"] = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    _write_state_raw(path, body)


def _clear_checkpoint(root: Path) -> None:
    path = _checkpoint_path(root)
    path.unlink(missing_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.unlink(missing_ok=True)


def _checkpoint_owner_stage(state: dict, stages: list[Stage] | None) -> Stage | None:
    if not stages:
        return None
    phase = str(state.get("phase") or "forward")
    by_name = {stage.name: stage for stage in stages}
    if phase == "forward":
        name = str(state.get("currentStage") or "")
        if name and name in by_name:
            return by_name[name]
        try:
            index = int(state.get("nextIndex", 0))
        except (TypeError, ValueError):
            return None
        return stages[index] if 0 <= index < len(stages) else None
    if phase == "convergence":
        names = state.get("convergenceStages")
        try:
            index = int(state.get("nextIndex", 0))
        except (TypeError, ValueError):
            return None
        if isinstance(names, list) and 0 <= index < len(names):
            return by_name.get(str(names[index]))
    return None


def _try_adopt_external_owner_fix(root: Path, state: dict, *, graph_signature: str, stages: list[Stage] | None) -> tuple[bool, str, list[str]]:
    stage = _checkpoint_owner_stage(state, stages)
    if stage is None:
        return False, "OWNER_STAGE_UNAVAILABLE", []
    report_path = _report_path(root)
    if not report_path.is_file() or report_path.is_symlink():
        return False, "REPORT_UNAVAILABLE", []
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False, "REPORT_INVALID", []
    if report.get("authority") != "AUTOPILOT_CAMPAIGN_REPORT_V1" or report.get("graphSignature") != graph_signature:
        return False, "REPORT_GRAPH_MISMATCH", []
    failure = report.get("lastFailure") if isinstance(report.get("lastFailure"), dict) else {}
    if str(failure.get("stage") or "") != stage.name:
        return False, "FAILURE_STAGE_MISMATCH", []
    if str(failure.get("classification") or "") != "CODE_DEFECT":
        return False, "REPORT_NOT_CODE_DEFECT_CLASSIFICATION", []
    if (
        str(state.get("lastFailureClassification") or "") != "CODE_DEFECT"
        or str(state.get("lastFailureStage") or "") != stage.name
        or str(state.get("lastFailureFingerprint") or "") != str(failure.get("fingerprint") or "")
    ):
        return False, "CHECKPOINT_DIAGNOSIS_MISMATCH", []
    checkpoint_head = str(state.get("gitHead") or "")
    current_head = _git_head(root)
    if not checkpoint_head or not current_head or checkpoint_head != current_head:
        return False, "GIT_HEAD_CHANGED", []
    before = state.get("workspaceDirtyManifest")
    after = _git_dirty_manifest(root)
    if not isinstance(before, dict) or after is None:
        return False, "DIRTY_MANIFEST_UNAVAILABLE", []
    before_clean = {str(key): str(value) for key, value in before.items()}
    delta = _workspace_manifest_delta(before_clean, after)
    if not delta:
        return False, "NO_EXTERNAL_DELTA", []
    outside = [item for item in delta if not _external_adoption_path_in_owner_scope(stage, item)]
    if outside:
        return False, "OWNER_SCOPE_VIOLATION:" + ",".join(outside[:8]), delta
    return True, stage.name, delta


def _load_checkpoint(root: Path, *, graph_signature: str, repair: bool, allow_owner_fix_adoption: bool = False, stages: list[Stage] | None = None) -> dict | None:
    path = _checkpoint_path(root)
    if not path.is_file():
        return None
    try:
        state = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        print("AUTOPILOT_RESUME=RESET reason=STATE_INVALID", flush=True)
        _clear_checkpoint(root)
        return None
    active_process_live = _cleanup_checkpoint_process(root, state)
    _write_state_raw(path, state)
    if active_process_live:
        # A live stage is the single execution authority. A second observer must
        # never clear or rebind its checkpoint merely because it selected a
        # different graph slice or because the working tree changed underneath
        # the still-running process. Rejoin first; reconcile after it exits.
        state["_activeProcessLive"] = True
        return state
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
        adopted = False
        adoption_reason = "WORKSPACE_CHANGED"
        adoption_delta: list[str] = []
        if allow_owner_fix_adoption:
            adopted, adoption_reason, adoption_delta = _try_adopt_external_owner_fix(
                root, state, graph_signature=graph_signature, stages=stages
            )
        if not adopted:
            print(f"AUTOPILOT_RESUME=RESET reason={adoption_reason}", flush=True)
            _clear_checkpoint(root)
            return None
        state["workspaceFingerprint"] = current
        dirty_manifest = _git_dirty_manifest(root)
        if dirty_manifest is not None:
            state["workspaceDirtyManifest"] = dirty_manifest
        state["externalOwnerFixAdopted"] = {
            "authority": EXTERNAL_OWNER_FIX_ADOPTION_AUTHORITY,
            "stage": adoption_reason,
            "paths": adoption_delta[:32],
        }
        state["updatedAt"] = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
        _write_state_raw(path, state)
        print(
            "AUTOPILOT_RESUME=ADOPT_OWNER_FIX "
            f"authority={EXTERNAL_OWNER_FIX_ADOPTION_AUTHORITY} stage={adoption_reason} "
            f"changed={len(adoption_delta)} paths={','.join(adoption_delta[:12])}",
            flush=True,
        )
    return state


def _resume_preflight_stage_scope(root: Path, stages: list[Stage], *, repair: bool) -> tuple[list[Stage] | None, str]:
    """Derive the smallest safe prerequisite scope from a durable checkpoint.

    This is intentionally read-only. Invalid/stale checkpoints return None so
    callers fall back to the full invocation preflight. A still-live recorded
    child returns an empty stage set because the next action is rejoin/observe,
    not execution; _load_checkpoint remains the authority that performs the
    actual identity cleanup/rejoin decision.
    """
    path = _checkpoint_path(root)
    if not path.is_file() or path.is_symlink():
        return None, "NO_CHECKPOINT"
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None, "CHECKPOINT_INVALID"

    active = state.get("activeProcess")
    if isinstance(active, dict):
        try:
            pid = int(active.get("pid", 0))
        except (TypeError, ValueError):
            pid = 0
        expected_ticks = str(active.get("startTicks") or "")
        current_ticks = _process_start_ticks(pid) if pid > 1 else None
        if current_ticks and expected_ticks and current_ticks == expected_ticks:
            return [], "LIVE_REJOIN"

    if state.get("schemaVersion") != _AUTOPILOT_STATE_SCHEMA:
        return None, "SCHEMA_MISMATCH"
    if state.get("graphSignature") != _stage_graph_signature(stages, repair=repair):
        return None, "GRAPH_MISMATCH"
    if state.get("repair") != repair:
        return None, "REPAIR_MODE_MISMATCH"
    if state.get("workspaceFingerprint") != _workspace_fingerprint(root):
        return None, "WORKSPACE_CHANGED"

    phase = str(state.get("phase") or "forward")
    try:
        next_index = int(state.get("nextIndex", 0))
    except (TypeError, ValueError):
        return None, "INDEX_INVALID"

    if phase == "forward":
        if next_index < 0 or next_index > len(stages):
            return None, "FORWARD_INDEX_INVALID"
        if next_index == len(stages):
            try:
                repair_count = int(state.get("repairCount", 0))
            except (TypeError, ValueError):
                return None, "REPAIR_COUNT_INVALID"
            if not repair or repair_count <= 0:
                return [], "FORWARD_COMPLETE"
            seen = _decode_seen_failures(state)
            repaired_stage_names = {stage_name for (stage_name, _fingerprint), count in seen.items() if count > 0}
            if not repaired_stage_names:
                return None, "FORWARD_REPAIR_HISTORY_MISSING"
            if bool(state.get("fullConvergenceRequired")):
                return list(stages), "FORWARD_COMPLETE_PENDING_FULL_CONVERGENCE"
            selected = _select_convergence_stages(stages, repaired_stage_names)
            return selected, "FORWARD_COMPLETE_PENDING_CONVERGENCE"
        return list(stages[next_index:]), "FORWARD_CURSOR"

    if phase == "convergence":
        names = state.get("convergenceStages")
        if not isinstance(names, list) or not names:
            return None, "CONVERGENCE_GRAPH_MISSING"
        by_name = {stage.name: stage for stage in stages}
        selected: list[Stage] = []
        for raw in names:
            name = str(raw)
            stage = by_name.get(name)
            if stage is None:
                return None, "CONVERGENCE_GRAPH_MISMATCH"
            selected.append(stage)
        if next_index < 0 or next_index >= len(selected):
            return None, "CONVERGENCE_COMPLETE_OR_INVALID"
        return selected[next_index:], "CONVERGENCE_CURSOR"

    return None, "PHASE_UNKNOWN"


def _checkpoint_forward(root: Path, *, graph_signature: str, repair: bool, next_index: int, repair_count: int, seen_failures: dict[tuple[str, str], int], current_stage: str | None = None, full_convergence_required: bool = False, run_id: str | None = None) -> None:
    _write_checkpoint(root, {
        "graphSignature": graph_signature,
        "repair": repair,
        "phase": "forward",
        "nextIndex": next_index,
        "currentStage": current_stage,
        "runId": run_id or "",
        "repairCount": repair_count,
        "fullConvergenceRequired": bool(full_convergence_required),
        "seenFailures": [{"stage": key[0], "fingerprint": key[1], "count": value} for key, value in sorted(seen_failures.items())],
    })


def _record_failure_capsule(root: Path, result: StageResult) -> None:
    path = _checkpoint_path(root)
    if not path.is_file():
        return
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    state["lastFailureCapsule"] = _failure_capsule(result.output_tail, max_lines=24, max_chars=3200)
    _write_state_raw(path, state)


def _checkpoint_convergence(root: Path, *, graph_signature: str, repair: bool, next_index: int, repair_count: int, seen_failures: dict[tuple[str, str], int], convergence_stages: list[Stage] | None = None, current_stage: str | None = None, full_convergence_required: bool = False, run_id: str | None = None) -> None:
    _write_checkpoint(root, {
        "graphSignature": graph_signature,
        "repair": repair,
        "phase": "convergence",
        "nextIndex": next_index,
        "currentStage": current_stage,
        "runId": run_id or "",
        "repairCount": repair_count,
        "fullConvergenceRequired": bool(full_convergence_required),
        "convergenceStages": [stage.name for stage in (convergence_stages or [])],
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


def _execute_stages(root: Path, stages: list[Stage], *, repair: bool, max_repairs: int, codex_timeout: int, enforce_supply_chain: bool = True, emit_ready_result: bool = True, allow_owner_fix_adoption: bool = False) -> int:
    results: list[StageResult] = []
    graph_signature = _stage_graph_signature(stages, repair=repair)
    state = _load_checkpoint(root, graph_signature=graph_signature, repair=repair, allow_owner_fix_adoption=allow_owner_fix_adoption, stages=stages)
    if state and state.pop("_activeProcessLive", False):
        active = state.get("activeProcess") or {}
        print(
            f"AUTOPILOT_RESULT=RUNNING_REJOIN runId={state.get('runId','')} "
            f"pid={active.get('pid','')} stage={state.get('currentStage','')}",
            flush=True,
        )
        return 4
    seen_failures: dict[tuple[str, str], int] = _decode_seen_failures(state or {})
    repair_count = int((state or {}).get("repairCount", 0))
    full_convergence_required = bool((state or {}).get("fullConvergenceRequired", False))
    phase = str((state or {}).get("phase", "forward"))
    next_index = int((state or {}).get("nextIndex", 0))
    if next_index < 0 or next_index > len(stages):
        print("AUTOPILOT_RESUME=RESET reason=INDEX_INVALID", flush=True)
        _clear_checkpoint(root)
        phase = "forward"
        next_index = 0
        repair_count = 0
        full_convergence_required = False
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
                _checkpoint_forward(root, graph_signature=graph_signature, repair=repair, next_index=index, repair_count=repair_count, seen_failures=seen_failures, current_stage=stage.name, full_convergence_required=full_convergence_required, run_id=run_id)
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
                    _checkpoint_forward(root, graph_signature=graph_signature, repair=repair, next_index=index + 1, repair_count=repair_count, seen_failures=seen_failures, full_convergence_required=full_convergence_required, run_id=run_id)
                    break

                key = (stage.name, result.fingerprint)
                seen_failures[key] = seen_failures.get(key, 0) + 1
                _checkpoint_forward(root, graph_signature=graph_signature, repair=repair, next_index=index, repair_count=repair_count, seen_failures=seen_failures, current_stage=stage.name, full_convergence_required=full_convergence_required, run_id=run_id)
                _record_failure_capsule(root, result)
                if result.status == "TIMEOUT" and not repair:
                    print(f"AUTOPILOT_RESULT=ENVIRONMENT_BLOCKED stage={stage.name} reason=TIMEOUT_UNTRIAGED fingerprint={result.fingerprint}", flush=True)
                    return terminal(3, "ENVIRONMENT_BLOCKED", current_stage=stage.name, last_failure={"stage": stage.name, "specialist": _stage_specialist(stage), "status": result.status, "fingerprint": result.fingerprint, "reason": "TIMEOUT_UNTRIAGED"})
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
                before_repair = _workspace_manifest(root)
                before_repair_head = _git_head(root)
                ok, detail = invoke_codex(root, stage, result, repair_count, codex_timeout)
                after_repair_head = _git_head(root)
                after_repair = _workspace_manifest(root)
                changed_paths = _workspace_manifest_delta(before_repair, after_repair)
                git_ref_mutated = bool(before_repair_head and after_repair_head and before_repair_head != after_repair_head)
                if git_ref_mutated:
                    ok = False
                    detail = (
                        "AUTOPILOT_REPAIR_GIT_REF_MUTATION "
                        f"before={before_repair_head} after={after_repair_head}; "
                        "operator reconciliation required"
                    )
                    changed_paths = sorted(set(changed_paths + ["__GIT_HEAD__"]))
                repair_requires_full = git_ref_mutated or _repair_requires_full_convergence(stage, changed_paths)
                full_convergence_required = full_convergence_required or repair_requires_full
                event_log.append(
                    "repair-delta",
                    phase="forward",
                    stage=stage.name,
                    specialist=_stage_specialist(stage),
                    status="FULL_CONVERGENCE" if repair_requires_full else "OWNER_SCOPED",
                    reason=",".join(changed_paths[:12]),
                    repairCount=repair_count,
                )
                print(
                    f"AUTOPILOT_REPAIR_DELTA stage={stage.name} changed={len(changed_paths)} "
                    f"fullConvergence={str(repair_requires_full).lower()} "
                    f"paths={','.join(changed_paths[:12])}",
                    flush=True,
                )
                print(f"AUTOPILOT_CODEX_REPAIR iteration={repair_count} status={'PASS' if ok else 'BLOCKED'}", flush=True)
                if detail:
                    print(detail, flush=True)
                if not ok:
                    reason = "CODEX_UNAVAILABLE_OR_FAILED"
                    if detail.startswith("AUTOPILOT_REPAIR_GIT_REF_MUTATION"):
                        reason = "REPAIR_GIT_REF_MUTATION"
                    elif detail.startswith("AUTOPILOT_TRIAGE_BLOCKED classification="):
                        classification = detail.split("classification=", 1)[1].splitlines()[0].strip()
                        reason = "TRIAGE_" + classification
                    print(f"AUTOPILOT_RESULT=ENVIRONMENT_BLOCKED stage={stage.name} reason={reason}", flush=True)
                    return terminal(3, "ENVIRONMENT_BLOCKED", current_stage=stage.name, last_failure={"stage": stage.name, "specialist": _stage_specialist(stage), "status": result.status, "fingerprint": result.fingerprint, "reason": reason})
                # Codex intentionally changed the workspace. Persist the new
                # fingerprint while keeping the same failing-stage boundary so
                # a runner crash immediately after repair resumes by proving the
                # repaired owner stage rather than replaying earlier green work.
                _checkpoint_forward(root, graph_signature=graph_signature, repair=repair, next_index=index, repair_count=repair_count, seen_failures=seen_failures, current_stage=stage.name, full_convergence_required=full_convergence_required, run_id=run_id)

        # Repairs are incremental: rerun only the failing owner stage while
        # fixing, then execute one final no-repair convergence pass. Persist the
        # convergence cursor so a runner/process interruption does not replay
        # already-converged expensive stages.
        if repair and repair_count > 0:
            phase = "convergence"
            next_index = 0
            repaired_stage_names = {stage_name for (stage_name, _fingerprint_value), count in seen_failures.items() if count > 0}
            convergence_stages = list(stages) if full_convergence_required else _select_convergence_stages(stages, repaired_stage_names)
            convergence_mode = "full" if full_convergence_required else "selective"
            event_log.append("phase-transition", phase="convergence", status="RUNNING", nextIndex=0, repairCount=repair_count, reason=f"{convergence_mode}:{len(convergence_stages)}/{len(stages)}")
            print(f"AUTOPILOT_CONVERGENCE_PLAN mode={convergence_mode} selected={len(convergence_stages)} total={len(stages)} stages={','.join(stage.name for stage in convergence_stages)}", flush=True)
            _checkpoint_convergence(root, graph_signature=graph_signature, repair=repair, next_index=0, repair_count=repair_count, seen_failures=seen_failures, convergence_stages=convergence_stages, run_id=run_id)
        else:
            phase = "done"

    if phase == "convergence":
        convergence_state = _load_checkpoint(root, graph_signature=graph_signature, repair=repair, allow_owner_fix_adoption=allow_owner_fix_adoption, stages=stages) or {}
        configured_names = convergence_state.get("convergenceStages")
        if isinstance(configured_names, list) and configured_names:
            by_name = {stage.name: stage for stage in stages}
            convergence_stages = [by_name[name] for name in configured_names if name in by_name]
            if len(convergence_stages) != len(configured_names):
                print("AUTOPILOT_RESUME=RESET reason=CONVERGENCE_STAGE_DRIFT", flush=True)
                _clear_checkpoint(root)
                return 3
        else:
            # Backward-compatible fail-safe for checkpoints written before
            # selective convergence existed.
            convergence_stages = list(stages)
        convergence_index = int(convergence_state.get("nextIndex", next_index))
        if convergence_index < 0 or convergence_index > len(convergence_stages):
            print("AUTOPILOT_RESUME=RESET reason=CONVERGENCE_INDEX_INVALID", flush=True)
            _clear_checkpoint(root)
            return 3
        print(f"AUTOPILOT_CONVERGENCE_START stages={len(convergence_stages)} fullGraph={len(stages)} repairs={repair_count}", flush=True)
        _write_autopilot_report(root, stages=convergence_stages, graph_signature=graph_signature, repair=repair, phase="convergence", next_index=convergence_index, repair_count=repair_count, status="RUNNING", current_stage=None, stage_results=report_rows)
        index = convergence_index
        while index < len(convergence_stages):
            stage = convergence_stages[index]
            next_index = index
            _checkpoint_convergence(
                root,
                graph_signature=graph_signature,
                repair=repair,
                next_index=index,
                repair_count=repair_count,
                seen_failures=seen_failures,
                convergence_stages=convergence_stages,
                current_stage=stage.name,
                full_convergence_required=full_convergence_required,
                run_id=run_id,
            )
            _write_autopilot_report(root, stages=convergence_stages, graph_signature=graph_signature, repair=repair, phase="convergence", next_index=index, repair_count=repair_count, status="RUNNING", current_stage=stage.name, stage_results=report_rows)
            event_log.append("stage-start", phase="convergence", stage=stage.name, specialist=_stage_specialist(stage), status="RUNNING", nextIndex=index, repairCount=repair_count)
            print(f"AUTOPILOT_CONVERGENCE_STAGE_START name={stage.name} timeout={stage.timeout}", flush=True)
            result = run_stage(root, stage)
            results.append(result)
            report_rows.append(_report_result(stage, result))
            event_log.append("stage-result", phase="convergence", stage=stage.name, specialist=_stage_specialist(stage), status=result.status, returncode=result.returncode, fingerprint=result.fingerprint, nextIndex=index + (1 if result.status == "PASS" else 0), repairCount=repair_count)
            _write_autopilot_report(root, stages=convergence_stages, graph_signature=graph_signature, repair=repair, phase="convergence", next_index=index + (1 if result.status == "PASS" else 0), repair_count=repair_count, status="RUNNING" if result.status == "PASS" else result.status, current_stage=stage.name, stage_results=report_rows, last_failure=None if result.status == "PASS" else {"stage": stage.name, "specialist": _stage_specialist(stage), "status": result.status, "fingerprint": result.fingerprint})
            print(json.dumps(dataclasses.asdict(result), sort_keys=True), flush=True)
            if result.status == "PASS":
                index += 1
                next_index = index
                _checkpoint_convergence(
                    root,
                    graph_signature=graph_signature,
                    repair=repair,
                    next_index=index,
                    repair_count=repair_count,
                    seen_failures=seen_failures,
                    convergence_stages=convergence_stages,
                    full_convergence_required=full_convergence_required,
                    run_id=run_id,
                )
                continue

            key = (stage.name, result.fingerprint)
            seen_failures[key] = seen_failures.get(key, 0) + 1
            _checkpoint_convergence(
                root,
                graph_signature=graph_signature,
                repair=repair,
                next_index=index,
                repair_count=repair_count,
                seen_failures=seen_failures,
                convergence_stages=convergence_stages,
                current_stage=stage.name,
                full_convergence_required=full_convergence_required,
                run_id=run_id,
            )
            _record_failure_capsule(root, result)
            if result.status == "TIMEOUT" and not repair:
                print(f"AUTOPILOT_RESULT=ENVIRONMENT_BLOCKED stage={stage.name} reason=CONVERGENCE_TIMEOUT_UNTRIAGED fingerprint={result.fingerprint}", flush=True)
                return terminal(3, "ENVIRONMENT_BLOCKED", current_stage=stage.name, last_failure={"stage": stage.name, "specialist": _stage_specialist(stage), "status": result.status, "fingerprint": result.fingerprint, "reason": "CONVERGENCE_TIMEOUT_UNTRIAGED"})
            if not repair:
                print(f"AUTOPILOT_RESULT=CODE_DEFECT stage={stage.name} reason=CONVERGENCE_REGRESSION fingerprint={result.fingerprint}", flush=True)
                return terminal(2, "CODE_DEFECT", current_stage=stage.name, last_failure={"stage": stage.name, "specialist": _stage_specialist(stage), "status": result.status, "fingerprint": result.fingerprint, "reason": "CONVERGENCE_REGRESSION"})
            if seen_failures[key] >= 2:
                print(f"AUTOPILOT_RESULT=CODE_DEFECT stage={stage.name} reason=CONVERGENCE_NO_PROGRESS fingerprint={result.fingerprint}", flush=True)
                return terminal(2, "CODE_DEFECT", current_stage=stage.name, last_failure={"stage": stage.name, "specialist": _stage_specialist(stage), "status": result.status, "fingerprint": result.fingerprint, "reason": "CONVERGENCE_NO_PROGRESS"})
            if repair_count >= max_repairs:
                print(f"AUTOPILOT_RESULT=CODE_DEFECT stage={stage.name} reason=REPAIR_LIMIT fingerprint={result.fingerprint}", flush=True)
                return terminal(2, "CODE_DEFECT", current_stage=stage.name, last_failure={"stage": stage.name, "specialist": _stage_specialist(stage), "status": result.status, "fingerprint": result.fingerprint, "reason": "REPAIR_LIMIT"})

            repair_count += 1
            event_log.append("repair-start", phase="convergence", stage=stage.name, specialist=_stage_specialist(stage), status="REPAIRING", fingerprint=result.fingerprint, nextIndex=index, repairCount=repair_count)
            _write_autopilot_report(root, stages=convergence_stages, graph_signature=graph_signature, repair=repair, phase="convergence", next_index=index, repair_count=repair_count, status="REPAIRING", current_stage=stage.name, stage_results=report_rows, last_failure={"stage": stage.name, "specialist": _stage_specialist(stage), "status": result.status, "fingerprint": result.fingerprint})
            before_repair = _workspace_manifest(root)
            before_repair_head = _git_head(root)
            ok, detail = invoke_codex(root, stage, result, repair_count, codex_timeout)
            after_repair_head = _git_head(root)
            after_repair = _workspace_manifest(root)
            changed_paths = _workspace_manifest_delta(before_repair, after_repair)
            git_ref_mutated = bool(before_repair_head and after_repair_head and before_repair_head != after_repair_head)
            if git_ref_mutated:
                ok = False
                detail = (
                    "AUTOPILOT_REPAIR_GIT_REF_MUTATION "
                    f"before={before_repair_head} after={after_repair_head}; "
                    "operator reconciliation required"
                )
                changed_paths = sorted(set(changed_paths + ["__GIT_HEAD__"]))
            repair_requires_full = git_ref_mutated or _repair_requires_full_convergence(stage, changed_paths)
            full_convergence_required = full_convergence_required or repair_requires_full
            event_log.append(
                "repair-delta",
                phase="convergence",
                stage=stage.name,
                specialist=_stage_specialist(stage),
                status="FULL_CONVERGENCE" if repair_requires_full else "OWNER_SCOPED",
                reason=",".join(changed_paths[:12]),
                repairCount=repair_count,
            )
            print(
                f"AUTOPILOT_CONVERGENCE_REPAIR_DELTA stage={stage.name} changed={len(changed_paths)} "
                f"fullConvergence={str(repair_requires_full).lower()} paths={','.join(changed_paths[:12])}",
                flush=True,
            )
            print(f"AUTOPILOT_CODEX_REPAIR iteration={repair_count} phase=convergence status={'PASS' if ok else 'BLOCKED'}", flush=True)
            if detail:
                print(detail, flush=True)
            if not ok:
                reason = "CODEX_UNAVAILABLE_OR_FAILED"
                if detail.startswith("AUTOPILOT_REPAIR_GIT_REF_MUTATION"):
                    reason = "REPAIR_GIT_REF_MUTATION"
                elif detail.startswith("AUTOPILOT_TRIAGE_BLOCKED classification="):
                    classification = detail.split("classification=", 1)[1].splitlines()[0].strip()
                    reason = "TRIAGE_" + classification
                print(f"AUTOPILOT_RESULT=ENVIRONMENT_BLOCKED stage={stage.name} reason={reason}", flush=True)
                return terminal(3, "ENVIRONMENT_BLOCKED", current_stage=stage.name, last_failure={"stage": stage.name, "specialist": _stage_specialist(stage), "status": result.status, "fingerprint": result.fingerprint, "reason": reason})

            if repair_requires_full:
                convergence_stages = list(stages)
                index = 0
                next_index = 0
                event_log.append("convergence-expanded", phase="convergence", stage=stage.name, specialist=_stage_specialist(stage), status="FULL_CONVERGENCE", reason="cross-owner-or-runner-change", nextIndex=0, repairCount=repair_count)
                print(f"AUTOPILOT_CONVERGENCE_EXPAND_FULL reason=repair-scope stage={stage.name} stages={len(convergence_stages)}", flush=True)
                _checkpoint_convergence(
                    root,
                    graph_signature=graph_signature,
                    repair=repair,
                    next_index=0,
                    repair_count=repair_count,
                    seen_failures=seen_failures,
                    convergence_stages=convergence_stages,
                    full_convergence_required=True,
                    run_id=run_id,
                )
                continue

            # Owner-scoped repair: persist the new workspace fingerprint at the
            # same convergence cursor, then rerun only this stage. A crash here
            # resumes on the repaired owner proof rather than replaying earlier
            # convergence stages.
            _checkpoint_convergence(
                root,
                graph_signature=graph_signature,
                repair=repair,
                next_index=index,
                repair_count=repair_count,
                seen_failures=seen_failures,
                convergence_stages=convergence_stages,
                current_stage=stage.name,
                full_convergence_required=full_convergence_required,
                run_id=run_id,
            )
            print(f"AUTOPILOT_CONVERGENCE_REPAIR_RETRY stage={stage.name} index={index} repairs={repair_count}", flush=True)
        print(f"AUTOPILOT_CONVERGENCE_PASS stages={len(convergence_stages)} fullGraph={len(stages)} repairs={repair_count}", flush=True)

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


def run_autopilot(root: Path, *, repair: bool, max_repairs: int, codex_timeout: int, start_stage: str | None = None, stop_stage: str | None = None, real_test: bool = False, real_test_timeout: int = 7200, release_ready: bool = False, adopt_owner_fix: bool = False) -> int:
    lock = _AutopilotRunLock(root)
    try:
        lock.acquire()
    except RuntimeError as exc:
        print(f"AUTOPILOT_RESULT=ENVIRONMENT_BLOCKED reason={exc}", flush=True)
        return 3
    try:
        return _run_autopilot_locked(
            root,
            repair=repair,
            max_repairs=max_repairs,
            codex_timeout=codex_timeout,
            start_stage=start_stage,
            stop_stage=stop_stage,
            real_test=real_test,
            real_test_timeout=real_test_timeout,
            release_ready=release_ready,
            adopt_owner_fix=adopt_owner_fix,
        )
    finally:
        lock.release()


def _select_stages(root: Path, start_stage: str | None, stop_stage: str | None) -> list[Stage]:
    stages = canonical_stages(root)
    names = [stage.name for stage in stages]
    if start_stage:
        if start_stage not in names:
            raise SystemExit(f"unknown start stage {start_stage}")
        stages = stages[names.index(start_stage):]
    if stop_stage:
        current_names = [stage.name for stage in stages]
        if stop_stage not in current_names:
            raise SystemExit(f"unknown stop stage {stop_stage}")
        stages = stages[:current_names.index(stop_stage) + 1]
    return stages


def _run_autopilot_locked(root: Path, *, repair: bool, max_repairs: int, codex_timeout: int, start_stage: str | None = None, stop_stage: str | None = None, real_test: bool = False, real_test_timeout: int = 7200, release_ready: bool = False, adopt_owner_fix: bool = False) -> int:
    stages = _select_stages(root, start_stage, stop_stage)

    # Preflight only what this invocation can actually execute. Explicit stage
    # slices are already bounded; a valid durable full-run checkpoint narrows
    # prerequisites to its remaining forward/convergence cursor. Invalid/stale
    # checkpoints fail safe to the full toolchain. A still-live child requires
    # only rejoin/observe, so unrelated toolchains and Codex must not block it.
    explicit_slice = start_stage is not None or stop_stage is not None
    selected_for_preflight = stages if explicit_slice else None
    preflight_scope = "EXPLICIT_STAGE_SLICE" if explicit_slice else "FULL_INVOCATION"
    require_codex_preflight = repair
    resumed_scope, resume_reason = _resume_preflight_stage_scope(root, stages, repair=repair)
    if resumed_scope is not None:
        selected_for_preflight = resumed_scope
        preflight_scope = resume_reason
        if resume_reason in {"LIVE_REJOIN", "FORWARD_COMPLETE"}:
            require_codex_preflight = False
    print(
        "AUTOPILOT_PREFLIGHT_SCOPE authority=" + RESUME_PREFLIGHT_CURSOR_AUTHORITY
        + " mode=" + preflight_scope
        + " stages=" + ",".join(stage.name for stage in (selected_for_preflight or [])),
        flush=True,
    )
    missing, preflight_details = environment_preflight(require_codex=require_codex_preflight, stages=selected_for_preflight)
    print("AUTOPILOT_PREFLIGHT_DETAILS=" + json.dumps(preflight_details, sort_keys=True), flush=True)
    if missing:
        handoff = _environment_preflight_handoff(missing, selected_for_preflight)
        print("AUTOPILOT_PREFLIGHT=BLOCKED missing=" + ",".join(handoff["missing"]), flush=True)
        graph_signature = _stage_graph_signature(stages, repair=repair)
        _write_autopilot_report(
            root,
            stages=stages,
            graph_signature=graph_signature,
            repair=repair,
            phase="preflight",
            next_index=0,
            repair_count=0,
            status="ENVIRONMENT_BLOCKED",
            current_stage=None,
            stage_results=[],
            last_failure={
                "stage": "environment-preflight",
                "specialist": "environment",
                "status": "BLOCKED",
                "fingerprint": handoff["fingerprint"],
                "reason": "MISSING_PREREQUISITES:" + ",".join(handoff["missing"]),
            },
            environment_preflight=handoff,
        )
        print("AUTOPILOT_RESULT=ENVIRONMENT_BLOCKED reason=ENVIRONMENT_PREFLIGHT fingerprint=" + handoff["fingerprint"], flush=True)
        return 3
    print("AUTOPILOT_PREFLIGHT=PASS requireCodex=" + str(require_codex_preflight).lower(), flush=True)

    # Local correctness and external supply-chain closure are distinct states.
    # Codex repair owns deterministic repository defects; unresolved third-party
    # acquisition must not turn a clean codebase into a fake CODE_DEFECT result.
    rc = _execute_stages(root, stages, repair=repair, max_repairs=max_repairs, codex_timeout=codex_timeout, enforce_supply_chain=False, emit_ready_result=False, allow_owner_fix_adoption=adopt_owner_fix)
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

            # If the observer/controller dies mid-stage, the checkpoint retains
            # the exact PID/start-time identity. A later observer must rejoin the
            # still-live child and MUST NOT kill it or start a duplicate.
            graph = _stage_graph_signature(resume_stages, repair=False)
            _checkpoint_forward(root, graph_signature=graph, repair=False, next_index=1, repair_count=0, seen_failures={})
            stranded = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(30)"], cwd=root, start_new_session=True)
            try:
                _mark_active_process(root, stranded.pid, "self-test-stranded-stage")
                loaded = _load_checkpoint(root, graph_signature=graph, repair=False)
                if loaded is None or loaded.pop("_activeProcessLive", False) is not True:
                    raise AssertionError("live checkpoint process was not classified for rejoin")
                if stranded.poll() is not None:
                    raise AssertionError("resume observer terminated the still-live stage process")
                original_run_stage = globals()["run_stage"]
                def forbidden_run_stage(*_args, **_kwargs):
                    raise AssertionError("RUNNING_REJOIN started a duplicate stage")
                globals()["run_stage"] = forbidden_run_stage
                try:
                    rc = _execute_stages(root, resume_stages, repair=False, max_repairs=0, codex_timeout=10, enforce_supply_chain=False)
                finally:
                    globals()["run_stage"] = original_run_stage
                if rc != 4:
                    raise AssertionError(f"live checkpoint did not return RUNNING_REJOIN rc={rc}")
                if stranded.poll() is not None:
                    raise AssertionError("RUNNING_REJOIN path killed the live stage process")
            finally:
                if stranded.poll() is None:
                    try:
                        os.killpg(stranded.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    stranded.wait(timeout=5)
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
    ap.add_argument("--event-summary", action="store_true", help="print the latest structured autopilot event-log summary and exit")
    ap.add_argument("--agent-context", action="store_true", help="print the full bounded continuation/diagnostic capsule and exit")
    ap.add_argument("--agent-context-compact", action="store_true", help="print the minimal hard-budget continuation capsule intended for the next coding/test agent and exit")
    ap.add_argument("--agent-run", action="store_true", help="single-entry agent mode: durable resume/checkpoint + bounded owner repair with compact failure context")
    ap.add_argument("--adopt-owner-fix", action="store_true", help="resume after an external CODE_DEFECT fix only when Git HEAD is unchanged and every changed path remains inside the failing owner scope")
    ap.add_argument("--preflight", action="store_true", help="check deterministic test/repair host prerequisites without running the suite")
    ap.add_argument("--repair", action="store_true", help="invoke Codex on deterministic failures")
    ap.add_argument("--max-repairs", type=int, default=None, help="bounded campaign repair budget; defaults to 8 in --agent-run and 3 otherwise")
    ap.add_argument("--codex-timeout", type=int, default=1800)
    ap.add_argument("--start-stage")
    ap.add_argument("--stop-stage")
    ap.add_argument("--release-ready", action="store_true", help="require third-party supply-chain closure after local deterministic gates")
    ap.add_argument("--real-test", action="store_true", help="after deterministic gates and supply-chain closure, run destructive PostgreSQL certification and a prepared live Field Campaign")
    ap.add_argument("--real-test-timeout", type=int, default=7200, help="maximum Field Campaign watch duration in seconds")
    args = ap.parse_args()
    if args.agent_run:
        if args.self_test or args.event_summary or args.agent_context or args.agent_context_compact or args.preflight:
            raise SystemExit("--agent-run cannot be combined with reporting/self-test/preflight-only modes")
        args.repair = True
        args.adopt_owner_fix = True
    if args.max_repairs is None:
        args.max_repairs = DEFAULT_AGENT_REPAIR_BUDGET if args.agent_run else DEFAULT_REPAIR_BUDGET
    if args.agent_run:
        print(
            "AUTOPILOT_AGENT_RUN=ENABLED authority=AUTOPILOT_AGENT_ENTRYPOINT_V1 "
            + "repairBudgetAuthority=" + AGENT_REPAIR_BUDGET_AUTHORITY
            + " maxRepairs=" + str(args.max_repairs),
            flush=True,
        )
    if args.self_test:
        return self_test()
    if args.event_summary:
        print(json.dumps(_summarize_event_log(ROOT), sort_keys=True))
        return 0
    if args.agent_context:
        print(json.dumps(_agent_context(ROOT), sort_keys=True))
        return 0
    if args.agent_context_compact:
        print(json.dumps(_compact_agent_context(ROOT), sort_keys=True, separators=(",", ":")))
        return 0
    if args.preflight:
        selected = None
        if args.start_stage is not None or args.stop_stage is not None:
            selected = _select_stages(ROOT, args.start_stage, args.stop_stage)
        return print_environment_preflight(require_codex=args.repair, stages=selected)
    if args.max_repairs < 0 or args.max_repairs > 10:
        raise SystemExit("--max-repairs must be between 0 and 10")
    if args.real_test_timeout < 300 or args.real_test_timeout > 86400:
        raise SystemExit("--real-test-timeout must be between 300 and 86400 seconds")
    return run_autopilot(ROOT, repair=args.repair, max_repairs=args.max_repairs, codex_timeout=args.codex_timeout, start_stage=args.start_stage, stop_stage=args.stop_stage, real_test=args.real_test, real_test_timeout=args.real_test_timeout, release_ready=args.release_ready, adopt_owner_fix=args.adopt_owner_fix)


if __name__ == "__main__":
    raise SystemExit(main())
