#!/usr/bin/env python3
"""Deterministic, exact-SHA physical lab runner for 4SO Platform Factory.

AI is failure-only: it receives a compact normalized packet after a deterministic
stage fails. It cannot decide PASS, alter evidence, or promote Physical PASS.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
GUIDE_PATH = ROOT / "internal" / "labmodel" / "certification-matrix.json"
DEFAULT_PACKET_BYTES = 8 * 1024
MAX_PACKET_BYTES = 16 * 1024
DEFAULT_OUTPUT_TOKENS = 800
MAX_OUTPUT_TOKENS = 1200

_AI_SENSITIVE_KEY = re.compile(r"(?i)(password|passphrase|secret|token|api.?key|authorization|cookie|private.?key|client.?secret|credential)")
_AI_SECRET_PATTERNS = [
    re.compile(r"(?i)-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"(?i)\b(?:password|passphrase|client[_-]?secret|api[_-]?key|access[_-]?token|refresh[_-]?token|authorization)\s*[:=]\s*[^\s,;]+"),
]


def _redact_ai_value(value: Any) -> tuple[Any, int]:
    count = 0
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if _AI_SENSITIVE_KEY.search(str(key)) and not re.search(r"(?i)(digest|fingerprint|ref|certificate.?id)$", str(key)):
                out[key] = "[REDACTED]"
                count += 1
            else:
                out[key], nested = _redact_ai_value(item)
                count += nested
        return out, count
    if isinstance(value, list):
        out = []
        for item in value:
            clean, nested = _redact_ai_value(item)
            out.append(clean); count += nested
        return out, count
    if isinstance(value, str):
        clean = value
        for pattern in _AI_SECRET_PATTERNS:
            clean, n = pattern.subn("[REDACTED]", clean)
            count += n
        return clean, count
    return value, count


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        value = json.load(f)
    if not isinstance(value, dict):
        raise SystemExit(f"JSON document must be an object: {path}")
    return value


def guide() -> dict[str, Any]:
    value = _load_json(GUIDE_PATH)
    if value.get("authority") != "LAB_CERTIFICATION_MATRIX_V1":
        raise SystemExit("canonical lab guide authority is invalid")
    return value


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _tail(value: str, limit: int = 12000) -> str:
    value = value.replace("\x00", "")
    return value if len(value) <= limit else value[-limit:]


def _fingerprint(stage: str, rc: int, output: str) -> str:
    normalized = re.sub(r"\b\d{4}-\d\d-\d\d[T ][0-9:.+Z-]+\b", "<time>", output)
    normalized = re.sub(r"\b[0-9a-f]{64}\b", "<sha256>", normalized.lower())
    return hashlib.sha256(f"{stage}\n{rc}\n{normalized}".encode()).hexdigest()[:24]


def _release_identity(archive: Path) -> tuple[str, str, str]:
    if archive.is_symlink() or not archive.is_file() or archive.stat().st_size <= 0:
        raise SystemExit("releaseArtifact must be a non-empty regular ZIP file")
    with zipfile.ZipFile(archive) as zf:
        roots = sorted({name.split("/", 1)[0] for name in zf.namelist() if "/" in name})
        if len(roots) != 1:
            raise SystemExit("release artifact must contain one canonical root")
        root = roots[0]
        version = zf.read(root + "/VERSION").decode().strip()
        release_name = zf.read(root + "/RELEASE-NAME").decode().strip()
        if root != f"4so-platform-factory-{version}-{release_name}":
            raise SystemExit("release artifact root does not match VERSION/RELEASE-NAME")
    return root, version, _sha256(archive)


def _safe_extract(archive: Path, dest: Path) -> Path:
    root, _, _ = _release_identity(archive)
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True, mode=0o700)
    with zipfile.ZipFile(archive) as zf:
        for info in zf.infolist():
            name = info.filename
            if name.startswith("/") or "\\" in name or any(p in ("", ".", "..") for p in name.split("/")):
                raise SystemExit(f"non-canonical ZIP path: {name!r}")
            mode = (info.external_attr >> 16) & 0o777
            target = dest / name
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, target.open("wb") as out:
                shutil.copyfileobj(src, out)
            target.chmod(mode or 0o644)
    return dest / root


def _roles_for_tier(tier: str) -> list[str]:
    for row in guide()["serverTiers"]:
        if row["id"] == tier:
            return list(row["roles"])
    raise SystemExit(f"unknown server tier: {tier}")


def validate_spec(spec: dict[str, Any], *, require_bundle: bool = False) -> dict[str, Any]:
    if spec.get("apiVersion") != "platform.4so.io/v1alpha1" or spec.get("kind") != "LabExecution":
        raise SystemExit("lab spec must be platform.4so.io/v1alpha1 LabExecution")
    body = spec.get("spec")
    if not isinstance(body, dict):
        raise SystemExit("spec is required")
    tier = str(body.get("serverTier", "")).strip()
    required = _roles_for_tier(tier)
    servers = body.get("servers")
    if not isinstance(servers, list):
        raise SystemExit("spec.servers must be an array")
    role_map: dict[str, str] = {}
    for item in servers:
        if not isinstance(item, dict):
            raise SystemExit("each server must be an object")
        role, host = str(item.get("role", "")).strip(), str(item.get("host", "")).strip()
        if not role or not host or role in role_map:
            raise SystemExit("each server needs a unique non-empty role and host")
        role_map[role] = host
    missing = [role for role in required if role not in role_map]
    extras = [role for role in role_map if role not in required]
    if missing or extras:
        raise SystemExit(f"server inventory does not match tier {tier}; missing={missing} extras={extras}")
    canonical_hosts = [host.strip().lower() for host in role_map.values()]
    if len(set(canonical_hosts)) != len(canonical_hosts):
        raise SystemExit("lab server inventory must map every physical role to a distinct host; duplicate hosts would invalidate topology evidence")
    ssh = body.get("ssh")
    if not isinstance(ssh, dict) or str(ssh.get("user", "root")).strip() != "root":
        raise SystemExit("lab SSH user must be root")
    for key in ("identityFile", "knownHostsFile"):
        p = Path(str(ssh.get(key, ""))).expanduser()
        if not p.is_file() or p.is_symlink():
            raise SystemExit(f"ssh.{key} must be an existing regular non-symlink file")
        if key == "identityFile" and p.stat().st_mode & 0o077:
            raise SystemExit("SSH identityFile permissions must not allow group/other access")
    artifact = Path(str(body.get("releaseArtifact", ""))).expanduser()
    _release_identity(artifact)
    if require_bundle:
        bundle = Path(str(body.get("bundleDirectory", ""))).expanduser()
        if not bundle.is_dir() or bundle.is_symlink():
            raise SystemExit("LAB_BLOCKED LAB_IMMUTABLE_BUNDLE_AUTO_ACQUISITION_CLOSURE_PENDING: run requires a canonical bundleDirectory until automatic immutable acquisition is closed")
    return body


def _server_map(body: dict[str, Any]) -> dict[str, str]:
    return {str(v["role"]): str(v["host"]) for v in body["servers"]}


def _canonical_server_inventory(body: dict[str, Any]) -> dict[str, Any]:
    servers = sorted(
        ({"role": str(item["role"]).strip(), "host": str(item["host"]).strip().lower()} for item in body["servers"]),
        key=lambda item: item["role"],
    )
    return {"serverTier": str(body["serverTier"]).strip(), "servers": servers}


def _server_inventory_digest(body: dict[str, Any]) -> str:
    raw = json.dumps(_canonical_server_inventory(body), sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def plan_document(spec: dict[str, Any]) -> dict[str, Any]:
    body = validate_spec(spec)
    tier = body["serverTier"]
    program_guide = guide()
    management_roles = [r for r in _roles_for_tier(tier) if r.startswith("management")]
    active_install_row = "M01" if len(management_roles) == 1 else "M02"
    matrix = [row for row in program_guide["matrix"] if row["id"] in {"M00", active_install_row}]
    return {
        "authority": "LAB_EXECUTION_PLAN_V1",
        "serverTier": tier,
        "releaseSha256": _release_identity(Path(body["releaseArtifact"]).expanduser())[2],
        "serverInventoryDigest": _server_inventory_digest(body),
        "servers": _server_map(body),
        "managementRoles": management_roles,
        "matrixRows": matrix,
        "fullProgramMatrix": program_guide["matrix"],
        "runnerCoverage": program_guide.get("runner", {}),
        "deterministicRunner": True,
        "ai": {"mode": "failure-only", "canDecidePass": False, "canDecidePhysicalPass": False},
        "bundleAuthority": "provided-and-verified" if body.get("bundleDirectory") else "BLOCKED_PENDING_AUTOMATIC_IMMUTABLE_ACQUISITION",
    }


def _ssh_command(body: dict[str, Any], host: str, remote: str) -> list[str]:
    ssh = body["ssh"]
    return [
        "ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
        "-o", f"UserKnownHostsFile={Path(ssh['knownHostsFile']).expanduser()}",
        "-o", "ConnectTimeout=10", "-i", str(Path(ssh["identityFile"]).expanduser()),
        f"root@{host}", "--", "sh", "-ceu", shlex.quote(remote),
    ]


def _run(stage: str, command: list[str], *, cwd: Path, timeout: int, env: dict[str, str] | None = None) -> dict[str, Any]:
    started = time.monotonic()
    try:
        proc = subprocess.run(command, cwd=cwd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout, env=env)
        output = proc.stdout or ""
        rc = proc.returncode
    except subprocess.TimeoutExpired as exc:
        output = (exc.stdout or "") + "\nTIMEOUT"
        rc = 124
    except OSError as exc:
        output, rc = str(exc), 127
    return {
        "stage": stage, "command": command, "returnCode": rc, "durationSeconds": round(time.monotonic() - started, 3),
        "outputTail": _tail(output), "fingerprint": _fingerprint(stage, rc, output), "status": "PASS" if rc == 0 else "FAIL",
    }


def failure_packet(result: dict[str, Any], *, artifact_sha: str, server_role: str = "", facts: list[str] | None = None, byte_limit: int = DEFAULT_PACKET_BYTES) -> dict[str, Any]:
    packet = {
        "schemaVersion": 1, "artifactSha256": artifact_sha, "stage": result["stage"], "returnCode": result["returnCode"],
        "fingerprint": result["fingerprint"], "serverRole": server_role, "command": result["command"],
        "outputTail": result["outputTail"], "facts": facts or [],
        "constraints": ["AI does not decide PASS", "AI does not decide Physical PASS", "recommend owner-layer checks; do not invent evidence"],
    }
    packet, redaction_count = _redact_ai_value(packet)
    packet["redactionCount"] = redaction_count
    byte_limit = max(2048, min(int(byte_limit), MAX_PACKET_BYTES))
    while len(json.dumps(packet, separators=(",", ":")).encode()) > byte_limit and len(packet["outputTail"]) > 512:
        packet["outputTail"] = packet["outputTail"][len(packet["outputTail"]) // 4 :]
    return packet


def _platformctl_for_ai(cwd: Path) -> Path:
    candidates = [cwd / "bin" / "linux-amd64" / "platformctl", ROOT / "bin" / "linux-amd64" / "platformctl"]
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    raise RuntimeError("platformctl AI runtime binary is unavailable")


def _diagnosis_prompt(packet: dict[str, Any]) -> str:
    return (
        "Diagnose this deterministic 4SO Platform Factory lab failure. Return ONLY one JSON object with keys "
        "classification (product-defect|test-defect|environment|supply-chain|unknown), summary, owner, recommendedChecks (array max 5), "
        "recommendedFix, confidence (0-100). Do not claim PASS or Physical PASS. Packet:\n" + json.dumps(packet, separators=(",", ":"))
    )


def _diagnosis_schema() -> dict[str, Any]:
    return {
        "type": "object", "additionalProperties": False,
        "required": ["classification", "summary", "owner", "recommendedChecks", "recommendedFix", "confidence"],
        "properties": {
            "classification": {"enum": ["product-defect", "test-defect", "environment", "supply-chain", "unknown"]},
            "summary": {"type": "string"}, "owner": {"type": "string"},
            "recommendedChecks": {"type": "array", "maxItems": 5, "items": {"type": "string"}},
            "recommendedFix": {"type": "string"},
            "confidence": {"type": "integer", "minimum": 0, "maximum": 100},
        },
    }


def _validate_diagnosis(raw: str) -> dict[str, Any]:
    raw = raw.strip()
    if raw.startswith("```"):
        raise ValueError("AI output must be strict JSON without markdown")
    value = json.loads(raw)
    if not isinstance(value, dict) or value.get("classification") not in {"product-defect", "test-defect", "environment", "supply-chain", "unknown"}:
        raise ValueError("invalid diagnosis classification")
    checks = value.get("recommendedChecks", [])
    if not isinstance(checks, list) or len(checks) > 5:
        raise ValueError("recommendedChecks must contain at most five entries")
    if not isinstance(value.get("confidence"), int) or not 0 <= value["confidence"] <= 100:
        raise ValueError("confidence must be 0-100")
    return value


def diagnose(packet: dict[str, Any], config: dict[str, Any] | None, *, cwd: Path) -> dict[str, Any]:
    config = config or {}
    provider = str(config.get("provider", "none")).strip() or "none"
    if provider == "none":
        return {"status": "SKIPPED", "provider": "none"}
    packet, additional_redactions = _redact_ai_value(packet)
    if additional_redactions:
        packet["redactionCount"] = int(packet.get("redactionCount", 0)) + additional_redactions
    prompt = _diagnosis_prompt(packet)
    max_tokens = min(int(config.get("maxOutputTokens", DEFAULT_OUTPUT_TOKENS)), MAX_OUTPUT_TOKENS)
    try:
        if provider == "codex-cli":
            command = os.environ.get("PLATFORM_FACTORY_CODEX_COMMAND", "").strip()
            argv = shlex.split(command) if command else ["codex", "exec", "--ephemeral", "--skip-git-repo-check", "--sandbox", "read-only"]
            proc = subprocess.run(argv + [prompt], cwd=cwd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600)
            if proc.returncode:
                raise RuntimeError(_tail(proc.stdout or ""))
            parsed = _validate_diagnosis(proc.stdout)
        elif provider == "claude-code":
            schema = _diagnosis_schema()
            argv = ["claude", "-p", "--bare", "--no-session-persistence", "--output-format", "json", "--json-schema", json.dumps(schema), "--max-turns", str(min(int(config.get("maxTurns",2)),4))]
            budget = float(config.get("maxBudgetUSD", 1.0))
            if budget > 0:
                argv += ["--max-budget-usd", str(min(budget,20.0))]
            proc = subprocess.run(argv + [prompt], cwd=cwd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600)
            if proc.returncode:
                raise RuntimeError(_tail(proc.stdout or ""))
            envelope = json.loads(proc.stdout)
            candidate = envelope.get("structured_output") or envelope.get("result") or envelope
            parsed = candidate if isinstance(candidate, dict) else _validate_diagnosis(str(candidate))
            parsed = _validate_diagnosis(json.dumps(parsed))
        elif provider in {"openai-responses", "openai-compatible-chat"}:
            endpoint = str(config.get("endpoint", "")).strip()
            api_env = str(config.get("apiKeyEnv", "PLATFORM_FACTORY_AI_API_KEY"))
            api_key = os.environ.get(api_env, "").strip()
            model = str(config.get("model", "")).strip() or os.environ.get("PLATFORM_FACTORY_AI_MODEL", "").strip()
            if not model:
                raise RuntimeError("AI model is not configured")
            env = os.environ.copy()
            env["PLATFORM_FACTORY_AI_PROVIDER"] = provider
            env["PLATFORM_FACTORY_AI_MODEL"] = model
            env["PLATFORM_FACTORY_AI_MAX_OUTPUT_TOKENS"] = str(max_tokens)
            env["PLATFORM_FACTORY_AI_MAX_INPUT_BYTES"] = str(min(MAX_PACKET_BYTES, max(DEFAULT_PACKET_BYTES, int(config.get("maxInputBytes", MAX_PACKET_BYTES)))))
            if endpoint:
                env["PLATFORM_FACTORY_AI_ENDPOINT"] = endpoint
            if api_key:
                env["PLATFORM_FACTORY_AI_API_KEY"] = api_key
            with tempfile.TemporaryDirectory(prefix="4so-ai-packet-") as td:
                packet_path = Path(td) / "failure-packet.json"
                packet_path.write_text(json.dumps(packet, separators=(",", ":")), encoding="utf-8")
                packet_path.chmod(0o600)
                platformctl = _platformctl_for_ai(cwd)
                proc = subprocess.run([str(platformctl), "ai", "diagnose", "-f", str(packet_path)], cwd=cwd, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
            if proc.returncode:
                raise RuntimeError(_tail(proc.stdout or ""))
            envelope = json.loads(proc.stdout)
            parsed = envelope.get("diagnosis")
            if not isinstance(parsed, dict):
                raise RuntimeError("platformctl AI runtime did not return a diagnosis")
            parsed = _validate_diagnosis(json.dumps(parsed))
            return {"status": "OK", "provider": provider, "diagnosis": parsed, "runtime": envelope.get("runtime", {})}
        elif provider == "antigravity-command":
            command = str(config.get("command", "")).strip() or os.environ.get("PLATFORM_FACTORY_ANTIGRAVITY_COMMAND", "").strip()
            if not command:
                raise RuntimeError("Antigravity command adapter is not configured")
            proc = subprocess.run(shlex.split(command), cwd=cwd, input=prompt, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600)
            if proc.returncode:
                raise RuntimeError(_tail(proc.stdout or ""))
            parsed = _validate_diagnosis(proc.stdout)
        else:
            raise RuntimeError(f"unsupported AI provider: {provider}")
        return {"status": "OK", "provider": provider, "diagnosis": parsed}
    except Exception as exc:
        return {"status": "BLOCKED", "provider": provider, "error": _tail(str(exc), 2000)}


def _write_json(path: Path, value: Any, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.chmod(mode)
    os.replace(tmp, path)


def _preflight(spec: dict[str, Any], *, require_bundle: bool) -> dict[str, Any]:
    body = validate_spec(spec, require_bundle=require_bundle)
    artifact = Path(body["releaseArtifact"]).expanduser().resolve()
    _, version, artifact_sha = _release_identity(artifact)
    results = []
    verify = _run("M00-release-verify", [sys.executable, str(ROOT / "scripts" / "verify_release.py"), str(artifact)], cwd=ROOT, timeout=900)
    results.append(verify)
    if verify["status"] != "PASS":
        return {"status":"FAIL","artifactSha256":artifact_sha,"results":results,"ai":diagnose(failure_packet(verify, artifact_sha=artifact_sha), body.get("ai"), cwd=ROOT)}
    if require_bundle:
        bundle = Path(body["bundleDirectory"]).expanduser().resolve()
        extracted = Path(tempfile.mkdtemp(prefix="4so-lab-preflight-"))
        try:
            release_root = _safe_extract(artifact, extracted)
            platformctl = release_root / "bin" / "linux-amd64" / "platformctl"
            bundle_result = _run("bundle-verify", [str(platformctl), "appliance-bundle", "verify", "--dir", str(bundle)], cwd=release_root, timeout=300)
            results.append(bundle_result)
            if bundle_result["status"] != "PASS":
                return {"status":"FAIL","artifactSha256":artifact_sha,"results":results,"ai":diagnose(failure_packet(bundle_result, artifact_sha=artifact_sha, facts=["bundle must be immutable and digest locked"]), body.get("ai"), cwd=release_root)}
        finally:
            shutil.rmtree(extracted, ignore_errors=True)
    management_roles = _management_roles(body["serverTier"])
    server_map = _server_map(body)
    for role in management_roles:
        host = server_map[role]
        remote = r'''test "$(id -u)" -eq 0
command -v systemctl >/dev/null
command -v awk >/dev/null
command -v df >/dev/null
arch=$(uname -m)
cpu=$(getconf _NPROCESSORS_ONLN 2>/dev/null || nproc)
mem_kib=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
disk_kib=$(df -Pk /var/lib | awk 'NR==2 {print $4}')
printf 'LAB_HOST_FACTS arch=%s cpu=%s mem_kib=%s disk_kib=%s\n' "$arch" "$cpu" "$mem_kib" "$disk_kib"
test -w /var/lib'''
        result = _run(f"ssh-preflight:{role}", _ssh_command(body, host, remote), cwd=ROOT, timeout=30)
        results.append(result)
        if result["status"] != "PASS":
            return {"status":"FAIL","artifactSha256":artifact_sha,"results":results,"ai":diagnose(failure_packet(result, artifact_sha=artifact_sha, server_role=role), body.get("ai"), cwd=ROOT)}
        match = re.search(r"LAB_HOST_FACTS arch=(\S+) cpu=(\d+) mem_kib=(\d+) disk_kib=(\d+)", result["outputTail"])
        if not match:
            resource_result = {**result, "stage": f"resource-preflight:{role}", "returnCode": 2, "status": "FAIL", "outputTail": _tail(result["outputTail"] + "\nmissing parseable LAB_HOST_FACTS")}
            return {"status":"FAIL","artifactSha256":artifact_sha,"results":results+[resource_result],"ai":diagnose(failure_packet(resource_result, artifact_sha=artifact_sha, server_role=role), body.get("ai"), cwd=ROOT)}
        arch, cpu, mem_kib, disk_kib = match.group(1), int(match.group(2)), int(match.group(3)), int(match.group(4))
        minimums = {"cpu": 4, "memKiB": 16 * 1024 * 1024, "diskKiB": 100 * 1024 * 1024}
        resource_status = "PASS" if arch in {"x86_64", "aarch64", "arm64"} and cpu >= minimums["cpu"] and mem_kib >= minimums["memKiB"] and disk_kib >= minimums["diskKiB"] else "FAIL"
        resource_result = {"stage": f"resource-preflight:{role}", "command": ["deterministic-host-facts"], "returnCode": 0 if resource_status == "PASS" else 3, "durationSeconds": 0, "outputTail": f"arch={arch} cpu={cpu} memKiB={mem_kib} freeDiskKiB={disk_kib}; required cpu>=4 memGiB>=16 freeDiskGiB>=100", "fingerprint": _fingerprint(f"resource-preflight:{role}", 0 if resource_status == "PASS" else 3, f"{arch}:{cpu}:{mem_kib}:{disk_kib}"), "status": resource_status}
        results.append(resource_result)
        if resource_status != "PASS":
            return {"status":"FAIL","artifactSha256":artifact_sha,"results":results,"ai":diagnose(failure_packet(resource_result, artifact_sha=artifact_sha, server_role=role), body.get("ai"), cwd=ROOT)}
    deferred_roles = [role for role in _roles_for_tier(body["serverTier"]) if role not in management_roles]
    return {"status":"PASS","version":version,"artifactSha256":artifact_sha,"serverInventoryDigest":_server_inventory_digest(body),"results":results,"preflightCoverage":"MANAGEMENT_HOSTS_AND_EXACT_ARTIFACT","deferredTargetRoles":deferred_roles,"physicalPass":False}


def _management_roles(tier: str) -> list[str]:
    return [r for r in _roles_for_tier(tier) if r.startswith("management")]


def _install_request(body: dict[str, Any]) -> dict[str, Any]:
    roles = _management_roles(body["serverTier"])
    hosts = [_server_map(body)[r] for r in roles]
    mgmt = body.get("management") or {}
    ha = len(hosts) == 3
    public = str(mgmt.get("publicEndpoint", "")).strip() or f"https://{hosts[0]}"
    req: dict[str, Any] = {
        "profileId": "production-standard-ha" if ha else "evaluation-single-node",
        "connectivity": "connected",
        "infrastructure": {"provider":"existing-hosts","existingCluster":False,"nodeAddresses":hosts,"credentialRef":"secret://installer/ssh-private-key","sshUser":"root"},
        "network": {"publicEndpoint":public,"tlsMode":"managed-private-ca" if ha else "bootstrap-self-signed"},
        "services": {"git":{},"registry":{},"database":{},"objectStorage":{},"identity":{}},
        "acceptRisk": True,
    }
    if ha:
        req["infrastructure"]["storageClass"] = str(mgmt.get("storageClass", "replicated-rwx"))
        req["network"]["dnsZone"] = str(mgmt.get("dnsZone", "")).strip()
        obj = mgmt.get("objectStorage") or {}
        req["services"]["objectStorage"] = {"mode":"external","provider":"s3-compatible", **{k:v for k,v in obj.items() if v not in (None,"")}}
    return req


def _find_free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _post_json(url: str, token: str, path: str, payload: dict[str, Any]) -> dict[str, Any]:
    req = urllib.request.Request(url + path, data=json.dumps(payload).encode(), headers={"Content-Type":"application/json","Authorization":"Bearer "+token}, method="POST")
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read(1 << 20))


def _boot_id_from_result(result: dict[str, Any]) -> str:
    if result.get("status") != "PASS":
        return ""
    matches = re.findall(r"\b[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\b", str(result.get("outputTail", "")))
    return matches[-1].lower() if matches else ""


def _reboot_management_host(body: dict[str, Any], role: str, host: str, *, timeout: int = 600) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    before = _run(f"m01-boot-id-before:{role}", _ssh_command(body, host, "cat /proc/sys/kernel/random/boot_id"), cwd=ROOT, timeout=30)
    results.append(before)
    before_id = _boot_id_from_result(before)
    if not before_id:
        before = {**before, "status": "FAIL", "returnCode": before.get("returnCode", 2) or 2, "outputTail": _tail(str(before.get("outputTail", "")) + "\nmissing parseable boot_id before reboot")}
        results[-1] = before
        return results
    trigger_script = r'''before=$(cat /proc/sys/kernel/random/boot_id)
printf 'LAB_REBOOT_SCHEDULED boot_id=%s\n' "$before"
nohup sh -c 'sleep 1; systemctl reboot' >/dev/null 2>&1 &
'''
    trigger = _run(f"m01-reboot-trigger:{role}", _ssh_command(body, host, trigger_script), cwd=ROOT, timeout=30)
    results.append(trigger)
    if trigger["status"] != "PASS":
        return results
    deadline = time.time() + timeout
    last_probe: dict[str, Any] | None = None
    while time.time() < deadline:
        time.sleep(3)
        probe = _run(f"m01-boot-id-after:{role}", _ssh_command(body, host, "cat /proc/sys/kernel/random/boot_id"), cwd=ROOT, timeout=20)
        last_probe = probe
        after_id = _boot_id_from_result(probe)
        if probe["status"] == "PASS" and after_id and after_id != before_id:
            results.append(probe)
            service = _run(
                f"m01-service-after-reboot:{role}",
                _ssh_command(body, host, "systemctl is-active --quiet 4so-platform-installer.service && systemctl is-enabled --quiet 4so-platform-installer.service"),
                cwd=ROOT,
                timeout=30,
            )
            results.append(service)
            return results
    detail = "host did not return with a different boot_id before reboot timeout"
    if last_probe and last_probe.get("outputTail"):
        detail += "; last probe: " + _tail(str(last_probe["outputTail"]), 1200)
    timeout_result = {
        "stage": f"m01-reboot-wait:{role}", "command": ["deterministic-boot-id-change"], "returnCode": 4,
        "durationSeconds": timeout, "outputTail": detail,
        "fingerprint": _fingerprint(f"m01-reboot-wait:{role}", 4, detail), "status": "FAIL",
    }
    results.append(timeout_result)
    return results


def _execute_management_install(spec: dict[str, Any], state_dir: Path) -> dict[str, Any]:
    body = validate_spec(spec, require_bundle=True)
    artifact = Path(body["releaseArtifact"]).expanduser().resolve()
    root_name, version, artifact_sha = _release_identity(artifact)
    inventory_digest = _server_inventory_digest(body)
    release_root = _safe_extract(artifact, state_dir / "artifact")
    bundle = Path(body["bundleDirectory"]).expanduser().resolve()
    platformctl = release_root / "bin" / "linux-amd64" / "platformctl"
    installer = release_root / "bin" / "linux-amd64" / "platform-installer"
    mgmt_roles = _management_roles(body["serverTier"])
    primary_role = mgmt_roles[0]
    primary = _server_map(body)[primary_role]
    generated = state_dir / "generated"
    host_spec = {
        "apiVersion":"platform.4so.io/v1alpha1","kind":"InstallerHostDeployment","metadata":{"name":"lab-installer","version":version},
        "spec":{"installerBinary":str(installer),"bundleDirectory":str(bundle),"listen":"127.0.0.1:9443","executionEnabled":True,"allowInsecureHttp":False,"tls":{},"health":{"path":"/healthz","timeoutSeconds":120,"intervalMilliseconds":500},"service":{"enable":True,"start":True},"admission":{"allowDowngrade":False}}
    }
    host_spec_path = generated / "installer-host.json"; _write_json(host_spec_path, host_spec)
    remote_spec = {
        "apiVersion":"platform.4so.io/v1alpha1","kind":"InstallerRemoteBootstrap","metadata":{"name":"lab-installer","version":version},
        "spec":{"target":{"host":primary,"user":"root","identityFile":str(Path(body["ssh"]["identityFile"]).expanduser().resolve()),"knownHostsFile":str(Path(body["ssh"]["knownHostsFile"]).expanduser().resolve()),"root":"/"},"platformctlBinary":str(platformctl),"deploymentSpec":str(host_spec_path)}
    }
    remote_spec_path = generated / "remote-bootstrap.json"; _write_json(remote_spec_path, remote_spec)
    install_req_path = generated / "installation-request.json"; _write_json(install_req_path, _install_request(body))
    token_file = state_dir / "installer.token"
    campaign = state_dir / "campaign.json"
    evidence = state_dir / "field-evidence.json"
    results: list[dict[str, Any]] = []
    for stage, command, timeout in [
        ("installer-remote-preflight", [str(platformctl),"installer-remote","preflight","--spec",str(remote_spec_path)], 300),
        ("installer-remote-plan", [str(platformctl),"installer-remote","plan","--spec",str(remote_spec_path)], 300),
        ("installer-remote-apply", [str(platformctl),"installer-remote","apply","--spec",str(remote_spec_path),"--confirmation","DEPLOY"], 1800),
        ("installer-remote-verify", [str(platformctl),"installer-remote","verify","--spec",str(remote_spec_path)], 300),
        ("installer-export-access", [str(platformctl),"installer-remote","export-access","--spec",str(remote_spec_path),"--out-token-file",str(token_file),"--confirmation","EXPORT"], 300),
    ]:
        r = _run(stage, command, cwd=release_root, timeout=timeout); results.append(r)
        if r["status"] != "PASS":
            return {"status":"FAIL","artifactSha256":artifact_sha,"results":results,"ai":diagnose(failure_packet(r, artifact_sha=artifact_sha, server_role=primary_role), body.get("ai"), cwd=release_root)}
    token = token_file.read_text().strip()
    local_port = _find_free_port()
    ssh = body["ssh"]
    tunnel_cmd = ["ssh","-N","-o","ExitOnForwardFailure=yes","-o","BatchMode=yes","-o","StrictHostKeyChecking=yes","-o",f"UserKnownHostsFile={Path(ssh['knownHostsFile']).expanduser()}","-i",str(Path(ssh["identityFile"]).expanduser()),"-L",f"127.0.0.1:{local_port}:127.0.0.1:9443",f"root@{primary}"]
    tunnel = subprocess.Popen(tunnel_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        url = f"http://127.0.0.1:{local_port}"
        deadline = time.time() + 20
        while time.time() < deadline:
            try:
                req = urllib.request.Request(url+"/healthz", headers={"Authorization":"Bearer "+token})
                with urllib.request.urlopen(req, timeout=2) as resp:
                    if resp.status == 200: break
            except Exception: time.sleep(.3)
        else:
            out = tunnel.stdout.read() if tunnel.stdout else ""
            r={"stage":"installer-ssh-tunnel","command":tunnel_cmd,"returnCode":1,"durationSeconds":20,"outputTail":_tail(out),"fingerprint":_fingerprint("installer-ssh-tunnel",1,out),"status":"FAIL"}
            results.append(r); return {"status":"FAIL","artifactSha256":artifact_sha,"results":results,"ai":diagnose(failure_packet(r, artifact_sha=artifact_sha, server_role=primary_role), body.get("ai"), cwd=release_root)}
        private_key = Path(ssh["identityFile"]).expanduser().read_text()
        known_hosts = Path(ssh["knownHostsFile"]).expanduser().read_text()
        _post_json(url, token, "/api/v1/secrets/ssh-private-key", {"privateKey":private_key.strip()})
        _post_json(url, token, "/api/v1/secrets/ssh-known-hosts", {"knownHosts":known_hosts.strip()})
        commands = [
            ("field-campaign-prepare", [str(platformctl),"field-campaign","prepare","--installer-url",url,"--request",str(install_req_path),"--state",str(campaign),"--release-artifact",str(artifact),"--token-file",str(token_file)], 300),
            ("field-campaign-start", [str(platformctl),"field-campaign","start","--state",str(campaign),"--confirmation","INSTALL","--token-file",str(token_file)], 300),
            ("field-campaign-watch", [str(platformctl),"field-campaign","watch","--state",str(campaign),"--poll-interval","5s","--timeout","2h","--token-file",str(token_file)], 7500),
            ("field-campaign-collect", [str(platformctl),"field-campaign","collect","--state",str(campaign),"--out",str(evidence),"--release-artifact",str(artifact),"--token-file",str(token_file)], 300),
        ]
        for stage, command, timeout in commands:
            r=_run(stage,command,cwd=release_root,timeout=timeout); results.append(r)
            if r["status"] != "PASS":
                # Produce canonical installer diagnosis first, then optional AI advice.
                diag_path=state_dir/"field-diagnostic.json"
                diag=_run("field-campaign-diagnose",[str(platformctl),"field-campaign","diagnose","--state",str(campaign),"--out",str(diag_path),"--token-file",str(token_file)],cwd=release_root,timeout=300)
                results.append(diag)
                facts=[]
                if diag_path.is_file(): facts=[_tail(diag_path.read_text(errors="replace"),4000)]
                return {"status":"FAIL","artifactSha256":artifact_sha,"results":results,"ai":diagnose(failure_packet(r,artifact_sha=artifact_sha,server_role=primary_role,facts=facts),body.get("ai"),cwd=release_root)}
    finally:
        tunnel.terminate()
        try: tunnel.wait(timeout=5)
        except subprocess.TimeoutExpired: tunnel.kill()

    post_restart_evidence = ""
    m01_restart_certified = False
    if len(mgmt_roles) == 1:
        reboot_results = _reboot_management_host(body, primary_role, primary)
        results.extend(reboot_results)
        failed_reboot = next((item for item in reboot_results if item.get("status") != "PASS"), None)
        if failed_reboot is not None:
            return {"status":"FAIL","artifactSha256":artifact_sha,"serverInventoryDigest":inventory_digest,"results":results,"ai":diagnose(failure_packet(failed_reboot, artifact_sha=artifact_sha, server_role=primary_role, facts=["M01 requires a real boot_id change and installer service recovery"]), body.get("ai"), cwd=release_root)}
        verify_after = _run("m01-installer-verify-after-reboot", [str(platformctl),"installer-remote","verify","--spec",str(remote_spec_path)], cwd=release_root, timeout=300)
        results.append(verify_after)
        if verify_after["status"] != "PASS":
            return {"status":"FAIL","artifactSha256":artifact_sha,"serverInventoryDigest":inventory_digest,"results":results,"ai":diagnose(failure_packet(verify_after, artifact_sha=artifact_sha, server_role=primary_role, facts=["M01 post-reboot installer verification failed"]), body.get("ai"), cwd=release_root)}
        # Reuse the same local port because campaign state binds InstallerURL to it.
        tunnel = subprocess.Popen(tunnel_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        try:
            deadline = time.time() + 30
            while time.time() < deadline:
                try:
                    req = urllib.request.Request(url+"/healthz", headers={"Authorization":"Bearer "+token})
                    with urllib.request.urlopen(req, timeout=2) as resp:
                        if resp.status == 200:
                            break
                except Exception:
                    time.sleep(.5)
            else:
                out = tunnel.stdout.read() if tunnel.stdout else ""
                tunnel_failure={"stage":"m01-installer-tunnel-after-reboot","command":tunnel_cmd,"returnCode":1,"durationSeconds":30,"outputTail":_tail(out),"fingerprint":_fingerprint("m01-installer-tunnel-after-reboot",1,out),"status":"FAIL"}
                results.append(tunnel_failure)
                return {"status":"FAIL","artifactSha256":artifact_sha,"serverInventoryDigest":inventory_digest,"results":results,"ai":diagnose(failure_packet(tunnel_failure,artifact_sha=artifact_sha,server_role=primary_role),body.get("ai"),cwd=release_root)}
            post_path = state_dir / "field-evidence-post-restart.json"
            post_collect = _run("m01-field-campaign-collect-after-reboot", [str(platformctl),"field-campaign","collect","--state",str(campaign),"--out",str(post_path),"--release-artifact",str(artifact),"--token-file",str(token_file)], cwd=release_root, timeout=300)
            results.append(post_collect)
            if post_collect["status"] != "PASS":
                return {"status":"FAIL","artifactSha256":artifact_sha,"serverInventoryDigest":inventory_digest,"results":results,"ai":diagnose(failure_packet(post_collect,artifact_sha=artifact_sha,server_role=primary_role,facts=["M01 exact-SHA field evidence must remain collectable after host reboot"]),body.get("ai"),cwd=release_root)}
            post_restart_evidence = str(post_path)
            m01_restart_certified = True
        finally:
            tunnel.terminate()
            try: tunnel.wait(timeout=5)
            except subprocess.TimeoutExpired: tunnel.kill()

    return {"status":"PASS","artifactSha256":artifact_sha,"serverInventoryDigest":inventory_digest,"releaseRoot":root_name,"results":results,"evidence":post_restart_evidence or str(evidence),"preRestartEvidence":str(evidence),"m01RestartCertified":m01_restart_certified,"physicalPass":False,"physicalPassReason":"management install success alone is not the four-layer release Physical PASS"}


def self_test() -> int:
    g=guide()
    assert len(g["serverTiers"])==4 and len(g["matrix"])==14
    fake={"stage":"x","command":["false"],"returnCode":1,"durationSeconds":0,"outputTail":"x"*50000,"fingerprint":"abc","status":"FAIL"}
    p=failure_packet(fake,artifact_sha="0"*64)
    assert len(json.dumps(p,separators=(",",":")).encode()) <= MAX_PACKET_BYTES
    assert diagnose(p,{"provider":"none"},cwd=ROOT)["status"]=="SKIPPED"
    print("LAB_RUNNER_SELF_TEST_PASS")
    return 0


def main() -> int:
    ap=argparse.ArgumentParser(description="4SO Platform Factory deterministic physical lab runner")
    sub=ap.add_subparsers(dest="command",required=True)
    sub.add_parser("guide")
    sub.add_parser("self-test")
    for name in ("plan","preflight","run"):
        p=sub.add_parser(name); p.add_argument("--spec",required=True)
        if name=="run":
            p.add_argument("--state-dir",required=True); p.add_argument("--confirmation",required=True)
    args=ap.parse_args()
    if args.command=="guide": print(json.dumps(guide(),indent=2)); return 0
    if args.command=="self-test": return self_test()
    spec=_load_json(Path(args.spec).expanduser())
    if args.command=="plan": print(json.dumps(plan_document(spec),indent=2)); return 0
    if args.command=="preflight":
        result=_preflight(spec,require_bundle=False); print(json.dumps(result,indent=2)); return 0 if result["status"]=="PASS" else 2
    if args.confirmation!="RUN_LAB": raise SystemExit("confirmation must be exactly RUN_LAB")
    state=Path(args.state_dir).expanduser().resolve(); state.mkdir(parents=True,exist_ok=True); state.chmod(0o700)
    pre=_preflight(spec,require_bundle=True); _write_json(state/"preflight.json",pre)
    if pre["status"]!="PASS": print(json.dumps(pre,indent=2)); return 2
    result=_execute_management_install(spec,state); _write_json(state/"result.json",result)
    print(json.dumps(result,indent=2)); return 0 if result["status"]=="PASS" else 3


if __name__=="__main__": raise SystemExit(main())
