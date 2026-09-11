#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

SECRET = "Bearer ai-native-smoke-secret-token-123456789"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def request(url: str, method: str = "GET", body=None, headers=None):
    data = None if body is None else json.dumps(body).encode()
    current = dict(headers or {})
    if data is not None:
        current["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=current)
    try:
        with urllib.request.urlopen(req, timeout=8) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else None, dict(response.headers)
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        payload = json.loads(raw) if raw else None
        raise AssertionError(f"HTTP {exc.code} {url}: {payload}") from exc


def request_any(url: str, method: str = "GET", body=None, headers=None):
    data = None if body is None else json.dumps(body).encode()
    current = dict(headers or {})
    if data is not None:
        current["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=current)
    try:
        with urllib.request.urlopen(req, timeout=8) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else None, dict(response.headers)
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        return exc.code, json.loads(raw) if raw else None, dict(exc.headers)



class ProviderState:
    def __init__(self):
        self.calls = 0
        self.bodies: list[dict] = []
        self.lock = threading.Lock()
        self.crash_entered = threading.Event()
        self.crash_release = threading.Event()


class MockProviderHandler(BaseHTTPRequestHandler):
    state: ProviderState

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        body = json.loads(raw)
        with self.state.lock:
            self.state.calls += 1
            self.state.bodies.append(body)
        if "crash-boundary" in json.dumps(body, sort_keys=True):
            self.state.crash_entered.set()
            self.state.crash_release.wait(timeout=10)
        diagnosis = {
            "classification": "environment",
            "summary": "The deterministic lab evidence indicates an environment-side connectivity failure.",
            "owner": "lab-runtime",
            "recommendedChecks": ["Verify the target route and API reachability."],
            "recommendedFix": "Restore target connectivity, then rerun the deterministic lab check.",
            "confidence": 93,
        }
        payload = {
            "output_text": json.dumps(diagnosis, separators=(",", ":")),
            "usage": {
                "input_tokens": 123,
                "output_tokens": 45,
                "input_tokens_details": {"cached_tokens": 23},
            },
        }
        encoded = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        try:
            self.wfile.write(encoded)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, *_args):
        return


def start_provider():
    state = ProviderState()
    handler = type("BoundMockProviderHandler", (MockProviderHandler,), {"state": state})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, state, f"http://127.0.0.1:{server.server_address[1]}/v1/responses"


def start_api(binary: Path, root: Path, state_file: Path, provider_url: str):
    port = free_port()
    env = os.environ.copy()
    env.update(
        {
            "PLATFORM_FACTORY_LISTEN": f"127.0.0.1:{port}",
            "PLATFORM_FACTORY_STATE_FILE": str(state_file),
            "PLATFORM_FACTORY_DEVELOPMENT_MODE": "true",
            "PLATFORM_FACTORY_AI_PROVIDER": "openai-responses",
            "PLATFORM_FACTORY_AI_RESPONSES_URL": provider_url,
            "PLATFORM_FACTORY_AI_MODEL": "smoke-model",
            "PLATFORM_FACTORY_AI_MAX_INPUT_BYTES": "8192",
            "PLATFORM_FACTORY_AI_MAX_OUTPUT_TOKENS": "300",
            "PLATFORM_FACTORY_AI_TIMEOUT": "5s",
        }
    )
    proc = subprocess.Popen(
        [str(binary)],
        cwd=root,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    base = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            status, _, _ = request(base + "/readyz")
            if status == 200:
                return proc, base
        except Exception:
            time.sleep(0.1)
    output = ""
    if proc.poll() is not None and proc.stdout is not None:
        output = proc.stdout.read()
    stop(proc)
    raise RuntimeError("AI smoke API did not become ready: " + output[-2000:])


def stop(proc):
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def crash(proc):
    # A crash-boundary negative control must not exercise graceful shutdown.
    # SIGKILL ensures the process cannot terminalize an in-flight DISPATCHED
    # claim while waiting for the provider response.
    if proc.poll() is None:
        proc.kill()
        proc.wait(timeout=5)


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: smoke_ai_control_plane.py /path/to/platform-api")
    binary = Path(sys.argv[1]).resolve()
    if not binary.is_file():
        raise SystemExit(f"platform-api binary not found: {binary}")
    root = Path(__file__).resolve().parents[1]
    provider, provider_state, provider_url = start_provider()
    try:
        with tempfile.TemporaryDirectory() as td:
            state_file = Path(td) / "state" / "control-plane.json"
            proc, base = start_api(binary, root, state_file, provider_url)
            try:
                actor = {"X-Actor-ID": "ai-smoke-operator"}
                status, policy, _ = request(base + "/api/v1/ai/policy")
                assert status == 200
                assert policy["runtimeAuthority"] == "UNIFIED_AI_RUNTIME_V1"
                assert policy["providerTransportAuthority"] == "AI_PROVIDER_TRANSPORT_AUTHORITY_V2"
                assert policy["providerDispatchAuthority"] == "AI_PROVIDER_DISPATCH_AUTHORITY_V1"
                assert policy["providerResultCommitAuthority"] == "AI_PROVIDER_RESULT_COMMIT_AUTHORITY_V2"
                assert policy["enabled"] is True and policy["provider"] == "openai-responses"
                assert policy["redactionRequired"] is True and policy["structuredOutputRequired"] is True
                assert policy["rawPromptPersisted"] is False
                assert policy["canDecidePass"] is False and policy["canDecidePhysicalPass"] is False

                registry = json.loads((root / "internal" / "api" / "mcp_route_parity_registry.json").read_text())
                expected_counts = registry["counts"]
                expected_route_count = registry["routeCount"]
                expected_ai_callable = expected_route_count - expected_counts["security-excluded"]
                expected_durable_mutations = sum(
                    1 for route in registry["routes"] if route.get("durableJob") is True
                )

                status, capabilities, _ = request(base + "/api/v1/ai/capabilities")
                assert status == 200
                assert capabilities["authority"] == registry["authority"] == "MCP_ROUTE_PARITY_AUTHORITY_V1"
                assert capabilities["routeCount"] == expected_route_count
                assert capabilities["routeDispositionCoveragePercent"] == 100
                assert capabilities["counts"] == expected_counts
                assert capabilities["aiCallableRoutes"] == expected_ai_callable
                assert capabilities["durableMutationAuthority"] == "MCP_DURABLE_CONTROL_JOB_AUTHORITY_V1"
                assert capabilities["durableMutationRoutes"] == expected_durable_mutations
                assert capabilities["durableMutationCoveragePercent"] == 100
                assert capabilities["idempotencyRequired"] is True and capabilities["terminalReplay"] is True
                assert capabilities["expiredInFlightPolicy"] == "RECOVERY_REQUIRED_NO_AUTOMATIC_REDISPATCH"
                assert capabilities["arbitraryRouteAllowed"] is False
                assert capabilities["rawCredentialAccess"] is False
                assert capabilities["canDecidePass"] is False and capabilities["canDecidePhysicalPass"] is False
                assert capabilities["persianWritingAuthority"] == "PERSIAN_WRITING_GATE_V1"
                assert capabilities["persianWritingUpstream"] == "ali2000hos/persian-writing@1.3.5"
                assert capabilities["persianWritingRegister"] == "formal-but-human"
                status, persian_writing, _ = request(base + "/api/v1/ai/persian-writing")
                assert status == 200
                assert persian_writing["authority"] == "PERSIAN_WRITING_INTEGRATION_V1"
                assert persian_writing["gateAuthority"] == "PERSIAN_WRITING_GATE_V1"
                assert persian_writing["upstream"]["version"] == "1.3.5"
                assert persian_writing["upstream"]["commit"] == "118c2167f30cafe18df13c0ba85f98f50dad1894"
                assert persian_writing["runtimeNetworkDependency"] is False
                assert persian_writing["fontAssetsRedistributed"] is False

                status, org, _ = request(
                    base + "/api/v1/organizations",
                    "POST",
                    {"name": "ai-smoke-org", "displayName": "AI Smoke Organization"},
                    actor,
                )
                assert status == 201
                status, project, _ = request(
                    base + "/api/v1/projects",
                    "POST",
                    {"organizationId": org["id"], "name": "ai-smoke", "displayName": "AI Smoke"},
                    actor,
                )
                assert status == 201
                operation_body = {
                    "projectId": project["id"],
                    "kind": "lab.diagnose",
                    "targetRef": "cluster/ai-smoke",
                    "desiredRevision": "sha256:" + "1" * 64,
                    "risk": "low",
                }
                operation_headers = dict(actor)
                operation_headers["Idempotency-Key"] = "ai-smoke-operation"
                status, operation, _ = request(base + "/api/v1/operations", "POST", operation_body, operation_headers)
                assert status == 201

                diagnose_headers = dict(actor)
                diagnose_headers["Idempotency-Key"] = "ai-smoke-diagnosis"
                diagnosis_body = {
                    "projectId": project["id"],
                    "operationId": operation["id"],
                    "question": "Diagnose this failure. Authorization: " + SECRET,
                }
                status, diagnosis, _ = request(base + "/api/v1/ai/diagnose", "POST", diagnosis_body, diagnose_headers)
                assert status == 201
                assert diagnosis["advisoryOnly"] is True and diagnosis["executionAllowed"] is False
                assert diagnosis["idempotentReplay"] is False
                assert diagnosis["diagnosis"]["classification"] == "environment"
                run = diagnosis["run"]
                assert run["projectId"] == project["id"] and run["linkedResourceId"] == operation["id"]
                assert run["redactionCount"] >= 1
                assert run["inputTokens"] == 123 and run["cachedTokens"] == 23 and run["outputTokens"] == 45
                assert run["promptDigest"].startswith("sha256:") and run["contextDigest"].startswith("sha256:")
                assert run["outputDigest"].startswith("sha256:") and run["requestDigest"].startswith("sha256:")

                persisted_after_success = json.loads(state_file.read_text())
                successful_claims = [claim for claim in persisted_after_success["snapshot"].get("aiExecutionClaims", []) if claim.get("idempotencyKey") == "ai-smoke-diagnosis"]
                assert len(successful_claims) == 1 and successful_claims[0]["state"] == "COMPLETED" and successful_claims[0]["aiRunId"] == run["id"], successful_claims

                with provider_state.lock:
                    assert provider_state.calls == 1
                    provider_body = json.dumps(provider_state.bodies[0], sort_keys=True)
                assert SECRET not in provider_body
                assert "ai-native-smoke-secret-token-123456789" not in provider_body
                assert "redacted" in provider_body.lower(), provider_body

                status, replay, _ = request(base + "/api/v1/ai/diagnose", "POST", diagnosis_body, diagnose_headers)
                assert status == 200 and replay["idempotentReplay"] is True
                assert replay["run"]["id"] == run["id"]
                with provider_state.lock:
                    assert provider_state.calls == 1, "idempotent replay performed a second model call"

                crash_headers = dict(actor)
                crash_headers["Idempotency-Key"] = "ai-smoke-crash-boundary"
                crash_body = {
                    "projectId": project["id"],
                    "operationId": operation["id"],
                    "question": "crash-boundary provider call",
                }
                crash_error: list[BaseException] = []
                def issue_crash_request():
                    try:
                        request(base + "/api/v1/ai/diagnose", "POST", crash_body, crash_headers)
                    except BaseException as exc:  # API is intentionally terminated mid-call.
                        crash_error.append(exc)
                crash_thread = threading.Thread(target=issue_crash_request, daemon=True)
                crash_thread.start()
                assert provider_state.crash_entered.wait(timeout=5), "provider never observed crash-boundary request"
                with provider_state.lock:
                    assert provider_state.calls == 2
                crash(proc)
                provider_state.crash_release.set()
                crash_thread.join(timeout=5)
                assert not crash_thread.is_alive()

                persisted = json.loads(state_file.read_text())
                claims = persisted["snapshot"].get("aiExecutionClaims", [])
                crash_claims = [claim for claim in claims if claim.get("idempotencyKey") == "ai-smoke-crash-boundary"]
                assert len(crash_claims) == 1 and crash_claims[0]["state"] == "DISPATCHED", crash_claims

                proc, base = start_api(binary, root, state_file, provider_url)
                status, blocked_retry, _ = request_any(base + "/api/v1/ai/diagnose", "POST", crash_body, crash_headers)
                assert status == 409, blocked_retry
                assert blocked_retry["error"]["code"] == "AI_EXECUTION_ALREADY_DISPATCHED", blocked_retry
                with provider_state.lock:
                    assert provider_state.calls == 2, "post-crash retry dispatched the provider a second time"

                status, runs, _ = request(base + f"/api/v1/ai/runs?projectId={project['id']}")
                assert status == 200 and len(runs) == 1 and runs[0]["id"] == run["id"]
                status, stored, _ = request(base + "/api/v1/ai/runs/" + run["id"])
                assert status == 200 and stored["outputDigest"] == run["outputDigest"]
                assert stored["redactionCount"] >= 1

                state_text = state_file.read_text() if state_file.exists() else ""
                assert SECRET not in state_text and "ai-native-smoke-secret-token-123456789" not in state_text

                print(
                    "AI_CONTROL_PLANE_RUNTIME_SMOKE_PASS",
                    policy["runtimeAuthority"],
                    run["id"],
                    run["inputTokens"],
                    run["cachedTokens"],
                    run["outputTokens"],
                    run["redactionCount"],
                    provider_state.calls,
                )
            finally:
                stop(proc)
    finally:
        provider.shutdown()
        provider.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
