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


class ProviderState:
    def __init__(self):
        self.calls = 0
        self.bodies: list[dict] = []
        self.lock = threading.Lock()


class MockProviderHandler(BaseHTTPRequestHandler):
    state: ProviderState

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        body = json.loads(raw)
        with self.state.lock:
            self.state.calls += 1
            self.state.bodies.append(body)
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
        self.wfile.write(encoded)

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
                assert policy["enabled"] is True and policy["provider"] == "openai-responses"
                assert policy["redactionRequired"] is True and policy["structuredOutputRequired"] is True
                assert policy["rawPromptPersisted"] is False
                assert policy["canDecidePass"] is False and policy["canDecidePhysicalPass"] is False

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
