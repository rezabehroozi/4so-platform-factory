#!/usr/bin/env python3
from __future__ import annotations

import datetime as dt
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def req(url: str, method: str = "GET", body=None, headers=None):
    data = None if body is None else json.dumps(body).encode()
    request_headers = dict(headers or {})
    if data is not None:
        request_headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, method=method, headers=request_headers)
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            raw = response.read()
            return response.status, json.loads(raw or b"null"), dict(response.headers)
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            parsed = json.loads(raw or b"null")
        except Exception:
            parsed = {"raw": raw.decode(errors="replace")}
        return exc.code, parsed, dict(exc.headers)


def start(binary: Path, state: Path):
    port = free_port()
    env = os.environ.copy()
    # This smoke owns its loopback development API boundary. It must not depend
    # on a parent Makefile/session development-mode setting.
    env["PLATFORM_FACTORY_DEVELOPMENT_MODE"] = "true"
    env["PLATFORM_FACTORY_LISTEN"] = f"127.0.0.1:{port}"
    env["PLATFORM_FACTORY_STATE_FILE"] = str(state)
    env["PLATFORM_FACTORY_AGENT_MTLS_REQUIRED"] = "false"
    env["PLATFORM_FACTORY_PUBLIC_URL"] = "https://platform.example.test"
    env["PLATFORM_FACTORY_FLEET_AGENT_IMAGE"] = "registry.local/platform-agent@sha256:" + "a" * 64
    env["PLATFORM_FACTORY_RUNTIME_PROBE_IMAGE"] = "registry.local/platform-probe@sha256:" + "b" * 64
    process = subprocess.Popen(
        [str(binary)], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    )
    base = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            if req(base + "/readyz")[0] == 200:
                return process, base
        except Exception:
            pass
        time.sleep(0.1)
    process.terminate()
    raise RuntimeError("api not ready")


def iso_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: smoke_workload_logs.py platform-api")
    api_bin = Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        process, base = start(api_bin, tmp / "state.json")
        enrollment = agent_token = ""
        try:
            status, version, _ = req(base + "/api/v1/version")
            assert status == 200, (status, version)

            status, org, _ = req(
                base + "/api/v1/organizations",
                "POST",
                {"name": "workload-log-smoke", "displayName": "Workload Log Smoke"},
            )
            assert status == 201, (status, org)
            status, project, _ = req(
                base + "/api/v1/projects",
                "POST",
                {"organizationId": org["id"], "name": "prod", "displayName": "Production"},
            )
            assert status == 201, (status, project)

            status, created, _ = req(
                base + "/api/v1/cluster-imports",
                "POST",
                {"projectId": project["id"], "name": "logs-1", "displayName": "Logs 1"},
            )
            assert status == 201, (status, created)
            enrollment = created["enrollmentToken"]
            cluster_import = created["import"]
            status, approved, _ = req(
                base + f"/api/v1/cluster-imports/{cluster_import['id']}/approve",
                "POST",
                {},
                {"If-Match": "1"},
            )
            assert status == 200, (status, approved)
            status, claimed, _ = req(
                base + f"/agent/v1/cluster-imports/{cluster_import['id']}/claim",
                "POST",
                {
                    "token": enrollment,
                    "externalUid": "workload-log-smoke-cluster",
                    "agentVersion": version["version"],
                },
            )
            assert status == 200, (status, claimed)
            cluster = claimed["cluster"]
            agent_token = claimed["agentToken"]

            inventory = {
                "observedAt": iso_now(),
                "externalUid": "workload-log-smoke-cluster",
                "distribution": "rke2",
                "kubernetesVersion": "v1.34.9+rke2r1",
                "capabilities": [
                    "read-only-inventory",
                    "workload-explorer-read",
                    "cert.logs",
                    "target-enrollment-principal-isolated",
                ],
                "workloadExplorer": {
                    "complete": True,
                    "truncated": False,
                    "workloads": [
                        {
                            "kind": "Deployment",
                            "namespace": "app",
                            "name": "web",
                            "desiredReplicas": 2,
                            "readyReplicas": 2,
                        }
                    ],
                    "services": [],
                    "ingresses": [],
                    "persistentVolumeClaims": [],
                    "events": [],
                },
            }
            status, reported, _ = req(
                base + f"/agent/v1/clusters/{cluster['id']}/inventory",
                "POST",
                inventory,
                {"Authorization": "Bearer " + agent_token},
            )
            assert status == 200, (status, reported)
            inventory_digest = reported["cluster"]["inventoryDigest"]
            assert inventory_digest.startswith("sha256:"), reported

            query = {
                "projectId": project["id"],
                "clusterId": cluster["id"],
                "namespace": "app",
                "workloadKind": "deployment",
                "workloadName": "web",
                "container": "app",
                "mode": "TAIL",
                "sinceSeconds": 300,
                "limit": 10,
            }
            idempotency_key = "workload-log-smoke-v1"
            status, created_query, _ = req(
                base + "/api/v1/workload-log-queries",
                "POST",
                query,
                {"Idempotency-Key": idempotency_key},
            )
            assert status == 202, (status, created_query)
            operation = created_query["operation"]
            assert operation["kind"] == "target.logs.query", operation
            assert operation["class"] == "READ_ONLY", operation
            assert operation["desiredRevision"] == inventory_digest, (operation, inventory_digest)

            # The exact idempotency replay must return the same durable operation.
            status, replay, _ = req(
                base + "/api/v1/workload-log-queries",
                "POST",
                query,
                {"Idempotency-Key": idempotency_key},
            )
            assert status == 200 and replay["replay"] is True, (status, replay)
            assert replay["operation"]["id"] == operation["id"], replay

            # Unknown workload must fail before creating another operation.
            invalid = dict(query)
            invalid["workloadName"] = "not-present"
            status, missing, _ = req(
                base + "/api/v1/workload-log-queries",
                "POST",
                invalid,
                {"Idempotency-Key": "workload-log-smoke-missing"},
            )
            assert status == 404 and missing.get("error", {}).get("code") == "WORKLOAD_NOT_FOUND", (status, missing)

            status, task, headers = req(
                base + f"/agent/v1/clusters/{cluster['id']}/workload-log-tasks/next",
                headers={"Authorization": "Bearer " + agent_token},
            )
            assert status == 200, (status, task)
            assert task["operationId"] == operation["id"], task
            assert task["inventoryDigest"] == inventory_digest, task
            assert task["taskFenceToken"] > 0, task
            assert task["request"]["workloadKind"] == "Deployment", task
            assert task["request"]["mode"] == "TAIL", task
            revision = int(task["operationRevision"])
            etag = headers.get("ETag", "").strip('"')
            assert not etag or int(etag) == revision, (headers, task)

            line_timestamp = iso_now()
            status, result, _ = req(
                base + f"/agent/v1/clusters/{cluster['id']}/workload-log-tasks/{operation['id']}/result",
                "POST",
                {
                    "success": True,
                    "taskFenceToken": task["taskFenceToken"],
                    "lines": [
                        {
                            "timestamp": line_timestamp,
                            "pod": "web-7d9",
                            "container": "app",
                            "line": "workload-log-smoke-ready",
                        }
                    ],
                },
                {
                    "Authorization": "Bearer " + agent_token,
                    "If-Match": str(revision),
                },
            )
            assert status == 200, (status, result)
            assert result["operation"]["state"] == "SUCCEEDED", result
            assert result["lineCount"] == 1, result
            assert result["evidenceDigest"].startswith("sha256:"), result

            status, view, _ = req(base + f"/api/v1/workload-log-queries/{operation['id']}")
            assert status == 200, (status, view)
            assert view["ready"] is True, view
            assert view["operation"]["state"] == "SUCCEEDED", view
            assert view["evidence"]["sealed"] is True and view["evidence"]["hasPayload"] is True, view
            assert len(view["lines"]) == 1 and view["lines"][0]["line"] == "workload-log-smoke-ready", view

            # Successful work is no longer claimable.
            status, empty, _ = req(
                base + f"/agent/v1/clusters/{cluster['id']}/workload-log-tasks/next",
                headers={"Authorization": "Bearer " + agent_token},
            )
            assert status == 204, (status, empty)

            print(
                "WORKLOAD_LOG_SMOKE_PASS",
                operation["id"],
                inventory_digest,
                result["evidenceDigest"],
            )
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            logs = process.stdout.read() if process.stdout else ""
            for secret in (enrollment, agent_token):
                if secret:
                    assert secret not in logs, "cluster credential leaked in logs"
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
