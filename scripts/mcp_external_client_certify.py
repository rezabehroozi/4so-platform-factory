#!/usr/bin/env python3
"""Black-box MCP 2026-07-28 interoperability certifier for 4SO Platform Factory.

This client intentionally uses only the Python standard library and runs outside
of the API server process. It validates the HTTP/JSON-RPC wire contract rather
than importing product handler code.
"""
from __future__ import annotations

import argparse
import base64
import json
import sys
import urllib.error
import urllib.request
from typing import Any

PROTOCOL_VERSION = "2026-07-28"
CLIENT_INFO = {"name": "4so-external-conformance-client", "version": "1.0.0"}
EXPECTED_TOOLS = {
    "lab_guide",
    "target_architecture_model",
    "mcp_delegation_architecture",
    "mcp_action_registry",
    "ai_runtime_policy",
    "platform_version",
    "baselines",
    "tenancy_plans",
    "day2_campaign_engine",
    "catalog_signing_identity",
    "projects",
    "project_clusters",
    "project_operations",
    "ops_search",
    "notification_routing_preview",
    "cluster_summary",
    "cluster_maintenance_context",
    "target_node_lifecycle_authority",
    "target_node_lifecycle_plan",
    "operation_status",
    "ai_run",
    "backup_policies",
    "data_protection_runs",
    "upgrade_campaigns",
    "upgrade_campaign",
    "managed_okd_install_runtime",
    "managed_okd_install",
    "workspaces",
    "workspace",
    "workspace_bindings",
}
FORBIDDEN_MUTATION_FRAGMENTS = ("create", "apply", "delete", "repair", "execute", "mutate", "patch")


def request_meta() -> dict[str, Any]:
    return {
        "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
        "io.modelcontextprotocol/clientInfo": dict(CLIENT_INFO),
        "io.modelcontextprotocol/clientCapabilities": {"tools": {}},
    }


def encode_header_value(value: str) -> str:
    if value and all(0x21 <= ord(ch) <= 0x7E for ch in value) and not any(ch.isspace() for ch in value):
        return value
    encoded = base64.b64encode(value.encode("utf-8")).decode("ascii")
    return f"=?base64?{encoded}?="


def fail(message: str) -> None:
    raise RuntimeError(message)


class MCPClient:
    def __init__(self, endpoint: str, token: str, timeout: float) -> None:
        self.endpoint = endpoint
        self.token = token
        self.timeout = timeout
        self.next_id = 1

    def call(self, method: str, params: dict[str, Any] | None = None, *, name: str = "", expect_http: int = 200) -> dict[str, Any]:
        params = dict(params or {})
        meta = dict(params.get("_meta") or {})
        meta.update(request_meta())
        params["_meta"] = meta
        request_id = self.next_id
        self.next_id += 1
        payload = json.dumps({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}, separators=(",", ":")).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": PROTOCOL_VERSION,
            "Mcp-Method": method,
        }
        if name:
            headers["Mcp-Name"] = encode_header_value(name)
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        req = urllib.request.Request(self.endpoint, data=payload, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                status = response.status
                raw = response.read()
        except urllib.error.HTTPError as exc:
            status = exc.code
            raw = exc.read()
        if status != expect_http:
            fail(f"{method}/{name or '-'} HTTP status={status}, expected={expect_http}, body={raw[:1000]!r}")
        try:
            message = json.loads(raw)
        except json.JSONDecodeError as exc:
            fail(f"{method}/{name or '-'} returned invalid JSON: {exc}")
        if message.get("jsonrpc") != "2.0" or message.get("id") != request_id:
            fail(f"{method}/{name or '-'} invalid JSON-RPC envelope: {message!r}")
        return message


def assert_complete(message: dict[str, Any], context: str) -> dict[str, Any]:
    if "error" in message:
        fail(f"{context} returned error: {message['error']!r}")
    result = message.get("result")
    if not isinstance(result, dict):
        fail(f"{context} missing result object")
    if result.get("resultType") != "complete":
        fail(f"{context} resultType={result.get('resultType')!r}")
    meta = result.get("_meta")
    server_info = meta.get("io.modelcontextprotocol/serverInfo") if isinstance(meta, dict) else None
    if not isinstance(server_info, dict) or server_info.get("name") != "4so-platform-factory" or not server_info.get("version"):
        fail(f"{context} missing canonical serverInfo metadata: {meta!r}")
    return result


def assert_cacheable(result: dict[str, Any], context: str) -> None:
    if not isinstance(result.get("ttlMs"), int) or result["ttlMs"] < 0:
        fail(f"{context} invalid ttlMs={result.get('ttlMs')!r}")
    if result.get("cacheScope") not in {"private", "public"}:
        fail(f"{context} invalid cacheScope={result.get('cacheScope')!r}")


def certify(args: argparse.Namespace) -> None:
    client = MCPClient(args.endpoint, args.token, args.timeout)

    discover = assert_complete(client.call("server/discover"), "server/discover")
    if PROTOCOL_VERSION not in discover.get("supportedVersions", []):
        fail(f"server/discover does not advertise {PROTOCOL_VERSION}")
    capabilities = discover.get("capabilities")
    if not isinstance(capabilities, dict) or not isinstance(capabilities.get("tools"), dict):
        fail("server/discover missing tools capability")
    assert_cacheable(discover, "server/discover")

    first = assert_complete(client.call("tools/list"), "tools/list#1")
    second = assert_complete(client.call("tools/list"), "tools/list#2")
    assert_cacheable(first, "tools/list#1")
    assert_cacheable(second, "tools/list#2")
    tools = first.get("tools")
    tools2 = second.get("tools")
    if tools != tools2:
        fail("tools/list is not deterministic across repeated calls")
    if not isinstance(tools, list):
        fail("tools/list did not return an array")
    names = {tool.get("name") for tool in tools if isinstance(tool, dict)}
    missing = EXPECTED_TOOLS - names
    if missing:
        fail(f"required MCP read tools are missing: {sorted(str(v) for v in missing)}")
    for tool in tools:
        if not isinstance(tool, dict) or not isinstance(tool.get("inputSchema"), dict):
            fail(f"tool is missing inputSchema: {tool!r}")
        if tool.get("requiredPermission") != "mcp.read":
            fail(f"non-read MCP tool leaked into read-only surface: {tool.get('name')!r}")
        if tool.get("administrationOnly"):
            fail(f"administration MCP tool leaked into read-only surface: {tool.get('name')!r}")

    lab = assert_complete(client.call("tools/call", {"name": "lab_guide", "arguments": {}}, name="lab_guide"), "tools/call lab_guide")
    structured = lab.get("structuredContent")
    if not isinstance(structured, dict) or structured.get("authority") != "LAB_CERTIFICATION_MATRIX_V2":
        fail("lab_guide did not return canonical lab authority")

    architecture = assert_complete(client.call("tools/call", {"name": "target_architecture_model", "arguments": {}}, name="target_architecture_model"), "tools/call target_architecture_model")
    structured = architecture.get("structuredContent")
    if not isinstance(structured, dict) or structured.get("authority") != "TARGET_ARCHITECTURE_MODEL_V1":
        fail("target_architecture_model did not return canonical authority")

    if args.project_id:
        preview = assert_complete(
            client.call(
                "tools/call",
                {"name": "notification_routing_preview", "arguments": {"projectId": args.project_id, "eventType": "operation.failed", "severity": "CRITICAL"}},
                name="notification_routing_preview",
            ),
            "tools/call notification_routing_preview",
        )
        structured = preview.get("structuredContent")
        if not isinstance(structured, dict) or structured.get("authority") != "NOTIFICATION_ROUTING_PREVIEW_AUTHORITY_V1" or structured.get("projectId") != args.project_id or structured.get("sideEffects") is not False or structured.get("deliveryCreated") is not False:
            fail(f"notification routing preview authority drifted: {structured!r}")

        search = assert_complete(
            client.call(
                "tools/call",
                {"name": "ops_search", "arguments": {"projectId": args.project_id, "query": args.operation_id or args.project_id}},
                name="ops_search",
            ),
            "tools/call ops_search",
        )
        structured = search.get("structuredContent")
        if not isinstance(structured, dict) or structured.get("authority") != "SEARCH_PROJECTION_AUTHORITY_V2" or structured.get("projectId") != args.project_id or structured.get("sourceOfTruth") is not False or structured.get("backend") != "postgresql-bounded":
            fail(f"operational search projection authority drifted: {structured!r}")

    if args.operation_id:
        op = assert_complete(client.call("tools/call", {"name": "operation_status", "arguments": {"id": args.operation_id}}, name="operation_status"), "tools/call operation_status")
        structured = op.get("structuredContent")
        if not isinstance(structured, dict) or structured.get("id") != args.operation_id or structured.get("projectId") != args.project_id:
            fail(f"project-scoped operation response drifted: {structured!r}")

    if args.forbidden_operation_id:
        denied = client.call(
            "tools/call",
            {"name": "operation_status", "arguments": {"id": args.forbidden_operation_id}},
            name="operation_status",
            expect_http=403,
        )
        error = denied.get("error")
        if not isinstance(error, dict) or error.get("code") != -32003:
            fail(f"cross-project operation was not denied with project-scope error: {denied!r}")

    print(
        "MCP_EXTERNAL_CLIENT_CERTIFICATION_PASS "
        f"protocol={PROTOCOL_VERSION} tools={len(EXPECTED_TOOLS)} "
        f"projectScope={'checked' if args.operation_id else 'not-requested'} "
        f"negativeScope={'checked' if args.forbidden_operation_id else 'not-requested'}"
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--token", default="")
    parser.add_argument("--operation-id", default="")
    parser.add_argument("--project-id", default="")
    parser.add_argument("--forbidden-operation-id", default="")
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args()
    if args.operation_id and not args.project_id:
        parser.error("--project-id is required with --operation-id")
    return args


if __name__ == "__main__":
    try:
        certify(parse_args())
    except Exception as exc:  # noqa: BLE001 - CLI boundary reports one bounded failure.
        print(f"MCP_EXTERNAL_CLIENT_CERTIFICATION_FAIL {exc}", file=sys.stderr)
        raise SystemExit(1)
