#!/usr/bin/env python3
"""Emit the pinned, isolated developer-browser MCP profile used by Autopilot.

The profile remains developer evidence only and never grants product mutation
authority. A companion prerequisite bootstrap detects Windows/Linux and can
provision compatible Node/npm/npx plus pinned Chrome for Testing user-locally
before the exact-pinned MCP server is started.
"""
from __future__ import annotations

import argparse
import json

AUTHORITY = "BROWSER_TRIAGE_PROFILE_V2"
PACKAGE = "chrome-devtools-mcp"
VERSION = "1.8.0"


def profile() -> dict:
    return {
        "authority": AUTHORITY,
        "purpose": "developer-autopilot-browser-triage-only",
        "productMutationAuthority": False,
        "productionCredentialUseAllowed": False,
        "package": {"name": PACKAGE, "version": VERSION, "source": "ChromeDevTools/chrome-devtools-mcp"},
        "prerequisites": {
            "authority": "BROWSER_TRIAGE_PREREQUISITE_AUTHORITY_V1",
            "supportedOperatingSystems": ["linux", "windows"],
            "required": ["Node.js >=20.19 (22.12+ for Node 22)", "npm", "npx", "Google Chrome current stable or Chrome for Testing"],
            "bootstrap": "python3 scripts/browser_triage_bootstrap.py --ensure",
            "launcher": "python3 scripts/browser_triage_bootstrap.py --run-mcp",
            "nodeFallback": "Node.js 22.12.0 exact archive with official SHA-256 verification",
            "browserFallback": "Chrome for Testing 152.0.7977.75 exact version, user-local",
            "administratorRequired": False,
        },
        "server": {
            "command": "npx",
            "args": [
                "-y",
                f"{PACKAGE}@{VERSION}",
                "--headless",
                "--isolated",
                "--no-usage-statistics",
                "--no-performance-crux",
            ],
            "env": {
                "CHROME_DEVTOOLS_MCP_NO_UPDATE_CHECKS": "1",
                "CHROME_DEVTOOLS_MCP_NO_USAGE_STATISTICS": "1",
                "CI": "1",
            },
        },
        "allowedEvidence": [
            "browser-console",
            "network-requests",
            "dom-snapshot",
            "screenshot",
            "performance-trace",
        ],
        "guardrails": [
            "use a disposable isolated browser profile",
            "never load production credentials, tokens or personal browser data",
            "Playwright remains the deterministic UI gate; browser MCP is triage/diagnostic assistance",
            "external MCP output is evidence for diagnosis, never product state or Physical PASS",
        ],
    }


def verify(value: dict) -> None:
    if value.get("authority") != AUTHORITY or value.get("productMutationAuthority") is not False:
        raise SystemExit("BROWSER_TRIAGE_PROFILE_AUTHORITY_INVALID")
    prereq = value.get("prerequisites", {})
    if prereq.get("authority") != "BROWSER_TRIAGE_PREREQUISITE_AUTHORITY_V1":
        raise SystemExit("BROWSER_TRIAGE_PROFILE_PREREQUISITE_AUTHORITY_MISSING")
    if set(prereq.get("supportedOperatingSystems", [])) != {"linux", "windows"}:
        raise SystemExit("BROWSER_TRIAGE_PROFILE_PLATFORM_COVERAGE_INCOMPLETE")
    if prereq.get("administratorRequired") is not False:
        raise SystemExit("BROWSER_TRIAGE_PROFILE_USER_LOCAL_PROVISIONING_REQUIRED")
    if "--ensure" not in str(prereq.get("bootstrap", "")) or "--run-mcp" not in str(prereq.get("launcher", "")):
        raise SystemExit("BROWSER_TRIAGE_PROFILE_BOOTSTRAP_CONTRACT_MISSING")
    server = value.get("server", {})
    args = server.get("args", [])
    required = {
        f"{PACKAGE}@{VERSION}",
        "--headless",
        "--isolated",
        "--no-usage-statistics",
        "--no-performance-crux",
    }
    if not required.issubset(set(args)):
        raise SystemExit("BROWSER_TRIAGE_PROFILE_HARDENING_INCOMPLETE")
    if "@latest" in " ".join(args):
        raise SystemExit("BROWSER_TRIAGE_PROFILE_FLOATING_VERSION_FORBIDDEN")
    env = server.get("env", {})
    if env.get("CHROME_DEVTOOLS_MCP_NO_UPDATE_CHECKS") != "1":
        raise SystemExit("BROWSER_TRIAGE_PROFILE_UPDATE_CHECK_NOT_DISABLED")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--compact", action="store_true")
    args = parser.parse_args()
    value = profile()
    verify(value)
    if args.check:
        print("BROWSER_TRIAGE_PROFILE_CHECK_PASS", AUTHORITY, f"{PACKAGE}@{VERSION}")
    else:
        print(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":") if args.compact else None, indent=None if args.compact else 2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
