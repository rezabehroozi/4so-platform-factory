#!/usr/bin/env python3
"""Machine-actionable C9 environment preflight handoff.

The final exact sealer remains the validation authority. This wrapper only
translates its blocker set into the next executable local action so agents do
not need to interpret free-form errors.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    import seal_final_exact_release as sealer
except ModuleNotFoundError:
    from scripts import seal_final_exact_release as sealer

AUTHORITY = "FINAL_EXACT_RELEASE_PREFLIGHT_HANDOFF_V1"
C9_COMMAND = [
    sys.executable,
    "scripts/seal_final_exact_release.py",
    "--root",
    ".",
    "--out",
    "lab/final-exact-release-evidence.json",
]
C9_COMMAND_TEMPLATE = [
    "<python>",
    "scripts/seal_final_exact_release.py",
    "--root",
    ".",
    "--out",
    "lab/final-exact-release-evidence.json",
]
TOOLCHAIN_ARCHIVE_BLOCKERS = {
    "FINAL_EXACT_RELEASE_TOOLCHAIN_ARCHIVE_MISSING",
    "FINAL_EXACT_RELEASE_TOOLCHAIN_ARCHIVE_MISMATCH",
    "FINAL_EXACT_RELEASE_TOOLCHAIN_ARCHIVE_INVALID",
}
TOOLCHAIN_SOURCE_BLOCKERS = {
    "FINAL_EXACT_RELEASE_TOOLCHAIN_AUTHORITY_INVALID",
    "FINAL_EXACT_RELEASE_TOOLCHAIN_NOT_ADMITTED",
    "FINAL_EXACT_RELEASE_TOOLCHAIN_PATH_INVALID",
    "FINAL_EXACT_RELEASE_TOOLCHAIN_LOCK_INVALID",
}


def enrich(result: dict) -> dict:
    if not isinstance(result, dict):
        raise RuntimeError("FINAL_EXACT_RELEASE_PREFLIGHT_RESULT_INVALID")
    out = dict(result)
    blockers = [str(x) for x in out.get("blockers") or []]
    blocker_set = set(blockers)
    required_inputs: list[str] = []
    if any(code.startswith("UI_BROWSER_AUTHORITY_") for code in blockers):
        required_inputs.append(sealer.browser_authority.ENV_AUTHORITY)
    if blocker_set & TOOLCHAIN_ARCHIVE_BLOCKERS:
        required_inputs.append("vendor/toolchains/<admitted-go-archive>")
    missing_host_tools = [str(x) for x in out.get("missingHostTools") or []]
    out.update(
        {
            "handoffAuthority": AUTHORITY,
            "requiredInputs": required_inputs,
            "requiredHostTools": missing_host_tools,
            "nextCommand": [],
            "nextCommandTemplate": [],
        }
    )
    if "FINAL_EXACT_RELEASE_LINUX_AMD64_HOST_REQUIRED" in blocker_set:
        out.update(
            {
                "nextActionCode": "RUN_C9_ON_EXACT_LINUX_HOST",
                "nextCommandTemplate": list(C9_COMMAND_TEMPLATE),
                "detail": "run the exact committed source on a linux/amd64 host with the admitted offline toolchain and browser authority",
            }
        )
    elif blocker_set & TOOLCHAIN_SOURCE_BLOCKERS:
        out.update(
            {
                "nextActionCode": "INSPECT_C9_SOURCE_AUTHORITY",
                "nextCommand": ["git", "status", "--short", "--", "lab/release-build-toolchain-lock.json"],
                "requiredInputs": [],
                "detail": "the tracked C9 toolchain authority/lock is invalid; inspect source authority rather than replacing environment inputs",
            }
        )
    elif blockers:
        out.update(
            {
                "nextActionCode": "PROVIDE_C9_ENVIRONMENT_INPUTS",
                "detail": "satisfy only the reported local tool/input blockers, then rerun c9-preflight",
            }
        )
    else:
        out.update(
            {
                "nextActionCode": "RUN_C9_SEAL",
                "nextCommand": list(C9_COMMAND),
                "detail": "C9 environment is ready for the local exact release seal",
            }
        )
    out["physicalCertified"] = False
    return out


def preflight(root: Path) -> dict:
    return enrich(sealer.exact_release_environment_preflight(root.resolve()))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("."))
    args = parser.parse_args()
    result = preflight(args.root)
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("ready") is True else 2


if __name__ == "__main__":
    raise SystemExit(main())
