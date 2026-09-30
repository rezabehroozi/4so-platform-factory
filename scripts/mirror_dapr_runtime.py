#!/usr/bin/env python3
"""Mirror the exact admitted Dapr image set into product Zot with digest readback.

This is release/acquisition tooling only. It never mutates target clusters and
never embeds registry credentials in evidence.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess

from upstream_acquisition_toolchain import require_toolchain
from acquire_dapr_runtime import VERSION, UPSTREAM_COMMIT
from seal_dapr_runtime import (
    MIRROR_AUTHORITY,
    load_json,
    validate_acquisition,
)

DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
REGISTRY_RE = re.compile(r"^[a-z0-9.-]+(?::[0-9]+)?$")


def run(cmd: list[str], timeout: int = 600) -> str:
    result = subprocess.run(
        cmd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout,
        env=os.environ.copy(),
    )
    if result.returncode:
        raise RuntimeError(f"DAPR_MIRROR_COMMAND_FAILED rc={result.returncode} cmd={cmd!r}\n{result.stdout[-6000:]}")
    return result.stdout


def validate_registry(value: str) -> str:
    registry = str(value or "").strip().lower()
    if not REGISTRY_RE.fullmatch(registry):
        raise RuntimeError("DAPR_MIRROR_REGISTRY_INVALID")
    return registry


def crane_digest(crane: str, ref: str) -> str:
    digest = run([crane, "digest", ref], timeout=180).strip().splitlines()[-1].lower()
    if not DIGEST_RE.fullmatch(digest):
        raise RuntimeError(f"DAPR_MIRROR_READBACK_DIGEST_INVALID {ref}:{digest}")
    return digest


def mirror(acquisition_path: Path, registry: str, out: Path) -> dict:
    registry = validate_registry(registry)
    acquisition, acquisition_digest = load_json(acquisition_path, "DAPR_ACQUISITION")
    acquired = validate_acquisition(acquisition)
    pinned = require_toolchain()
    crane = str(pinned["crane"][0])

    rows = []
    for role in sorted(acquired):
        item = acquired[role]
        source_ref = item["sourceReference"]
        source_digest = item["sourceDigest"]
        destination_tag = f"{registry}/dapr/{role}:{VERSION.removeprefix('v')}"
        run([crane, "copy", source_ref, destination_tag], timeout=900)
        mirror_digest = crane_digest(crane, destination_tag)
        if mirror_digest != source_digest:
            raise RuntimeError(f"DAPR_MIRROR_DIGEST_MISMATCH role={role} source={source_digest} mirror={mirror_digest}")
        mirror_ref = f"{registry}/dapr/{role}@{mirror_digest}"
        digest_readback = crane_digest(crane, mirror_ref)
        if digest_readback != source_digest:
            raise RuntimeError(f"DAPR_MIRROR_DIGEST_READBACK_MISMATCH role={role}")
        rows.append({
            "role": role,
            "sourceRepository": item["sourceRepository"],
            "sourceReference": source_ref,
            "sourceDigest": source_digest,
            "mirrorTagReference": destination_tag,
            "mirrorReference": mirror_ref,
            "mirrorDigest": mirror_digest,
        })

    evidence = {
        "authority": MIRROR_AUTHORITY,
        "registryAuthority": "zot",
        "registryIdentity": registry,
        "version": VERSION,
        "upstreamCommit": UPSTREAM_COMMIT,
        "acquisitionReceiptDigest": acquisition_digest,
        "images": rows,
        "mirrorReady": True,
        "registryReadback": True,
        "offlineReplayReady": True,
        "credentialsEmbedded": False,
        "runtimeMutationPerformed": False,
        "physicalCertificationInferred": False,
    }

    candidate = Path(os.path.abspath(os.fspath(out.expanduser())))
    if candidate.is_symlink():
        raise RuntimeError("DAPR_MIRROR_EVIDENCE_OUTPUT_SYMLINK_FORBIDDEN")
    candidate.parent.mkdir(parents=True, exist_ok=True)
    tmp = candidate.with_suffix(candidate.suffix + ".tmp")
    tmp.write_bytes(json.dumps(evidence, indent=2, sort_keys=True).encode() + b"\n")
    os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
    tmp.replace(candidate)
    return evidence


def self_test() -> int:
    if validate_registry("platform-zot:5000") != "platform-zot:5000":
        raise RuntimeError("DAPR_MIRROR_REGISTRY_SELF_TEST_FAILED")
    for invalid in ("https://platform-zot:5000", "platform-zot:5000/dapr", "PLATFORM ZOT"):
        try:
            validate_registry(invalid)
        except RuntimeError:
            continue
        raise RuntimeError(f"DAPR_MIRROR_REGISTRY_NEGATIVE_CONTROL_FAILED {invalid}")
    print("DAPR_RUNTIME_MIRROR_SELF_TEST_PASS")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--acquisition", type=Path)
    parser.add_argument("--registry")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()

    try:
        if args.self_test:
            return self_test()
        if not all((args.acquisition, args.registry, args.out)):
            parser.error("--acquisition, --registry and --out are required")
        evidence = mirror(args.acquisition, args.registry, args.out)
    except (OSError, ValueError, json.JSONDecodeError, RuntimeError, subprocess.TimeoutExpired) as exc:
        print(f"DAPR_RUNTIME_MIRROR_BLOCKED {exc}", file=__import__("sys").stderr)
        return 3
    print(json.dumps(evidence, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
