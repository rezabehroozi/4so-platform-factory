#!/usr/bin/env python3
"""Acquire the exact Gateway API 1.6.1 dependency bytes for Cilium runtime transition.

This closes only external-byte acquisition. It never mutates a cluster and
never promotes runtime or physical certification.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import tempfile
import urllib.request
from pathlib import Path

import runtime_dependency_transition as transition

ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = ROOT / "catalog" / "runtime-dependency-transition.json"
USER_AGENT = "4so-platform-factory-runtime-dependency-acquirer/1"


def bounded_download(url: str, expected_size: int, timeout: int) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        final_url = response.geturl()
        if not str(final_url).startswith("https://"):
            raise RuntimeError("RUNTIME_DEPENDENCY_GATEWAY_HTTPS_DOWNGRADE_DENIED")
        raw = response.read(expected_size + 1)
    if len(raw) != expected_size:
        raise RuntimeError(f"RUNTIME_DEPENDENCY_GATEWAY_DOWNLOAD_SIZE_MISMATCH expected={expected_size} actual={len(raw)}")
    return raw


def acquire(root: Path, timeout: int = 60) -> dict:
    authority_path = root / "catalog" / "runtime-dependency-transition.json"
    if authority_path.is_symlink() or not authority_path.is_file():
        raise RuntimeError("RUNTIME_DEPENDENCY_TRANSITION_PATH_INVALID")
    original = authority_path.read_bytes()
    doc = json.loads(original)
    spec = doc.get("spec") or {}
    ga = spec.get("gatewayApi") or {}
    if spec.get("authority") != transition.AUTHORITY or spec.get("status") != "acquisition-pending" or ga.get("sourceStatus") != "pending-byte-acquisition":
        raise RuntimeError("RUNTIME_DEPENDENCY_GATEWAY_ACQUISITION_NOT_PENDING")
    release = str(ga.get("targetRelease") or "")
    assets = ga.get("assets") or []
    if release != "1.6.1" or len(assets) != 2:
        raise RuntimeError("RUNTIME_DEPENDENCY_GATEWAY_ACQUISITION_CONTRACT_INVALID")

    target_dir = root / "catalog" / "runtime-dependencies" / "gateway-api" / release
    if target_dir.is_symlink():
        raise RuntimeError("RUNTIME_DEPENDENCY_GATEWAY_OUTPUT_SYMLINK_FORBIDDEN")
    written: list[Path] = []
    with tempfile.TemporaryDirectory(prefix="4so-gateway-api-1.6.1-") as td:
        stage = Path(td)
        for asset in assets:
            name = str(asset.get("name") or "")
            expected_size = int(asset.get("size") or 0)
            expected_sha = str(asset.get("sha256") or "")
            url = str(asset.get("url") or "")
            if name not in transition.EXPECTED_GATEWAY_ASSETS or not url.startswith("https://"):
                raise RuntimeError(f"RUNTIME_DEPENDENCY_GATEWAY_ASSET_CONTRACT_INVALID {name}")
            raw = bounded_download(url, expected_size, timeout)
            got = hashlib.sha256(raw).hexdigest()
            if got != expected_sha:
                raise RuntimeError(f"RUNTIME_DEPENDENCY_GATEWAY_DOWNLOAD_DIGEST_MISMATCH {name}")
            staged = stage / name
            staged.write_bytes(raw)

        target_dir.mkdir(parents=True, exist_ok=True)
        try:
            for asset in assets:
                name = str(asset["name"])
                dest = target_dir / name
                if dest.is_symlink():
                    raise RuntimeError(f"RUNTIME_DEPENDENCY_GATEWAY_OUTPUT_SYMLINK_FORBIDDEN {name}")
                tmp = dest.with_suffix(dest.suffix + ".tmp")
                shutil.copyfile(stage / name, tmp)
                os.replace(tmp, dest)
                written.append(dest)

            ga["sourceStatus"] = "source-acquired"
            spec["status"] = "runtime-certification-pending"
            encoded = (json.dumps(doc, indent=2, sort_keys=False) + "\n").encode()
            tmp_authority = authority_path.with_suffix(".json.tmp")
            tmp_authority.write_bytes(encoded)
            os.replace(tmp_authority, authority_path)
            transition.validate(root)
        except Exception:
            authority_path.write_bytes(original)
            for path in written:
                path.unlink(missing_ok=True)
            try:
                target_dir.rmdir()
                target_dir.parent.rmdir()
            except OSError:
                pass
            raise

    return {
        "authority": "GATEWAY_API_RUNTIME_DEPENDENCY_ACQUISITION_V1",
        "version": release,
        "sourceStatus": ga["sourceStatus"],
        "transitionStatus": spec["status"],
        "runtimeCertified": False,
        "physicalCertified": False,
        "assets": [
            {
                "name": str(asset["name"]),
                "path": transition.gateway_asset_path(root, release, str(asset["name"])).relative_to(root).as_posix(),
                "size": int(asset["size"]),
                "sha256": str(asset["sha256"]),
            }
            for asset in assets
        ],
    }


def self_test() -> int:
    payload = b"fixture"
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        p = root / "asset"
        p.write_bytes(payload)
        if hashlib.sha256(p.read_bytes()).hexdigest() != hashlib.sha256(payload).hexdigest():
            raise RuntimeError("RUNTIME_DEPENDENCY_GATEWAY_SELF_TEST_DIGEST_FAILED")
    print("GATEWAY_API_RUNTIME_DEPENDENCY_ACQUISITION_SELF_TEST_PASS")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--network-timeout", type=int, default=60)
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    try:
        result = acquire(args.root.resolve(), args.network_timeout)
    except Exception as exc:
        print(f"GATEWAY_API_RUNTIME_DEPENDENCY_ACQUISITION_BLOCKED {exc}", file=__import__("sys").stderr)
        return 3
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
