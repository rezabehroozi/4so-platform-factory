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
import tempfile
import urllib.parse

from upstream_acquisition_toolchain import require_toolchain
from acquire_dapr_runtime import VERSION, IMAGE_TAG, UPSTREAM_COMMIT, sha256_bytes
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


def validate_registry_url(value: str) -> tuple[str, str]:
    raw = str(value or "").strip()
    parsed = urllib.parse.urlsplit(raw)
    scheme = parsed.scheme.lower()
    if (
        scheme not in {"http", "https"} or not parsed.hostname or parsed.username is not None
        or parsed.password is not None or parsed.path not in {"", "/"} or parsed.query or parsed.fragment
    ):
        raise RuntimeError("DAPR_MIRROR_REGISTRY_URL_INVALID")
    registry = parsed.netloc.lower()
    if not REGISTRY_RE.fullmatch(registry):
        raise RuntimeError("DAPR_MIRROR_REGISTRY_INVALID")
    return scheme, registry


def crane_args(crane: str, scheme: str, *args: str) -> list[str]:
    prefix = [crane]
    if scheme == "http":
        prefix.append("--insecure")
    return [*prefix, *args]


def crane_digest(crane: str, ref: str, scheme: str = "https") -> str:
    digest = run(crane_args(crane, scheme, "digest", ref), timeout=180).strip().splitlines()[-1].lower()
    if not DIGEST_RE.fullmatch(digest):
        raise RuntimeError(f"DAPR_MIRROR_READBACK_DIGEST_INVALID {ref}:{digest}")
    return digest


def chart_path_admission(path: Path, acquisition: dict) -> tuple[Path, str]:
    candidate = Path(os.path.abspath(os.fspath(path.expanduser())))
    info = candidate.lstat()
    if candidate.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_size <= 0 or info.st_size > 64 * 1024 * 1024:
        raise RuntimeError("DAPR_MIRROR_HELM_PACKAGE_FILE_INVALID")
    if candidate.name != acquisition.get("helmPackageName"):
        raise RuntimeError("DAPR_MIRROR_HELM_PACKAGE_NAME_MISMATCH")
    raw = candidate.read_bytes()
    if len(raw) != info.st_size:
        raise RuntimeError("DAPR_MIRROR_HELM_PACKAGE_FILE_CHANGED")
    digest = sha256_bytes(raw)
    if digest != acquisition.get("helmPackageDigest"):
        raise RuntimeError("DAPR_MIRROR_HELM_PACKAGE_DIGEST_MISMATCH")
    return candidate, digest


def mirror_chart(helm: str, crane: str, chart: Path, package_digest: str, scheme: str, registry: str) -> dict:
    destination = f"oci://{registry}/dapr-charts"
    command = [helm, "push", str(chart), destination]
    if scheme == "http":
        command.append("--plain-http")
    run(command, timeout=900)
    tagged = f"{registry}/dapr-charts/dapr:{IMAGE_TAG}"
    manifest_digest = crane_digest(crane, tagged, scheme)
    manifest_raw = run(crane_args(crane, scheme, "manifest", tagged), timeout=180)
    try:
        manifest = json.loads(manifest_raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("DAPR_MIRROR_HELM_MANIFEST_INVALID") from exc
    layers = manifest.get("layers") if isinstance(manifest, dict) else None
    content_layers = [
        row for row in (layers or [])
        if isinstance(row, dict) and "helm.chart.content" in str(row.get("mediaType") or "")
    ]
    if len(content_layers) != 1:
        raise RuntimeError("DAPR_MIRROR_HELM_CONTENT_LAYER_INVALID")
    content_digest = str(content_layers[0].get("digest") or "").strip().lower()
    if content_digest != package_digest:
        raise RuntimeError("DAPR_MIRROR_HELM_CONTENT_DIGEST_MISMATCH")
    exact = f"{registry}/dapr-charts/dapr@{manifest_digest}"
    if crane_digest(crane, exact, scheme) != manifest_digest:
        raise RuntimeError("DAPR_MIRROR_HELM_MANIFEST_READBACK_MISMATCH")
    return {
        "helmPackageDigest": package_digest,
        "helmMirrorTagReference": tagged,
        "helmMirrorReference": exact,
        "helmMirrorManifestDigest": manifest_digest,
        "helmMirrorContentDigest": content_digest,
    }


def mirror(acquisition_path: Path, chart_path: Path, registry_url: str, out: Path) -> dict:
    scheme, registry = validate_registry_url(registry_url)
    acquisition, acquisition_digest = load_json(acquisition_path, "DAPR_ACQUISITION")
    acquired = validate_acquisition(acquisition)
    pinned = require_toolchain()
    helm = str(pinned["helm"][0])
    crane = str(pinned["crane"][0])
    chart, package_digest = chart_path_admission(chart_path, acquisition)
    chart_evidence = mirror_chart(helm, crane, chart, package_digest, scheme, registry)

    rows = []
    for role in sorted(acquired):
        item = acquired[role]
        source_ref = item["sourceReference"]
        source_digest = item["sourceDigest"]
        destination_tag = f"{registry}/dapr/{role}:{VERSION.removeprefix('v')}"
        if scheme == "https":
            run([crane, "copy", source_ref, destination_tag], timeout=900)
        else:
            with tempfile.TemporaryDirectory(prefix=f"4so-dapr-{role}-oci-") as td:
                layout = Path(td) / "layout"
                run([crane, "pull", source_ref, str(layout), "--format=oci"], timeout=900)
                run(crane_args(crane, scheme, "push", str(layout), destination_tag), timeout=900)
        mirror_digest = crane_digest(crane, destination_tag, scheme)
        if mirror_digest != source_digest:
            raise RuntimeError(f"DAPR_MIRROR_DIGEST_MISMATCH role={role} source={source_digest} mirror={mirror_digest}")
        mirror_ref = f"{registry}/dapr/{role}@{mirror_digest}"
        digest_readback = crane_digest(crane, mirror_ref, scheme)
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
        "registryScheme": scheme,
        "registryIdentity": registry,
        "version": VERSION,
        "upstreamCommit": UPSTREAM_COMMIT,
        "acquisitionReceiptDigest": acquisition_digest,
        **chart_evidence,
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
    if validate_registry_url("http://platform-zot:5000") != ("http", "platform-zot:5000"):
        raise RuntimeError("DAPR_MIRROR_REGISTRY_SELF_TEST_FAILED")
    if validate_registry_url("https://registry.example") != ("https", "registry.example"):
        raise RuntimeError("DAPR_MIRROR_REGISTRY_SELF_TEST_FAILED")
    for invalid in ("platform-zot:5000", "http://platform-zot:5000/dapr", "ftp://platform-zot:5000", "http://user:pass@platform-zot:5000"):
        try:
            validate_registry_url(invalid)
        except RuntimeError:
            continue
        raise RuntimeError(f"DAPR_MIRROR_REGISTRY_NEGATIVE_CONTROL_FAILED {invalid}")
    print("DAPR_RUNTIME_MIRROR_SELF_TEST_PASS")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--acquisition", type=Path)
    parser.add_argument("--chart", type=Path)
    parser.add_argument("--registry-url")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()

    try:
        if args.self_test:
            return self_test()
        if not all((args.acquisition, args.chart, args.registry_url, args.out)):
            parser.error("--acquisition, --chart, --registry-url and --out are required")
        evidence = mirror(args.acquisition, args.chart, args.registry_url, args.out)
    except (OSError, ValueError, json.JSONDecodeError, RuntimeError, subprocess.TimeoutExpired) as exc:
        print(f"DAPR_RUNTIME_MIRROR_BLOCKED {exc}", file=__import__("sys").stderr)
        return 3
    print(json.dumps(evidence, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
