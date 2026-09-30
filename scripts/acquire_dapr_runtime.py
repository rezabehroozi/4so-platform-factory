#!/usr/bin/env python3
"""Acquire exact Dapr v1.18.4 source/chart/image identities for later zot sealing.

This script performs no target mutation. It downloads the exact upstream source
archive by commit, materializes only charts/dapr, renders the minimal 4SO profile,
and resolves the four required runtime image tags to immutable OCI digests.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tarfile
import tempfile
import urllib.parse
import urllib.request

import yaml

from upstream_acquisition_toolchain import require_toolchain

ROOT = Path(__file__).resolve().parents[1]
AUTHORITY = "DAPR_RUNTIME_ACQUISITION_V1"
SOURCE_PLAN_AUTHORITY = "DAPR_RUNTIME_SOURCE_PLAN_V1"
VERSION = "v1.18.4"
IMAGE_TAG = "1.18.4"
UPSTREAM_REPOSITORY = "https://github.com/dapr/dapr"
UPSTREAM_COMMIT = "6d1c53f430205c0c0f3bc3589ce5a3ec3f6f1647"
CHART_PATH = "charts/dapr"
IMAGE_REGISTRY = "ghcr.io/dapr"
REQUIRED_IMAGES = {
    "sidecar": f"{IMAGE_REGISTRY}/daprd",
    "operator": f"{IMAGE_REGISTRY}/operator",
    "injector": f"{IMAGE_REGISTRY}/injector",
    "sentry": f"{IMAGE_REGISTRY}/sentry",
}
FORBIDDEN_IMAGES = {f"{IMAGE_REGISTRY}/placement", f"{IMAGE_REGISTRY}/scheduler"}
HELM_OVERRIDES = {
    "global.registry": IMAGE_REGISTRY,
    "global.tag": IMAGE_TAG,
    "global.actors.enabled": "false",
    "global.scheduler.enabled": "false",
    "global.mtls.enabled": "true",
    "global.prometheus.enabled": "true",
    "dapr_config.dapr_config_chart_included": "false",
    "dapr_sidecar_injector.sidecarRunAsNonRoot": "true",
    "dapr_sidecar_injector.sidecarReadOnlyRootFilesystem": "true",
    "dapr_sidecar_injector.sidecarDropALLCapabilities": "true",
}
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
MAX_CHART_MEMBERS = 4096
MAX_CHART_BYTES = 64 * 1024 * 1024


def sha256_bytes(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def canonical_json(value) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def safe_output(path: Path) -> Path:
    candidate = Path(os.path.abspath(os.fspath(path.expanduser())))
    if candidate.is_symlink():
        raise RuntimeError("DAPR_ACQUISITION_OUTPUT_SYMLINK_FORBIDDEN")
    return candidate


def https_download(url: str, timeout: int) -> tuple[bytes, str]:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise RuntimeError("DAPR_SOURCE_URL_INVALID")
    request = urllib.request.Request(url, headers={"User-Agent": "4so-platform-factory-dapr-acquirer/1"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        final = urllib.parse.urlsplit(response.geturl())
        if final.scheme != "https" or not final.hostname:
            raise RuntimeError("DAPR_SOURCE_HTTPS_DOWNGRADE_DENIED")
        raw = response.read(MAX_ARCHIVE_BYTES + 1)
    if len(raw) <= 1024 or len(raw) > MAX_ARCHIVE_BYTES:
        raise RuntimeError("DAPR_SOURCE_ARCHIVE_SIZE_INVALID")
    return raw, response.geturl()


def materialize_chart(archive_raw: bytes, destination: Path) -> list[str]:
    count = 0
    total = 0
    written: list[str] = []
    prefix = f"dapr-{UPSTREAM_COMMIT}/{CHART_PATH}/"
    with tarfile.open(fileobj=io.BytesIO(archive_raw), mode="r:gz") as tf:
        members = tf.getmembers()
        roots = {Path(m.name).parts[0] for m in members if Path(m.name).parts}
        if roots != {f"dapr-{UPSTREAM_COMMIT}"}:
            raise RuntimeError("DAPR_SOURCE_ARCHIVE_ROOT_INVALID")
        for member in members:
            if not member.name.startswith(prefix):
                continue
            relative = member.name[len(prefix):].rstrip("/")
            if not relative:
                continue
            parts = Path(relative).parts
            if relative.startswith("/") or "\\" in relative or ".." in parts:
                raise RuntimeError("DAPR_CHART_ARCHIVE_PATH_INVALID")
            if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                raise RuntimeError("DAPR_CHART_ARCHIVE_ENTRY_INVALID")
            if not (member.isfile() or member.isdir()):
                raise RuntimeError("DAPR_CHART_ARCHIVE_ENTRY_INVALID")
            count += 1
            if count > MAX_CHART_MEMBERS:
                raise RuntimeError("DAPR_CHART_MEMBER_LIMIT_EXCEEDED")
            target = destination.joinpath(*parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            total += member.size
            if member.size < 0 or total > MAX_CHART_BYTES:
                raise RuntimeError("DAPR_CHART_UNPACKED_LIMIT_EXCEEDED")
            stream = tf.extractfile(member)
            if stream is None:
                raise RuntimeError("DAPR_CHART_MEMBER_UNREADABLE")
            raw = stream.read(member.size + 1)
            if len(raw) != member.size:
                raise RuntimeError("DAPR_CHART_MEMBER_SIZE_MISMATCH")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
            written.append(relative)
    if not written or not (destination / "Chart.yaml").is_file() or not (destination / "values.yaml").is_file():
        raise RuntimeError("DAPR_CHART_TREE_INCOMPLETE")
    return sorted(written)


def chart_tree_digest(root: Path, files: list[str]) -> str:
    rows = []
    for relative in sorted(files):
        path = root / relative
        if path.is_symlink() or not path.is_file():
            raise RuntimeError("DAPR_CHART_TREE_FILE_INVALID")
        rows.append({"path": relative, "sha256": sha256_bytes(path.read_bytes())})
    return sha256_bytes(canonical_json(rows))


def run(cmd: list[str], *, env: dict[str, str] | None = None, timeout: int = 300) -> str:
    import subprocess
    merged = os.environ.copy()
    if env:
        merged.update(env)
    result = subprocess.run(
        cmd, cwd=ROOT, env=merged, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout,
    )
    if result.returncode:
        raise RuntimeError(f"DAPR_COMMAND_FAILED rc={result.returncode} cmd={cmd!r}\n{result.stdout[-6000:]}")
    return result.stdout


def helm_env(root: Path) -> dict[str, str]:
    return {
        "HELM_CONFIG_HOME": str(root / "config"),
        "HELM_CACHE_HOME": str(root / "cache"),
        "HELM_DATA_HOME": str(root / "data"),
    }


def render_chart(helm: str, chart: Path, env: dict[str, str]) -> tuple[list[dict], str]:
    cmd = [
        helm, "template", "dapr", str(chart), "--namespace", "dapr-system",
        "--include-crds", "--kube-version", "1.34.0",
    ]
    for path, value in HELM_OVERRIDES.items():
        cmd += ["--set-string", f"{path}={value}"]
    rendered = run(cmd, env=env)
    docs = []
    for doc in yaml.safe_load_all(rendered):
        if doc is None:
            continue
        if not isinstance(doc, dict):
            raise RuntimeError("DAPR_HELM_RENDER_DOCUMENT_INVALID")
        docs.append(doc)
    if not docs:
        raise RuntimeError("DAPR_HELM_RENDER_EMPTY")
    names = []
    rendered_images = []
    default_config_seen = False
    for doc in docs:
        meta = doc.get("metadata") if isinstance(doc.get("metadata"), dict) else {}
        name = str(meta.get("name") or "")
        kind = str(doc.get("kind") or "")
        if name:
            names.append(name)
        low = name.lower()
        if "placement" in low or "scheduler" in low:
            raise RuntimeError(f"DAPR_FORBIDDEN_CONTROL_PLANE_RESOURCE_RENDERED {kind}/{name}")
        if kind == "Configuration" and name == "daprsystem":
            default_config_seen = True
        def walk(value):
            if isinstance(value, dict):
                for key, item in value.items():
                    if key == "image" and isinstance(item, str):
                        rendered_images.append(item.strip())
                    walk(item)
            elif isinstance(value, list):
                for item in value:
                    walk(item)
        walk(doc)
    if default_config_seen:
        raise RuntimeError("DAPR_DEFAULT_CONFIGURATION_RENDERED")
    for forbidden in FORBIDDEN_IMAGES:
        if any(ref.startswith(forbidden + ":") or ref.startswith(forbidden + "@") for ref in rendered_images):
            raise RuntimeError("DAPR_FORBIDDEN_IMAGE_RENDERED")
    return docs, sha256_bytes(canonical_json(docs))


def resolve_images(crane: str) -> list[dict]:
    rows = []
    for role, repository in sorted(REQUIRED_IMAGES.items()):
        tag_ref = f"{repository}:{IMAGE_TAG}"
        digest = run([crane, "digest", tag_ref], timeout=180).strip().splitlines()[-1].lower()
        if not DIGEST_RE.fullmatch(digest):
            raise RuntimeError(f"DAPR_IMAGE_DIGEST_INVALID {tag_ref}:{digest}")
        rows.append({
            "role": role,
            "sourceRepository": repository,
            "sourceTagReference": tag_ref,
            "sourceDigest": digest,
            "sourceReference": f"{repository}@{digest}",
        })
    return rows


def acquire(out: Path, timeout: int) -> dict:
    pinned = require_toolchain()
    helm = str(pinned["helm"][0])
    crane = str(pinned["crane"][0])
    source_url = f"{UPSTREAM_REPOSITORY}/archive/{UPSTREAM_COMMIT}.tar.gz"
    archive_raw, final_url = https_download(source_url, timeout)
    source_digest = sha256_bytes(archive_raw)
    with tempfile.TemporaryDirectory(prefix="4so-dapr-acquire-") as td:
        tmp = Path(td)
        chart = tmp / "chart"
        files = materialize_chart(archive_raw, chart)
        tree_digest = chart_tree_digest(chart, files)
        meta = yaml.safe_load((chart / "Chart.yaml").read_text())
        if not isinstance(meta, dict) or meta.get("apiVersion") != "v2" or meta.get("name") != "dapr":
            raise RuntimeError("DAPR_CHART_IDENTITY_INVALID")
        docs, render_digest = render_chart(helm, chart, helm_env(tmp / "helm"))
        images = resolve_images(crane)
        receipt = {
            "authority": AUTHORITY,
            "sourcePlanAuthority": SOURCE_PLAN_AUTHORITY,
            "version": VERSION,
            "runtimeImageTag": IMAGE_TAG,
            "upstreamRepository": UPSTREAM_REPOSITORY,
            "upstreamRef": VERSION,
            "upstreamCommit": UPSTREAM_COMMIT,
            "sourceArchiveUrl": source_url,
            "sourceArchiveFinalUrl": final_url,
            "sourceArchiveDigest": source_digest,
            "helmChartPath": CHART_PATH,
            "helmChartDigest": tree_digest,
            "helmOverrides": [{"path": k, "value": v} for k, v in sorted(HELM_OVERRIDES.items())],
            "helmRenderDigest": render_digest,
            "requiredImages": images,
            "resolved": True,
            "mirrorReady": False,
            "runtimeMutationPerformed": False,
            "physicalCertificationInferred": False,
        }
    out = safe_output(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp_out = out.with_suffix(out.suffix + ".tmp")
    tmp_out.write_bytes(json.dumps(receipt, indent=2, sort_keys=True).encode() + b"\n")
    os.chmod(tmp_out, stat.S_IRUSR | stat.S_IWUSR)
    tmp_out.replace(out)
    return receipt


def self_test() -> int:
    if VERSION != "v1.18.4" or IMAGE_TAG != "1.18.4" or UPSTREAM_COMMIT != "6d1c53f430205c0c0f3bc3589ce5a3ec3f6f1647":
        raise RuntimeError("DAPR_ACQUISITION_IDENTITY_DRIFT")
    if HELM_OVERRIDES.get("global.tag") != IMAGE_TAG or HELM_OVERRIDES.get("global.registry") != IMAGE_REGISTRY:
        raise RuntimeError("DAPR_ACQUISITION_IMAGE_SELECTION_DRIFT")
    if HELM_OVERRIDES.get("global.actors.enabled") != "false" or HELM_OVERRIDES.get("global.scheduler.enabled") != "false":
        raise RuntimeError("DAPR_ACQUISITION_DUPLICATE_AUTHORITY_PROFILE_INVALID")
    if set(REQUIRED_IMAGES) != {"sidecar", "operator", "injector", "sentry"}:
        raise RuntimeError("DAPR_ACQUISITION_IMAGE_ROLE_SET_INVALID")
    print("DAPR_RUNTIME_ACQUISITION_SELF_TEST_PASS")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--network-timeout", type=int, default=60)
    parser.add_argument("--out", type=Path, default=ROOT / "dist" / "dapr" / "dapr-runtime-acquisition.json")
    args = parser.parse_args()
    try:
        if args.self_test:
            return self_test()
        result = acquire(args.out, args.network_timeout)
    except (OSError, RuntimeError, ValueError, tarfile.TarError, yaml.YAMLError) as exc:
        print(f"DAPR_RUNTIME_ACQUISITION_BLOCKED {exc}", file=__import__("sys").stderr)
        return 3
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
