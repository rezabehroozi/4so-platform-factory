#!/usr/bin/env python3
"""Build/push the exact Dapr executor image and emit registry readback evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import urllib.parse

import upstream_acquisition_toolchain as toolchain

AUTHORITY = "DAPR_EXECUTOR_IMAGE_EVIDENCE_V1"
CONTEXT_AUTHORITY = "DAPR_EXECUTOR_CONTEXT_AUTHORITY_V1"
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
REGISTRY_RE = re.compile(r"^[a-z0-9.-]+(?::[0-9]+)?$")


def digest_path(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def context_digest(root: Path) -> str:
    rows = []
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).as_posix()
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or (not stat.S_ISREG(info.st_mode) and not stat.S_ISDIR(info.st_mode)):
            raise RuntimeError(f"DAPR_EXECUTOR_CONTEXT_ENTRY_INVALID {rel}")
        if stat.S_ISREG(info.st_mode):
            rows.append({"path": rel, "mode": stat.S_IMODE(info.st_mode), "sha256": digest_path(path), "size": info.st_size})
    if not rows:
        raise RuntimeError("DAPR_EXECUTOR_CONTEXT_EMPTY")
    raw = json.dumps(rows, separators=(",", ":"), sort_keys=True).encode()
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def registry_url(value: str) -> tuple[str, str]:
    parsed = urllib.parse.urlsplit(str(value or "").strip())
    scheme = parsed.scheme.lower()
    if (
        scheme not in {"http", "https"} or not parsed.hostname or parsed.username is not None
        or parsed.password is not None or parsed.path not in {"", "/"} or parsed.query or parsed.fragment
    ):
        raise RuntimeError("DAPR_EXECUTOR_REGISTRY_URL_INVALID")
    host = parsed.netloc.lower()
    if not REGISTRY_RE.fullmatch(host):
        raise RuntimeError("DAPR_EXECUTOR_REGISTRY_IDENTITY_INVALID")
    return scheme, host


def load_context(root: Path) -> tuple[dict, str]:
    root = root.expanduser()
    if root.is_symlink() or not root.is_dir():
        raise RuntimeError("DAPR_EXECUTOR_CONTEXT_INVALID")
    root = root.resolve()
    lock_path = root / "executor-context.lock.json"
    dockerfile = root / "Dockerfile"
    required = {"helm", "dapr-runtime", "dapr-1.18.4.tgz", "Dockerfile", "executor-context.lock.json"}
    got = {p.name for p in root.iterdir() if p.is_file()}
    if got != required:
        raise RuntimeError(f"DAPR_EXECUTOR_CONTEXT_FILE_SET_INVALID got={sorted(got)}")
    if lock_path.is_symlink() or dockerfile.is_symlink():
        raise RuntimeError("DAPR_EXECUTOR_CONTEXT_REQUIRED_FILE_INVALID")
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    if lock.get("authority") != CONTEXT_AUTHORITY:
        raise RuntimeError("DAPR_EXECUTOR_CONTEXT_AUTHORITY_INVALID")
    build = lock.get("build") or {}
    output = lock.get("output") or {}
    if build.get("authority") != "buildkit" or build.get("networkRequired") is not False or build.get("baseImageRequired") is not False:
        raise RuntimeError("DAPR_EXECUTOR_CONTEXT_BUILD_BOUNDARY_INVALID")
    if output.get("repository") != "dapr-runtime" or output.get("zotMirrorRequired") is not True:
        raise RuntimeError("DAPR_EXECUTOR_CONTEXT_OUTPUT_BOUNDARY_INVALID")
    if digest_path(dockerfile) != build.get("dockerfileSha256"):
        raise RuntimeError("DAPR_EXECUTOR_DOCKERFILE_DIGEST_MISMATCH")
    return lock, context_digest(root)


def run(command: list[str], timeout: int = 1800) -> str:
    proc = subprocess.run(command, text=True, capture_output=True, timeout=timeout)
    if proc.returncode:
        tail = (proc.stdout + "\n" + proc.stderr)[-8192:].strip()
        raise RuntimeError(f"DAPR_EXECUTOR_BUILD_COMMAND_FAILED {' '.join(command)} {tail}")
    return (proc.stdout or proc.stderr).strip()


def crane_args(crane: str, scheme: str, *args: str) -> list[str]:
    out = [crane]
    if scheme == "http":
        out.append("--insecure")
    out.extend(args)
    return out


def build(context: Path, buildctl: Path, address: str, registry: str, out: Path) -> dict:
    context = context.expanduser()
    buildctl = buildctl.expanduser()
    if buildctl.is_symlink() or not buildctl.is_file() or not os.access(buildctl, os.X_OK):
        raise RuntimeError("DAPR_BUILDKIT_CLIENT_INVALID")
    buildctl = buildctl.resolve()
    scheme, host = registry_url(registry)
    lock, ctx_digest = load_context(context)
    repository = host + "/4so/dapr-runtime"
    tag = "ctx-" + ctx_digest.removeprefix("sha256:")[:24]
    tagged = repository + ":" + tag

    release_digest = str((lock.get("sourceRelease") or {}).get("sha256") or "")
    acquisition_digest = str((lock.get("runtimeAcquisition") or {}).get("sha256") or "")
    if not DIGEST_RE.fullmatch(release_digest) or not DIGEST_RE.fullmatch(acquisition_digest):
        raise RuntimeError("DAPR_EXECUTOR_CONTEXT_UPSTREAM_DIGEST_INVALID")

    version = run([str(buildctl), "--version"], 30).splitlines()[0].strip()
    command = [str(buildctl)]
    if address.strip():
        command += ["--addr", address.strip()]
    output = f"type=image,name={tagged},push=true"
    if scheme == "http":
        output += ",registry.insecure=true"
    command += [
        "build", "--frontend", "dockerfile.v0",
        "--local", f"context={context}", "--local", f"dockerfile={context}",
        "--opt", "filename=Dockerfile",
        "--opt", f"build-arg:SOURCE_RELEASE_DIGEST={release_digest}",
        "--opt", f"build-arg:DAPR_ACQUISITION_DIGEST={acquisition_digest}",
        "--output", output,
    ]
    run(command)

    pinned = toolchain.require_toolchain()
    crane = str(pinned["crane"][0])
    digest = run(crane_args(crane, scheme, "digest", tagged), 300).strip().lower()
    if not DIGEST_RE.fullmatch(digest):
        raise RuntimeError("DAPR_EXECUTOR_IMAGE_DIGEST_INVALID")
    exact = repository + "@" + digest
    if run(crane_args(crane, scheme, "digest", exact), 300).strip().lower() != digest:
        raise RuntimeError("DAPR_EXECUTOR_IMAGE_READBACK_MISMATCH")

    evidence = {
        "authority": AUTHORITY,
        "executorContextAuthority": CONTEXT_AUTHORITY,
        "executorContextDigest": ctx_digest,
        "acquisitionReceiptDigest": acquisition_digest,
        "sourceReleaseDigest": release_digest,
        "buildAuthority": "buildkit",
        "buildctlVersion": version,
        "registryAuthority": "zot",
        "registryScheme": scheme,
        "registryIdentity": host,
        "imageReference": exact,
        "imageDigest": digest,
        "registryReadback": True,
        "credentialsEmbedded": False,
        "runtimeMutationPerformed": False,
        "physicalCertificationInferred": False,
    }
    candidate = Path(os.path.abspath(os.fspath(out.expanduser())))
    if candidate.is_symlink():
        raise RuntimeError("DAPR_EXECUTOR_EVIDENCE_OUTPUT_SYMLINK_FORBIDDEN")
    candidate.parent.mkdir(parents=True, exist_ok=True)
    tmp = candidate.with_suffix(candidate.suffix + ".tmp")
    tmp.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(candidate)
    return evidence


def self_test() -> int:
    if registry_url("http://platform-zot:5000") != ("http", "platform-zot:5000"):
        raise RuntimeError("DAPR_EXECUTOR_REGISTRY_SELF_TEST_FAILED")
    if registry_url("https://registry.example") != ("https", "registry.example"):
        raise RuntimeError("DAPR_EXECUTOR_REGISTRY_SELF_TEST_FAILED")
    for bad in ("platform-zot:5000", "ftp://platform-zot:5000", "http://platform-zot:5000/path"):
        try:
            registry_url(bad)
        except RuntimeError:
            continue
        raise RuntimeError(f"DAPR_EXECUTOR_REGISTRY_NEGATIVE_CONTROL_FAILED {bad}")
    print("DAPR_EXECUTOR_IMAGE_SELF_TEST_PASS")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--context", type=Path)
    parser.add_argument("--buildctl", type=Path)
    parser.add_argument("--buildkit-address", default="")
    parser.add_argument("--registry-url")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    try:
        if args.self_test:
            return self_test()
        if not all((args.context, args.buildctl, args.registry_url, args.out)):
            parser.error("--context, --buildctl, --registry-url and --out are required")
        evidence = build(args.context, args.buildctl, args.buildkit_address, args.registry_url, args.out)
    except (RuntimeError, OSError, ValueError, json.JSONDecodeError, subprocess.TimeoutExpired) as exc:
        print(f"DAPR_EXECUTOR_IMAGE_BLOCKED {exc}", file=__import__("sys").stderr)
        return 3
    print(json.dumps(evidence, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
