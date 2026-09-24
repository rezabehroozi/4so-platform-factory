#!/usr/bin/env python3
"""Build and push the exact OpenChoreo executor image through BuildKit.

The build context must be produced by prepare_openchoreo_executor.py. The image
is built FROM scratch with no external base image and pushed to product-owned
zot. This command emits evidence only after registry digest readback.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

import acquire_upstream_helm as helm

AUTHORITY = "OPENCHOREO_EXECUTOR_IMAGE_EVIDENCE_V1"
CONTEXT_AUTHORITY = "OPENCHOREO_EXECUTOR_CONTEXT_AUTHORITY_V1"
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
REPO_RE = re.compile(r"^[a-z0-9.-]+(?::[0-9]+)?/[a-z0-9._/-]*openchoreo-runtime$")

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
            raise RuntimeError(f"OPENCHOREO_EXECUTOR_CONTEXT_ENTRY_INVALID {rel}")
        if stat.S_ISREG(info.st_mode):
            rows.append({"path": rel, "mode": stat.S_IMODE(info.st_mode), "sha256": digest_path(path), "size": info.st_size})
    if not rows:
        raise RuntimeError("OPENCHOREO_EXECUTOR_CONTEXT_EMPTY")
    raw = json.dumps(rows, separators=(",", ":"), sort_keys=True).encode()
    return "sha256:" + hashlib.sha256(raw).hexdigest()

def load_context(root: Path) -> tuple[dict, str]:
    root = root.expanduser().resolve()
    if not root.is_dir() or root.is_symlink():
        raise RuntimeError("OPENCHOREO_EXECUTOR_CONTEXT_INVALID")
    lock_path = root / "executor-context.lock.json"
    dockerfile = root / "Dockerfile"
    if not lock_path.is_file() or lock_path.is_symlink() or not dockerfile.is_file() or dockerfile.is_symlink():
        raise RuntimeError("OPENCHOREO_EXECUTOR_CONTEXT_REQUIRED_FILE_MISSING")
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    if lock.get("authority") != CONTEXT_AUTHORITY:
        raise RuntimeError("OPENCHOREO_EXECUTOR_CONTEXT_AUTHORITY_INVALID")
    build = lock.get("build") or {}
    output = lock.get("output") or {}
    if build.get("authority") != "buildkit" or build.get("networkRequired") is not False or build.get("baseImageRequired") is not False:
        raise RuntimeError("OPENCHOREO_EXECUTOR_CONTEXT_BUILD_BOUNDARY_INVALID")
    if output.get("repository") != "openchoreo-runtime" or output.get("zotMirrorRequired") is not True:
        raise RuntimeError("OPENCHOREO_EXECUTOR_CONTEXT_OUTPUT_BOUNDARY_INVALID")
    if digest_path(dockerfile) != build.get("dockerfileSha256"):
        raise RuntimeError("OPENCHOREO_EXECUTOR_DOCKERFILE_DIGEST_MISMATCH")
    return lock, context_digest(root)

def run(command: list[str], timeout: int = 1800) -> str:
    proc = subprocess.run(command, text=True, capture_output=True, timeout=timeout)
    if proc.returncode != 0:
        tail = (proc.stdout + "\n" + proc.stderr)[-8192:].strip()
        raise RuntimeError(f"OPENCHOREO_EXECUTOR_BUILD_COMMAND_FAILED {' '.join(command)} {tail}")
    return (proc.stdout or proc.stderr).strip()

def build(context: Path, buildctl: Path, address: str, repository: str, out: Path) -> dict:
    context = context.expanduser().resolve()
    buildctl = buildctl.expanduser().resolve()
    if not buildctl.is_file() or buildctl.is_symlink() or not os.access(buildctl, os.X_OK):
        raise RuntimeError("OPENCHOREO_BUILDKIT_CLIENT_INVALID")
    repository = repository.strip().rstrip("/")
    if not REPO_RE.fullmatch(repository) or "://" in repository:
        raise RuntimeError("OPENCHOREO_EXECUTOR_ZOT_REPOSITORY_INVALID")
    lock, ctx_digest = load_context(context)
    tag = "ctx-" + ctx_digest.removeprefix("sha256:")[:24]
    tagged = repository + ":" + tag
    release_digest = str((lock.get("sourceRelease") or {}).get("sha256") or "")
    acquisition_digest = str((lock.get("runtimeAcquisition") or {}).get("sha256") or "")
    if not DIGEST_RE.fullmatch(release_digest) or not DIGEST_RE.fullmatch(acquisition_digest):
        raise RuntimeError("OPENCHOREO_EXECUTOR_CONTEXT_UPSTREAM_DIGEST_INVALID")

    version = run([str(buildctl), "--version"], 30).splitlines()[0].strip()
    command = [str(buildctl)]
    if address.strip():
        command += ["--addr", address.strip()]
    command += [
        "build", "--frontend", "dockerfile.v0",
        "--local", f"context={context}", "--local", f"dockerfile={context}",
        "--opt", "filename=Dockerfile",
        "--opt", f"build-arg:SOURCE_RELEASE_DIGEST={release_digest}",
        "--opt", f"build-arg:OPENCHOREO_ACQUISITION_DIGEST={acquisition_digest}",
        "--output", f"type=image,name={tagged},push=true",
    ]
    run(command)

    pinned = helm.require_toolchain()
    crane = str(pinned["crane"][0])
    digest = run([crane, "digest", tagged], 300).strip().lower()
    if not DIGEST_RE.fullmatch(digest):
        raise RuntimeError("OPENCHOREO_EXECUTOR_IMAGE_DIGEST_INVALID")
    exact = repository + "@" + digest
    evidence = {
        "apiVersion": "platform.4so.io/v1alpha1",
        "kind": "OpenChoreoExecutorImageEvidence",
        "authority": AUTHORITY,
        "executorContextAuthority": CONTEXT_AUTHORITY,
        "executorContextSha256": ctx_digest,
        "acquisitionBundleSha256": acquisition_digest,
        "sourceReleaseSha256": release_digest,
        "buildAuthority": "buildkit",
        "buildctlVersion": version,
        "registryAuthority": "zot",
        "imageReference": exact,
        "imageDigest": digest,
        "registryReadback": True,
        "mirrorReady": True,
    }
    out = out.expanduser().resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(out.suffix + ".tmp")
    tmp.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(out)
    return evidence

def self_test() -> int:
    if not REPO_RE.fullmatch("zot.internal/4so/openchoreo-runtime"):
        raise RuntimeError("OPENCHOREO_EXECUTOR_REPOSITORY_POLICY_SELF_TEST_FAILED")
    for bad in ("https://zot/openchoreo-runtime", "docker.io/library/openchoreo-runtime:latest", "zot/openchoreo-other"):
        if REPO_RE.fullmatch(bad):
            raise RuntimeError("OPENCHOREO_EXECUTOR_REPOSITORY_NEGATIVE_CONTROL_FAILED")
    print("OPENCHOREO_EXECUTOR_IMAGE_SELF_TEST_PASS")
    return 0

def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--self-test", action="store_true")
    p.add_argument("--context", type=Path)
    p.add_argument("--buildctl", type=Path)
    p.add_argument("--buildkit-address", default="")
    p.add_argument("--zot-repository")
    p.add_argument("--out", type=Path)
    args = p.parse_args()
    if args.self_test:
        return self_test()
    if not all((args.context, args.buildctl, args.zot_repository, args.out)):
        p.error("--context, --buildctl, --zot-repository and --out are required")
    try:
        evidence = build(args.context, args.buildctl, args.buildkit_address, args.zot_repository, args.out)
    except (RuntimeError, OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print(f"OPENCHOREO_EXECUTOR_IMAGE_BLOCKED {exc}", file=__import__("sys").stderr)
        return 3
    print(json.dumps(evidence, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
