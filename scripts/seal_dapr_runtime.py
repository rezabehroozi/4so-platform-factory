#!/usr/bin/env python3
"""Seal exact Dapr acquisition + Zot mirror evidence into the API runtime lock."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import urllib.parse

from acquire_dapr_runtime import (
    AUTHORITY as ACQUISITION_AUTHORITY,
    SOURCE_PLAN_AUTHORITY,
    VERSION,
    IMAGE_TAG,
    UPSTREAM_REPOSITORY,
    UPSTREAM_COMMIT,
    REQUIRED_IMAGES,
    HELM_OVERRIDES,
)

LOCK_AUTHORITY = "DAPR_RUNTIME_SUPPLY_CHAIN_LOCK_V1"
MIRROR_AUTHORITY = "DAPR_ZOT_MIRROR_EVIDENCE_V1"
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
REGISTRY_RE = re.compile(r"^[a-z0-9.-]+(?::[0-9]+)?$")
ACQUISITION_KEYS = {
    "authority", "sourcePlanAuthority", "version", "runtimeImageTag",
    "upstreamRepository", "upstreamRef", "upstreamCommit", "sourceArchiveUrl",
    "sourceArchiveFinalUrl", "sourceArchiveDigest", "helmChartPath",
    "helmChartDigest", "helmPackageName", "helmPackageDigest", "helmOverrides",
    "helmRenderDigest", "requiredImages",
    "resolved", "mirrorReady", "runtimeMutationPerformed",
    "physicalCertificationInferred",
}
ACQUISITION_IMAGE_KEYS = {
    "role", "sourceRepository", "sourceTagReference", "sourceDigest", "sourceReference",
}
MIRROR_KEYS = {
    "authority", "registryAuthority", "registryScheme", "registryIdentity", "version", "upstreamCommit",
    "acquisitionReceiptDigest", "helmPackageDigest", "helmMirrorTagReference",
    "helmMirrorReference", "helmMirrorManifestDigest", "helmMirrorContentDigest",
    "images", "mirrorReady", "registryReadback", "offlineReplayReady",
    "credentialsEmbedded", "runtimeMutationPerformed",
    "physicalCertificationInferred",
}
MIRROR_IMAGE_KEYS = {
    "role", "sourceRepository", "sourceReference", "sourceDigest",
    "mirrorTagReference", "mirrorReference", "mirrorDigest",
}
EXECUTOR_AUTHORITY = "DAPR_EXECUTOR_IMAGE_EVIDENCE_V1"
EXECUTOR_CONTEXT_AUTHORITY = "DAPR_EXECUTOR_CONTEXT_AUTHORITY_V1"
EXECUTOR_KEYS = {
    "authority", "executorContextAuthority", "executorContextDigest",
    "acquisitionReceiptDigest", "sourceReleaseDigest", "buildAuthority",
    "buildctlVersion", "registryAuthority", "registryScheme", "registryIdentity",
    "imageReference", "imageDigest", "registryReadback", "credentialsEmbedded",
    "runtimeMutationPerformed", "physicalCertificationInferred",
}


def exact_keys(value: dict, expected: set[str], label: str) -> None:
    got = set(value)
    if got != expected:
        extra = sorted(got - expected)
        missing = sorted(expected - got)
        raise RuntimeError(f"{label}_SCHEMA_INVALID extra={extra} missing={missing}")



def sha256_bytes(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def strict_json(raw: bytes, label: str) -> dict:
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise RuntimeError(f"{label}_DUPLICATE_KEY {key}")
            out[key] = value
        return out
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    if not isinstance(value, dict):
        raise RuntimeError(f"{label}_NOT_OBJECT")
    return value


def load_json(path: Path, label: str, max_bytes: int = 4 << 20) -> tuple[dict, str]:
    candidate = Path(os.path.abspath(os.fspath(path.expanduser())))
    info = candidate.lstat()
    if candidate.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_size <= 0 or info.st_size > max_bytes:
        raise RuntimeError(f"{label}_FILE_INVALID")
    raw = candidate.read_bytes()
    if len(raw) != info.st_size:
        raise RuntimeError(f"{label}_FILE_CHANGED")
    return strict_json(raw, label), sha256_bytes(raw)


def valid_digest(value: object) -> str:
    digest = str(value or "").strip().lower()
    if not DIGEST_RE.fullmatch(digest):
        raise RuntimeError("DAPR_DIGEST_INVALID")
    return digest


def valid_registry(value: object) -> str:
    registry = str(value or "").strip().lower()
    if not REGISTRY_RE.fullmatch(registry):
        raise RuntimeError("DAPR_MIRROR_REGISTRY_INVALID")
    return registry


def valid_registry_scheme(value: object) -> str:
    scheme = str(value or "").strip().lower()
    if scheme not in {"http", "https"}:
        raise RuntimeError("DAPR_MIRROR_REGISTRY_SCHEME_INVALID")
    return scheme


def validate_source_ref(repository: str, digest: str, ref: str) -> None:
    if ref != f"{repository}@{digest}":
        raise RuntimeError("DAPR_ACQUIRED_IMAGE_REFERENCE_INVALID")


def acquisition_images(acquisition: dict) -> dict[str, dict]:
    rows = acquisition.get("requiredImages")
    if not isinstance(rows, list) or len(rows) != len(REQUIRED_IMAGES):
        raise RuntimeError("DAPR_ACQUIRED_IMAGE_SET_INVALID")
    out = {}
    for row in rows:
        if not isinstance(row, dict):
            raise RuntimeError("DAPR_ACQUIRED_IMAGE_ROW_INVALID")
        exact_keys(row, ACQUISITION_IMAGE_KEYS, "DAPR_ACQUIRED_IMAGE")
        role = str(row.get("role") or "").strip()
        repository = str(row.get("sourceRepository") or "").strip()
        digest = valid_digest(row.get("sourceDigest"))
        tag_ref = str(row.get("sourceTagReference") or "").strip()
        source_ref = str(row.get("sourceReference") or "").strip()
        expected_repo = REQUIRED_IMAGES.get(role)
        if expected_repo is None or repository != expected_repo or role in out:
            raise RuntimeError("DAPR_ACQUIRED_IMAGE_IDENTITY_INVALID")
        if tag_ref != f"{repository}:{IMAGE_TAG}":
            raise RuntimeError("DAPR_ACQUIRED_IMAGE_TAG_INVALID")
        validate_source_ref(repository, digest, source_ref)
        out[role] = {
            "role": role,
            "sourceRepository": repository,
            "sourceDigest": digest,
            "sourceReference": source_ref,
        }
    if set(out) != set(REQUIRED_IMAGES):
        raise RuntimeError("DAPR_ACQUIRED_IMAGE_SET_INVALID")
    return out


def validate_acquisition(acquisition: dict) -> dict[str, dict]:
    exact_keys(acquisition, ACQUISITION_KEYS, "DAPR_ACQUISITION")
    if (
        acquisition.get("authority") != ACQUISITION_AUTHORITY
        or acquisition.get("sourcePlanAuthority") != SOURCE_PLAN_AUTHORITY
        or acquisition.get("version") != VERSION
        or acquisition.get("runtimeImageTag") != IMAGE_TAG
        or acquisition.get("upstreamRepository") != UPSTREAM_REPOSITORY
        or acquisition.get("upstreamRef") != VERSION
        or acquisition.get("upstreamCommit") != UPSTREAM_COMMIT
    ):
        raise RuntimeError("DAPR_ACQUISITION_IDENTITY_INVALID")
    if acquisition.get("resolved") is not True or acquisition.get("mirrorReady") is not False:
        raise RuntimeError("DAPR_ACQUISITION_STATE_INVALID")
    if acquisition.get("runtimeMutationPerformed") is not False or acquisition.get("physicalCertificationInferred") is not False:
        raise RuntimeError("DAPR_ACQUISITION_RUNTIME_CLAIM_INVALID")
    expected_source_url = f"{UPSTREAM_REPOSITORY}/archive/{UPSTREAM_COMMIT}.tar.gz"
    if acquisition.get("sourceArchiveUrl") != expected_source_url or acquisition.get("helmChartPath") != "charts/dapr":
        raise RuntimeError("DAPR_ACQUISITION_SOURCE_PATH_INVALID")
    final_url = urllib.parse.urlsplit(str(acquisition.get("sourceArchiveFinalUrl") or ""))
    if final_url.scheme != "https" or final_url.hostname not in {"github.com", "codeload.github.com"} or UPSTREAM_COMMIT not in final_url.path:
        raise RuntimeError("DAPR_ACQUISITION_FINAL_SOURCE_URL_INVALID")
    valid_digest(acquisition.get("sourceArchiveDigest"))
    valid_digest(acquisition.get("helmChartDigest"))
    package_digest = valid_digest(acquisition.get("helmPackageDigest"))
    if acquisition.get("helmPackageName") != f"dapr-{IMAGE_TAG}.tgz":
        raise RuntimeError("DAPR_ACQUISITION_HELM_PACKAGE_IDENTITY_INVALID")
    valid_digest(acquisition.get("helmRenderDigest"))
    overrides = acquisition.get("helmOverrides")
    if not isinstance(overrides, list):
        raise RuntimeError("DAPR_ACQUISITION_HELM_OVERRIDES_INVALID")
    got = {}
    for row in overrides:
        if not isinstance(row, dict):
            raise RuntimeError("DAPR_ACQUISITION_HELM_OVERRIDES_INVALID")
        path = str(row.get("path") or "").strip()
        value = str(row.get("value") or "").strip()
        if not path or path in got:
            raise RuntimeError("DAPR_ACQUISITION_HELM_OVERRIDES_INVALID")
        got[path] = value
    if got != HELM_OVERRIDES:
        raise RuntimeError("DAPR_ACQUISITION_HELM_PROFILE_DRIFT")
    return acquisition_images(acquisition)


def mirror_images(mirror: dict, acquired: dict[str, dict], registry: str) -> list[dict]:
    rows = mirror.get("images")
    if not isinstance(rows, list) or len(rows) != len(acquired):
        raise RuntimeError("DAPR_MIRROR_IMAGE_SET_INVALID")
    out = []
    seen = set()
    for row in rows:
        if not isinstance(row, dict):
            raise RuntimeError("DAPR_MIRROR_IMAGE_ROW_INVALID")
        exact_keys(row, MIRROR_IMAGE_KEYS, "DAPR_MIRROR_IMAGE")
        role = str(row.get("role") or "").strip()
        if role in seen or role not in acquired:
            raise RuntimeError("DAPR_MIRROR_IMAGE_IDENTITY_INVALID")
        expected = acquired[role]
        source_repo = str(row.get("sourceRepository") or "").strip()
        source_digest = valid_digest(row.get("sourceDigest"))
        mirror_digest = valid_digest(row.get("mirrorDigest"))
        source_ref = str(row.get("sourceReference") or "").strip()
        mirror_ref = str(row.get("mirrorReference") or "").strip()
        if source_repo != expected["sourceRepository"] or source_digest != expected["sourceDigest"] or source_ref != expected["sourceReference"]:
            raise RuntimeError("DAPR_MIRROR_SOURCE_MISMATCH")
        if mirror_digest != source_digest:
            raise RuntimeError("DAPR_MIRROR_DIGEST_MISMATCH")
        expected_tag = f"{registry}/dapr/{role}:{VERSION.removeprefix('v')}"
        expected_ref = f"{registry}/dapr/{role}@{mirror_digest}"
        if str(row.get("mirrorTagReference") or "").strip() != expected_tag or mirror_ref != expected_ref:
            raise RuntimeError("DAPR_MIRROR_REFERENCE_INVALID")
        out.append({
            "role": role,
            "sourceRepository": source_repo,
            "sourceDigest": source_digest,
            "mirrorReference": mirror_ref,
            "mirrorDigest": mirror_digest,
        })
        seen.add(role)
    if seen != set(acquired):
        raise RuntimeError("DAPR_MIRROR_IMAGE_SET_INVALID")
    return sorted(out, key=lambda row: row["role"])


def seal(acquisition_path: Path, mirror_path: Path, executor_path: Path, out: Path) -> dict:
    acquisition, acquisition_digest = load_json(acquisition_path, "DAPR_ACQUISITION")
    acquired = validate_acquisition(acquisition)
    mirror, mirror_digest = load_json(mirror_path, "DAPR_MIRROR_EVIDENCE")
    exact_keys(mirror, MIRROR_KEYS, "DAPR_MIRROR_EVIDENCE")
    if (
        mirror.get("authority") != MIRROR_AUTHORITY
        or str(mirror.get("registryAuthority") or "").strip().lower() != "zot"
        or mirror.get("version") != VERSION
        or mirror.get("upstreamCommit") != UPSTREAM_COMMIT
        or mirror.get("acquisitionReceiptDigest") != acquisition_digest
        or mirror.get("mirrorReady") is not True
        or mirror.get("registryReadback") is not True
        or mirror.get("offlineReplayReady") is not True
        or mirror.get("credentialsEmbedded") is not False
        or mirror.get("runtimeMutationPerformed") is not False
        or mirror.get("physicalCertificationInferred") is not False
    ):
        raise RuntimeError("DAPR_MIRROR_EVIDENCE_AUTHORITY_INVALID")
    scheme = valid_registry_scheme(mirror.get("registryScheme"))
    registry = valid_registry(mirror.get("registryIdentity"))
    package_digest = valid_digest(acquisition.get("helmPackageDigest"))
    manifest_digest = valid_digest(mirror.get("helmMirrorManifestDigest"))
    content_digest = valid_digest(mirror.get("helmMirrorContentDigest"))
    chart_tag = f"{registry}/dapr-charts/dapr:{IMAGE_TAG}"
    chart_ref = f"{registry}/dapr-charts/dapr@{manifest_digest}"
    if (
        mirror.get("helmPackageDigest") != package_digest
        or content_digest != package_digest
        or str(mirror.get("helmMirrorTagReference") or "").strip() != chart_tag
        or str(mirror.get("helmMirrorReference") or "").strip() != chart_ref
    ):
        raise RuntimeError("DAPR_MIRROR_HELM_CHART_EVIDENCE_INVALID")
    images = mirror_images(mirror, acquired, registry)
    executor, executor_evidence_digest = load_json(executor_path, "DAPR_EXECUTOR_EVIDENCE")
    exact_keys(executor, EXECUTOR_KEYS, "DAPR_EXECUTOR_EVIDENCE")
    executor_digest = valid_digest(executor.get("imageDigest"))
    executor_context_digest = valid_digest(executor.get("executorContextDigest"))
    valid_digest(executor.get("sourceReleaseDigest"))
    if (
        executor.get("authority") != EXECUTOR_AUTHORITY
        or executor.get("executorContextAuthority") != EXECUTOR_CONTEXT_AUTHORITY
        or executor.get("acquisitionReceiptDigest") != acquisition_digest
        or executor.get("buildAuthority") != "buildkit"
        or executor.get("registryAuthority") != "zot"
        or valid_registry_scheme(executor.get("registryScheme")) != scheme
        or valid_registry(executor.get("registryIdentity")) != registry
        or str(executor.get("imageReference") or "").strip() != f"{registry}/4so/dapr-runtime@{executor_digest}"
        or executor.get("registryReadback") is not True
        or executor.get("credentialsEmbedded") is not False
        or executor.get("runtimeMutationPerformed") is not False
        or executor.get("physicalCertificationInferred") is not False
    ):
        raise RuntimeError("DAPR_EXECUTOR_EVIDENCE_AUTHORITY_INVALID")
    if not str(executor.get("buildctlVersion") or "").strip():
        raise RuntimeError("DAPR_EXECUTOR_BUILDKIT_VERSION_MISSING")
    lock = {
        "authority": LOCK_AUTHORITY,
        "sourcePlanAuthority": SOURCE_PLAN_AUTHORITY,
        "version": VERSION,
        "upstreamRepository": UPSTREAM_REPOSITORY,
        "upstreamRef": VERSION,
        "upstreamCommit": UPSTREAM_COMMIT,
        "sourceArchiveDigest": valid_digest(acquisition.get("sourceArchiveDigest")),
        "helmChartDigest": valid_digest(acquisition.get("helmChartDigest")),
        "helmPackageDigest": package_digest,
        "helmRenderDigest": valid_digest(acquisition.get("helmRenderDigest")),
        "helmMirrorReference": chart_ref,
        "helmMirrorManifestDigest": manifest_digest,
        "acquisitionReceiptDigest": acquisition_digest,
        "mirrorEvidenceDigest": mirror_digest,
        "executorEvidenceDigest": executor_evidence_digest,
        "executorSourceReleaseDigest": valid_digest(executor.get("sourceReleaseDigest")),
        "executorImageReference": executor["imageReference"],
        "executorImageDigest": executor_digest,
        "registryAuthority": "zot",
        "registryScheme": scheme,
        "mirrorRegistry": registry,
        "imageLocks": images,
        "zotMirrorVerified": True,
        "offlineReplayReady": True,
        "admitted": True,
    }
    out = Path(os.path.abspath(os.fspath(out.expanduser())))
    if out.is_symlink():
        raise RuntimeError("DAPR_RUNTIME_LOCK_OUTPUT_SYMLINK_FORBIDDEN")
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(out.suffix + ".tmp")
    tmp.write_bytes(json.dumps(lock, indent=2, sort_keys=True).encode() + b"\n")
    os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
    tmp.replace(out)
    return lock


def self_test() -> int:
    digest = "sha256:" + "a" * 64
    validate_source_ref("ghcr.io/dapr/daprd", digest, "ghcr.io/dapr/daprd@" + digest)
    try:
        validate_source_ref("ghcr.io/dapr/daprd", digest, "ghcr.io/dapr/daprd:1.18.4")
    except RuntimeError:
        pass
    else:
        raise RuntimeError("DAPR_RUNTIME_SEAL_MUTABLE_REFERENCE_NEGATIVE_CONTROL_FAILED")
    if valid_registry("platform-zot:5000") != "platform-zot:5000":
        raise RuntimeError("DAPR_RUNTIME_SEAL_REGISTRY_SELF_TEST_FAILED")
    print("DAPR_RUNTIME_SEAL_SELF_TEST_PASS")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--acquisition", type=Path)
    parser.add_argument("--mirror-evidence", type=Path)
    parser.add_argument("--executor-evidence", type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    if args.self_test:
        try:
            return self_test()
        except RuntimeError as exc:
            print(f"DAPR_RUNTIME_SEAL_BLOCKED {exc}", file=__import__("sys").stderr)
            return 3
    if not all((args.acquisition, args.mirror_evidence, args.executor_evidence, args.out)):
        parser.error("--acquisition, --mirror-evidence, --executor-evidence and --out are required")
    try:
        lock = seal(args.acquisition, args.mirror_evidence, args.executor_evidence, args.out)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError, RuntimeError) as exc:
        print(f"DAPR_RUNTIME_SEAL_BLOCKED {exc}", file=__import__("sys").stderr)
        return 3
    print(json.dumps(lock, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
