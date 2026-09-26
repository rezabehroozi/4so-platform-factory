#!/usr/bin/env python3
"""Seal public distribution authority for the canonical appliance input pack.

This tool never uploads bytes. It converts the shipped V8 acquisition lock from
incomplete to ready only after a caller supplies:
- a deterministic local input-pack ZIP containing every locked staging artifact,
- one immutable public HTTPS URL for that exact ZIP, and
- one immutable public HTTPS URL for the exact management workload OCI archive.

Both URLs are authority metadata only; local bytes are re-hashed before the lock
is mutated. Runtime or Physical PASS is never inferred.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import urllib.parse
import zipfile

ROOT = Path(__file__).resolve().parents[1]
LOCK_REL = Path("lab/appliance-bundle-acquisition-lock.json")
RECEIPT_REL = Path("lab/management-workload-oci-archive-receipt.json")
LOCK_AUTHORITY = "LAB_APPLIANCE_BUNDLE_ACQUISITION_LOCK_V8"
RECEIPT_AUTHORITY = "MANAGEMENT_WORKLOAD_OCI_ARCHIVE_RECEIPT_V1"
ARCHIVE_AUTHORITY = "management-workload-oci-archive"
ZERO_RELEASE_DIGEST = "sha256:" + "0" * 64
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_PACK_BYTES = 32 * 1024 * 1024 * 1024
MAX_FILES = 4096


def sha256_file(path: Path) -> tuple[str, int]:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_size <= 0:
        raise RuntimeError(f"regular non-empty file required: {path}")
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest(), info.st_size


def immutable_https_url(raw: str, label: str) -> str:
    value = str(raw or "").strip()
    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise RuntimeError(f"{label}_IMMUTABLE_PUBLIC_HTTPS_REQUIRED")
    host = parsed.hostname.lower().rstrip(".")
    if host in {"localhost"} or host.endswith(".localhost"):
        raise RuntimeError(f"{label}_PUBLIC_HOST_REQUIRED")
    return value


def safe_member(name: str) -> str:
    if not name or "\\" in name or name.startswith("/"):
        raise RuntimeError("INPUT_PACK_MEMBER_PATH_INVALID")
    p = PurePosixPath(name)
    if any(part in {"", ".", ".."} for part in p.parts):
        raise RuntimeError("INPUT_PACK_MEMBER_PATH_INVALID")
    return p.as_posix()


def inspect_input_pack(path: Path, lock: dict, receipt: dict) -> tuple[str, int]:
    digest, size = sha256_file(path)
    if size > MAX_PACK_BYTES:
        raise RuntimeError("INPUT_PACK_TOO_LARGE")
    required: dict[str, tuple[str, int]] = {}
    for authority in lock.get("resolvedAuthorities") or []:
        for artifact in authority.get("artifacts") or []:
            required["staging/" + artifact["stagingPath"]] = (artifact["sha256"], int(artifact["sizeBytes"]))
    archive_hex = str(receipt.get("archiveSha256") or "").removeprefix("sha256:")
    archive_size = int(receipt.get("archiveBytes") or 0)
    required["staging/workloads/platform-workloads.oci.tar"] = (archive_hex, archive_size)

    with zipfile.ZipFile(path) as zf:
        infos = zf.infolist()
        if not infos or len(infos) > MAX_FILES:
            raise RuntimeError("INPUT_PACK_MEMBER_COUNT_INVALID")
        names: set[str] = set()
        for info in infos:
            name = safe_member(info.filename.rstrip("/")) if not info.is_dir() else safe_member(info.filename.rstrip("/"))
            if name in names:
                raise RuntimeError("INPUT_PACK_DUPLICATE_MEMBER")
            names.add(name)
            mode = (info.external_attr >> 16) & 0o170000
            if mode == stat.S_IFLNK:
                raise RuntimeError("INPUT_PACK_SYMLINK_FORBIDDEN")
        if "build-spec.json" not in names:
            raise RuntimeError("INPUT_PACK_BUILD_SPEC_MISSING")
        try:
            build = json.loads(zf.read("build-spec.json"))
        except Exception as exc:
            raise RuntimeError("INPUT_PACK_BUILD_SPEC_INVALID") from exc
        if (build.get("apiVersion"), build.get("kind")) != ("platform.4so.io/v1alpha1", "ApplianceBundleBuild"):
            raise RuntimeError("INPUT_PACK_BUILD_SPEC_AUTHORITY_INVALID")
        if (build.get("metadata") or {}).get("sourceReleaseDigest") != ZERO_RELEASE_DIGEST:
            raise RuntimeError("INPUT_PACK_RELEASE_PLACEHOLDER_INVALID")
        if (build.get("metadata") or {}).get("version") != lock.get("releaseVersion"):
            raise RuntimeError("INPUT_PACK_RELEASE_VERSION_MISMATCH")

        for member, (expected_digest, expected_size) in required.items():
            if member not in names:
                raise RuntimeError(f"INPUT_PACK_REQUIRED_MEMBER_MISSING {member}")
            info = zf.getinfo(member)
            if info.file_size != expected_size:
                raise RuntimeError(f"INPUT_PACK_REQUIRED_MEMBER_SIZE_MISMATCH {member}")
            h = hashlib.sha256()
            with zf.open(info) as fh:
                for block in iter(lambda: fh.read(1024 * 1024), b""):
                    h.update(block)
            if h.hexdigest() != expected_digest:
                raise RuntimeError(f"INPUT_PACK_REQUIRED_MEMBER_DIGEST_MISMATCH {member}")
    return digest, size


def build_ready_lock(lock: dict, receipt: dict, *, archive_url: str, input_pack_url: str, pack_sha: str, pack_size: int) -> dict:
    if lock.get("authority") != LOCK_AUTHORITY or lock.get("schemaVersion") != 8 or lock.get("status") != "incomplete":
        raise RuntimeError("ACQUISITION_LOCK_STATE_INVALID")
    if lock.get("missingAuthorities"):
        raise RuntimeError("ACQUISITION_LOCK_STILL_HAS_MISSING_AUTHORITIES")
    partial = list(lock.get("partialAuthorities") or [])
    if len(partial) != 1 or partial[0].get("id") != ARCHIVE_AUTHORITY:
        raise RuntimeError("ACQUISITION_LOCK_ARCHIVE_PARTIAL_STATE_INVALID")
    if receipt.get("authority") != RECEIPT_AUTHORITY or receipt.get("archiveBuilt") is not True:
        raise RuntimeError("MANAGEMENT_ARCHIVE_RECEIPT_INVALID")
    if receipt.get("distributionReady") is not False or receipt.get("runtimeCertified") is not False or receipt.get("physicalCertified") is not False:
        raise RuntimeError("MANAGEMENT_ARCHIVE_RECEIPT_SCOPE_INFLATED")
    if str(receipt.get("releaseVersion")) != str(lock.get("releaseVersion")):
        raise RuntimeError("MANAGEMENT_ARCHIVE_RELEASE_MISMATCH")
    archive_sha = str(receipt.get("archiveSha256") or "")
    archive_hex = archive_sha.removeprefix("sha256:")
    archive_size = receipt.get("archiveBytes")
    if not SHA_RE.fullmatch(archive_hex) or not isinstance(archive_size, int) or archive_size <= 0:
        raise RuntimeError("MANAGEMENT_ARCHIVE_RECEIPT_DIGEST_INVALID")
    immutable_https_url(archive_url, "ARCHIVE_URL")
    immutable_https_url(input_pack_url, "INPUT_PACK_URL")
    if not SHA_RE.fullmatch(pack_sha) or pack_size <= 0:
        raise RuntimeError("INPUT_PACK_DIGEST_INVALID")

    archive = {
        "id": ARCHIVE_AUTHORITY,
        "kind": "oci-archive",
        "provider": "4so",
        "version": str(lock["releaseVersion"]),
        "scope": "management-plane-workload-images-offline-distribution",
        "artifacts": [{
            "name": "platform-workloads.oci.tar",
            "stagingPath": "workloads/platform-workloads.oci.tar",
            "urls": [archive_url],
            "sha256": archive_hex,
            "sizeBytes": archive_size,
        }],
    }
    out = json.loads(json.dumps(lock))
    out["resolvedAuthorities"] = sorted([*(out.get("resolvedAuthorities") or []), archive], key=lambda row: row["id"])
    out["partialAuthorities"] = []
    out["missingAuthorities"] = []
    out["inputPack"] = {
        "urls": [input_pack_url],
        "sha256": pack_sha,
        "sizeBytes": pack_size,
        "format": "zip",
        "buildSpecPath": "build-spec.json",
        "stagingDirectory": "staging",
    }
    out["status"] = "ready"
    return out


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--root", type=Path, default=ROOT)
    p.add_argument("--input-pack", type=Path, required=True)
    p.add_argument("--input-pack-url", required=True)
    p.add_argument("--archive-url", required=True)
    p.add_argument("--write", action="store_true")
    args = p.parse_args()
    root = args.root.resolve()
    lock_path = root / LOCK_REL
    receipt_path = root / RECEIPT_REL
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    pack_sha, pack_size = inspect_input_pack(args.input_pack.resolve(), lock, receipt)
    ready = build_ready_lock(lock, receipt, archive_url=args.archive_url, input_pack_url=args.input_pack_url, pack_sha=pack_sha, pack_size=pack_size)
    if args.write:
        tmp = lock_path.with_suffix(lock_path.suffix + ".tmp")
        tmp.write_text(json.dumps(ready, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(tmp, lock_path)
    print(json.dumps({
        "authority": LOCK_AUTHORITY,
        "status": ready["status"],
        "archiveURL": args.archive_url,
        "inputPackURL": args.input_pack_url,
        "inputPackSha256": "sha256:" + pack_sha,
        "inputPackBytes": pack_size,
        "runtimeCertified": False,
        "physicalCertified": False,
        "written": bool(args.write),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
