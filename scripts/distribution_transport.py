#!/usr/bin/env python3
"""Shared fail-closed distribution transport contracts.

Multipart transport is only a byte-delivery mechanism. The canonical artifact
identity remains the full-object sha256 + size. Every part is independently
content-addressed and the reconstructed object must be re-verified by consumers.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path
from urllib.parse import urlsplit

SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_URLS = 4
MAX_PARTS = 64
MAX_OBJECT_BYTES = 32 * 1024 * 1024 * 1024


def file_sha256(path: Path) -> tuple[str, int]:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"DISTRIBUTION_FILE_INVALID {path}")
    size = path.stat().st_size
    if size <= 0 or size > MAX_OBJECT_BYTES:
        raise RuntimeError(f"DISTRIBUTION_FILE_SIZE_INVALID {path}")
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest(), size


def validate_content_addressed_https_url(raw: str, digest: str, label: str) -> str:
    value = str(raw or "").strip()
    parsed = urlsplit(value)
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
    if not SHA256_HEX_RE.fullmatch(str(digest or "")):
        raise RuntimeError(f"{label}_SHA256_INVALID")
    if digest not in parsed.path.lower():
        raise RuntimeError(f"{label}_CONTENT_ADDRESS_REQUIRED")
    return value


def validate_urls(urls: object, digest: str, label: str) -> list[str]:
    if (
        not isinstance(urls, list)
        or not 1 <= len(urls) <= MAX_URLS
        or any(not isinstance(url, str) for url in urls)
        or len(set(urls)) != len(urls)
    ):
        raise RuntimeError(f"{label}_URL_COVERAGE_INVALID")
    return [validate_content_addressed_https_url(url, digest, f"{label}_URL") for url in urls]


def validate_parts(parts: object, expected_size: int, label: str) -> list[dict]:
    if not isinstance(parts, list) or not 1 <= len(parts) <= MAX_PARTS:
        raise RuntimeError(f"{label}_PART_COVERAGE_INVALID")
    if not isinstance(expected_size, int) or isinstance(expected_size, bool) or expected_size <= 0 or expected_size > MAX_OBJECT_BYTES:
        raise RuntimeError(f"{label}_OBJECT_SIZE_INVALID")
    out: list[dict] = []
    total = 0
    for expected_index, part in enumerate(parts):
        if not isinstance(part, dict) or set(part) != {"index", "urls", "sha256", "sizeBytes"}:
            raise RuntimeError(f"{label}_PART_FIELDS_INVALID")
        if part.get("index") != expected_index:
            raise RuntimeError(f"{label}_PART_INDEX_INVALID")
        digest = str(part.get("sha256") or "")
        if not SHA256_HEX_RE.fullmatch(digest):
            raise RuntimeError(f"{label}_PART_SHA256_INVALID")
        size = part.get("sizeBytes")
        if not isinstance(size, int) or isinstance(size, bool) or size <= 0 or size > MAX_OBJECT_BYTES:
            raise RuntimeError(f"{label}_PART_SIZE_INVALID")
        urls = validate_urls(part.get("urls"), digest, f"{label}_PART_{expected_index}")
        total += size
        if total > expected_size:
            raise RuntimeError(f"{label}_PART_SIZE_SUM_INVALID")
        out.append({"index": expected_index, "urls": urls, "sha256": digest, "sizeBytes": size})
    if total != expected_size:
        raise RuntimeError(f"{label}_PART_SIZE_SUM_INVALID")
    return out


def validate_locator(value: dict, *, expected_sha256: str, expected_size: int, label: str) -> dict:
    if not isinstance(value, dict):
        raise RuntimeError(f"{label}_LOCATOR_INVALID")
    if not SHA256_HEX_RE.fullmatch(str(expected_sha256 or "")):
        raise RuntimeError(f"{label}_SHA256_INVALID")
    if not isinstance(expected_size, int) or isinstance(expected_size, bool) or expected_size <= 0 or expected_size > MAX_OBJECT_BYTES:
        raise RuntimeError(f"{label}_SIZE_INVALID")
    has_urls = "urls" in value
    has_parts = "parts" in value
    if has_urls == has_parts:
        raise RuntimeError(f"{label}_TRANSPORT_MODE_INVALID")
    if has_urls:
        return {"urls": validate_urls(value.get("urls"), expected_sha256, label)}
    return {"parts": validate_parts(value.get("parts"), expected_size, label)}


def split_file(path: Path, out_dir: Path, *, max_part_bytes: int, name: str) -> dict:
    full_sha, full_size = file_sha256(path)
    if not isinstance(max_part_bytes, int) or max_part_bytes <= 0 or max_part_bytes > 1900 * 1024 * 1024:
        raise RuntimeError("DISTRIBUTION_PART_SIZE_LIMIT_INVALID")
    safe_name = str(name or "").strip()
    if not safe_name or "/" in safe_name or "\\" in safe_name:
        raise RuntimeError("DISTRIBUTION_PART_NAME_INVALID")
    out_dir.mkdir(parents=True, exist_ok=True)
    if out_dir.is_symlink():
        raise RuntimeError("DISTRIBUTION_PART_OUTPUT_SYMLINK_FORBIDDEN")
    parts = []
    with path.open("rb") as src:
        index = 0
        while True:
            data = src.read(max_part_bytes)
            if not data:
                break
            digest = hashlib.sha256(data).hexdigest()
            filename = f"{safe_name}.part{index:04d}.sha256-{digest}"
            target = out_dir / filename
            if target.exists() or target.is_symlink():
                raise RuntimeError("DISTRIBUTION_PART_OUTPUT_EXISTS")
            target.write_bytes(data)
            parts.append({"index": index, "fileName": filename, "sha256": digest, "sizeBytes": len(data)})
            index += 1
    if not parts or sum(row["sizeBytes"] for row in parts) != full_size:
        raise RuntimeError("DISTRIBUTION_PART_SPLIT_INVALID")
    return {
        "sha256": full_sha,
        "sizeBytes": full_size,
        "partCount": len(parts),
        "maxPartBytes": max_part_bytes,
        "parts": parts,
    }


def reassemble_files(parts: list[dict], directory: Path, output: Path, *, expected_sha256: str, expected_size: int) -> None:
    if output.exists() or output.is_symlink():
        raise RuntimeError("DISTRIBUTION_REASSEMBLY_OUTPUT_EXISTS")
    output.parent.mkdir(parents=True, exist_ok=True)
    total = 0
    whole = hashlib.sha256()
    with output.open("wb") as dst:
        for expected_index, row in enumerate(parts):
            if row.get("index") != expected_index:
                raise RuntimeError("DISTRIBUTION_REASSEMBLY_PART_INDEX_INVALID")
            filename = str(row.get("fileName") or "")
            if not filename or "/" in filename or "\\" in filename:
                raise RuntimeError("DISTRIBUTION_REASSEMBLY_PART_NAME_INVALID")
            source = directory / filename
            got_sha, got_size = file_sha256(source)
            if got_sha != row.get("sha256") or got_size != row.get("sizeBytes"):
                raise RuntimeError("DISTRIBUTION_REASSEMBLY_PART_DRIFT")
            with source.open("rb") as fh:
                for block in iter(lambda: fh.read(1024 * 1024), b""):
                    total += len(block)
                    if total > expected_size:
                        raise RuntimeError("DISTRIBUTION_REASSEMBLY_SIZE_EXCEEDED")
                    whole.update(block)
                    dst.write(block)
    if total != expected_size or whole.hexdigest() != expected_sha256:
        output.unlink(missing_ok=True)
        raise RuntimeError("DISTRIBUTION_REASSEMBLY_FULL_IDENTITY_MISMATCH")
