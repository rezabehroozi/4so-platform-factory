#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

AUTHORITY = "CERT_MANAGER_CRD_RUNTIME_DEPENDENCY_LOCK_V1"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
CRD_KIND = re.compile(r"(?m)^kind:\s*CustomResourceDefinition\s*$")
EXPECTED = {
    "certificates.cert-manager.io",
    "certificaterequests.cert-manager.io",
    "issuers.cert-manager.io",
    "clusterissuers.cert-manager.io",
    "orders.acme.cert-manager.io",
    "challenges.acme.cert-manager.io",
}
RELEASES = ("1.21.0", "1.21.1")


def digest(path: Path) -> tuple[str, int]:
    st = path.lstat()
    if path.is_symlink() or not path.is_file() or st.st_size <= 0:
        raise RuntimeError(f"CERT_MANAGER_CRD_FILE_INVALID {path}")
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest(), st.st_size


def crd_names(raw: str) -> set[str]:
    names: set[str] = set()
    for document in re.split(r"(?m)^---\s*$", raw):
        if not CRD_KIND.search(document):
            continue
        lines = document.splitlines()
        for index, line in enumerate(lines):
            if line.strip() != "metadata:":
                continue
            for candidate in lines[index + 1 : index + 12]:
                stripped = candidate.strip()
                if not stripped.startswith("name:"):
                    continue
                value = stripped.split(":", 1)[1].strip()
                if len(value) >= 2 and value[0] in ('"', "'") and value[-1] == value[0]:
                    value = value[1:-1]
                if value:
                    names.add(value)
                break
            break
    return names


def verify(root: Path, require_bytes: bool = False) -> dict:
    lock_path = root / "catalog/runtime-dependencies/cert-manager/crd-runtime-dependency-lock.json"
    if lock_path.is_symlink() or not lock_path.is_file() or lock_path.stat().st_size <= 0:
        raise RuntimeError("CERT_MANAGER_CRD_LOCK_FILE_INVALID")
    doc = json.loads(lock_path.read_text(encoding="utf-8"))
    if (
        doc.get("authority") != AUTHORITY
        or doc.get("schemaVersion") != 1
        or doc.get("kind") != "CertManagerCRDRuntimeDependencyLock"
        or doc.get("component") != "cert-manager"
    ):
        raise RuntimeError("CERT_MANAGER_CRD_LOCK_AUTHORITY_INVALID")
    if set(doc.get("expectedCRDs") or []) != EXPECTED or len(doc.get("expectedCRDs") or []) != len(EXPECTED):
        raise RuntimeError("CERT_MANAGER_CRD_EXPECTED_SET_INVALID")

    rows = doc.get("assets")
    if not isinstance(rows, list) or tuple(row.get("release") for row in rows) != RELEASES:
        raise RuntimeError("CERT_MANAGER_CRD_RELEASE_COVERAGE_INVALID")

    for row in rows:
        release = str(row.get("release") or "")
        rel = f"catalog/runtime-dependencies/cert-manager/{release}/cert-manager.crds.yaml"
        if row.get("name") != "cert-manager.crds.yaml" or row.get("path") != rel:
            raise RuntimeError("CERT_MANAGER_CRD_PATH_INVALID")
        parsed = urlsplit(str(row.get("url") or ""))
        if (
            parsed.scheme != "https"
            or parsed.netloc != "github.com"
            or parsed.path != f"/cert-manager/cert-manager/releases/download/v{release}/cert-manager.crds.yaml"
            or parsed.query
            or parsed.fragment
            or parsed.username
            or parsed.password
        ):
            raise RuntimeError("CERT_MANAGER_CRD_URL_INVALID")
        if not SHA256.fullmatch(str(row.get("sha256") or "")) or row.get("sizeBytes") != 997110:
            raise RuntimeError("CERT_MANAGER_CRD_DIGEST_IDENTITY_INVALID")
        if not require_bytes:
            continue
        target = root / rel
        got_sha, got_size = digest(target)
        if got_sha != row["sha256"] or got_size != row["sizeBytes"]:
            raise RuntimeError(f"CERT_MANAGER_CRD_BYTE_DRIFT {release}")
        raw = target.read_text(encoding="utf-8")
        if len(CRD_KIND.findall(raw)) != 6:
            raise RuntimeError(f"CERT_MANAGER_CRD_RESOURCE_COUNT_INVALID {release}")
        names = crd_names(raw)
        if names != EXPECTED:
            raise RuntimeError(
                f"CERT_MANAGER_CRD_RESOURCE_IDENTITY_INVALID {release} "
                f"missing={sorted(EXPECTED-names)} extra={sorted(names-EXPECTED)}"
            )

    if (
        doc.get("bytesRequiredForRuntime") is not True
        or doc.get("runtimeCertified") is not False
        or doc.get("physicalCertified") is not False
    ):
        raise RuntimeError("CERT_MANAGER_CRD_LOCK_SCOPE_INFLATED")
    return doc


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--require-bytes", action="store_true")
    args = parser.parse_args()
    doc = verify(args.root.resolve(), args.require_bytes)
    print(
        "CERT_MANAGER_CRD_DEPENDENCY_PASS "
        f"assets={len(doc['assets'])} bytes={str(args.require_bytes).lower()}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
