#!/usr/bin/env python3
"""Canonical exact OpenChoreo runtime selection identity for closure tooling."""

import os
import re
from pathlib import Path

VERSION = "1.3.0"
UPSTREAM_REPOSITORY = "https://github.com/openchoreo/openchoreo"
UPSTREAM_COMMIT = "178dfbde3e3343e5ac151b88a2f203f523f97480"
OCI_BASE = "oci://ghcr.io/openchoreo/helm-charts"

SOURCE_AUTHORITY = "OPENCHOREO_RUNTIME_SOURCE_AUTHORITY_V1"
ACQUISITION_AUTHORITY = "OPENCHOREO_RUNTIME_ACQUISITION_AUTHORITY_V1"
REGISTRY_ID_RE = re.compile(r"^[a-z0-9.-]+(?::[0-9]+)?$")


def registry_identity_from_reference(ref: str, label: str) -> str:
    value = str(ref or "").strip()
    if not value or any(c.isspace() for c in value) or "://" in value or "/" not in value:
        raise RuntimeError(f"{label}_REFERENCE_REGISTRY_INVALID")
    registry = value.split("/", 1)[0].lower()
    if not REGISTRY_ID_RE.fullmatch(registry):
        raise RuntimeError(f"{label}_REFERENCE_REGISTRY_INVALID")
    return registry


def admit_output_path(path: Path, label: str) -> Path:
    """Preserve direct output-path identity and reject symlinks before any resolve."""
    candidate = Path(os.path.abspath(os.fspath(path.expanduser())))
    if candidate.is_symlink():
        raise RuntimeError(f"{label}_SYMLINK_FORBIDDEN")
    return candidate
