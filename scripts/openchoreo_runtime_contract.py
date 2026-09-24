#!/usr/bin/env python3
"""Canonical exact OpenChoreo runtime selection identity for closure tooling."""

import os
from pathlib import Path

VERSION = "1.3.0"
UPSTREAM_REPOSITORY = "https://github.com/openchoreo/openchoreo"
UPSTREAM_COMMIT = "178dfbde3e3343e5ac151b88a2f203f523f97480"
OCI_BASE = "oci://ghcr.io/openchoreo/helm-charts"

SOURCE_AUTHORITY = "OPENCHOREO_RUNTIME_SOURCE_AUTHORITY_V1"
ACQUISITION_AUTHORITY = "OPENCHOREO_RUNTIME_ACQUISITION_AUTHORITY_V1"


def admit_output_path(path: Path, label: str) -> Path:
    """Preserve direct output-path identity and reject symlinks before any resolve."""
    candidate = Path(os.path.abspath(os.fspath(path.expanduser())))
    if candidate.is_symlink():
        raise RuntimeError(f"{label}_SYMLINK_FORBIDDEN")
    return candidate
