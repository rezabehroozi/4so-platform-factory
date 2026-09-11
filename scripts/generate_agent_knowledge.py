#!/usr/bin/env python3
"""Generate discardable, source-grounded agent/architecture evidence.

This artifact is deliberately *not* product authority. It is a deterministic
projection for coding/operator agents and release review. Every material claim
links back to hashed product-owned source files and the target-architecture
model emitted by platformctl.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
from typing import Any

KNOWLEDGE_AUTHORITY = "DERIVED_AGENT_KNOWLEDGE_V1"
ARCHITECTURE_AUTHORITY = "DERIVED_ARCHITECTURE_EVIDENCE_V1"
SCHEMA_VERSION = 1


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def evidence(root: Path, relative: str) -> dict[str, Any]:
    path = root / relative
    if not path.is_file() or path.is_symlink():
        raise SystemExit(f"AGENT_KNOWLEDGE_EVIDENCE_MISSING {relative}")
    return {"path": relative, "sha256": sha256_file(path), "size": path.stat().st_size}


def target_architecture(root: Path, binary: str | None) -> dict[str, Any]:
    if binary:
        candidate = Path(binary)
        if not candidate.is_absolute():
            candidate = root / candidate
        command = [str(candidate), "target-architecture"]
    else:
        command = ["go", "run", "./cmd/platformctl", "target-architecture"]
    result = subprocess.run(command, cwd=root, text=True, capture_output=True, check=False, timeout=120)
    if result.returncode != 0:
        raise SystemExit(f"AGENT_KNOWLEDGE_TARGET_MODEL_FAILED rc={result.returncode} {result.stderr.strip()}")
    try:
        model = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"AGENT_KNOWLEDGE_TARGET_MODEL_INVALID_JSON {exc}") from exc
    if model.get("authority") != "TARGET_ARCHITECTURE_MODEL_V1":
        raise SystemExit(f"AGENT_KNOWLEDGE_TARGET_MODEL_AUTHORITY_INVALID {model.get('authority')!r}")
    return model


def _claim(claim_id: str, value: Any, *refs: dict[str, Any]) -> dict[str, Any]:
    return {"id": claim_id, "value": value, "evidence": list(refs)}


def build_document(root: Path, *, binary: str | None = None) -> dict[str, Any]:
    root = root.resolve()
    version = (root / "VERSION").read_text(encoding="utf-8").strip()
    release_name = (root / "RELEASE-NAME").read_text(encoding="utf-8").strip()
    model = target_architecture(root, binary)
    roadmap = model.get("programRoadmap", {})
    search_projection = model.get("searchProjection", {})

    version_ev = evidence(root, "VERSION")
    release_ev = evidence(root, "RELEASE-NAME")
    model_ev = evidence(root, "internal/targetmodel/model.go")
    program_ev = evidence(root, "internal/targetmodel/program.go")
    design_ev = evidence(root, "DESIGN.md")
    readme_ev = evidence(root, "README.md")

    claims: list[dict[str, Any]] = [
        _claim("release.version", version, version_ev),
        _claim("release.name", release_name, release_ev),
        _claim("target-model.authority", model.get("authority"), model_ev),
        _claim("program-roadmap.authority", roadmap.get("authority"), program_ev),
        _claim("program-roadmap.current-phase", roadmap.get("currentPhase"), program_ev),
        _claim("program-roadmap.goal-ready", roadmap.get("goalReady"), program_ev),
        _claim("management-plane.target", model.get("managementPlane"), model_ev, design_ev),
        _claim("management-plane.storage", model.get("managementPlaneStorage"), model_ev, design_ev),
        _claim("search-projection.boundary", search_projection, model_ev, program_ev),
        _claim("documentation.release-contract", "current README/DESIGN are explanatory consumers; source/runtime/evidence remain canonical authority", readme_ev, design_ev),
    ]
    for phase in roadmap.get("phases", []):
        claims.append(
            _claim(
                "program-phase." + str(phase.get("id")),
                {
                    "status": phase.get("status"),
                    "dependsOn": phase.get("dependsOn", []),
                    "parallelWith": phase.get("parallelWith", []),
                    "blockers": phase.get("blockers", []),
                },
                program_ev,
            )
        )

    management = model.get("managementPlane", {})
    storage = model.get("managementPlaneStorage", {})
    architecture_nodes = [
        {
            "id": "management-plane",
            "kind": "control-plane",
            "label": "4SO Management Plane",
            "attributes": management,
            "sourceAuthority": model.get("authority"),
        },
        {
            "id": "management-storage",
            "kind": "storage",
            "label": str(storage.get("provider", "management storage")),
            "attributes": storage,
            "sourceAuthority": storage.get("authority"),
        },
        {
            "id": "search-projection",
            "kind": "derived-projection",
            "label": "Optional Search / Analytics Projection",
            "attributes": search_projection,
            "sourceAuthority": search_projection.get("authority"),
        },
    ]
    for distribution in model.get("distributions", []):
        architecture_nodes.append(
            {
                "id": "distribution:" + str(distribution.get("id")),
                "kind": "target-distribution",
                "label": str(distribution.get("id")),
                "attributes": distribution,
                "sourceAuthority": model.get("authority"),
            }
        )
    architecture_edges = [
        {"from": "management-plane", "to": "management-storage", "relation": "uses-internal-storage-authority"},
        {"from": "management-plane", "to": "search-projection", "relation": "may-project-observability-search-data"},
    ]

    document: dict[str, Any] = {
        "schemaVersion": SCHEMA_VERSION,
        "authority": KNOWLEDGE_AUTHORITY,
        "derived": True,
        "notSourceOfTruth": True,
        "discardableAndRebuildable": True,
        "release": {"version": version, "releaseName": release_name},
        "sourceAuthorities": {
            "targetArchitecture": model.get("authority"),
            "programRoadmap": roadmap.get("authority"),
            "searchProjection": search_projection.get("authority"),
        },
        "claims": claims,
        "architecture": {
            "authority": ARCHITECTURE_AUTHORITY,
            "derived": True,
            "notRuntimeImpactProof": True,
            "nodes": architecture_nodes,
            "edges": architecture_edges,
        },
    }
    document["digest"] = sha256_bytes(canonical_bytes(document))
    return document


def verify_document(document: dict[str, Any]) -> None:
    if document.get("authority") != KNOWLEDGE_AUTHORITY or document.get("schemaVersion") != SCHEMA_VERSION:
        raise SystemExit("AGENT_KNOWLEDGE_CONTRACT_INVALID")
    if document.get("notSourceOfTruth") is not True or document.get("discardableAndRebuildable") is not True:
        raise SystemExit("AGENT_KNOWLEDGE_AUTHORITY_BOUNDARY_INVALID")
    digest = document.get("digest")
    unsigned = dict(document)
    unsigned.pop("digest", None)
    if digest != sha256_bytes(canonical_bytes(unsigned)):
        raise SystemExit("AGENT_KNOWLEDGE_DIGEST_MISMATCH")
    claims = document.get("claims")
    if not isinstance(claims, list) or len(claims) < 10:
        raise SystemExit("AGENT_KNOWLEDGE_CLAIMS_INCOMPLETE")
    for claim in claims:
        refs = claim.get("evidence")
        if not isinstance(refs, list) or not refs:
            raise SystemExit(f"AGENT_KNOWLEDGE_UNGROUNDED_CLAIM {claim.get('id')}")
        for ref in refs:
            digest_value = str(ref.get("sha256", ""))
            if not digest_value.startswith("sha256:") or len(digest_value) != 71:
                raise SystemExit(f"AGENT_KNOWLEDGE_EVIDENCE_DIGEST_INVALID {claim.get('id')}")
    architecture = document.get("architecture", {})
    if architecture.get("authority") != ARCHITECTURE_AUTHORITY or architecture.get("notRuntimeImpactProof") is not True:
        raise SystemExit("AGENT_KNOWLEDGE_ARCHITECTURE_BOUNDARY_INVALID")


def atomic_write(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    fd, temp = tempfile.mkstemp(prefix=".agent-knowledge-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp, 0o600)
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--binary", help="platformctl binary relative to --root or absolute")
    parser.add_argument("--out")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    document = build_document(root, binary=args.binary)
    verify_document(document)
    if args.out:
        atomic_write(Path(args.out), document)
    if args.check or not args.out:
        print(
            "DERIVED_AGENT_KNOWLEDGE_CHECK_PASS",
            document["digest"],
            f"claims={len(document['claims'])}",
            f"nodes={len(document['architecture']['nodes'])}",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
