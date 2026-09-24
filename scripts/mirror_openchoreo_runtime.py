#!/usr/bin/env python3
"""Mirror exact OpenChoreo runtime images into the product-owned zot authority."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

import acquire_upstream_helm as helm
from prepare_openchoreo_executor import acquisition_payload, digest_path

AUTHORITY = "OPENCHOREO_ZOT_MIRROR_EVIDENCE_V1"
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
PREFIX_RE = re.compile(r"^[a-z0-9.-]+(?::[0-9]+)?/[a-z0-9._/-]+$")

def source_repository(ref: str) -> str:
    ref = str(ref).strip()
    if "@sha256:" not in ref:
        raise RuntimeError(f"OPENCHOREO_MIRROR_SOURCE_NOT_EXACT {ref}")
    return ref.rsplit("@sha256:", 1)[0]

def mirror_plan(images: list[dict], prefix: str) -> list[dict]:
    prefix = prefix.strip().rstrip("/")
    if not PREFIX_RE.fullmatch(prefix) or "://" in prefix:
        raise RuntimeError("OPENCHOREO_ZOT_PREFIX_INVALID")
    out = []
    destinations = set()
    for row in images:
        source = str(row.get("sourceReference") or "").strip()
        digest = str(row.get("digest") or "").strip().lower()
        if not DIGEST_RE.fullmatch(digest) or not source.endswith("@" + digest):
            raise RuntimeError("OPENCHOREO_MIRROR_SOURCE_DIGEST_INVALID")
        repository = source_repository(source)
        leaf = repository.rsplit("/", 1)[-1].lower()
        if not re.fullmatch(r"[a-z0-9._-]+", leaf):
            raise RuntimeError("OPENCHOREO_MIRROR_REPOSITORY_INVALID")
        suffix = hashlib.sha256(repository.encode()).hexdigest()[:12]
        destination_repo = f"{prefix}/{leaf}-{suffix}"
        tag = "sha256-" + digest.removeprefix("sha256:")
        tagged = destination_repo + ":" + tag
        exact = destination_repo + "@" + digest
        if tagged in destinations:
            raise RuntimeError("OPENCHOREO_MIRROR_DESTINATION_COLLISION")
        destinations.add(tagged)
        out.append({"sourceReference": source, "digest": digest, "destinationTaggedReference": tagged, "mirrorReference": exact})
    if not out:
        raise RuntimeError("OPENCHOREO_MIRROR_IMAGE_INVENTORY_EMPTY")
    return sorted(out, key=lambda row: row["sourceReference"])

def run_crane(crane: str, args: list[str]) -> str:
    proc = subprocess.run([crane, *args], text=True, capture_output=True, timeout=600)
    if proc.returncode != 0:
        tail = (proc.stdout + "\n" + proc.stderr)[-4096:].strip()
        raise RuntimeError(f"OPENCHOREO_CRANE_FAILED {' '.join(args)} {tail}")
    return (proc.stdout or proc.stderr).strip()

def mirror(acquisition: Path, prefix: str, out: Path) -> dict:
    acquisition = acquisition.expanduser().resolve()
    out = out.expanduser().resolve()
    lock, _ = acquisition_payload(acquisition)
    plan = mirror_plan(lock.get("images") or [], prefix)

    pinned = helm.require_toolchain()
    crane = str(pinned["crane"][0])
    crane_version = helm.tool_version([crane, "version"], "CRANE")

    evidence_rows = []
    for row in plan:
        run_crane(crane, ["copy", row["sourceReference"], row["destinationTaggedReference"]])
        got = run_crane(crane, ["digest", row["destinationTaggedReference"]]).strip().lower()
        if got != row["digest"]:
            raise RuntimeError(f"OPENCHOREO_ZOT_MIRROR_DIGEST_MISMATCH {row['sourceReference']}")
        evidence_rows.append({
            "sourceReference": row["sourceReference"],
            "digest": row["digest"],
            "mirrorReference": row["mirrorReference"],
        })

    evidence = {
        "apiVersion": "platform.4so.io/v1alpha1",
        "kind": "OpenChoreoZotMirrorEvidence",
        "authority": AUTHORITY,
        "acquisitionBundleSha256": digest_path(acquisition),
        "acquisitionAuthority": lock["authority"],
        "version": lock["version"],
        "upstreamCommit": lock["upstreamCommit"],
        "registryAuthority": "zot",
        "mirrorReady": True,
        "toolchain": {"craneVersion": crane_version},
        "images": evidence_rows,
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(out.suffix + ".tmp")
    tmp.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(out)
    return evidence

def self_test() -> int:
    images = [
        {"sourceReference": "ghcr.io/openchoreo/api@sha256:" + "a" * 64, "digest": "sha256:" + "a" * 64},
        {"sourceReference": "ghcr.io/openchoreo/agent@sha256:" + "b" * 64, "digest": "sha256:" + "b" * 64},
    ]
    first = mirror_plan(images, "zot.internal/openchoreo")
    second = mirror_plan(list(reversed(images)), "zot.internal/openchoreo")
    if first != second or any(not row["mirrorReference"].endswith("@" + row["digest"]) for row in first):
        raise RuntimeError("OPENCHOREO_MIRROR_PLAN_NOT_DETERMINISTIC")
    try:
        mirror_plan([{"sourceReference": "ghcr.io/openchoreo/api:latest", "digest": "sha256:" + "a" * 64}], "zot.internal/openchoreo")
    except RuntimeError:
        pass
    else:
        raise RuntimeError("OPENCHOREO_MIRROR_MUTABLE_SOURCE_NEGATIVE_CONTROL_FAILED")
    print("OPENCHOREO_ZOT_MIRROR_SELF_TEST_PASS")
    return 0

def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--self-test", action="store_true")
    p.add_argument("--acquisition", type=Path)
    p.add_argument("--zot-repository-prefix")
    p.add_argument("--out", type=Path)
    args = p.parse_args()
    if args.self_test:
        return self_test()
    if not args.acquisition or not args.zot_repository_prefix or not args.out:
        p.error("--acquisition, --zot-repository-prefix and --out are required")
    try:
        evidence = mirror(args.acquisition, args.zot_repository_prefix, args.out)
    except (RuntimeError, OSError, ValueError) as exc:
        print(f"OPENCHOREO_ZOT_MIRROR_BLOCKED {exc}", file=__import__("sys").stderr)
        return 3
    print(json.dumps(evidence, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
