#!/usr/bin/env python3
"""Build a byte-reproducible, self-verifying source and binary release."""
from __future__ import annotations

from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import zipfile

EXCLUDE = {".git", "bin", "dist", "release", "__pycache__", ".pytest_cache", ".state", ".tmpbin"}
FIXED_DATE = (2026, 1, 1, 0, 0, 0)
FIXED_CREATED = "2026-01-01T00:00:00Z"
TARGETS = ("linux-amd64",)
BINARIES = ("platform-api", "platformctl", "platform-installer", "platform-agent", "platform-probe")


def checked_regular_file(path: Path, *, label: str) -> os.stat_result:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or path.is_symlink():
        raise SystemExit(f"{label}_NON_REGULAR_FILE {path}")
    return info


def source_files(root: Path, *, apply_excludes: bool = False) -> list[Path]:
    files: list[Path] = []
    for src in root.rglob("*"):
        rel = src.relative_to(root)
        if apply_excludes and any(part in EXCLUDE for part in rel.parts):
            continue
        if src.name.startswith(".durable-"):
            raise SystemExit(f"SOURCE_TREE_STALE_DURABLE_TEMP_FORBIDDEN {rel}")
        info = src.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise SystemExit(f"SOURCE_TREE_SYMLINK_FORBIDDEN {rel}")
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode):
            raise SystemExit(f"SOURCE_TREE_SPECIAL_FILE_FORBIDDEN {rel}")
        files.append(src)
    return sorted(files)


def sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha(path: Path) -> str:
    return sha_bytes(path.read_bytes())


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def source_rows(stage: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    excluded_generated = {
        "ARTIFACT-MANIFEST.json",
        "BUILD-PROVENANCE.json",
        "SBOM.spdx.json",
    }
    for file in source_files(stage):
        rel = str(file.relative_to(stage))
        if rel in excluded_generated or rel.startswith("bin/"):
            continue
        rows.append({"path": rel, "sha256": sha(file), "size": file.stat().st_size})
    return rows




def elf_metadata(path: Path) -> dict[str, object]:
    notes = subprocess.run(["readelf", "-n", str(path)], capture_output=True, text=True, check=False)
    dynamic = subprocess.run(["readelf", "-d", str(path)], capture_output=True, text=True, check=False)
    if notes.returncode != 0 or dynamic.returncode != 0:
        raise SystemExit(f"ELF_METADATA_FAILED {path}")
    match = re.search(r"Build ID:\s*([0-9a-fA-F]+)", notes.stdout)
    build_id = match.group(1).lower() if match else ""
    needed = sorted(set(re.findall(r"Shared library: \[(.*?)\]", dynamic.stdout)))
    return {"gnuBuildID": build_id, "runtimeNeeded": needed}


def build_provenance(stage: Path, version: str, release_name: str) -> None:
    sources = source_rows(stage)
    canonical = json.dumps(sources, separators=(",", ":"), sort_keys=True).encode("utf-8")
    binaries = []
    for target in TARGETS:
        for name in BINARIES:
            file = stage / "bin" / target / name
            metadata = elf_metadata(file)
            binaries.append(
                {
                    "target": target,
                    "name": name,
                    "sha256": sha(file),
                    "size": file.stat().st_size,
                    **metadata,
                }
            )
    provenance = {
        "schemaVersion": 1,
        "product": "4SO Platform Factory",
        "version": version,
        "releaseName": release_name,
        "buildType": "deterministic-local-release",
        "created": FIXED_CREATED,
        "sourceTreeDigest": "sha256:" + sha_bytes(canonical),
        "sourceFileCount": len(sources),
        "module": "platform.4so.io/factory",
        "buildContract": {
            "cgo": True,
            "trimpath": True,
            "stripped": True,
            "goBuildIDCleared": True,
            "externalELFBuildID": "recorded-per-binary",
        },
        "binaries": binaries,
    }
    write_json(stage / "BUILD-PROVENANCE.json", provenance)


def build_sbom(stage: Path, version: str, release_name: str) -> None:
    files = []
    for file in sorted(path for path in stage.rglob("*") if path.is_file()):
        rel = str(file.relative_to(stage))
        if rel in {"ARTIFACT-MANIFEST.json", "SBOM.spdx.json"}:
            continue
        files.append(
            {
                "SPDXID": "SPDXRef-File-" + hashlib.sha256(rel.encode()).hexdigest()[:16],
                "fileName": "./" + rel,
                "checksums": [{"algorithm": "SHA256", "checksumValue": sha(file)}],
            }
        )
    runtime_libraries = sorted({lib for target in TARGETS for name in BINARIES for lib in elf_metadata(stage / "bin" / target / name)["runtimeNeeded"]})
    packages = [
        {
            "name": "4SO Platform Factory",
            "SPDXID": "SPDXRef-Package-PlatformFactory",
            "versionInfo": version,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": True,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "Proprietary",
            "copyrightText": "NOASSERTION",
        }
    ]
    relationships = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": "SPDXRef-Package-PlatformFactory",
        }
    ]
    for library in runtime_libraries:
        ref = "SPDXRef-Runtime-" + hashlib.sha256(library.encode()).hexdigest()[:16]
        packages.append({
            "name": library,
            "SPDXID": ref,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "primaryPackagePurpose": "LIBRARY",
        })
        relationships.append({
            "spdxElementId": "SPDXRef-Package-PlatformFactory",
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": ref,
        })

    sbom = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"4so-platform-factory-{version}-{release_name}",
        "documentNamespace": (
            "https://platform.4so.io/sbom/"
            + version
            + "/"
            + sha_bytes((version + ":" + release_name).encode())[:24]
        ),
        "creationInfo": {
            "created": FIXED_CREATED,
            "creators": [f"Tool: 4SO release-builder-{version}"],
        },
        "packages": packages,
        "files": files,
        "relationships": relationships,
        "annotations": [
            {
                "annotationDate": FIXED_CREATED,
                "annotationType": "OTHER",
                "annotator": f"Tool: 4SO release-builder-{version}",
                "comment": (
                    "The API binary links to the system libpq PostgreSQL client library. Appliance bundles separately inventory the digest-locked runtime artifacts they actually include; optional integrations such as Open Cluster Management are recorded only when explicitly bundled. Included third-party artifacts retain their original license notices."
                ),
            }
        ],
    }
    write_json(stage / "SBOM.spdx.json", sbom)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default=".")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    version = (root / "VERSION").read_text(encoding="utf-8").strip()
    release_name = (root / "RELEASE-NAME").read_text(encoding="utf-8").strip()
    name = f"4so-platform-factory-{version}-{release_name}"
    release = root / "release"
    release.mkdir(exist_ok=True)
    stage = release / name
    if stage.exists():
        shutil.rmtree(stage)

    for src in source_files(root, apply_excludes=True):
        rel = src.relative_to(root)
        checked_regular_file(src, label="SOURCE_TREE")
        dst = stage / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)

    for target in TARGETS:
        for binary in BINARIES:
            src = root / "bin" / target / binary
            if not src.is_file():
                raise SystemExit(f"BINARY_MISSING {src}")
            probe = subprocess.run([str(src), "version"], capture_output=True, text=True, check=False)
            if probe.returncode != 0 or probe.stdout.strip() != version:
                raise SystemExit(f"BINARY_VERSION_MISMATCH {binary} expected={version} actual={probe.stdout.strip() or probe.stderr.strip()}")
            dst = stage / "bin" / target / binary
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            dst.chmod(0o755)

    build_provenance(stage, version, release_name)
    build_sbom(stage, version, release_name)

    entries = []
    for file in (path for path in source_files(stage) if path.name != "ARTIFACT-MANIFEST.json"):
        entries.append(
            {
                "path": str(file.relative_to(stage)),
                "sha256": sha(file),
                "size": file.stat().st_size,
                "mode": oct(stat.S_IMODE(file.stat().st_mode)),
            }
        )
    manifest = {
        "schemaVersion": 2,
        "product": "4SO Platform Factory",
        "version": version,
        "releaseName": release_name,
        "fileCount": len(entries),
        "files": entries,
    }
    write_json(stage / "ARTIFACT-MANIFEST.json", manifest)

    zip_path = release / (name + ".zip")
    if zip_path.exists():
        zip_path.unlink()
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for file in source_files(stage):
            rel = Path(name) / file.relative_to(stage)
            info = zipfile.ZipInfo(str(rel), FIXED_DATE)
            mode = stat.S_IMODE(file.stat().st_mode)
            info.create_system = 3
            info.external_attr = ((stat.S_IFREG | mode) & 0xFFFF) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, file.read_bytes())

    digest = sha(zip_path)
    checksum = release / (zip_path.name + ".sha256")
    checksum.write_text(f"{digest}  {zip_path.name}\n", encoding="utf-8")
    print("RELEASE_BUILD_PASS", zip_path, digest, len(entries) + 1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
