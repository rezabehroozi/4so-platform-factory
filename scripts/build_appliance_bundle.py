#!/usr/bin/env python3
"""Compatibility builder for a sealed digest-locked appliance bundle.

The canonical interface is `platformctl appliance-bundle build --spec ...`.
This wrapper preserves the earlier flag-based workflow while emitting the same
bundle.json + bundle.lock.json admission contract and never downloads content.
"""
from __future__ import annotations
import argparse, hashlib, json, os, posixpath, re, shutil, stat, tempfile, zipfile
from pathlib import Path


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def digest_bytes(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()




def _strict_release_json_loads(raw: str | bytes) -> object:
    def no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise SystemExit(f"release artifact manifest contains duplicate JSON key {key!r}")
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=no_duplicates)
    except json.JSONDecodeError as exc:
        raise SystemExit("release artifact manifest JSON is invalid") from exc


def _canonical_release_path(raw: object) -> str:
    if (
        not isinstance(raw, str) or not raw or raw.strip() != raw or "\\" in raw or "\x00" in raw
        or raw.startswith("/") or raw.endswith("/") or posixpath.normpath(raw) != raw
        or any(part in {"", ".", ".."} for part in raw.split("/"))
    ):
        raise SystemExit(f"release artifact path is not canonical: {raw!r}")
    return raw


def inspect_release_artifact(path: Path, expected_version: str) -> str:
    resolved = Path(os.path.abspath(os.path.expanduser(str(path))))
    info = resolved.lstat()
    if resolved.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_size <= 0:
        raise SystemExit("release artifact must be a non-empty regular non-symlink file")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(resolved, flags)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or opened.st_size <= 0 or not os.path.samestat(info, opened):
            raise SystemExit("release artifact changed while opening")
        h = hashlib.sha256()
        with tempfile.TemporaryFile("w+b") as snapshot, os.fdopen(os.dup(fd), "rb", closefd=True) as source:
            written = 0
            while True:
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                snapshot.write(chunk)
                h.update(chunk)
                written += len(chunk)
            if written != opened.st_size:
                raise SystemExit("release artifact changed size while snapshotting")
            snapshot.flush()
            snapshot.seek(0)
            try:
                with zipfile.ZipFile(snapshot) as zf:
                    infos = zf.infolist()
                    names: list[str] = []
                    info_by_name: dict[str, zipfile.ZipInfo] = {}
                    for item in infos:
                        if item.is_dir():
                            raise SystemExit("release artifact contains non-canonical directory entries")
                        name = _canonical_release_path(item.filename)
                        if name in info_by_name:
                            raise SystemExit(f"release artifact duplicates archive path {name}")
                        names.append(name)
                        info_by_name[name] = item
                    manifests = [name for name in names if name.endswith("/ARTIFACT-MANIFEST.json") and name.count("/") == 1]
                    if len(manifests) != 1:
                        raise SystemExit("release artifact must contain one canonical ARTIFACT-MANIFEST.json")
                    root = manifests[0].split("/", 1)[0]
                    version_name = root + "/VERSION"
                    release_name_name = root + "/RELEASE-NAME"
                    if version_name not in info_by_name or release_name_name not in info_by_name:
                        raise SystemExit("release artifact must contain VERSION and RELEASE-NAME")
                    version_raw = zf.read(version_name)
                    release_name_raw = zf.read(release_name_name)
                    version = version_raw.decode("utf-8", errors="strict").strip()
                    release_name = release_name_raw.decode("utf-8", errors="strict").strip()
                    if version_raw != (version + "\n").encode("utf-8") or release_name_raw != (release_name + "\n").encode("utf-8"):
                        raise SystemExit("release artifact identity files are not canonical")
                    manifest = _strict_release_json_loads(zf.read(manifests[0]))
                    if not isinstance(manifest, dict) or set(manifest) != {"schemaVersion", "product", "version", "releaseName", "fileCount", "files"}:
                        raise SystemExit("release artifact manifest schema is invalid")
                    if (
                        manifest.get("schemaVersion") != 2 or manifest.get("product") != "4SO Platform Factory"
                        or manifest.get("version") != version or manifest.get("releaseName") != release_name
                        or re.fullmatch(r"\d+\.\d+\.\d+", version) is None
                        or re.fullmatch(r"[a-z0-9][a-z0-9-]*", release_name) is None
                        or root != f"4so-platform-factory-{version}-{release_name}"
                    ):
                        raise SystemExit("release artifact identity contract is invalid")
                    if version != expected_version:
                        raise SystemExit(f"release artifact version {version} does not match requested version {expected_version}")
                    rows = manifest.get("files")
                    if not isinstance(rows, list) or manifest.get("fileCount") != len(rows):
                        raise SystemExit("release artifact manifest fileCount is invalid")
                    row_by_path: dict[str, dict[str, object]] = {}
                    for row in rows:
                        if not isinstance(row, dict) or set(row) != {"path", "sha256", "size", "mode"}:
                            raise SystemExit("release artifact manifest file record is invalid")
                        relative = _canonical_release_path(row.get("path"))
                        if relative == "ARTIFACT-MANIFEST.json" or relative in row_by_path:
                            raise SystemExit("release artifact manifest path is invalid or duplicated")
                        claimed = row.get("sha256"); size = row.get("size"); mode = row.get("mode")
                        if not isinstance(claimed, str) or re.fullmatch(r"[0-9a-f]{64}", claimed) is None:
                            raise SystemExit(f"release artifact manifest sha256 is invalid: {relative}")
                        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
                            raise SystemExit(f"release artifact manifest size is invalid: {relative}")
                        if not isinstance(mode, str) or re.fullmatch(r"0o[0-7]{3}", mode) is None:
                            raise SystemExit(f"release artifact manifest mode is invalid: {relative}")
                        row_by_path[relative] = row
                    if any(not name.startswith(root + "/") for name in names):
                        raise SystemExit("release artifact contains entries outside the canonical root")
                    actual_relatives = {name[len(root)+1:] for name in names if name != manifests[0]}
                    if set(row_by_path) != actual_relatives:
                        raise SystemExit("release artifact manifest does not cover archive contents")
                    for relative, row in row_by_path.items():
                        name = root + "/" + relative
                        item = info_by_name[name]
                        unix_mode = (item.external_attr >> 16) & 0xFFFF
                        if item.create_system != 3 or stat.S_IFMT(unix_mode) not in (0, stat.S_IFREG):
                            raise SystemExit(f"release artifact file type is invalid: {relative}")
                        raw = zf.read(name)
                        if hashlib.sha256(raw).hexdigest() != row["sha256"] or len(raw) != row["size"]:
                            raise SystemExit(f"release artifact content binding is invalid: {relative}")
                        if f"0o{stat.S_IMODE(unix_mode):03o}" != row["mode"]:
                            raise SystemExit(f"release artifact mode binding is invalid: {relative}")
            except zipfile.BadZipFile as exc:
                raise SystemExit("release artifact must be a ZIP archive") from exc
        return "sha256:" + h.hexdigest()
    finally:
        os.close(fd)


def image_ref(value: str) -> str:
    prefix, marker, suffix = value.rpartition("@sha256:")
    if not marker or not prefix or len(suffix) != 64:
        raise SystemExit(f"image reference must be digest-pinned: {value}")
    try:
        int(suffix, 16)
    except ValueError as exc:
        raise SystemExit(f"image reference contains invalid sha256: {value}") from exc
    return value


def manifest_images(path: Path) -> list[str]:
    images = []
    for line in path.read_text(encoding="utf-8", errors="strict").splitlines():
        match = re.match(r'^\s*image:\s*["\']?([^"\' #\t]+)', line)
        if match:
            images.append(image_ref(match.group(1).strip()))
    if not images:
        raise SystemExit(f"manifest must contain at least one digest-pinned image: {path}")
    return sorted(set(images))


def copy_rows(values: list[str], target: Path) -> list[dict[str, str]]:
    rows = []
    for value in values:
        src = Path(value).resolve()
        info = src.lstat() if src.exists() else None
        if info is None or not src.is_file() or src.is_symlink() or info.st_size <= 0:
            raise SystemExit(f"artifact must be a non-empty regular non-symlink file: {src}")
        dst = target / src.name
        if dst.exists() and digest(dst) != digest(src):
            raise SystemExit(f"conflicting artifact name: {src.name}; use platformctl build spec to preserve paths")
        if not dst.exists():
            shutil.copy2(src, dst)
        rows.append({"path": "artifacts/" + dst.name, "sha256": digest(dst)})
    return rows


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--output", required=True)
    p.add_argument("--version", default=(Path(__file__).resolve().parents[1] / "VERSION").read_text().strip())
    p.add_argument("--release-artifact", required=True)
    p.add_argument("--rke2-version", required=True)
    p.add_argument("--rke2-installer", required=True)
    p.add_argument("--rke2-install-artifact", action="append", required=True)
    p.add_argument("--rke2-image-archive", action="append", required=True)
    p.add_argument("--workload-image-archive", action="append", required=True)
    p.add_argument("--postgres-image", required=True)
    p.add_argument("--platform-api-image", required=True)
    p.add_argument("--forgejo-image", required=True)
    p.add_argument("--zot-image", required=True)
    p.add_argument("--keycloak-image", required=True)
    p.add_argument("--maintenance-image", required=True)
    p.add_argument("--gitops-manifest", required=True)
    p.add_argument("--cloudnative-pg-manifest", required=True)
    p.add_argument("--ocm-manifest", required=True)
    p.add_argument("--storage-manifest", required=True)
    p.add_argument("--fleet-agent-image", required=True)
    p.add_argument("--runtime-probe-image", required=True)
    a = p.parse_args()

    source_release_digest = inspect_release_artifact(Path(a.release_artifact), a.version)

    root = Path(a.output).resolve()
    if root.exists() and any(root.iterdir()):
        raise SystemExit("output directory must be empty")
    artifacts = root / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)

    installer = copy_rows([a.rke2_installer], artifacts)[0]
    rke2_install = copy_rows(a.rke2_install_artifact, artifacts)
    rke2_images = copy_rows(a.rke2_image_archive, artifacts)
    workload_archives = copy_rows(a.workload_image_archive, artifacts)
    gitops = copy_rows([a.gitops_manifest], artifacts)[0]
    cnpg = copy_rows([a.cloudnative_pg_manifest], artifacts)[0]
    ocm = copy_rows([a.ocm_manifest], artifacts)[0]
    storage = copy_rows([a.storage_manifest], artifacts)[0]
    images = [image_ref(v) for v in [a.postgres_image, a.platform_api_image, a.forgejo_image, a.zot_image, a.keycloak_image, a.maintenance_image, a.fleet_agent_image, a.runtime_probe_image]]
    for source in [Path(a.gitops_manifest), Path(a.cloudnative_pg_manifest), Path(a.ocm_manifest), Path(a.storage_manifest)]:
        images.extend(manifest_images(source.resolve()))
    images = sorted(set(images))

    indexed = [installer, gitops, cnpg, ocm, storage] + rke2_install + rke2_images + workload_archives
    artifact_paths = sorted(row["path"] for row in indexed)
    artifact_digests = {row["path"]: row["sha256"] for row in indexed}
    index = {"version": a.version, "images": images, "artifacts": artifact_paths, "artifactDigests": artifact_digests}
    index_path = artifacts / "airgap-index.json"
    index_path.write_text(json.dumps(index, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    airgap_index = {"path": "artifacts/airgap-index.json", "sha256": digest(index_path)}

    by_name = {
        "postgresqlImage": image_ref(a.postgres_image),
        "platformApiImage": image_ref(a.platform_api_image),
        "forgejoImage": image_ref(a.forgejo_image),
        "zotImage": image_ref(a.zot_image),
        "keycloakImage": image_ref(a.keycloak_image),
        "maintenanceImage": image_ref(a.maintenance_image),
        "fleetAgentImage": image_ref(a.fleet_agent_image),
        "runtimeProbeImage": image_ref(a.runtime_probe_image),
    }
    manifest = {
        "apiVersion": "platform.4so.io/v1alpha1",
        "kind": "ApplianceBundle",
        "metadata": {"version": a.version, "sourceReleaseDigest": source_release_digest},
        "spec": {
            "rke2": {"version": a.rke2_version, "installer": installer, "installArtifacts": rke2_install, "imageArchives": rke2_images},
            "airgap": {"complete": True, "index": airgap_index, "requiredImages": images},
            "workloads": {
                "imageArchives": workload_archives,
                **by_name,
                "gitOpsManifest": gitops,
                "cloudNativePGManifest": cnpg,
                "ocmManifest": ocm,
                "storageManifest": storage,
            },
        },
    }
    manifest_raw = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    (root / "bundle.json").write_bytes(manifest_raw)

    all_rows = indexed + [airgap_index]
    lock_artifacts = []
    for row in sorted(all_rows, key=lambda value: value["path"]):
        path = root / row["path"]
        lock_artifacts.append({"path": row["path"], "sha256": row["sha256"], "size": path.stat().st_size})
    lock = {
        "apiVersion": "platform.4so.io/v1alpha1",
        "kind": "ApplianceBundleLock",
        "metadata": {"bundleVersion": a.version, "sourceReleaseDigest": source_release_digest},
        "manifestDigest": digest_bytes(manifest_raw),
        "artifacts": lock_artifacts,
        "requiredImages": images,
    }
    lock_path = root / "bundle.lock.json"
    lock_path.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(lock_path, 0o600)
    print("APPLIANCE_BUNDLE_BUILD_PASS", root, digest_bytes(manifest_raw), digest(lock_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
