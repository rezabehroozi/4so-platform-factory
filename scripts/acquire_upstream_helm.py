#!/usr/bin/env python3
"""Acquire one unresolved Helm component into an immutable offline catalog bundle.

This is build/release tooling, not a runtime dependency. It deliberately refuses
"latest" resolution: callers must supply an exact component version and an
upstream chart source. The expected chart digest comes from upstream metadata
(Helm index.yaml or the OCI chart-content layer), never from the downloaded file
itself.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse
import urllib.request

from catalog_upstream_admission import DEFAULT_AUTHORITY, validate as validate_upstream_admission
from component_upgrade_source_admission import validate as validate_upgrade_source_admission
from upstream_acquisition_toolchain import input_limits, require_toolchain

try:
    import yaml
except ImportError as exc:  # pragma: no cover - environment preflight
    raise SystemExit("PY_YAML_REQUIRED: install PyYAML on the acquisition host") from exc

ROOT = Path(__file__).resolve().parents[1]
HELM_BIN = "helm"
CRANE_BIN = "crane"
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
EXACT_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
_INPUT_LIMITS = input_limits()
MAX_HELM_INDEX_BYTES = _INPUT_LIMITS["maxHelmIndexBytes"]
MAX_CHART_ARCHIVE_BYTES = _INPUT_LIMITS["maxChartArchiveBytes"]
MAX_CHART_MEMBERS = _INPUT_LIMITS["maxChartMembers"]
MAX_CHART_UNPACKED_BYTES = _INPUT_LIMITS["maxChartUnpackedBytes"]
MAX_CHART_METADATA_BYTES = _INPUT_LIMITS["maxChartMetadataBytes"]


def _absolute_no_follow(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path.expanduser())))


def run(cmd: list[str], *, cwd: Path = ROOT, env: dict[str, str] | None = None, timeout: int = 600) -> str:
    merged = os.environ.copy()
    if env:
        merged.update(env)
    p = subprocess.run(cmd, cwd=cwd, env=merged, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, timeout=timeout)
    if p.returncode:
        raise RuntimeError(f"COMMAND_FAILED rc={p.returncode} cmd={cmd!r}\n{p.stdout[-8000:]}")
    return p.stdout


def post_install_repository_validation() -> str:
    out = run(
        [sys.executable, "scripts/supply_chain_handoff.py", "--write", "--plan", "lab/supply-chain-handoff-plan.json"],
        timeout=180,
    )
    out += run([sys.executable, "scripts/validate_repository.py", "."], timeout=180)
    return out


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return "sha256:" + h.hexdigest()


def tool_version(cmd: list[str], label: str) -> str:
    value = run(cmd, timeout=60).strip().splitlines()[-1].strip()
    if not value or len(value) > 128 or any(ch in value for ch in "\r\n\t"):
        raise RuntimeError(f"{label}_VERSION_INVALID")
    return value


def repo_value_inputs(values: list[Path]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    seen: set[str] = set()
    for value in values:
        candidate = _absolute_no_follow(value)
        try:
            st = candidate.lstat()
        except OSError as exc:
            raise RuntimeError(f"VALUES_FILE_NOT_FOUND {candidate}") from exc
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            raise RuntimeError(f"VALUES_FILE_NOT_REGULAR {candidate}")
        resolved = candidate.resolve()
        try:
            relative = resolved.relative_to(ROOT).as_posix()
        except ValueError as exc:
            raise RuntimeError(f"VALUES_FILE_OUTSIDE_REPOSITORY {resolved}") from exc
        if relative in seen:
            raise RuntimeError(f"VALUES_FILE_DUPLICATE {relative}")
        seen.add(relative)
        rows.append({"path": relative, "sha256": sha256_file(candidate)})
    return rows


def normalized_version(v: str) -> str:
    return v.strip().removeprefix("v")


def constraint_matches(constraint: str, version: str) -> bool:
    v = normalized_version(version)
    if not EXACT_VERSION_RE.fullmatch(v):
        return False
    c = normalized_version(constraint.lower())
    if EXACT_VERSION_RE.fullmatch(c):
        return c == v
    parts, vp = c.split("."), v.split(".")
    return len(parts) == 3 and parts[2] == "x" and parts[:2] == vp[:2]


def load_component(name: str, *, historical: bool = False) -> tuple[Path, dict]:
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", name):
        raise RuntimeError("COMPONENT_NAME_INVALID")
    path = ROOT / "catalog" / "components" / f"{name}.json"
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"COMPONENT_NOT_FOUND_OR_NOT_REGULAR {name}")
    doc = json.loads(path.read_text())
    if doc.get("metadata", {}).get("name") != name:
        raise RuntimeError("COMPONENT_IDENTITY_MISMATCH")
    spec = doc.get("spec", {})
    source = spec.get("source", {})
    if historical:
        if source.get("resolved") is not True:
            raise RuntimeError(f"HISTORICAL_TARGET_SOURCE_NOT_RESOLVED {name}")
    elif source.get("resolved"):
        raise RuntimeError(f"COMPONENT_ALREADY_RESOLVED {name}")
    if spec.get("delivery", {}).get("type") != "helm":
        raise RuntimeError(f"COMPONENT_NOT_HELM_CHART {name}")
    if historical:
        if source.get("type") not in {"helm-chart", "external-tagged-source-set", "embedded-native"}:
            raise RuntimeError(f"HISTORICAL_TARGET_SOURCE_TYPE_INVALID {name}")
    elif source.get("type") != "helm-chart":
        raise RuntimeError(f"COMPONENT_NOT_HELM_CHART {name}")
    return path, doc


def bounded_read(stream, limit: int, label: str) -> bytes:
    if limit <= 0:
        raise RuntimeError(f"{label}_LIMIT_INVALID")
    raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise RuntimeError(f"{label}_TOO_LARGE limit={limit}")
    return raw


def chart_metadata(chart: Path) -> dict:
    if chart.is_symlink() or not chart.is_file():
        raise RuntimeError("HELM_CHART_ARCHIVE_NOT_REGULAR")
    archive_size = chart.stat().st_size
    if archive_size <= 0 or archive_size > MAX_CHART_ARCHIVE_BYTES:
        raise RuntimeError(f"HELM_CHART_ARCHIVE_SIZE_INVALID size={archive_size} limit={MAX_CHART_ARCHIVE_BYTES}")
    with tarfile.open(chart, "r:gz") as tf:
        members = tf.getmembers()
        if len(members) > MAX_CHART_MEMBERS:
            raise RuntimeError(f"HELM_CHART_MEMBER_LIMIT_EXCEEDED count={len(members)} limit={MAX_CHART_MEMBERS}")
        roots: set[str] = set()
        chart_member = None
        unpacked = 0
        for member in members:
            raw = member.name
            parts = Path(raw.rstrip("/")).parts
            if not raw or raw.startswith("/") or "\\" in raw or ".." in parts:
                raise RuntimeError(f"UNSAFE_CHART_PATH {raw!r}")
            if not (member.isfile() or member.isdir()) or member.issym() or member.islnk() or member.isdev() or member.isfifo():
                raise RuntimeError(f"UNSAFE_CHART_ENTRY {raw!r}")
            if member.size < 0:
                raise RuntimeError(f"UNSAFE_CHART_ENTRY_SIZE {raw!r}")
            unpacked += member.size
            if unpacked > MAX_CHART_UNPACKED_BYTES:
                raise RuntimeError(f"HELM_CHART_UNPACKED_LIMIT_EXCEEDED bytes={unpacked} limit={MAX_CHART_UNPACKED_BYTES}")
            if parts:
                roots.add(parts[0])
            if len(parts) == 2 and parts[1] == "Chart.yaml":
                chart_member = member
        if len(roots) != 1 or chart_member is None:
            raise RuntimeError("HELM_CHART_LAYOUT_INVALID")
        if chart_member.size > MAX_CHART_METADATA_BYTES:
            raise RuntimeError(f"HELM_CHART_METADATA_TOO_LARGE size={chart_member.size} limit={MAX_CHART_METADATA_BYTES}")
        fh = tf.extractfile(chart_member)
        if fh is None:
            raise RuntimeError("HELM_CHART_METADATA_UNREADABLE")
        doc = yaml.safe_load(bounded_read(fh, MAX_CHART_METADATA_BYTES, "HELM_CHART_METADATA"))
    if not isinstance(doc, dict):
        raise RuntimeError("HELM_CHART_METADATA_INVALID")
    return doc


def require_https_response(source_url: str, final_url: str) -> None:
    source = urllib.parse.urlsplit(source_url)
    final = urllib.parse.urlsplit(final_url)
    if source.scheme.lower() != "https" or not source.hostname:
        raise RuntimeError(f"UPSTREAM_HTTPS_SOURCE_INVALID {source_url}")
    if final.scheme.lower() != "https" or not final.hostname:
        raise RuntimeError(f"UPSTREAM_HTTPS_DOWNGRADE_DENIED {source_url}->{final_url}")


def http_index_metadata(source: str, chart: str, upstream_version: str, timeout: int) -> tuple[str, str]:
    url = source.rstrip("/") + "/index.yaml"
    request = urllib.request.Request(url, headers={"User-Agent": "4so-platform-factory-upstream-acquisition/3"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        final_url = response.geturl()
        require_https_response(url, final_url)
        if response.status != 200:
            raise RuntimeError(f"HELM_INDEX_HTTP_{response.status} {url}")
        raw = bounded_read(response, MAX_HELM_INDEX_BYTES, "HELM_INDEX")
    index = yaml.safe_load(raw)
    rows = (index or {}).get("entries", {}).get(chart, [])
    wanted = normalized_version(upstream_version)
    matches = [r for r in rows if normalized_version(str((r or {}).get("version", ""))) == wanted]
    if len(matches) != 1:
        raise RuntimeError(f"HELM_INDEX_VERSION_NOT_UNIQUE {chart}@{upstream_version} count={len(matches)}")
    row = matches[0]
    digest = str(row.get("digest") or "").lower()
    if re.fullmatch(r"[0-9a-f]{64}", digest):
        digest = "sha256:" + digest
    if not DIGEST_RE.fullmatch(digest):
        raise RuntimeError(f"HELM_INDEX_DIGEST_MISSING {chart}@{upstream_version}")
    raw_version = str(row.get("version") or upstream_version)
    return digest, raw_version


def oci_layer_digest(source: str, upstream_version: str) -> str:
    ref = source.removeprefix("oci://") + ":" + upstream_version
    manifest = json.loads(run([CRANE_BIN, "manifest", ref], timeout=180))
    layers = manifest.get("layers") or []
    chart_layers = [x for x in layers if "helm.chart.content" in str((x or {}).get("mediaType", ""))]
    if len(chart_layers) != 1:
        raise RuntimeError(f"OCI_HELM_CONTENT_LAYER_INVALID count={len(chart_layers)} ref={ref}")
    digest = str(chart_layers[0].get("digest") or "").lower()
    if not DIGEST_RE.fullmatch(digest):
        raise RuntimeError(f"OCI_HELM_CONTENT_DIGEST_INVALID {digest}")
    return digest


def helm_env(root: Path) -> dict[str, str]:
    return {
        "HELM_CONFIG_HOME": str(root / "config"),
        "HELM_CACHE_HOME": str(root / "cache"),
        "HELM_DATA_HOME": str(root / "data"),
    }


def pull_chart(source: str, chart: str, upstream_version: str, dest: Path, env: dict[str, str]) -> Path:
    if source.startswith("oci://"):
        run([HELM_BIN, "pull", source, "--version", upstream_version, "--destination", str(dest)], env=env, timeout=300)
    elif source.startswith("https://"):
        alias = "pf-upstream"
        run([HELM_BIN, "repo", "add", alias, source, "--force-update"], env=env, timeout=180)
        run([HELM_BIN, "repo", "update"], env=env, timeout=180)
        run([HELM_BIN, "pull", f"{alias}/{chart}", "--version", upstream_version, "--destination", str(dest)], env=env, timeout=300)
    else:
        raise RuntimeError("SOURCE_URL_MUST_BE_HTTPS_OR_OCI")
    charts = sorted(dest.glob("*.tgz"))
    if len(charts) != 1:
        raise RuntimeError(f"HELM_PULL_OUTPUT_INVALID count={len(charts)}")
    return charts[0]


def parse_rendered_yaml(raw: str) -> list[dict]:
    resources: list[dict] = []
    for doc in yaml.safe_load_all(raw):
        if doc is None:
            continue
        if not isinstance(doc, dict):
            raise RuntimeError("HELM_RENDER_DOCUMENT_NOT_OBJECT")
        if doc.get("kind") == "List" and isinstance(doc.get("items"), list):
            for item in doc["items"]:
                if not isinstance(item, dict):
                    raise RuntimeError("HELM_RENDER_LIST_ITEM_NOT_OBJECT")
                resources.append(item)
        else:
            resources.append(doc)
    if not resources:
        raise RuntimeError("HELM_RENDER_EMPTY")
    for i, r in enumerate(resources):
        md = r.get("metadata") or {}
        if not r.get("apiVersion") or not r.get("kind") or not isinstance(md, dict) or not md.get("name"):
            raise RuntimeError(f"HELM_RENDER_RESOURCE_IDENTITY_INVALID index={i}")
    return resources


def render_chart(chart: Path, namespace: str, kube_version: str, values: list[Path], env: dict[str, str]) -> list[dict]:
    cmd = [HELM_BIN, "template", "platform-factory", str(chart), "--namespace", namespace, "--include-crds", "--kube-version", kube_version]
    for value in values:
        cmd += ["--values", str(value)]
    return parse_rendered_yaml(run(cmd, env=env, timeout=300))


def canonical_resources(resources: list[dict]) -> bytes:
    return (json.dumps(resources, sort_keys=True, separators=(",", ":")) + "\n").encode()


def kubernetes_render_evidence(renders: dict[str, list[dict]]) -> dict[str, str]:
    if not renders:
        raise RuntimeError("HELM_RENDER_EVIDENCE_EMPTY")
    out: dict[str, str] = {}
    for version, resources in sorted(renders.items()):
        if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", str(version)):
            raise RuntimeError(f"HELM_RENDER_EVIDENCE_VERSION_INVALID {version}")
        raw = canonical_resources(resources)
        out[str(version)] = "sha256:" + hashlib.sha256(raw).hexdigest()
    return out


def image_repository(ref: str) -> str:
    ref = ref.strip()
    if "@" in ref:
        return ref.split("@", 1)[0]
    last_slash = ref.rfind("/")
    last_colon = ref.rfind(":")
    if last_colon > last_slash:
        return ref[:last_colon]
    return ref


def pin_images(value, resolver) -> set[str]:
    pinned: set[str] = set()
    if isinstance(value, list):
        for item in value:
            pinned.update(pin_images(item, resolver))
    elif isinstance(value, dict):
        for key, item in list(value.items()):
            if key == "image" and isinstance(item, str) and item.strip():
                original = item.strip()
                if "@sha256:" in original:
                    digest = original.split("@", 1)[1]
                    if not DIGEST_RE.fullmatch(digest):
                        raise RuntimeError(f"IMAGE_DIGEST_INVALID {original}")
                    rewritten = image_repository(original) + "@" + digest
                else:
                    digest = resolver(original)
                    if not DIGEST_RE.fullmatch(digest):
                        raise RuntimeError(f"IMAGE_RESOLVER_DIGEST_INVALID {original}:{digest}")
                    rewritten = image_repository(original) + "@" + digest
                value[key] = rewritten
                pinned.add(rewritten)
            else:
                pinned.update(pin_images(item, resolver))
    return pinned


def crane_digest(ref: str) -> str:
    out = run([CRANE_BIN, "digest", ref], timeout=180).strip().splitlines()[-1].strip().lower()
    if not DIGEST_RE.fullmatch(out):
        raise RuntimeError(f"CRANE_DIGEST_INVALID {ref}:{out}")
    return out


def chart_license(meta: dict, override: str | None) -> str:
    if override:
        return override.strip()
    annotations = meta.get("annotations") or {}
    value = str(annotations.get("artifacthub.io/license") or "").strip()
    if not value:
        raise RuntimeError("LICENSE_SPDX_REQUIRED: chart has no artifacthub.io/license; pass --license-spdx")
    return value


def spdx(component: str, chart: str, version: str, chart_digest: str, images: list[str]) -> dict:
    suffix = chart_digest.split(":", 1)[1][:16]
    packages = [{
        "SPDXID": f"SPDXRef-Package-{re.sub(r'[^A-Za-z0-9.-]', '-', chart)}",
        "name": chart,
        "versionInfo": version,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
    }]
    for i, ref in enumerate(images, 1):
        packages.append({
            "SPDXID": f"SPDXRef-Image-{i}",
            "name": image_repository(ref),
            "versionInfo": ref.split("@", 1)[1],
            "downloadLocation": ref,
            "filesAnalyzed": False,
        })
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{component}-{version}-offline-inputs",
        "documentNamespace": f"https://platform.4so.io/sbom/{component}/{version}/{suffix}",
        "creationInfo": {"creators": ["Tool: 4SO Platform Factory upstream acquisition"], "created": "1970-01-01T00:00:00Z"},
        "packages": packages,
    }


def platformctl_prefix(path: str | None) -> list[str]:
    if path:
        p = _absolute_no_follow(Path(path))
        try:
            st = p.lstat()
        except OSError as exc:
            raise RuntimeError(f"PLATFORMCTL_NOT_FOUND {p}") from exc
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode) or not os.access(p, os.X_OK):
            raise RuntimeError(f"PLATFORMCTL_NOT_REGULAR_EXECUTABLE {p}")
        return [str(p)]
    built = ROOT / "bin" / "platformctl"
    if built.is_file() and not built.is_symlink() and os.access(built, os.X_OK):
        return [str(built)]
    if shutil.which("go"):
        return ["go", "run", "./cmd/platformctl"]
    raise RuntimeError("PLATFORMCTL_OR_GO_REQUIRED")


def apply_admission(args: argparse.Namespace) -> None:
    # Current and historical acquisition have separate canonical authorities.
    # CLI flags are consistency assertions only; they never become an alternate
    # source/version authority.
    if args.from_upgrade_admission:
        if not args.historical:
            raise RuntimeError("UPGRADE_SOURCE_ADMISSION_REQUIRES_HISTORICAL_MODE")
        if args.from_admission:
            raise RuntimeError("ACQUISITION_AUTHORITY_MODE_CONFLICT")
        authority = ROOT / "catalog" / "component-upgrade-source-admission.json"
        doc = json.loads(authority.read_text())
        errs = validate_upgrade_source_admission(doc, ROOT)
        if errs:
            raise RuntimeError("UPGRADE_SOURCE_ADMISSION_INVALID " + "; ".join(errs))
        matches=[r for r in doc.get("components",[]) if r.get("component")==args.component]
        if len(matches)!=1:
            raise RuntimeError(f"UPGRADE_SOURCE_ADMISSION_COMPONENT_NOT_UNIQUE {args.component}")
        entry=matches[0]
        if entry.get("status") != "admitted-for-acquisition":
            raise RuntimeError(f"UPGRADE_SOURCE_ADMISSION_NOT_ACQUIRABLE {args.component}:{entry.get('status')}")
        selected=str(entry.get("previousVersion") or "")
        source=str(entry.get("source") or "")
        canonical_license=str(entry.get("licenseSPDX") or "").strip()
        canonical_values=[str(v) for v in (entry.get("valuesFiles") or [])]
        if not canonical_license:
            raise RuntimeError(f"UPGRADE_SOURCE_ADMISSION_LICENSE_MISSING {args.component}")
        if args.version and normalized_version(args.version) != normalized_version(selected):
            raise RuntimeError(f"UPGRADE_SOURCE_ADMISSION_VERSION_OVERRIDE_DENIED {args.version}!={selected}")
        if args.source and args.source != source:
            raise RuntimeError(f"UPGRADE_SOURCE_ADMISSION_SOURCE_OVERRIDE_DENIED {args.source}!={source}")
        if args.upstream_version and normalized_version(args.upstream_version) != normalized_version(selected):
            raise RuntimeError(f"UPGRADE_SOURCE_ADMISSION_UPSTREAM_VERSION_OVERRIDE_DENIED {args.upstream_version}!={selected}")
        if args.license_spdx and args.license_spdx.strip() != canonical_license:
            raise RuntimeError(f"UPGRADE_SOURCE_ADMISSION_LICENSE_OVERRIDE_DENIED {args.component}")
        caller_values=[str(v) for v in (args.values or [])]
        if caller_values and caller_values != canonical_values:
            raise RuntimeError(f"UPGRADE_SOURCE_ADMISSION_VALUES_OVERRIDE_DENIED {args.component}")
        args.version=selected; args.source=source; args.upstream_version=selected; args.license_spdx=canonical_license; args.values=canonical_values
        return
    if args.historical:
        raise RuntimeError("HISTORICAL_MODE_REQUIRES_UPGRADE_SOURCE_ADMISSION")
    if not args.from_admission:
        raise RuntimeError("UPSTREAM_ADMISSION_REQUIRED")
    if not args.component:
        raise RuntimeError("UPSTREAM_ADMISSION_COMPONENT_REQUIRED")
    requested_authority = Path(os.path.abspath(args.authority))
    canonical_authority = Path(os.path.abspath(DEFAULT_AUTHORITY))
    if requested_authority != canonical_authority:
        raise RuntimeError(f"UPSTREAM_ADMISSION_AUTHORITY_OVERRIDE_DENIED {requested_authority}!={canonical_authority}")
    _, entries = validate_upstream_admission(ROOT, canonical_authority)
    matches = [e for e in entries if e.get("component") == args.component]
    if len(matches) != 1:
        raise RuntimeError(f"UPSTREAM_ADMISSION_COMPONENT_NOT_UNIQUE {args.component}")
    entry = matches[0]
    if entry.get("status") != "ready-for-acquisition":
        raise RuntimeError(f"UPSTREAM_ADMISSION_NOT_READY {args.component}:{entry.get('status')}")
    selected = str(entry.get("selectedVersion") or "")
    source = str(entry.get("source") or "")
    upstream = str(entry.get("upstreamVersion") or selected)
    if args.version and normalized_version(args.version) != normalized_version(selected):
        raise RuntimeError(f"UPSTREAM_ADMISSION_VERSION_OVERRIDE_DENIED {args.version}!={selected}")
    if args.source and args.source != source:
        raise RuntimeError(f"UPSTREAM_ADMISSION_SOURCE_OVERRIDE_DENIED {args.source}!={source}")
    if args.upstream_version and normalized_version(args.upstream_version) != normalized_version(upstream):
        raise RuntimeError(f"UPSTREAM_ADMISSION_UPSTREAM_VERSION_OVERRIDE_DENIED {args.upstream_version}!={upstream}")
    canonical_license = str(entry.get("licenseSPDX") or "").strip()
    canonical_values = [str(v) for v in (entry.get("valuesFiles") or [])]
    if args.license_spdx and (not canonical_license or args.license_spdx.strip() != canonical_license):
        raise RuntimeError(f"UPSTREAM_ADMISSION_LICENSE_OVERRIDE_DENIED {args.component}")
    caller_values = [str(v) for v in (args.values or [])]
    if caller_values and caller_values != canonical_values:
        raise RuntimeError(f"UPSTREAM_ADMISSION_VALUES_OVERRIDE_DENIED {args.component}")
    args.version = selected; args.source = source; args.upstream_version = upstream; args.values = canonical_values
    if canonical_license:
        args.license_spdx = canonical_license


def acquire(args: argparse.Namespace) -> int:
    global HELM_BIN, CRANE_BIN
    apply_admission(args)
    pinned = require_toolchain()
    HELM_BIN = str(pinned["helm"][0])
    CRANE_BIN = str(pinned["crane"][0])
    component_path, component = load_component(args.component, historical=args.historical)
    spec = component["spec"]
    version = normalized_version(args.version)
    if args.historical:
        current=normalized_version(str(spec.get("release", "")))
        if not EXACT_VERSION_RE.fullmatch(current) or not EXACT_VERSION_RE.fullmatch(version) or tuple(map(int,version.split('.'))) >= tuple(map(int,current.split('.'))):
            raise RuntimeError(f"HISTORICAL_VERSION_NOT_STRICTLY_OLDER {version}!<{current}")
    elif not constraint_matches(str(spec.get("release", "")), version):
        raise RuntimeError(f"VERSION_OUTSIDE_COMPONENT_CONSTRAINT {version} not-in {spec.get('release')}")
    chart = str(spec.get("delivery", {}).get("chart") or "").strip()
    if not chart:
        raise RuntimeError("COMPONENT_CHART_NAME_MISSING")
    upstream_version = args.upstream_version or args.version
    values = [_absolute_no_follow(Path(v)) for v in args.values]
    value_inputs = repo_value_inputs(values)
    helm_version = tool_version([HELM_BIN, "version", "--short"], "HELM")
    crane_version = tool_version([CRANE_BIN, "version"], "CRANE")

    with tempfile.TemporaryDirectory(prefix=f"4so-acquire-{args.component}-") as td:
        tmp = Path(td)
        env = helm_env(tmp / "helm")
        if args.source.startswith("oci://"):
            expected_digest = oci_layer_digest(args.source, upstream_version)
            upstream_index_version = upstream_version
        else:
            expected_digest, upstream_index_version = http_index_metadata(args.source, chart, upstream_version, args.network_timeout)
        artifact = pull_chart(args.source, chart, upstream_index_version, tmp, env)
        archive_size = artifact.stat().st_size
        if archive_size <= 0 or archive_size > MAX_CHART_ARCHIVE_BYTES:
            raise RuntimeError(f"HELM_CHART_ARCHIVE_SIZE_INVALID size={archive_size} limit={MAX_CHART_ARCHIVE_BYTES}")
        got = sha256_file(artifact)
        if got != expected_digest:
            raise RuntimeError(f"UPSTREAM_CHART_DIGEST_MISMATCH expected={expected_digest} got={got}")

        meta = chart_metadata(artifact)
        if meta.get("apiVersion") != "v2" or str(meta.get("name") or "") != chart or normalized_version(str(meta.get("version") or "")) != version:
            raise RuntimeError(f"CHART_IDENTITY_MISMATCH metadata={meta.get('name')}@{meta.get('version')} expected={chart}@{version}")
        license_spdx = chart_license(meta, args.license_spdx)

        kube = spec.get("compatibility", {}).get("kubernetes", {})
        min_kube = str(kube.get("minVersion") or "").strip() + ".0"
        max_kube = str(kube.get("maxVersion") or "").strip() + ".0"
        if not re.fullmatch(r"[0-9]+\.[0-9]+\.0", min_kube) or not re.fullmatch(r"[0-9]+\.[0-9]+\.0", max_kube):
            raise RuntimeError("COMPONENT_KUBERNETES_RANGE_INVALID")
        rendered_min = render_chart(artifact, str(spec.get("namespace") or "default"), min_kube, values, env)
        rendered_max = render_chart(artifact, str(spec.get("namespace") or "default"), max_kube, values, env)
        render_digests = kubernetes_render_evidence({min_kube: rendered_min, max_kube: rendered_max})

        generation_path = tmp / "render-generation.json"
        generation_path.write_text(json.dumps({
            "tool": "helm-template",
            "toolVersion": helm_version,
            "releaseName": "platform-factory",
            "namespace": str(spec.get("namespace") or "default"),
            "includeCRDs": True,
            "kubernetesVersions": [min_kube, max_kube],
            "kubernetesRenderDigests": render_digests,
            "values": value_inputs,
            "imageResolver": "crane-digest",
            "imageResolverVersion": crane_version,
        }, indent=2, sort_keys=True) + "\n")

        # The immutable bundle carries the canonical minimum-Kubernetes render.
        # The max-Kubernetes render is retained as digest evidence only. Image
        # inventory must therefore describe exactly the carried render bytes,
        # otherwise bundle verification correctly rejects unrelated images.
        resources = copy.deepcopy(rendered_min)
        images = sorted(pin_images(resources, crane_digest))
        render_path = tmp / "render-manifest.json"
        render_path.write_text(json.dumps(resources, indent=2, sort_keys=True) + "\n")
        image_path = tmp / "image-inventory.json"
        image_path.write_text(json.dumps({"images": [{"reference": r} for r in images]}, indent=2, sort_keys=True) + "\n")
        license_path = tmp / "licenses.json"
        license_path.write_text(json.dumps({"licenses": [{"file": "artifact.bin", "spdxExpression": license_spdx, "sha256": expected_digest}]}, indent=2, sort_keys=True) + "\n")
        sbom_path = tmp / "sbom.spdx.json"
        sbom_path.write_text(json.dumps(spdx(args.component, chart, version, expected_digest, images), indent=2, sort_keys=True) + "\n")

        out = _absolute_no_follow(Path(args.out)) if args.out else ROOT / "dist" / ("upstream-history" if args.historical else "upstream") / f"{args.component}-{version}.zip"
        if out.is_symlink():
            raise RuntimeError(f"UPSTREAM_OUTPUT_SYMLINK_FORBIDDEN {out}")
        out.parent.mkdir(parents=True, exist_ok=True)
        ctl = platformctl_prefix(args.platformctl)
        assemble = ctl + [
            "catalog-bundle", "assemble",
        ]
        if args.historical:
            assemble.append("--historical")
        assemble += [
            "--component", str(component_path),
            "--artifact", str(artifact),
            "--render-manifest", str(render_path),
            "--image-inventory", str(image_path),
            "--licenses", str(license_path),
            "--sbom", str(sbom_path),
            "--render-generation", str(generation_path),
            "--version", version,
            "--source-type", "helm-chart",
            "--source-url", args.source,
            "--source-revision", upstream_index_version,
            "--upstream-artifact-name", artifact.name,
            "--artifact-digest", expected_digest,
            "--bundle-key", f"{args.component}/{version}",
            "--out", str(out),
        ]
        print(run(assemble, timeout=300), end="")
        print(run(ctl + ["catalog-bundle", "verify", "-f", str(out)], timeout=180), end="")
        if args.install:
            install_action = "install-historical" if args.historical else "install"
            confirmation = "IMPORT-HISTORICAL" if args.historical else "IMPORT"
            print(run(ctl + ["catalog-bundle", install_action, "-f", str(out), "--repo-root", str(ROOT), "--confirmation", confirmation], timeout=180), end="")
            print(post_install_repository_validation(), end="")
        print(f"UPSTREAM_ACQUISITION_PASS component={args.component} version={version} chartDigest={expected_digest} images={len(images)} out={out}")
    return 0


def preflight() -> int:
    tool_status = "PASS"
    try:
        pinned = require_toolchain()
        tool_status = ",".join(f"{name}@{version}" for name, (_, version) in sorted(pinned.items()))
    except RuntimeError as exc:
        tool_status = "BLOCKED:" + str(exc).replace(" ", "_")
    _, admission_rows = validate_upstream_admission(ROOT, DEFAULT_AUTHORITY)
    ready = [str(r.get("component")) for r in admission_rows if r.get("status") == "ready-for-acquisition"]
    review = [str(r.get("component")) for r in admission_rows if r.get("status") != "ready-for-acquisition"]
    print("UPSTREAM_ACQUISITION_PREFLIGHT tools=%s unresolved=%d ready=%d review=%d readyComponents=%s reviewComponents=%s" % (
        tool_status,
        len(admission_rows), len(ready), len(review), ",".join(ready), ",".join(review),
    ))
    return 0 if not tool_status.startswith("BLOCKED:") else 3


def self_test() -> int:
    assert constraint_matches("1.20.x", "1.20.3")
    assert constraint_matches("1.20.x", "v1.20.3")
    assert not constraint_matches("1.20.x", "1.21.0")
    fixture = {"spec": {"template": {"spec": {"containers": [{"image": "registry.example/app:1.2.3"}], "initContainers": [{"image": "registry.example/init@sha256:" + "b" * 64}]}}}}
    def fake(ref: str) -> str:
        assert ref == "registry.example/app:1.2.3"
        return "sha256:" + "a" * 64
    refs = pin_images(fixture, fake)
    assert refs == {"registry.example/app@sha256:" + "a" * 64, "registry.example/init@sha256:" + "b" * 64}
    assert fixture["spec"]["template"]["spec"]["containers"][0]["image"] == "registry.example/app@sha256:" + "a" * 64
    resources = parse_rendered_yaml("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: x\n---\n")
    assert len(resources) == 1
    assert normalized_version("v1.2.3") == "1.2.3"
    require_https_response("https://charts.example.test/index.yaml", "https://cdn.example.test/index.yaml")
    for insecure_final in ("http://charts.example.test/index.yaml", "file:///tmp/index.yaml", ""):
        try:
            require_https_response("https://charts.example.test/index.yaml", insecure_final)
        except RuntimeError as exc:
            assert "UPSTREAM_HTTPS_DOWNGRADE_DENIED" in str(exc)
        else:
            raise AssertionError(f"insecure upstream redirect was accepted: {insecure_final!r}")
    _, admission_rows = validate_upstream_admission(ROOT, DEFAULT_AUTHORITY)
    assert any(r.get("status") == "ready-for-acquisition" for r in admission_rows)
    with tempfile.TemporaryDirectory(dir=ROOT) as td:
        value = Path(td) / "values.yaml"
        value.write_text("replicas: 2\n")
        rows = repo_value_inputs([value])
        assert rows == [{"path": value.resolve().relative_to(ROOT).as_posix(), "sha256": sha256_file(value)}]
        try:
            repo_value_inputs([value, value])
        except RuntimeError as exc:
            assert "VALUES_FILE_DUPLICATE" in str(exc)
        else:
            raise AssertionError("duplicate values input was accepted")
    with tempfile.TemporaryDirectory() as td:
        outside = Path(td) / "values.yaml"
        outside.write_text("replicas: 3\n")
        try:
            repo_value_inputs([outside])
        except RuntimeError as exc:
            assert "VALUES_FILE_OUTSIDE_REPOSITORY" in str(exc)
        else:
            raise AssertionError("outside-repository values input was accepted")
    print("UPSTREAM_ACQUISITION_SELF_TEST_PASS")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description="Acquire one real upstream Helm chart into the 4SO offline catalog")
    p.add_argument("--preflight", action="store_true")
    p.add_argument("--self-test", action="store_true")
    p.add_argument("--component")
    p.add_argument("--from-admission", action="store_true", help="resolve current exact version/source only from catalog/upstream-admission.json")
    p.add_argument("--from-upgrade-admission", action="store_true", help="resolve historical exact predecessor/source only from catalog/component-upgrade-source-admission.json")
    p.add_argument("--historical", action="store_true", help="assemble an explicitly reviewed previous release for S2 without mutating the current target component")
    p.add_argument("--authority", default=str(DEFAULT_AUTHORITY), help="upstream admission authority path")
    p.add_argument("--version", help="exact numeric component/chart version; never inferred from latest")
    p.add_argument("--upstream-version", help="upstream spelling when it uses a v-prefix; defaults to --version")
    p.add_argument("--source", help="official HTTPS Helm repository URL or exact oci:// chart reference")
    p.add_argument("--values", action="append", default=[], help="product-owned Helm values file; may be repeated")
    p.add_argument("--license-spdx", help="required only when Chart.yaml has no artifacthub.io/license annotation")
    p.add_argument("--platformctl")
    p.add_argument("--out")
    p.add_argument("--install", action="store_true", help="verify and atomically install the resulting bundle into this repository")
    p.add_argument("--network-timeout", type=int, default=60)
    a = p.parse_args()
    if a.self_test:
        return self_test()
    if a.preflight:
        return preflight()
    if not a.component:
        p.error("--component is required unless --preflight/--self-test is used")
    try:
        return acquire(a)
    except (RuntimeError, subprocess.TimeoutExpired, urllib.error.URLError, OSError, ValueError) as exc:
        print(f"UPSTREAM_ACQUISITION_BLOCKED {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
