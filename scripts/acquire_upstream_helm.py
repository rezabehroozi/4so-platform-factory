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
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse
import urllib.request

from catalog_upstream_admission import DEFAULT_AUTHORITY, validate as validate_upstream_admission

try:
    import yaml
except ImportError as exc:  # pragma: no cover - environment preflight
    raise SystemExit("PY_YAML_REQUIRED: install PyYAML on the acquisition host") from exc

ROOT = Path(__file__).resolve().parents[1]
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
EXACT_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")


def run(cmd: list[str], *, cwd: Path = ROOT, env: dict[str, str] | None = None, timeout: int = 600) -> str:
    merged = os.environ.copy()
    if env:
        merged.update(env)
    p = subprocess.run(cmd, cwd=cwd, env=merged, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, timeout=timeout)
    if p.returncode:
        raise RuntimeError(f"COMMAND_FAILED rc={p.returncode} cmd={cmd!r}\n{p.stdout[-8000:]}")
    return p.stdout


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
        resolved = value.resolve()
        try:
            relative = resolved.relative_to(ROOT).as_posix()
        except ValueError as exc:
            raise RuntimeError(f"VALUES_FILE_OUTSIDE_REPOSITORY {resolved}") from exc
        if relative in seen:
            raise RuntimeError(f"VALUES_FILE_DUPLICATE {relative}")
        seen.add(relative)
        rows.append({"path": relative, "sha256": sha256_file(resolved)})
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


def load_component(name: str) -> tuple[Path, dict]:
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
    if source.get("resolved"):
        raise RuntimeError(f"COMPONENT_ALREADY_RESOLVED {name}")
    if source.get("type") != "helm-chart" or spec.get("delivery", {}).get("type") != "helm":
        raise RuntimeError(f"COMPONENT_NOT_HELM_CHART {name}")
    return path, doc


def chart_metadata(chart: Path) -> dict:
    with tarfile.open(chart, "r:gz") as tf:
        members = tf.getmembers()
        roots: set[str] = set()
        chart_member = None
        for member in members:
            raw = member.name
            parts = Path(raw.rstrip("/")).parts
            if not raw or raw.startswith("/") or "\\" in raw or ".." in parts:
                raise RuntimeError(f"UNSAFE_CHART_PATH {raw!r}")
            if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                raise RuntimeError(f"UNSAFE_CHART_ENTRY {raw!r}")
            if parts:
                roots.add(parts[0])
            if len(parts) == 2 and parts[1] == "Chart.yaml":
                chart_member = member
        if len(roots) != 1 or chart_member is None:
            raise RuntimeError("HELM_CHART_LAYOUT_INVALID")
        fh = tf.extractfile(chart_member)
        if fh is None:
            raise RuntimeError("HELM_CHART_METADATA_UNREADABLE")
        doc = yaml.safe_load(fh.read())
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
    with urllib.request.urlopen(url, timeout=timeout) as response:
        final_url = response.geturl()
        require_https_response(url, final_url)
        if response.status != 200:
            raise RuntimeError(f"HELM_INDEX_HTTP_{response.status} {url}")
        raw = response.read(32 * 1024 * 1024)
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
    if not shutil.which("crane"):
        raise RuntimeError("CRANE_REQUIRED_FOR_OCI_DIGEST")
    ref = source.removeprefix("oci://") + ":" + upstream_version
    manifest = json.loads(run(["crane", "manifest", ref], timeout=180))
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
        run(["helm", "pull", source, "--version", upstream_version, "--destination", str(dest)], env=env, timeout=300)
    elif source.startswith("https://"):
        alias = "pf-upstream"
        run(["helm", "repo", "add", alias, source, "--force-update"], env=env, timeout=180)
        run(["helm", "repo", "update"], env=env, timeout=180)
        run(["helm", "pull", f"{alias}/{chart}", "--version", upstream_version, "--destination", str(dest)], env=env, timeout=300)
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
    cmd = ["helm", "template", "platform-factory", str(chart), "--namespace", namespace, "--include-crds", "--kube-version", kube_version]
    for value in values:
        cmd += ["--values", str(value)]
    return parse_rendered_yaml(run(cmd, env=env, timeout=300))


def canonical_resources(resources: list[dict]) -> bytes:
    return (json.dumps(resources, sort_keys=True, separators=(",", ":")) + "\n").encode()


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
    out = run(["crane", "digest", ref], timeout=180).strip().splitlines()[-1].strip().lower()
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
        p = Path(path).resolve()
        if not p.is_file():
            raise RuntimeError(f"PLATFORMCTL_NOT_FOUND {p}")
        return [str(p)]
    built = ROOT / "bin" / "platformctl"
    if built.is_file():
        return [str(built)]
    if shutil.which("go"):
        return ["go", "run", "./cmd/platformctl"]
    raise RuntimeError("PLATFORMCTL_OR_GO_REQUIRED")


def apply_admission(args: argparse.Namespace) -> None:
    # CatalogUpstreamAdmission is the product-owned execution authority for every
    # unresolved Helm acquisition. Version/source CLI flags are consistency
    # assertions only; they must never become an alternate authority path.
    if not args.from_admission:
        raise RuntimeError("UPSTREAM_ADMISSION_REQUIRED")
    if not args.component:
        raise RuntimeError("UPSTREAM_ADMISSION_COMPONENT_REQUIRED")
    requested_authority = Path(os.path.abspath(args.authority))
    canonical_authority = Path(os.path.abspath(DEFAULT_AUTHORITY))
    if requested_authority != canonical_authority:
        raise RuntimeError(
            f"UPSTREAM_ADMISSION_AUTHORITY_OVERRIDE_DENIED {requested_authority}!={canonical_authority}"
        )
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
    args.version = selected
    args.source = source
    args.upstream_version = upstream


def acquire(args: argparse.Namespace) -> int:
    apply_admission(args)
    if not shutil.which("helm"):
        raise RuntimeError("HELM_REQUIRED")
    if not shutil.which("crane"):
        raise RuntimeError("CRANE_REQUIRED")
    component_path, component = load_component(args.component)
    spec = component["spec"]
    version = normalized_version(args.version)
    if not constraint_matches(str(spec.get("release", "")), version):
        raise RuntimeError(f"VERSION_OUTSIDE_COMPONENT_CONSTRAINT {version} not-in {spec.get('release')}")
    chart = str(spec.get("delivery", {}).get("chart") or "").strip()
    if not chart:
        raise RuntimeError("COMPONENT_CHART_NAME_MISSING")
    upstream_version = args.upstream_version or args.version
    values = [Path(v).resolve() for v in args.values]
    for value in values:
        if not value.is_file():
            raise RuntimeError(f"VALUES_FILE_NOT_FOUND {value}")
    value_inputs = repo_value_inputs(values)
    helm_version = tool_version(["helm", "version", "--short"], "HELM")
    crane_version = tool_version(["crane", "version"], "CRANE")

    with tempfile.TemporaryDirectory(prefix=f"4so-acquire-{args.component}-") as td:
        tmp = Path(td)
        env = helm_env(tmp / "helm")
        if args.source.startswith("oci://"):
            expected_digest = oci_layer_digest(args.source, upstream_version)
            upstream_index_version = upstream_version
        else:
            expected_digest, upstream_index_version = http_index_metadata(args.source, chart, upstream_version, args.network_timeout)
        artifact = pull_chart(args.source, chart, upstream_index_version, tmp, env)
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
        if canonical_resources(rendered_min) != canonical_resources(rendered_max):
            raise RuntimeError(f"HELM_RENDER_KUBE_RANGE_DRIFT {min_kube}!={max_kube}: single immutable render cannot represent declared range")

        generation_path = tmp / "render-generation.json"
        generation_path.write_text(json.dumps({
            "tool": "helm-template",
            "toolVersion": helm_version,
            "releaseName": "platform-factory",
            "namespace": str(spec.get("namespace") or "default"),
            "includeCRDs": True,
            "kubernetesVersions": [min_kube, max_kube],
            "values": value_inputs,
            "imageResolver": "crane-digest",
            "imageResolverVersion": crane_version,
        }, indent=2, sort_keys=True) + "\n")

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

        out = Path(args.out).resolve() if args.out else ROOT / "dist" / "upstream" / f"{args.component}-{version}.zip"
        out.parent.mkdir(parents=True, exist_ok=True)
        ctl = platformctl_prefix(args.platformctl)
        assemble = ctl + [
            "catalog-bundle", "assemble",
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
            print(run(ctl + ["catalog-bundle", "install", "-f", str(out), "--repo-root", str(ROOT), "--confirmation", "IMPORT"], timeout=180), end="")
            print(run(["python3", "scripts/validate_repository.py", "."], timeout=180), end="")
        print(f"UPSTREAM_ACQUISITION_PASS component={args.component} version={version} chartDigest={expected_digest} images={len(images)} out={out}")
    return 0


def preflight() -> int:
    missing = [x for x in ("helm", "crane") if not shutil.which(x)]
    _, admission_rows = validate_upstream_admission(ROOT, DEFAULT_AUTHORITY)
    ready = [str(r.get("component")) for r in admission_rows if r.get("status") == "ready-for-acquisition"]
    review = [str(r.get("component")) for r in admission_rows if r.get("status") != "ready-for-acquisition"]
    print("UPSTREAM_ACQUISITION_PREFLIGHT tools=%s unresolved=%d ready=%d review=%d readyComponents=%s reviewComponents=%s" % (
        "PASS" if not missing else "BLOCKED:" + ",".join(missing),
        len(admission_rows), len(ready), len(review), ",".join(ready), ",".join(review),
    ))
    return 0 if not missing else 3


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
    p.add_argument("--from-admission", action="store_true", help="resolve exact version/source only from catalog/upstream-admission.json; review-required entries fail closed")
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
