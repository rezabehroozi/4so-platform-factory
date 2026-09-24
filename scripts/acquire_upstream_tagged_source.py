#!/usr/bin/env python3
"""Acquire commit-pinned external tagged source sets for current or S2 historical use.

The recipe pins the GitHub repository, exact tag, full commit SHA and exact file set.
The acquisition host must prove tag->commit identity, fetch every byte from that
commit (never from a moving branch), build a deterministic source-set archive,
render Kubernetes resources, pin images by digest, and hand the result to the
canonical catalog-bundle transaction. Acquisition never implies runtime or
physical certification.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request
import zipfile

try:
    import yaml
except ImportError as exc:  # pragma: no cover
    raise SystemExit("PY_YAML_REQUIRED: install PyYAML on the acquisition host") from exc

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from component_upgrade_source_admission import validate as validate_upgrade_source_admission
from upstream_acquisition_toolchain import require_toolchain

AUTHORITY = "TAGGED_SOURCE_ACQUISITION_RECIPE_V1"
EXACT = re.compile(r"^\d+\.\d+\.\d+$")
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
SHA1 = re.compile(r"^[0-9a-f]{40}$")
SAFE_COMPONENT = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 48 * 1024 * 1024
MAX_FILES = 128


def _absolute_no_follow(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path.expanduser())))


def _json(path: Path) -> dict:
    return json.loads(path.read_text())


def _sha_bytes(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _sha_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def _safe_source_path(value: str) -> str:
    p = PurePosixPath(value)
    if not value or value.startswith("/") or "\\" in value or ".." in p.parts:
        raise RuntimeError(f"TAGGED_SOURCE_PATH_INVALID {value!r}")
    return str(p)


def _https(url: str, *, hosts: set[str] | None = None) -> urllib.parse.SplitResult:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme.lower() != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise RuntimeError(f"TAGGED_SOURCE_HTTPS_REQUIRED {url}")
    if hosts is not None and parsed.hostname.lower() not in hosts:
        raise RuntimeError(f"TAGGED_SOURCE_HOST_DENIED {parsed.hostname}")
    return parsed


def _bounded_fetch(url: str, *, timeout: int, limit: int, accept: str = "application/octet-stream") -> bytes:
    _https(url, hosts={"api.github.com", "raw.githubusercontent.com"})
    req = urllib.request.Request(url, headers={"User-Agent": "4so-platform-factory-tagged-source/1", "Accept": accept})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        final = response.geturl()
        _https(final, hosts={"api.github.com", "raw.githubusercontent.com"})
        if response.status != 200:
            raise RuntimeError(f"TAGGED_SOURCE_HTTP_{response.status} {url}")
        raw = response.read(limit + 1)
    if len(raw) > limit:
        raise RuntimeError(f"TAGGED_SOURCE_INPUT_TOO_LARGE limit={limit} url={url}")
    return raw


def _resolve_tag_commit(repo: str, tag: str, *, timeout: int, fetch=_bounded_fetch) -> str:
    ref_url = f"https://api.github.com/repos/{repo}/git/ref/tags/{urllib.parse.quote(tag, safe='')}"
    doc = json.loads(fetch(ref_url, timeout=timeout, limit=1024 * 1024, accept="application/vnd.github+json"))
    obj = doc.get("object") or {}
    sha = str(obj.get("sha") or "").lower()
    typ = str(obj.get("type") or "")
    if not SHA1.fullmatch(sha) or typ not in {"commit", "tag"}:
        raise RuntimeError("TAGGED_SOURCE_TAG_REF_INVALID")
    if typ == "tag":
        tag_url = f"https://api.github.com/repos/{repo}/git/tags/{sha}"
        tag_doc = json.loads(fetch(tag_url, timeout=timeout, limit=1024 * 1024, accept="application/vnd.github+json"))
        obj = tag_doc.get("object") or {}
        sha = str(obj.get("sha") or "").lower()
        typ = str(obj.get("type") or "")
        if typ != "commit" or not SHA1.fullmatch(sha):
            raise RuntimeError("TAGGED_SOURCE_ANNOTATED_TAG_TARGET_INVALID")
    return sha


def _recipe_path(component: str, version: str, root: Path = ROOT) -> Path:
    return root / "catalog" / "tagged-source-recipes" / component / f"{version}.json"


def load_historical_authority(component: str, root: Path = ROOT) -> dict:
    doc = _json(root / "catalog" / "component-upgrade-source-admission.json")
    errs = validate_upgrade_source_admission(doc, root)
    if errs:
        raise RuntimeError("UPGRADE_SOURCE_ADMISSION_INVALID " + "; ".join(errs))
    rows = [r for r in doc.get("components", []) if r.get("component") == component]
    if len(rows) != 1:
        raise RuntimeError(f"UPGRADE_SOURCE_ADMISSION_COMPONENT_NOT_UNIQUE {component}")
    row = rows[0]
    if row.get("status") != "admitted-for-acquisition":
        raise RuntimeError(f"UPGRADE_SOURCE_ADMISSION_NOT_ACQUIRABLE {component}:{row.get('status')}")
    return row


def load_recipe(component: str, version: str, *, historical: bool, root: Path = ROOT) -> tuple[dict, dict]:
    if not SAFE_COMPONENT.fullmatch(component) or not EXACT.fullmatch(version):
        raise RuntimeError("TAGGED_SOURCE_IDENTITY_INVALID")
    if not historical:
        raise RuntimeError("TAGGED_SOURCE_CURRENT_MODE_NOT_ADMITTED_YET")
    row = load_historical_authority(component, root)
    if row.get("previousVersion") != version:
        raise RuntimeError(f"TAGGED_SOURCE_RECIPE_VERSION_NOT_ADMITTED {component}:{version}")
    path = _recipe_path(component, version, root)
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"TAGGED_SOURCE_RECIPE_NOT_FOUND {path}")
    recipe = _json(path)
    md, spec = recipe.get("metadata") or {}, recipe.get("spec") or {}
    if recipe.get("apiVersion") != "platform.4so.io/v1alpha1" or recipe.get("kind") != "TaggedSourceAcquisitionRecipe" or spec.get("authority") != AUTHORITY:
        raise RuntimeError("TAGGED_SOURCE_RECIPE_AUTHORITY_INVALID")
    if md.get("component") != component or md.get("version") != version or spec.get("tag") != "v" + version:
        raise RuntimeError("TAGGED_SOURCE_RECIPE_IDENTITY_DRIFT")
    repo = str(spec.get("repository") or "")
    commit = str(spec.get("commitSHA") or "").lower()
    release_url = str(spec.get("releaseURL") or "")
    files = spec.get("files") or []
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo) or not SHA1.fullmatch(commit):
        raise RuntimeError("TAGGED_SOURCE_RECIPE_REPOSITORY_OR_COMMIT_INVALID")
    if release_url != row.get("source"):
        raise RuntimeError(f"TAGGED_SOURCE_RECIPE_SOURCE_DRIFT {component}")
    if len(files) < 1 or len(files) > MAX_FILES:
        raise RuntimeError("TAGGED_SOURCE_RECIPE_FILE_COUNT_INVALID")
    seen_src, seen_out = set(), set()
    for item in files:
        if set(item) != {"sourcePath", "archivePath", "render"} or not isinstance(item.get("render"), bool):
            raise RuntimeError("TAGGED_SOURCE_RECIPE_FILE_ENTRY_INVALID")
        src = _safe_source_path(str(item.get("sourcePath") or ""))
        out = str(item.get("archivePath") or "")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", out) or src in seen_src or out in seen_out or out == "source-index.json":
            raise RuntimeError("TAGGED_SOURCE_RECIPE_FILE_IDENTITY_INVALID")
        seen_src.add(src); seen_out.add(out)
    if str(spec.get("licenseFile") or "") not in seen_out:
        raise RuntimeError("TAGGED_SOURCE_LICENSE_FILE_MISSING")
    if not str(spec.get("licenseSPDX") or "").strip() or not str(spec.get("channel") or "").strip():
        raise RuntimeError("TAGGED_SOURCE_LICENSE_OR_CHANNEL_INVALID")
    return recipe, row


def _parse_resources(blobs: list[tuple[str, bytes]]) -> list[dict]:
    resources: list[dict] = []
    for name, raw in blobs:
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RuntimeError(f"TAGGED_SOURCE_RENDER_NOT_UTF8 {name}") from exc
        for doc in yaml.safe_load_all(text):
            if doc is None:
                continue
            if not isinstance(doc, dict):
                raise RuntimeError(f"TAGGED_SOURCE_RENDER_DOCUMENT_INVALID {name}")
            if doc.get("kind") == "List" and isinstance(doc.get("items"), list):
                resources.extend(doc["items"])
            else:
                resources.append(doc)
    if not resources:
        raise RuntimeError("TAGGED_SOURCE_RENDER_EMPTY")
    for idx, r in enumerate(resources):
        md = r.get("metadata") or {}
        if not isinstance(r, dict) or not r.get("apiVersion") or not r.get("kind") or not isinstance(md, dict) or not md.get("name"):
            raise RuntimeError(f"TAGGED_SOURCE_RENDER_IDENTITY_INVALID index={idx}")
    return resources


def _image_repository(ref: str) -> str:
    if "@" in ref:
        return ref.split("@", 1)[0]
    slash, colon = ref.rfind("/"), ref.rfind(":")
    return ref[:colon] if colon > slash else ref


def _pin_images(value, resolver) -> set[str]:
    pinned: set[str] = set()
    if isinstance(value, list):
        for item in value:
            pinned |= _pin_images(item, resolver)
    elif isinstance(value, dict):
        for key, item in list(value.items()):
            if key == "image" and isinstance(item, str) and item.strip():
                ref = item.strip()
                if "@sha256:" in ref:
                    digest = ref.split("@", 1)[1]
                    if not SHA256.fullmatch(digest):
                        raise RuntimeError(f"TAGGED_SOURCE_IMAGE_DIGEST_INVALID {ref}")
                else:
                    digest = resolver(ref)
                    if not SHA256.fullmatch(digest):
                        raise RuntimeError(f"TAGGED_SOURCE_IMAGE_RESOLUTION_INVALID {ref}:{digest}")
                new = _image_repository(ref) + "@" + digest
                value[key] = new; pinned.add(new)
            else:
                pinned |= _pin_images(item, resolver)
    return pinned


def _crane_resolver():
    pinned = require_toolchain()
    crane = str(pinned["crane"][0])
    def resolve(ref: str) -> str:
        p = subprocess.run([crane, "digest", ref], cwd=ROOT, text=True, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180)
        if p.returncode:
            raise RuntimeError(f"TAGGED_SOURCE_CRANE_FAILED {ref} {p.stdout[-1000:]}")
        out = p.stdout.strip().splitlines()[-1].strip().lower()
        if not SHA256.fullmatch(out):
            raise RuntimeError(f"TAGGED_SOURCE_CRANE_DIGEST_INVALID {ref}:{out}")
        return out
    return resolve


def deterministic_zip(files: dict[str, bytes], source_index: dict, out: Path) -> None:
    payload = dict(files)
    payload["source-index.json"] = (json.dumps(source_index, indent=2, sort_keys=True) + "\n").encode()
    out.parent.mkdir(parents=True, exist_ok=True)
    temp = out.with_name("." + out.name + ".tmp")
    try:
        with zipfile.ZipFile(temp, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
            for name in sorted(payload):
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o100644 << 16
                zf.writestr(info, payload[name])
        os.replace(temp, out)
    finally:
        try: temp.unlink()
        except FileNotFoundError: pass


def _sbom(component: str, version: str, release_url: str, source_rows: list[dict], license_spdx: str, images: list[str], artifact_digest: str) -> dict:
    files = []
    for row in source_rows:
        token = re.sub(r"[^A-Za-z0-9.-]", "-", row["path"])
        files.append({"SPDXID":"SPDXRef-File-"+token,"fileName":row["path"],"checksums":[{"algorithm":"SHA256","checksumValue":row["sha256"].split(":",1)[1]}],"licenseConcluded":license_spdx,"copyrightText":"NOASSERTION"})
    packages=[{"SPDXID":"SPDXRef-Package-"+component,"name":component,"versionInfo":version,"downloadLocation":release_url,"filesAnalyzed":True,"licenseConcluded":license_spdx,"licenseDeclared":license_spdx,"copyrightText":"NOASSERTION"}]
    for i, ref in enumerate(images,1):
        packages.append({"SPDXID":f"SPDXRef-Image-{i}","name":_image_repository(ref),"versionInfo":ref.split("@",1)[1],"downloadLocation":ref,"filesAnalyzed":False})
    return {"spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0","SPDXID":"SPDXRef-DOCUMENT","name":f"{component}-{version}-official-tag-source-set","documentNamespace":f"https://platform.4so.io/sbom/{component}/{version}/{artifact_digest.split(':',1)[1]}","creationInfo":{"creators":["Tool: 4SO Platform Factory tagged-source acquisition"],"created":"1970-01-01T00:00:00Z"},"files":files,"packages":packages}


def _platformctl(path: str | None) -> list[str]:
    if path:
        p = _absolute_no_follow(Path(path))
        try:
            st = p.lstat()
        except OSError as exc:
            raise RuntimeError(f"PLATFORMCTL_NOT_EXECUTABLE {p}") from exc
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode) or not os.access(p, os.X_OK):
            raise RuntimeError(f"PLATFORMCTL_NOT_EXECUTABLE {p}")
        return [str(p)]
    built = ROOT / "bin/platformctl"
    if built.is_file() and not built.is_symlink() and os.access(built, os.X_OK):
        return [str(built)]
    if shutil.which("go"):
        return ["go", "run", "./cmd/platformctl"]
    raise RuntimeError("PLATFORMCTL_OR_GO_REQUIRED")


def _run(cmd: list[str], timeout: int = 300) -> str:
    p = subprocess.run(cmd, cwd=ROOT, text=True, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
    if p.returncode:
        raise RuntimeError(f"COMMAND_FAILED rc={p.returncode} cmd={cmd!r}\n{p.stdout[-8000:]}")
    return p.stdout


def acquire(component: str, version: str, *, historical: bool, out: Path | None, install: bool, platformctl: str | None, network_timeout: int) -> int:
    recipe, row = load_recipe(component, version, historical=historical)
    spec = recipe["spec"]
    resolved_commit = _resolve_tag_commit(spec["repository"], spec["tag"], timeout=network_timeout)
    if resolved_commit != spec["commitSHA"]:
        raise RuntimeError(f"TAGGED_SOURCE_TAG_COMMIT_DRIFT {component}:{resolved_commit}!={spec['commitSHA']}")
    blobs: dict[str, bytes] = {}; source_rows=[]; render_blobs=[]; total=0
    for item in spec["files"]:
        src = _safe_source_path(item["sourcePath"]); name=item["archivePath"]
        url=f"https://raw.githubusercontent.com/{spec['repository']}/{spec['commitSHA']}/{src}"
        raw=_bounded_fetch(url,timeout=network_timeout,limit=MAX_FILE_BYTES)
        total += len(raw)
        if total > MAX_TOTAL_BYTES: raise RuntimeError(f"TAGGED_SOURCE_TOTAL_TOO_LARGE limit={MAX_TOTAL_BYTES}")
        blobs[name]=raw
        source_rows.append({"path":name,"sha256":_sha_bytes(raw),"url":url})
        if item["render"]: render_blobs.append((name,raw))
    resources=_parse_resources(render_blobs)
    unresolved=[]
    def collect(v):
        if isinstance(v,list):
            for x in v: collect(x)
        elif isinstance(v,dict):
            for k,x in v.items():
                if k=="image" and isinstance(x,str) and x.strip() and "@sha256:" not in x: unresolved.append(x.strip())
                else: collect(x)
    collect(resources)
    images=sorted(_pin_images(resources,_crane_resolver() if unresolved else lambda ref: (_ for _ in ()).throw(RuntimeError("UNEXPECTED_IMAGE_RESOLUTION"))))
    source_index={"apiVersion":"platform.4so.io/v1alpha1","kind":"UpstreamSourceSet","component":component,"version":version,"upstream":{"project":spec["repository"],"revision":spec["tag"],"releaseCommit":spec["commitSHA"],"releaseCommitShort":spec["commitSHA"][:7],"releaseUrl":spec["releaseURL"],"channel":spec["channel"]},"assembly":{"method":"deterministic-zip-from-official-tag-files","networkFetchRequired":False,"note":"Bytes were fetched from the full reviewed Git commit after tag-to-commit verification; the aggregate zip is Platform Factory assembly, not an upstream release asset."},"files":source_rows}
    with tempfile.TemporaryDirectory(prefix=f"4so-tagged-{component}-") as td:
        tmp=Path(td); artifact=tmp/f"{component}-v{version}-official-tag-source-set.zip"; deterministic_zip(blobs,source_index,artifact); artifact_digest=_sha_file(artifact)
        render=tmp/"render-manifest.json"; render.write_text(json.dumps(resources,indent=2,sort_keys=True)+"\n")
        inventory=tmp/"image-inventory.json"; inventory.write_text(json.dumps({"images":[{"reference":r} for r in images]},indent=2,sort_keys=True)+"\n")
        license_row=next(r for r in source_rows if r["path"]==spec["licenseFile"])
        licenses=tmp/"licenses.json"; licenses.write_text(json.dumps({"licenses":[{"file":spec["licenseFile"],"spdxExpression":spec["licenseSPDX"],"sha256":license_row["sha256"]}]},indent=2,sort_keys=True)+"\n")
        sbom=tmp/"sbom.spdx.json"; sbom.write_text(json.dumps(_sbom(component,version,spec["releaseURL"],source_rows,spec["licenseSPDX"],images,artifact_digest),indent=2,sort_keys=True)+"\n")
        component_path=ROOT/"catalog/components"/f"{component}.json"; ctl=_platformctl(platformctl)
        final=_absolute_no_follow(out) if out else ROOT/"dist/upstream-history"/f"{component}-{version}.zip"
        if final.is_symlink(): raise RuntimeError(f"TAGGED_SOURCE_OUTPUT_SYMLINK_FORBIDDEN {final}")
        final.parent.mkdir(parents=True,exist_ok=True)
        cmd=ctl+["catalog-bundle","assemble","--historical","--component",str(component_path),"--artifact",str(artifact),"--render-manifest",str(render),"--image-inventory",str(inventory),"--licenses",str(licenses),"--sbom",str(sbom),"--version",version,"--source-type","external-tagged-source-set","--source-url",spec["releaseURL"],"--source-revision",spec["tag"],"--upstream-artifact-name",artifact.name,"--artifact-digest",artifact_digest,"--bundle-key",f"{component}/{version}","--out",str(final)]
        print(_run(cmd),end=""); print(_run(ctl+["catalog-bundle","verify","-f",str(final)]),end="")
        if install:
            print(_run(ctl+["catalog-bundle","install-historical","-f",str(final),"--repo-root",str(ROOT),"--confirmation","IMPORT-HISTORICAL"]),end="")
            print(_run([sys.executable,"scripts/validate_repository.py","."]),end="")
        print(f"TAGGED_SOURCE_ACQUISITION_PASS component={component} version={version} commit={spec['commitSHA']} files={len(blobs)} images={len(images)} artifactDigest={artifact_digest} out={final}")
    return 0


def self_test() -> int:
    for component, version, commit in (("gateway-api","1.5.0","3797b631d20f9ff4e2b4571f62d91d84a1fbdf5a"),("snapshot-controller","8.4.0","f21cb02763e7cd6a7fc84846f106b83119b5371d")):
        recipe,row=load_recipe(component,version,historical=True)
        assert recipe["spec"]["commitSHA"]==commit and row["previousVersion"]==version
    raw={"install.yaml":b"apiVersion: v1\nkind: Namespace\nmetadata:\n  name: x\n"}
    idx={"apiVersion":"platform.4so.io/v1alpha1","kind":"UpstreamSourceSet","component":"x","version":"1.0.0","upstream":{"revision":"v1.0.0"},"assembly":{"method":"deterministic-zip-from-official-tag-files","networkFetchRequired":False},"files":[{"path":"install.yaml","sha256":_sha_bytes(raw["install.yaml"]),"url":"https://raw.githubusercontent.com/x/y/"+"a"*40+"/install.yaml"}]}
    with tempfile.TemporaryDirectory(dir=ROOT) as td:
        a=Path(td)/"a.zip"; b=Path(td)/"b.zip"; deterministic_zip(raw,idx,a); deterministic_zip(raw,idx,b); assert a.read_bytes()==b.read_bytes()
        with zipfile.ZipFile(a) as zf: assert set(zf.namelist())=={"install.yaml","source-index.json"}
    try: _safe_source_path("../escape")
    except RuntimeError: pass
    else: raise AssertionError("path traversal accepted")
    print("TAGGED_SOURCE_ACQUISITION_SELF_TEST_PASS recipes=2 deterministic_zip=PASS")
    return 0


def main() -> int:
    p=argparse.ArgumentParser(); p.add_argument("--component"); p.add_argument("--version"); p.add_argument("--historical",action="store_true"); p.add_argument("--from-upgrade-admission",action="store_true"); p.add_argument("--out",type=Path); p.add_argument("--install",action="store_true"); p.add_argument("--platformctl"); p.add_argument("--network-timeout",type=int,default=60); p.add_argument("--self-test",action="store_true"); a=p.parse_args()
    if a.self_test: return self_test()
    if not a.from_upgrade_admission or not a.historical or not a.component:
        p.error("historical tagged-source acquisition requires --component --historical --from-upgrade-admission")
    row=load_historical_authority(a.component); version=str(row.get("previousVersion") or "")
    if a.version and a.version != version: raise SystemExit("TAGGED_SOURCE_VERSION_OVERRIDE_DENIED")
    try: return acquire(a.component,version,historical=True,out=a.out,install=a.install,platformctl=a.platformctl,network_timeout=a.network_timeout)
    except (RuntimeError,OSError,ValueError,urllib.error.URLError,subprocess.TimeoutExpired,json.JSONDecodeError) as exc:
        print("TAGGED_SOURCE_ACQUISITION_BLOCKED "+str(exc),file=sys.stderr); return 3

if __name__=="__main__": raise SystemExit(main())
