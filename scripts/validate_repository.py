#!/usr/bin/env python3
"""Validate current repository/package invariants without historical prose gates."""
from __future__ import annotations

from pathlib import Path
import argparse
import hashlib
import json
import re
import stat
import sys
import tarfile

SCAN_SUFFIXES = {'.go','.py','.md','.yaml','.yml','.json','.html','.css','.js','.sh','.txt','.service','.toml','.mod','.sql'}
RISK = {'low','medium','high','critical'}
CERT = {'candidate','render-certified','ephemeral-runtime-certified','target-runtime-certified','upgrade-certified','revoked','deprecated'}
REQUIRED_OPERATIONS = {'preflight','install','verify','upgrade','rollback','uninstall'}
FORBIDDEN_MARKERS = tuple(''.join(chr(x) for x in row) for row in (
    (67,79,78,70,73,71,95,82,69,81,85,73,82,69,68),
    (83,69,84,95,65,70,84,69,82,95,77,73,82,82,79,82),
    (82,85,78,84,73,77,69,95,84,69,83,84,95,82,69,81,85,73,82,69,68),
    (78,79,84,95,73,77,80,76,69,77,69,78,84,69,68),
    (70,73,88,77,69),
))
FORBIDDEN_BRANDS = tuple(''.join(chr(x) for x in row) for row in (
    (107,117,98,97,114,97),
    (104,111,115,116,105,114,97,110,45,112,97,97,115,45,112,108,97,116,102,111,114,109),
    (104,111,115,116,105,114,97,110,32,112,97,97,115,32,118,53,46,49),
))


def sha256(path: Path) -> str:
    return 'sha256:' + hashlib.sha256(path.read_bytes()).hexdigest()


def load_json(path: Path, errors: list[tuple[str,str]]):
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except Exception as exc:
        errors.append(('JSON_PARSE', f'{path}: {exc}'))
        return None


def safe_repo_path(root: Path, rel: str) -> Path | None:
    try:
        p = (root / rel).resolve()
        p.relative_to(root.resolve())
        return p
    except Exception:
        return None



def collect_image_refs(value, out: set[str]) -> None:
    if isinstance(value, list):
        for item in value:
            collect_image_refs(item, out)
    elif isinstance(value, dict):
        for key, item in value.items():
            if key == 'image' and isinstance(item, str) and item.strip():
                out.add(item.strip())
            collect_image_refs(item, out)


def validate_helm_chart(path: Path, expected_name: str, expected_version: str, errors: list[tuple[str,str]], component: str) -> None:
    try:
        with tarfile.open(path, 'r:gz') as tf:
            members = tf.getmembers()
            if not members or len(members) > 8192:
                raise ValueError('invalid chart entry count')
            roots = set()
            chart_member = None
            for m in members:
                raw = m.name.strip()
                clean = raw.rstrip('/') if m.isdir() else raw
                parts = Path(clean).parts
                if not raw or raw.startswith('/') or '\\' in raw or '..' in parts:
                    raise ValueError(f'unsafe chart path {raw!r}')
                if m.issym() or m.islnk() or m.isdev() or m.isfifo():
                    raise ValueError(f'unsupported chart entry {raw!r}')
                if parts:
                    roots.add(parts[0])
                if len(parts) == 2 and parts[1] == 'Chart.yaml':
                    chart_member = m
            if len(roots) != 1 or chart_member is None:
                raise ValueError('chart must contain one root and top-level Chart.yaml')
            fh = tf.extractfile(chart_member)
            if fh is None:
                raise ValueError('Chart.yaml is unreadable')
            raw = fh.read(1 << 20).decode('utf-8')
    except Exception as exc:
        errors.append(('HELM_CHART_ARTIFACT_INVALID', f'{component}:{exc}'))
        return
    fields = {}
    for line in raw.splitlines():
        if not line or line[0].isspace() or line.lstrip().startswith('#') or ':' not in line:
            continue
        key, value = line.split(':', 1)
        key = key.strip()
        if key in {'apiVersion','name','version'}:
            value = value.strip().strip('"').strip("'")
            fields[key] = value
    if fields.get('apiVersion') != 'v2' or fields.get('name') != expected_name or str(fields.get('version') or '').removeprefix('v') != expected_version:
        errors.append(('HELM_CHART_IDENTITY_MISMATCH', f'{component}:{fields!r}:expected={expected_name}@{expected_version}'))


def validate_source_bundle(root: Path, name: str, spec: dict, errors: list[tuple[str,str]]) -> None:
    src = spec.get('source') or {}
    if src.get('resolved') is not True:
        return
    source_type = str(src.get('type') or '')
    delivery = spec.get('delivery') or {}
    delivery_type = delivery.get('type')
    if source_type == 'helm-chart':
        if delivery_type != 'helm':
            errors.append(('HELM_CHART_DELIVERY_INVALID', name))
    elif delivery_type != 'native-manifest':
        errors.append(('RESOLVED_SOURCE_NOT_RENDERABLE', name))
    if src.get('signatureVerification') != 'sha256-pinned-offline':
        errors.append(('RESOLVED_SOURCE_ARTIFACT_VERIFICATION_CONTRACT', name))
    bundle_key = str(src.get('bundleKey') or '').strip()
    if not bundle_key:
        errors.append(('RESOLVED_SOURCE_BUNDLE_KEY_MISSING', name))
        return
    bundle_dir = safe_repo_path(root, 'catalog/runtime/' + bundle_key)
    if bundle_dir is None or not bundle_dir.is_dir():
        errors.append(('RESOLVED_SOURCE_BUNDLE_MISSING', f'{name}:{bundle_key}'))
        return
    digest_files = {
        'artifactDigest': 'artifact.bin' if (bundle_dir/'artifact.bin').is_file() else 'manifest.json',
        'sourceLockDigest': 'source-lock.json',
        'imageInventoryDigest': 'image-inventory.json',
        'licenseManifestDigest': 'licenses.json',
        'sbom': 'sbom.spdx.json',
        'provenance': 'provenance.json',
    }
    if src.get('renderManifestDigest'):
        digest_files['renderManifestDigest'] = 'render-manifest.json'
    for field, filename in digest_files.items():
        expected = str(src.get(field) or '')
        file = bundle_dir / filename
        if not re.fullmatch(r'sha256:[0-9a-f]{64}', expected):
            errors.append(('RESOLVED_SOURCE_DIGEST_INVALID', f'{name}:{field}'))
            continue
        if not file.is_file():
            errors.append(('RESOLVED_SOURCE_FILE_MISSING', f'{name}:{filename}'))
            continue
        actual = sha256(file)
        if actual != expected:
            errors.append(('RESOLVED_SOURCE_DIGEST_MISMATCH', f'{name}:{filename}:{actual}!={expected}'))

    release = str(spec.get('release') or '').strip()
    if source_type == 'helm-chart' and (bundle_dir/'artifact.bin').is_file():
        validate_helm_chart(bundle_dir/'artifact.bin', str(delivery.get('chart') or '').strip(), release, errors, name)

    lock_path = bundle_dir/'source-lock.json'
    if lock_path.is_file():
        lock = load_json(lock_path, errors)
        if isinstance(lock, dict):
            bad = lock.get('component') != name or lock.get('version') != release or lock.get('sourceType') != source_type or lock.get('networkFetchRequired') is not False
            if source_type == 'embedded-native':
                bad = bad or lock.get('renderer') != 'json-template-v1'
            else:
                bad = bad or lock.get('renderer') != 'json-resource-list-v1' or lock.get('upstreamVerification') != 'sha256-pinned-offline'
            if bad:
                errors.append(('SOURCE_LOCK_IDENTITY_INVALID', name))
            if source_type == 'helm-chart':
                generation = lock.get('generation')
                compatibility = spec.get('compatibility') or {}
                kube = compatibility.get('kubernetes') or {}
                def kube_render_version(value):
                    value = str(value or '').strip()
                    if re.fullmatch(r'[0-9]+\.[0-9]+', value):
                        return value + '.0'
                    if re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', value):
                        return value
                    return ''
                expected_kube = [kube_render_version(kube.get('minVersion')), kube_render_version(kube.get('maxVersion'))]
                generation_bad = not isinstance(generation, dict) or generation.get('tool') != 'helm-template' or not str(generation.get('toolVersion') or '').strip() or generation.get('releaseName') != 'platform-factory' or generation.get('namespace') != str(spec.get('namespace') or '').strip() or generation.get('includeCRDs') is not True or generation.get('kubernetesVersions') != expected_kube or generation.get('imageResolver') != 'crane-digest' or not str(generation.get('imageResolverVersion') or '').strip()
                values = generation.get('values') if isinstance(generation, dict) else None
                if not isinstance(values, list):
                    generation_bad = True
                    values = []
                seen_values = set()
                for row in values:
                    rel = str((row or {}).get('path') or '').strip() if isinstance(row, dict) else ''
                    digest = str((row or {}).get('sha256') or '').strip() if isinstance(row, dict) else ''
                    value_path = safe_repo_path(root, rel) if rel else None
                    if not rel or rel in seen_values or value_path is None or not value_path.is_file() or not re.fullmatch(r'sha256:[0-9a-f]{64}', digest) or sha256(value_path) != digest:
                        generation_bad = True
                    seen_values.add(rel)
                if generation_bad:
                    errors.append(('HELM_RENDER_GENERATION_INVALID', name))

    provenance_path = bundle_dir/'provenance.json'
    if provenance_path.is_file():
        provenance = load_json(provenance_path, errors)
        if isinstance(provenance, dict) and source_type == 'helm-chart':
            lock = load_json(lock_path, errors) if lock_path.is_file() else None
            if not isinstance(lock, dict) or provenance.get('generation') != lock.get('generation'):
                errors.append(('HELM_RENDER_PROVENANCE_DRIFT', name))

    sbom_path = bundle_dir/'sbom.spdx.json'
    if sbom_path.is_file():
        sbom = load_json(sbom_path, errors)
        if isinstance(sbom, dict):
            packages = sbom.get('packages') or []
            expected_package = str(delivery.get('chart') or '').strip() if source_type == 'helm-chart' else name
            if not packages or not any(isinstance(pkg, dict) and str(pkg.get('versionInfo') or '').strip().removeprefix('v') == release and str(pkg.get('SPDXID') or '').strip() and str(pkg.get('name') or '').strip() == expected_package for pkg in packages):
                errors.append(('SBOM_SOURCE_PACKAGE_MISSING', f'{name}:{expected_package}@{release}'))

    inv = bundle_dir / 'image-inventory.json'
    if inv.is_file():
        obj = load_json(inv, errors)
        if isinstance(obj, dict):
            for row in obj.get('images') or []:
                ref = str((row or {}).get('reference') or '')
                if ref and '@sha256:' not in ref:
                    errors.append(('MUTABLE_RUNTIME_IMAGE', f'{name}:{ref}'))
            inventory_refs = {str((row or {}).get('reference') or '').strip() for row in obj.get('images') or [] if str((row or {}).get('reference') or '').strip()}
            if len(inventory_refs) != len(obj.get('images') or []):
                errors.append(('IMAGE_INVENTORY_DUPLICATE_OR_EMPTY', name))
            render_path = bundle_dir/'render-manifest.json'
            if render_path.is_file():
                render = load_json(render_path, errors)
                if isinstance(render, list):
                    render_refs: set[str] = set()
                    collect_image_refs(render, render_refs)
                    for ref in render_refs:
                        if '@sha256:' not in ref:
                            errors.append(('MUTABLE_RENDER_IMAGE', f'{name}:{ref}'))
                    if render_refs != inventory_refs:
                        errors.append(('RENDER_IMAGE_INVENTORY_DRIFT', f'{name}:render={sorted(render_refs)} inventory={sorted(inventory_refs)}'))


def detect_cycle(graph: dict[str,list[str]]) -> list[str]:
    visiting, done = set(), set()
    stack: list[str] = []
    def visit(node: str):
        if node in done:
            return None
        if node in visiting:
            i = stack.index(node)
            return stack[i:] + [node]
        visiting.add(node); stack.append(node)
        for dep in graph.get(node, []):
            found = visit(dep)
            if found:
                return found
        stack.pop(); visiting.remove(node); done.add(node)
        return None
    for node in graph:
        found = visit(node)
        if found:
            return found
    return []


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('root', nargs='?', default='.')
    args = parser.parse_args()
    root = Path(args.root).resolve()
    errors: list[tuple[str,str]] = []
    ignored = {'.git','bin','dist','release','__pycache__','.pytest_cache','.state','.tmpbin'}
    files: list[Path] = []
    for path in root.rglob('*'):
        rel = path.relative_to(root)
        if any(part in ignored for part in rel.parts):
            continue
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            errors.append(('SOURCE_TREE_SYMLINK_FORBIDDEN', str(rel)))
            continue
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode):
            errors.append(('SOURCE_TREE_SPECIAL_FILE_FORBIDDEN', str(rel)))
            continue
        if path.name.startswith('.durable-'):
            errors.append(('STALE_DURABLE_TEMP_FORBIDDEN', str(rel)))
        files.append(path)

    # Repository hygiene/security scan. Do not make prose wording a product contract.
    secret_re = re.compile(r'(?i)(?<![A-Za-z0-9_])(password|token|secret)\s*[:=]\s*["\'][A-Za-z0-9_\-]{12,}["\']')
    for file in files:
        rel = file.relative_to(root)
        if file.suffix == '.pyc':
            errors.append(('COMPILED_PYTHON_FORBIDDEN', str(rel)))
        if file.suffix.lower() not in SCAN_SUFFIXES and file.name not in {'Makefile','VERSION','RELEASE-NAME'}:
            continue
        text = file.read_text(errors='ignore')
        low = text.lower()
        for brand in FORBIDDEN_BRANDS:
            if brand in low:
                errors.append(('BRAND_INDEPENDENCE', f'{rel}:{brand}'))
        for marker in FORBIDDEN_MARKERS:
            if marker in text:
                errors.append(('UNRESOLVED_MARKER', f'{rel}:{marker}'))
        if secret_re.search(text) and 'example.invalid' not in text:
            errors.append(('POSSIBLE_SECRET', str(rel)))

    required_root = ('VERSION','RELEASE-NAME','go.mod','Makefile','Dockerfile','THIRD_PARTY_COMPONENTS.md','LICENSE.txt')
    for rel in required_root:
        if not (root/rel).is_file():
            errors.append(('REQUIRED_ROOT_FILE_MISSING', rel))
    version = (root/'VERSION').read_text().strip() if (root/'VERSION').exists() else ''
    release_name = (root/'RELEASE-NAME').read_text().strip() if (root/'RELEASE-NAME').exists() else ''
    if not re.fullmatch(r'\d+\.\d+\.\d+', version):
        errors.append(('VERSION_FORMAT_INVALID', version))
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]*', release_name):
        errors.append(('RELEASE_NAME_FORMAT_INVALID', release_name))
    if (root/'go.mod').exists() and (root/'go.mod').read_text().splitlines()[0].strip() != 'module platform.4so.io/factory':
        errors.append(('GO_MODULE_IDENTITY','go.mod'))

    # Container/deployment contracts that materially affect installability/state durability.
    dockerfiles = [root/'Dockerfile', root/'deploy/images/Dockerfile.agent', root/'deploy/images/Dockerfile.probe', root/'deploy/images/Dockerfile.maintenance']
    for dockerfile in dockerfiles:
        if not dockerfile.is_file():
            errors.append(('CONTAINER_DOCKERFILE_MISSING', str(dockerfile.relative_to(root))))
            continue
        docker = dockerfile.read_text()
        rel = str(dockerfile.relative_to(root))
        if dockerfile.name == 'Dockerfile' and ('ARG GO_BUILD_IMAGE' not in docker or 'ARG RUNTIME_IMAGE' not in docker):
            errors.append(('CONTAINER_DIGEST_INPUTS_MISSING', rel))
        if dockerfile.name in {'Dockerfile.agent','Dockerfile.probe'} and ('ARG GO_BUILD_IMAGE' not in docker or 'ARG RUNTIME_IMAGE' not in docker):
            errors.append(('CONTAINER_DIGEST_INPUTS_MISSING', rel))
        if dockerfile.name == 'Dockerfile.maintenance' and 'ARG POSTGRES_BASE_IMAGE' not in docker:
            errors.append(('CONTAINER_DIGEST_INPUTS_MISSING', rel))
        if dockerfile.name in {'Dockerfile','Dockerfile.agent','Dockerfile.probe'} and 'internal/buildinfo.Version=$VERSION' not in docker:
            errors.append(('CONTAINER_BINARY_VERSION_INJECTION_MISSING', rel))
        for line in docker.splitlines():
            row = line.strip()
            if row.startswith('FROM ') and '${' not in row and '@sha256:' not in row:
                errors.append(('MUTABLE_CONTAINER_BASE', f'{rel}:{row}'))
    compose_path = root/'deploy/compose/docker-compose.yaml'
    compose = compose_path.read_text() if compose_path.exists() else ''
    if 'PLATFORM_FACTORY_IMAGE:?' not in compose or 'build:' in compose:
        errors.append(('COMPOSE_IMAGE_CONTRACT_INVALID', str(compose_path.relative_to(root))))
    systemd = root/'deploy/systemd/4so-platform-factory.service'
    env_example = root/'deploy/systemd/platform-factory.env.example'
    for p in (systemd, env_example):
        if not p.is_file():
            errors.append(('SYSTEMD_RUNTIME_FILE_MISSING', str(p.relative_to(root))))
    if systemd.exists() and 'EnvironmentFile=' not in systemd.read_text():
        errors.append(('SYSTEMD_ENVIRONMENT_FILE_MISSING', str(systemd.relative_to(root))))
    if env_example.exists() and 'PLATFORM_FACTORY_POSTGRES_DSN' not in env_example.read_text():
        errors.append(('SYSTEMD_DURABLE_AUTHORITY_CONFIG_MISSING', str(env_example.relative_to(root))))

    # Machine schemas must parse; settings schemas are resolved from component contracts below.
    schema_files = sorted((root/'schemas').rglob('*.json'))
    if not schema_files:
        errors.append(('SCHEMA_SET_EMPTY','schemas'))
    for p in schema_files:
        load_json(p, errors)

    # Catalog contract and supply-chain integrity.
    component_files = sorted((root/'catalog/components').glob('*.json'))
    if not component_files:
        errors.append(('CATALOG_EMPTY','catalog/components'))
    components: dict[str,dict] = {}
    required = ('displayName','category','release','versionPolicy','supportTier','mandatory','dependencies','provides','requiresCapabilities','exclusiveCapabilities','conflictsWith','risk','capabilities','namespace','wave','settingsSchemaRef','compatibility','delivery','source','operations','readiness','rollback','evidenceRequired','certification')
    for p in component_files:
        obj = load_json(p, errors)
        if not isinstance(obj, dict):
            continue
        if obj.get('apiVersion') != 'platform.4so.io/v1alpha1' or obj.get('kind') != 'PlatformComponent':
            errors.append(('CATALOG_TYPE_INVALID', p.name)); continue
        name = str((obj.get('metadata') or {}).get('name') or '')
        spec = obj.get('spec') or {}
        if not name or p.stem != name or name in components:
            errors.append(('CATALOG_IDENTITY_INVALID', f'{p.name}:{name}')); continue
        components[name] = obj
        for field in required:
            if field not in spec:
                errors.append(('CATALOG_FIELD_MISSING', f'{name}:{field}'))
        if spec.get('risk') not in RISK:
            errors.append(('CATALOG_RISK_INVALID', f'{name}:{spec.get("risk")}'))
        if (spec.get('certification') or {}).get('status') not in CERT:
            errors.append(('CERTIFICATION_STATUS_INVALID', name))
        if set((spec.get('operations') or {}).keys()) != REQUIRED_OPERATIONS:
            errors.append(('OPERATIONS_CONTRACT_INCOMPLETE', name))
        compat = spec.get('compatibility') or {}
        for field in ('kubernetes','architectures','distributionProfiles','providers'):
            if field not in compat:
                errors.append(('COMPATIBILITY_FIELD_MISSING', f'{name}:{field}'))
        delivery_type = (spec.get('delivery') or {}).get('type')
        if delivery_type not in {'helm','native-manifest'}:
            errors.append(('CATALOG_DELIVERY_TYPE_INVALID', f'{name}:{delivery_type}'))
        settings_rel = str(spec.get('settingsSchemaRef') or '')
        settings = safe_repo_path(root, settings_rel)
        if settings is None or not settings.is_file():
            errors.append(('SETTINGS_SCHEMA_MISSING', f'{name}:{settings_rel}'))
        else:
            load_json(settings, errors)
        src = spec.get('source') or {}
        source_type = src.get('type')
        if source_type not in {'embedded-native','external-tagged-source-set','helm-chart'}:
            errors.append(('SOURCE_TYPE_INVALID', f'{name}:{source_type}'))
        if source_type == 'helm-chart' and delivery_type != 'helm':
            errors.append(('HELM_CHART_DELIVERY_INVALID', name))
        if source_type in {'embedded-native','external-tagged-source-set'} and delivery_type != 'native-manifest':
            errors.append(('NATIVE_SOURCE_DELIVERY_INVALID', f'{name}:{source_type}:{delivery_type}'))
        for field in ('type','resolved','artifactDigest','sourceLockDigest','imageInventoryDigest','licenseManifestDigest','signatureVerification','sbom','provenance'):
            if field not in src:
                errors.append(('SOURCE_CONTRACT_FIELD_MISSING', f'{name}:{field}'))
        validate_source_bundle(root, name, spec, errors)

    graph: dict[str,list[str]] = {}
    for name,obj in components.items():
        spec = obj.get('spec') or {}
        deps = list(spec.get('dependencies') or [])
        graph[name] = deps
        for dep in deps:
            if dep not in components:
                errors.append(('CATALOG_DEPENDENCY_MISSING', f'{name}:{dep}'))
            elif int((components[dep].get('spec') or {}).get('wave',0)) > int(spec.get('wave',0)):
                errors.append(('CATALOG_DEPENDENCY_WAVE_INVALID', f'{name}:{dep}'))
    cycle = detect_cycle(graph)
    if cycle:
        errors.append(('CATALOG_DEPENDENCY_CYCLE',' -> '.join(cycle)))

    # Unresolved Helm acquisition is governed by one product-owned admission authority.
    # Exact version selection is intentionally separate from source-resolution and runtime
    # certification: ready rows may pin a version, but must remain source.resolved=false
    # until immutable upstream artifacts are actually acquired and verified.
    admission_path = root/'catalog/upstream-admission.json'
    if admission_path.is_symlink():
        errors.append(('UPSTREAM_ADMISSION_PATH_INVALID','catalog/upstream-admission.json'))
        admission = None
    else:
        admission = load_json(admission_path, errors) if admission_path.exists() else None
    unresolved_helm = {
        name: obj for name, obj in components.items()
        if ((obj.get('spec') or {}).get('source') or {}).get('type') == 'helm-chart'
        and not bool(((obj.get('spec') or {}).get('source') or {}).get('resolved'))
    }
    allowed_admission = {'ready-for-acquisition','architecture-review-required','dependency-review-required','version-selection-required','version-review-required'}
    if not isinstance(admission, dict) or admission.get('apiVersion') != 'platform.4so.io/v1alpha1' or admission.get('kind') != 'CatalogUpstreamAdmission':
        errors.append(('UPSTREAM_ADMISSION_INVALID','catalog/upstream-admission.json'))
    else:
        admission_spec = admission.get('spec') or {}
        policy = admission_spec.get('policy') or {}
        expected_policy = {
            'sourceAuthority':'official-upstream-only',
            'versionSelection':'exact-semver-no-prerelease',
            'sourceResolution':'separate-immutable-acquisition-required',
            'runtimeCertification':'separate-runtime-evidence-required',
            'autoWidenCatalogConstraint':False,
            'allowLatestResolution':False,
        }
        for key, expected in expected_policy.items():
            if policy.get(key) != expected:
                errors.append(('UPSTREAM_ADMISSION_POLICY_INVALID', f'{key}:{policy.get(key)}'))
        rows = admission_spec.get('components') or []
        admission_rows = {}
        for row in rows if isinstance(rows, list) else []:
            name = str((row or {}).get('component') or '') if isinstance(row, dict) else ''
            if not name or name in admission_rows:
                errors.append(('UPSTREAM_ADMISSION_IDENTITY_INVALID', name or '<empty>'))
                continue
            admission_rows[name] = row
        if set(admission_rows) != set(unresolved_helm):
            errors.append(('UPSTREAM_ADMISSION_COVERAGE_INVALID', f'missing={sorted(set(unresolved_helm)-set(admission_rows))};extra={sorted(set(admission_rows)-set(unresolved_helm))}'))
        exact_semver = re.compile(r'^[0-9]+\.[0-9]+\.[0-9]+$')
        series_semver = re.compile(r'^[0-9]+\.[0-9]+\.x$')
        for name, row in admission_rows.items():
            if name not in unresolved_helm:
                continue
            spec = unresolved_helm[name].get('spec') or {}
            status = str(row.get('status') or '')
            constraint = str(row.get('catalogConstraint') or '')
            selected = row.get('selectedVersion')
            upstream_version = row.get('upstreamVersion')
            source = str(row.get('source') or '')
            chart = str(row.get('chart') or '')
            if status not in allowed_admission:
                errors.append(('UPSTREAM_ADMISSION_STATUS_INVALID', f'{name}:{status}'))
            if not (exact_semver.fullmatch(constraint) or series_semver.fullmatch(constraint)):
                errors.append(('UPSTREAM_ADMISSION_CONSTRAINT_INVALID', f'{name}:{constraint}'))
            if chart != str((spec.get('delivery') or {}).get('chart') or ''):
                errors.append(('UPSTREAM_ADMISSION_CHART_MISMATCH', f'{name}:{chart}'))
            if not (source.startswith('https://') or source.startswith('oci://')):
                errors.append(('UPSTREAM_ADMISSION_SOURCE_INVALID', f'{name}:{source}'))
            if not str(row.get('rationale') or '').strip():
                errors.append(('UPSTREAM_ADMISSION_RATIONALE_MISSING', name))
            normalized_selected = str(selected or '').removeprefix('v')
            if selected is not None:
                if not exact_semver.fullmatch(normalized_selected):
                    errors.append(('UPSTREAM_ADMISSION_VERSION_INVALID', f'{name}:{selected}'))
                else:
                    cp, vp = constraint.removeprefix('v').split('.'), normalized_selected.split('.')
                    if (series_semver.fullmatch(constraint) and cp[:2] != vp[:2]) or (exact_semver.fullmatch(constraint) and constraint != normalized_selected):
                        errors.append(('UPSTREAM_ADMISSION_VERSION_OUTSIDE_CONSTRAINT', f'{name}:{selected}:{constraint}'))
                if not upstream_version or str(upstream_version).removeprefix('v') != normalized_selected:
                    errors.append(('UPSTREAM_ADMISSION_UPSTREAM_VERSION_INVALID', f'{name}:{upstream_version}'))
            if status == 'ready-for-acquisition':
                if selected is None:
                    errors.append(('UPSTREAM_ADMISSION_READY_VERSION_MISSING', name))
                if str(spec.get('release') or '') != normalized_selected:
                    errors.append(('UPSTREAM_ADMISSION_CATALOG_PIN_MISMATCH', f'{name}:{spec.get("release")}:{normalized_selected}'))
                if spec.get('versionPolicy') != 'exact-upstream-admitted-pending-source-acquisition':
                    errors.append(('UPSTREAM_ADMISSION_VERSION_POLICY_INVALID', name))
            elif str(spec.get('release') or '') != constraint:
                errors.append(('UPSTREAM_ADMISSION_REVIEW_COMPONENT_MUTATED', f'{name}:{spec.get("release")}:{constraint}'))
            if ((spec.get('source') or {}).get('resolved')):
                errors.append(('UPSTREAM_ADMISSION_RESOLVED_COMPONENT_PRESENT', name))

    # Current blueprints must reference the current catalog and include their enabled dependencies.
    blueprint_files = sorted((root/'blueprints').glob('*.json'))
    if not blueprint_files:
        errors.append(('BLUEPRINT_SET_EMPTY','blueprints'))
    for p in blueprint_files:
        obj = load_json(p, errors)
        if not isinstance(obj, dict):
            continue
        if obj.get('apiVersion') != 'platform.4so.io/v1alpha1' or obj.get('kind') != 'PlatformBlueprint':
            errors.append(('BLUEPRINT_TYPE_INVALID',p.name)); continue
        rows = (obj.get('spec') or {}).get('components') or []
        names = [str(row.get('name') or '') for row in rows if row.get('enabled', True)]
        if len(names) != len(set(names)):
            errors.append(('BLUEPRINT_DUPLICATE_COMPONENT',p.name))
        enabled = set(names)
        exclusive: dict[str,str] = {}
        for name in enabled:
            if name not in components:
                errors.append(('BLUEPRINT_UNKNOWN_COMPONENT', f'{p.name}:{name}')); continue
            spec = components[name].get('spec') or {}
            for dep in spec.get('dependencies') or []:
                if dep not in enabled:
                    errors.append(('BLUEPRINT_DEPENDENCY_MISSING', f'{p.name}:{name}->{dep}'))
            for cap in spec.get('exclusiveCapabilities') or []:
                if cap in exclusive and exclusive[cap] != name:
                    errors.append(('BLUEPRINT_EXCLUSIVE_CAPABILITY_CONFLICT', f'{p.name}:{cap}:{exclusive[cap]},{name}'))
                exclusive[cap] = name

    # Tenant/policy machine data.
    plans_path = root/'catalog/tenancy/plans.json'
    plans = load_json(plans_path, errors) if plans_path.exists() else None
    if not isinstance(plans, dict) or plans.get('kind') != 'TenantPlanCatalog':
        errors.append(('TENANT_PLAN_CATALOG_INVALID', str(plans_path.relative_to(root))))
        plan_count = 0
    else:
        plan_rows = (plans.get('spec') or {}).get('plans') or []
        plan_count = len(plan_rows)
        if not plan_rows or len({row.get('name') for row in plan_rows}) != len(plan_rows):
            errors.append(('TENANT_PLAN_SET_INVALID','catalog/tenancy/plans.json'))
    policy_files = sorted((root/'catalog/policies').glob('*.yaml'))
    if not policy_files:
        errors.append(('POLICY_TEMPLATE_SET_EMPTY','catalog/policies'))

    # Migration filenames form one monotonic, gap-free schema sequence.
    migration_files = sorted((root/'migrations').glob('[0-9][0-9][0-9][0-9]_*.sql'))
    nums = [int(p.name[:4]) for p in migration_files]
    if not nums or nums != list(range(1, max(nums)+1)):
        errors.append(('MIGRATION_SEQUENCE_INVALID', str(nums)))

    if errors:
        print('REPOSITORY_VALIDATION_FAIL')
        for code, detail in sorted(errors):
            print(code, detail)
        print('ERROR_COUNT', len(errors))
        return 1
    print('BRAND_INDEPENDENCE_GATE_PASS')
    print('CATALOG_CONTRACT_GATE_PASS', len(components))
    print('BLUEPRINT_CONTRACT_GATE_PASS', len(blueprint_files))
    print('SCHEMA_PARSE_GATE_PASS', len(schema_files))
    print('TENANT_PLAN_GATE_PASS', plan_count)
    print('POLICY_TEMPLATE_GATE_PASS', len(policy_files))
    print('SUPPLY_CHAIN_DIGEST_GATE_PASS', sum(1 for o in components.values() if (o.get('spec') or {}).get('source',{}).get('resolved') is True))
    print('SECRET_AND_PLACEHOLDER_GATE_PASS')
    print('REPOSITORY_VALIDATION_PASS', len(files))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
