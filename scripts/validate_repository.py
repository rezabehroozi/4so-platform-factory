#!/usr/bin/env python3
"""Validate current repository/package invariants without historical prose gates."""
from __future__ import annotations

from pathlib import Path
try:
    import distribution_transport as transport
except ModuleNotFoundError:
    from scripts import distribution_transport as transport
import argparse
import ast
import hashlib
import ipaddress
import json
import re
import stat
import sys
import tarfile
import urllib.parse

from management_workload_evidence import external_receipt_evidence, manifest_receipt_evidence, product_receipt_evidence
from seal_management_workload_oci_archive import verify_structure as verify_management_workload_archive_receipt_structure
from runtime_evidence_registry import verify_all as verify_runtime_evidence_registry

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
    def reject_duplicate_keys(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate JSON key {key!r}")
            value[key] = item
        return value
    try:
        return json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=reject_duplicate_keys)
    except Exception as exc:
        errors.append(('JSON_PARSE', f'{path}: {exc}'))
        return None


def validate_release_documentation_truth(root: Path, version: str, release_name: str, errors: list[tuple[str, str]]) -> tuple[str, Path | None]:
    """Bind executable roadmap authority to one canonical current status document.

    Versioned PHASE_STATUS files are historical records only. Current truth is the
    executable roadmap plus docs/PROGRAM_STATUS.md and README; Git/CHANGELOG retain
    history without forcing one new status artifact per roadmap revision.
    """
    program_path = root / 'internal/targetmodel/program.go'
    if not program_path.is_file():
        errors.append(('PROGRAM_AUTHORITY_SOURCE_MISSING', 'internal/targetmodel/program.go'))
        return '', None
    program_text = program_path.read_text(encoding='utf-8', errors='strict')
    match = re.search(r'ProgramAuthorityMethod\s*=\s*"(PROGRAM_PHASE_MODEL_V([0-9]+))"', program_text)
    if not match:
        errors.append(('PROGRAM_AUTHORITY_UNREADABLE', 'internal/targetmodel/program.go'))
        return '', None
    authority = match.group(1)
    status_path = root / 'docs' / 'PROGRAM_STATUS.md'
    if not status_path.is_file():
        errors.append(('CURRENT_PROGRAM_STATUS_MISSING', str(status_path.relative_to(root))))
        return authority, status_path
    status_text = status_path.read_text(encoding='utf-8', errors='strict')
    if authority not in status_text:
        errors.append(('CURRENT_PROGRAM_STATUS_AUTHORITY_MISMATCH', authority))
    if f'Release **{version}**' not in status_text:
        errors.append(('CURRENT_PROGRAM_STATUS_VERSION_MISMATCH', version))

    readme_path = root / 'README.md'
    changelog_path = root / 'CHANGELOG.md'
    if not readme_path.is_file():
        errors.append(('CURRENT_README_MISSING', 'README.md'))
    else:
        readme = readme_path.read_text(encoding='utf-8', errors='strict')
        if authority not in readme:
            errors.append(('CURRENT_README_AUTHORITY_MISMATCH', authority))
        if 'docs/PROGRAM_STATUS.md' not in readme:
            errors.append(('CURRENT_README_PROGRAM_STATUS_LINK_MISSING', 'docs/PROGRAM_STATUS.md'))

    if not changelog_path.is_file():
        errors.append(('CURRENT_CHANGELOG_MISSING', 'CHANGELOG.md'))
    else:
        changelog = changelog_path.read_text(encoding='utf-8', errors='strict')
        headings = re.findall(r'(?m)^## ([0-9]+\.[0-9]+\.[0-9]+)(?:\s|$)', changelog)
        if not headings or headings[0] != version:
            errors.append(('CURRENT_CHANGELOG_TOP_VERSION_MISMATCH', headings[0] if headings else '<missing>'))
        if headings.count(version) != 1:
            errors.append(('CURRENT_CHANGELOG_VERSION_COUNT_INVALID', f'{version}:{headings.count(version)}'))

    if not release_name:
        errors.append(('RELEASE_NAME_EMPTY', 'RELEASE-NAME'))
    return authority, status_path

def public_https_source_url(value: object) -> bool:
    if not isinstance(value, str):
        return False
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        return False
    host = parsed.hostname.rstrip('.')
    if not host or host.lower() == 'localhost' or host.lower().endswith('.localhost'):
        return False
    try:
        address = ipaddress.ip_address(host.split('%', 1)[0])
    except ValueError:
        return True
    return address.is_global


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
        render_file = bundle_dir / 'render-manifest.json'
        if render_file.is_file() and render_file.stat().st_size == 0:
            holds_path = root / 'catalog/component-runtime-certification.json'
            holds_doc = load_json(holds_path, errors) if holds_path.is_file() else {}
            holds = ((holds_doc or {}).get('spec') or {}).get('runtimeSuitabilityHolds') or []
            explicit_hold = any(isinstance(h, dict) and h.get('component') == name and h.get('status') in {'review-required','dependency-transition-required'} for h in holds)
            exact_normalized_runtime = False
            if name == 'kyverno':
                evidence_path = root / 'lab/rke2-kyverno-runtime-evidence.json'
                evidence = load_json(evidence_path, errors) if evidence_path.is_file() else {}
                exact_normalized_runtime = (
                    isinstance(evidence, dict)
                    and evidence.get('authority') == 'RKE2_KYVERNO_RUNTIME_CERTIFICATION_V1'
                    and evidence.get('kyvernoRelease') == '3.8.2'
                    and evidence.get('normalizationAuthority') == 'KYVERNO_3_8_2_GITOPS_CRD_NORMALIZATION_V1'
                    and evidence.get('normalizedCRDCount') == 11
                    and evidence.get('rke2Certified') is True
                    and evidence.get('secondApplyConverged') is True
                    and evidence.get('runtimeHoldReleaseEligible') is True
                    and evidence.get('productTopologyHACertified') is False
                    and evidence.get('physicalCertified') is False
                )
            if not explicit_hold and not exact_normalized_runtime:
                errors.append(('RESOLVED_SOURCE_RENDER_EMPTY_WITHOUT_RUNTIME_HOLD', name))
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




def validate_persian_writing_integration(root: Path, errors: list[tuple[str,str]]) -> int:
    """Validate the pinned offline Persian writing dependency and live product-copy gate."""
    upstream_path = root/'third_party/persian-writing/UPSTREAM.json'
    admission_path = root/'dependencies/persian-writing-admission.json'
    gate_path = root/'scripts/persian_writing_gate.py'
    required = [upstream_path, admission_path, gate_path, root/'third_party/persian-writing/LICENSE', root/'third_party/persian-writing/SKILL.md']
    for path in required:
        if not path.is_file():
            errors.append(('PERSIAN_WRITING_INTEGRATION_FILE_MISSING', str(path.relative_to(root))))
    if any(not path.is_file() for path in required):
        return 0
    upstream = load_json(upstream_path, errors)
    admission = load_json(admission_path, errors)
    expected_commit='118c2167f30cafe18df13c0ba85f98f50dad1894'
    expected_tree='9fd2300bfee50ac7cc666a2e8cbffc47a71e8857'
    if not isinstance(upstream,dict) or upstream.get('version')!='1.3.5' or upstream.get('commit')!=expected_commit or upstream.get('tree')!=expected_tree or upstream.get('runtimeNetworkDependency') is not False:
        errors.append(('PERSIAN_WRITING_UPSTREAM_PIN_INVALID', str(upstream)))
        return 0
    if not isinstance(admission,dict) or admission.get('component')!='persian-writing' or admission.get('version')!='1.3.5' or admission.get('commit')!=expected_commit or admission.get('gateAuthority')!='PERSIAN_WRITING_GATE_V1' or admission.get('runtimeNetworkDependency') is not False or admission.get('binaryFontsRedistributed') is not False or admission.get('largeLexiconRedistributed') is not False:
        errors.append(('PERSIAN_WRITING_ADMISSION_INVALID', str(admission)))
    digests=upstream.get('fileDigests') or {}
    if not isinstance(digests,dict) or not digests:
        errors.append(('PERSIAN_WRITING_VENDOR_DIGESTS_MISSING','UPSTREAM.json'))
    else:
        for rel,want in digests.items():
            path=root/'third_party/persian-writing'/rel
            if not path.is_file():
                errors.append(('PERSIAN_WRITING_VENDOR_FILE_MISSING',rel)); continue
            got=sha256(path)
            if got!=want:
                errors.append(('PERSIAN_WRITING_VENDOR_DIGEST_DRIFT',f'{rel}:{got}!={want}'))
        if (admission.get('curatedFileDigests') or {}) != digests:
            errors.append(('PERSIAN_WRITING_ADMISSION_DIGEST_DRIFT','dependencies/persian-writing-admission.json'))
    if (root/'third_party/persian-writing/assets/fonts').exists():
        errors.append(('PERSIAN_WRITING_FONT_BINARY_FORBIDDEN','third_party/persian-writing/assets/fonts'))
    if (root/'third_party/persian-writing/assets/persian_words.txt').exists():
        errors.append(('PERSIAN_WRITING_LARGE_LEXICON_FORBIDDEN','third_party/persian-writing/assets/persian_words.txt'))
    import importlib.util
    spec=importlib.util.spec_from_file_location('fourso_persian_writing_gate',gate_path)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    report=module.build_report(root)
    if not report.get('complete') or report.get('issueCount')!=0:
        errors.append(('PERSIAN_WRITING_GATE_FAILED',json.dumps((report.get('issues') or [])[:5],ensure_ascii=False)))
    report_path = root/'webconsole/persian_writing_report.json'
    if (root/'webconsole/static/app.js').is_file():
        if not report_path.is_file():
            errors.append(('PERSIAN_WRITING_REPORT_MISSING', str(report_path.relative_to(root))))
        else:
            committed = load_json(report_path, errors)
            if isinstance(committed, dict):
                drift = sorted(k for k in set(committed) | set(report) if committed.get(k) != report.get(k))
                if drift:
                    errors.append(('PERSIAN_WRITING_REPORT_STALE', f'{report_path.relative_to(root)}: {", ".join(drift[:8])}'))
    return int(report.get('uniquePersianStrings') or 0)

def validate_mcp_route_parity(root: Path, errors: list[tuple[str,str]]) -> int:
    """Validate 100% route disposition plus durable semantics for every AI mutation."""
    registry_path = root/'internal/api/mcp_route_parity_registry.json'
    server_path = root/'internal/api/server.go'
    if not registry_path.is_file() or not server_path.is_file():
        errors.append(('MCP_ROUTE_PARITY_FILES_MISSING', 'internal/api'))
        return 0
    registry = load_json(registry_path, errors)
    if not isinstance(registry, dict) or registry.get('authority') != 'MCP_ROUTE_PARITY_AUTHORITY_V1':
        errors.append(('MCP_ROUTE_PARITY_INVALID', str(registry_path.relative_to(root))))
        return 0
    route_re = re.compile(r'HandleFunc\("(GET|POST|PUT|PATCH|DELETE) (/api/v1/[^\"]+)"')
    runtime_routes = route_re.findall(server_path.read_text())
    rows = registry.get('routes') or []
    if registry.get('routeCount') != len(runtime_routes) or len(rows) != len(runtime_routes):
        errors.append(('MCP_ROUTE_PARITY_COUNT_DRIFT', f'registry={registry.get("routeCount")}/{len(rows)} runtime={len(runtime_routes)}'))
    runtime_set = set(runtime_routes)
    seen: set[tuple[str,str]] = set()
    tool_names: set[str] = set()
    allowed = {'tool-read','tool-operate','tool-admin','security-excluded'}
    mutation_count = 0
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            errors.append(('MCP_ROUTE_PARITY_ROW_INVALID', str(index))); continue
        key=(str(row.get('method') or ''),str(row.get('path') or ''))
        if key in seen:
            errors.append(('MCP_ROUTE_PARITY_DUPLICATE_ROUTE', f'{key[0]} {key[1]}'))
        seen.add(key)
        if key not in runtime_set:
            errors.append(('MCP_ROUTE_PARITY_EXTRA_ROUTE', f'{key[0]} {key[1]}'))
        disposition=str(row.get('disposition') or '')
        if disposition not in allowed:
            errors.append(('MCP_ROUTE_PARITY_DISPOSITION_INVALID', f'{key}:{disposition}'))
        tool=str(row.get('toolName') or '')
        if disposition == 'security-excluded':
            if tool:
                errors.append(('MCP_ROUTE_PARITY_EXCLUDED_TOOL_CONFLICT', f'{key}:{tool}'))
            if not str(row.get('exclusionReason') or '').strip():
                errors.append(('MCP_ROUTE_PARITY_EXCLUSION_RATIONALE_MISSING', f'{key[0]} {key[1]}'))
            continue
        if not tool or tool in tool_names:
            errors.append(('MCP_ROUTE_PARITY_TOOL_IDENTITY_INVALID', f'{key}:{tool}'))
        tool_names.add(tool)
        if disposition in {'tool-operate','tool-admin'}:
            mutation_count += 1
            if row.get('durableJob') is not True or row.get('idempotencyRequired') is not True:
                errors.append(('MCP_ROUTE_PARITY_DURABLE_MUTATION_MISSING', f'{key[0]} {key[1]}'))
        elif row.get('durableJob') is True:
            if disposition != 'tool-read' or key[0] != 'POST' or row.get('idempotencyRequired') is not True:
                errors.append(('MCP_ROUTE_PARITY_DURABLE_READ_INVALID', f'{key[0]} {key[1]}'))
        elif row.get('idempotencyRequired') is True:
            errors.append(('MCP_ROUTE_PARITY_IDEMPOTENCY_WITHOUT_DURABILITY', f'{key[0]} {key[1]}'))
    for key in sorted(runtime_set-seen):
        errors.append(('MCP_ROUTE_PARITY_COVERAGE_MISSING', f'{key[0]} {key[1]}'))
    for row in rows:
        if not isinstance(row, dict): continue
        path=str(row.get('path') or '')
        method=str(row.get('method') or '')
        if method != 'GET' and (path.startswith('/api/v1/mcp/trusted-clients') or path.startswith('/api/v1/mcp/delegation-grants')) and row.get('disposition') != 'security-excluded':
            errors.append(('MCP_SELF_DELEGATION_EXCLUSION_MISSING', f'{method} {path}'))
    counts = registry.get('counts') or {}
    expected_counts = {name:sum(1 for r in rows if isinstance(r,dict) and r.get('disposition')==name) for name in allowed}
    for name,count in expected_counts.items():
        if int(counts.get(name,0)) != count:
            errors.append(('MCP_ROUTE_PARITY_SUMMARY_DRIFT', f'{name}:registry={counts.get(name)} actual={count}'))
    if mutation_count != expected_counts['tool-operate'] + expected_counts['tool-admin']:
        errors.append(('MCP_ROUTE_PARITY_MUTATION_SUMMARY_INVALID', str(mutation_count)))
    return len(runtime_routes)


def validate_mcp_action_registry(root: Path, errors: list[tuple[str,str]]) -> int:
    registry_path = root/'internal/api/mcp_action_registry.json'
    route_registry_path = root/'internal/api/mcp_route_parity_registry.json'
    if not registry_path.is_file() or not route_registry_path.is_file():
        errors.append(('MCP_ACTION_REGISTRY_FILES_MISSING', 'internal/api'))
        return 0
    registry = load_json(registry_path, errors)
    route_registry = load_json(route_registry_path, errors)
    if not isinstance(registry, dict) or registry.get('kind') != 'MCPProductActionRegistry' or registry.get('authority') != 'MCP_PRODUCT_ACTION_REGISTRY_V1':
        errors.append(('MCP_ACTION_REGISTRY_INVALID', str(registry_path.relative_to(root))))
        return 0
    policy = (registry.get('spec') or {}).get('policy') or {}
    if policy.get('genericMutationToolAllowed') is not False or policy.get('rawShellSSHSQLSecretsAllowed') is not False or policy.get('selfDelegationMutationAllowed') is not False or policy.get('pendingParityFailsC7W') is not True or policy.get('securityExclusionRequiresRationale') is not True or policy.get('routeParityAuthority') != 'MCP_ROUTE_PARITY_AUTHORITY_V1' or policy.get('durableMutationAuthority') != 'MCP_DURABLE_CONTROL_JOB_AUTHORITY_V1':
        errors.append(('MCP_ACTION_REGISTRY_POLICY_INVALID', str(policy)))
    route_rows=(route_registry or {}).get('routes') or []
    by_family: dict[str,list[dict]] = {}
    for row in route_rows:
        if isinstance(row,dict): by_family.setdefault(str(row.get('family') or ''),[]).append(row)
    rows=(registry.get('spec') or {}).get('families') or []
    if not isinstance(rows,list):
        errors.append(('MCP_ACTION_REGISTRY_FAMILIES_INVALID','families must be an array')); return 0
    seen:set[str]=set()
    for index,item in enumerate(rows):
        if not isinstance(item,dict): errors.append(('MCP_ACTION_REGISTRY_ROW_INVALID',str(index))); continue
        family=str(item.get('family') or '').strip()
        if not family or family in seen: errors.append(('MCP_ACTION_REGISTRY_FAMILY_IDENTITY_INVALID',family or f'<row-{index}>')); continue
        seen.add(family)
        actual=by_family.get(family)
        if actual is None: errors.append(('MCP_ACTION_REGISTRY_EXTRA_FAMILY',family)); continue
        callable_rows=[r for r in actual if r.get('disposition')!='security-excluded']
        excluded=[r for r in actual if r.get('disposition')=='security-excluded']
        mutation_count=sum(1 for r in actual if r.get('method')!='GET')
        expected_disposition='typed-tool-complete' if callable_rows else 'security-excluded'
        expected_tools=[str(r.get('toolName') or '') for r in callable_rows]
        if item.get('routeCount')!=len(actual) or item.get('mutationCount')!=mutation_count or item.get('callableRouteCount')!=len(callable_rows) or item.get('securityExcludedRouteCount')!=len(excluded):
            errors.append(('MCP_ACTION_REGISTRY_ROUTE_DRIFT',f'{family}:registry={item.get("routeCount")}/{item.get("mutationCount")}/{item.get("callableRouteCount")}/{item.get("securityExcludedRouteCount")} runtime={len(actual)}/{mutation_count}/{len(callable_rows)}/{len(excluded)}'))
        if item.get('disposition')!=expected_disposition:
            errors.append(('MCP_ACTION_REGISTRY_DISPOSITION_INVALID',f'{family}:{item.get("disposition")} expected={expected_disposition}'))
        if item.get('toolNames')!=expected_tools:
            errors.append(('MCP_ACTION_REGISTRY_TOOLS_DRIFT',family))
        if not str(item.get('rationale') or '').strip():
            errors.append(('MCP_ACTION_REGISTRY_RATIONALE_MISSING',family))
    for family in sorted(set(by_family)-seen): errors.append(('MCP_ACTION_REGISTRY_COVERAGE_MISSING',family))
    return len(by_family)


def validate_product_api_contract(root: Path, errors: list[tuple[str,str]], expected_route_count: int) -> int:
    contract_path = root/'sdk/product-api-contract.json'
    go_path = root/'sdk/go/routes_gen.go'
    server_path = root/'internal/api/server.go'
    if not contract_path.is_file() or not go_path.is_file() or not server_path.is_file():
        errors.append(('PRODUCT_API_CONTRACT_FILES_MISSING','sdk/product-api-contract.json;sdk/go/routes_gen.go'))
        return 0
    contract = load_json(contract_path, errors)
    if not isinstance(contract,dict) or contract.get('authority')!='PRODUCT_API_CONTRACT_AUTHORITY_V1' or contract.get('source')!='internal/api/server.go':
        errors.append(('PRODUCT_API_CONTRACT_INVALID',str(contract_path.relative_to(root))))
        return 0
    version=(root/'VERSION').read_text().strip() if (root/'VERSION').is_file() else ''
    if contract.get('version')!=version:
        errors.append(('PRODUCT_API_CONTRACT_VERSION_DRIFT',f'{contract.get("version")} != {version}'))
    rows=contract.get('routes') or []
    runtime_routes=re.findall(r'HandleFunc\("(GET|POST|PUT|PATCH|DELETE) (/api/v1/[^\"]+)"',server_path.read_text())
    keys=[(str(r.get('method') or ''),str(r.get('path') or '')) for r in rows if isinstance(r,dict)]
    if contract.get('routeCount')!=len(rows) or len(rows)!=len(runtime_routes) or len(rows)!=expected_route_count or set(keys)!=set(runtime_routes):
        errors.append(('PRODUCT_API_CONTRACT_ROUTE_DRIFT',f'contract={contract.get("routeCount")}/{len(rows)} runtime={len(runtime_routes)} parity={expected_route_count}'))
    canonical=json.dumps(rows,separators=(',',':'),sort_keys=True).encode()
    digest='sha256:'+hashlib.sha256(canonical).hexdigest()
    if contract.get('routeDigest')!=digest:
        errors.append(('PRODUCT_API_CONTRACT_DIGEST_DRIFT',f'{contract.get("routeDigest")} != {digest}'))
    scope_registry=load_json(root/'internal/api/resource_scope_registry.json',errors) if (root/'internal/api/resource_scope_registry.json').is_file() else None
    scope_by_family={str(row.get('family') or ''):(str(row.get('scope') or ''),str(row.get('status') or '')) for row in ((scope_registry or {}).get('families') or []) if isinstance(row,dict)}
    for row in rows:
        if not isinstance(row,dict): continue
        family=str(row.get('family') or '')
        expected_scope,expected_status=scope_by_family.get(family,('UNCLASSIFIED','OWNER_REVIEW_REQUIRED'))
        if row.get('resourceScope')!=expected_scope or row.get('resourceScopeStatus')!=expected_status:
            errors.append(('PRODUCT_API_RESOURCE_SCOPE_DRIFT',f'{row.get("method")} {row.get("path")}:{row.get("resourceScope")}/{row.get("resourceScopeStatus")} expected={expected_scope}/{expected_status}'))
    policy=contract.get('policy') or {}
    required_false=('approvalBypassAllowed','automaticMutationRetryAllowed','businessLogicInGeneratedClientAllowed','rawCredentialEmbeddingAllowed')
    if any(policy.get(k) is not False for k in required_false) or policy.get('durableOperationAuthorityRemainsServerSide') is not True:
        errors.append(('PRODUCT_API_CONTRACT_POLICY_INVALID',str(policy)))
    go=go_path.read_text()
    for marker in ('Code generated by scripts/generate_product_api_contract.py; DO NOT EDIT.','ProductAPIContractAuthority = "PRODUCT_API_CONTRACT_AUTHORITY_V1"',f'ProductAPIContractDigest = "{digest}"',f'ProductAPIRouteCount = {len(rows)}','ResourceScope:','ResourceScopeStatus:'):
        if marker not in go:
            errors.append(('PRODUCT_API_GO_CATALOG_DRIFT',marker))
    return len(rows)


def validate_resource_scope_registry(root: Path, errors: list[tuple[str,str]]) -> tuple[int,int]:
    registry_path=root/'internal/api/resource_scope_registry.json'
    classifications_path=root/'internal/api/resource_scope_owner_classifications.json'
    parity_path=root/'internal/api/mcp_route_parity_registry.json'
    if not registry_path.is_file() or not classifications_path.is_file() or not parity_path.is_file():
        errors.append(('RESOURCE_SCOPE_REGISTRY_FILES_MISSING','internal/api/resource_scope_registry.json'))
        return 0,0
    registry=load_json(registry_path,errors); classifications=load_json(classifications_path,errors); parity=load_json(parity_path,errors)
    if not isinstance(registry,dict) or registry.get('authority')!='RESOURCE_SCOPE_REGISTRY_V1':
        errors.append(('RESOURCE_SCOPE_REGISTRY_INVALID', str(registry_path.relative_to(root))))
        return 0, 0
    if not isinstance(classifications,dict) or classifications.get('authority')!='RESOURCE_SCOPE_OWNER_CLASSIFICATIONS_V1':
        errors.append(('RESOURCE_SCOPE_CLASSIFICATIONS_INVALID', str(classifications_path.relative_to(root))))
        return 0, 0
    policy=classifications.get('policy') or {}
    if policy.get('inferenceAllowed') is not False or policy.get('defaultScope')!='UNCLASSIFIED' or policy.get('ownerReviewRequiredWhenMissing') is not True:
        errors.append(('RESOURCE_SCOPE_INFERENCE_POLICY_INVALID',str(policy)))
    expected=sorted({str(r.get('family') or '') for r in ((parity or {}).get('routes') or []) if isinstance(r,dict)})
    rows=registry.get('families') or []
    if registry.get('familyCount')!=len(rows) or [r.get('family') for r in rows if isinstance(r,dict)]!=expected:
        errors.append(('RESOURCE_SCOPE_REGISTRY_COVERAGE_DRIFT',f'registry={registry.get("familyCount")}/{len(rows)} expected={len(expected)}'))
    configured=classifications.get('families') or {}
    allowed={'PLATFORM_SCOPED','ORGANIZATION_SCOPED','PROJECT_SCOPED','DYNAMIC_SCOPED'}
    classified=0
    for row in rows:
        if not isinstance(row,dict): errors.append(('RESOURCE_SCOPE_ROW_INVALID',str(row))); continue
        family=str(row.get('family') or '')
        cfg=configured.get(family)
        if cfg is None:
            if row.get('status')!='OWNER_REVIEW_REQUIRED' or row.get('scope')!='UNCLASSIFIED' or row.get('evidence')!='':
                errors.append(('RESOURCE_SCOPE_UNREVIEWED_WAS_INFERRED',family))
            continue
        classified += 1
        if row.get('status')!='OWNER_CLASSIFIED' or row.get('scope') not in allowed or row.get('scope')!=cfg.get('scope') or not str(row.get('evidence') or '').strip() or row.get('evidence')!=cfg.get('evidence'):
            errors.append(('RESOURCE_SCOPE_CLASSIFICATION_DRIFT',family))
        evidence=str(cfg.get('evidence') or '')
        evidence_paths=re.findall(r'(?:internal|scripts|sdk|webconsole|migrations)/[A-Za-z0-9_./-]+\.(?:go|py|json|sql|js|html)',evidence)
        if not evidence_paths or not any((root/path).is_file() for path in evidence_paths):
            errors.append(('RESOURCE_SCOPE_EVIDENCE_SOURCE_MISSING',f'{family}:{evidence_paths}'))
    scope_by_family={str(row.get('family') or ''):(str(row.get('scope') or ''),str(row.get('status') or '')) for row in rows if isinstance(row,dict)}
    for route in ((parity or {}).get('routes') or []):
        if not isinstance(route,dict): continue
        family=str(route.get('family') or '')
        expected_scope, expected_status=scope_by_family.get(family,('UNCLASSIFIED','OWNER_REVIEW_REQUIRED'))
        if route.get('resourceScope')!=expected_scope or route.get('resourceScopeStatus')!=expected_status:
            errors.append(('RESOURCE_SCOPE_MCP_CONSUMER_DRIFT',f'{route.get("method")} {route.get("path")}:{route.get("resourceScope")}/{route.get("resourceScopeStatus")} expected={expected_scope}/{expected_status}'))
    if registry.get('classifiedCount')!=classified or registry.get('ownerReviewRequiredCount')!=len(rows)-classified:
        errors.append(('RESOURCE_SCOPE_SUMMARY_DRIFT',f'{registry.get("classifiedCount")}/{registry.get("ownerReviewRequiredCount")} actual={classified}/{len(rows)-classified}'))
    for family in ('projects','workspaces','provider-profiles','provider-clusters','finops','ai'):
        if family not in configured:
            errors.append(('RESOURCE_SCOPE_HIGH_IMPACT_OWNER_MISSING',family))
    return len(rows),classified

def repository_source_files(root: Path, errors: list[tuple[str,str]]) -> list[Path]:
    ignored = {'.git','bin','dist','release','__pycache__','.pytest_cache','.state','.tmpbin','.ruff_cache','.mypy_cache','.pyright-cache','.tox'}
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
    return files


def validate_repository_hygiene(root: Path, files: list[Path], errors: list[tuple[str,str]]) -> None:
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


def validate_release_recipes(root: Path, errors: list[tuple[str,str]]) -> None:
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
        if dockerfile.name == 'Dockerfile.maintenance' and 'ARG MAINTENANCE_RUNTIME_IMAGE' not in docker:
            errors.append(('CONTAINER_DIGEST_INPUTS_MISSING', rel))
        if dockerfile.name in {'Dockerfile','Dockerfile.agent','Dockerfile.probe'}:
            if 'internal/buildinfo.Version=$VERSION' not in docker:
                errors.append(('CONTAINER_BINARY_VERSION_INJECTION_MISSING', rel))
            source_regex="grep -Eq '^[0-9a-f]{40}$'"
            source_ldflag='internal/buildinfo.SourceCommit=$SOURCE_COMMIT'
            from_rows=[line.strip() for line in docker.splitlines() if line.strip().startswith('FROM ')]
            if ('ARG SOURCE_COMMIT' not in docker or docker.count(source_regex)!=1 or docker.count(source_ldflag)!=1 or len(from_rows)!=2 or from_rows[0]!='FROM ${GO_BUILD_IMAGE} AS build' or from_rows[1]!='FROM ${RUNTIME_IMAGE}'):
                errors.append(('CONTAINER_BINARY_SOURCE_COMMIT_INJECTION_MISSING', rel))
        for line in docker.splitlines():
            row = line.strip()
            if row.startswith('FROM ') and '${' not in row and '@sha256:' not in row:
                errors.append(('MUTABLE_CONTAINER_BASE', f'{rel}:{row}'))
    release_recipes = {
        'deploy/images/Dockerfile.api-release': ('ARG RUNTIME_IMAGE', 'ARG SOURCE_RELEASE_DIGEST', 'platform.4so.io/product-role=\"platform-api\"', 'platform.4so.io/source-release-digest=\"${SOURCE_RELEASE_DIGEST}\"', 'COPY bin/linux-amd64/platform-api /platform-api', 'USER 65532:65532'),
        'deploy/images/Dockerfile.agent-release': ('ARG RUNTIME_IMAGE', 'ARG SOURCE_RELEASE_DIGEST', 'platform.4so.io/product-role=\"platform-agent\"', 'platform.4so.io/source-release-digest=\"${SOURCE_RELEASE_DIGEST}\"', 'COPY bin/linux-amd64/platform-agent /platform-agent', 'USER 65532:65532'),
        'deploy/images/Dockerfile.probe-release': ('ARG RUNTIME_IMAGE', 'ARG SOURCE_RELEASE_DIGEST', 'platform.4so.io/product-role=\"platform-probe\"', 'platform.4so.io/source-release-digest=\"${SOURCE_RELEASE_DIGEST}\"', 'COPY bin/linux-amd64/platform-probe /platform-probe', 'USER 65532:65532'),
    }
    api_base_recipe = root/'deploy/images/Dockerfile.api-runtime-base'
    if not api_base_recipe.is_file():
        errors.append(('MANAGEMENT_WORKLOAD_API_BASE_RECIPE_MISSING', 'deploy/images/Dockerfile.api-runtime-base'))
    else:
        api_base_text = api_base_recipe.read_text()
        for token in ('ARG CA_RUNTIME_IMAGE','ARG POSTGRES_RUNTIME_IMAGE','FROM ${CA_RUNTIME_IMAGE} AS ca','FROM ${POSTGRES_RUNTIME_IMAGE}','COPY --from=ca /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt','USER 65532:65532'):
            if token not in api_base_text:
                errors.append(('MANAGEMENT_WORKLOAD_API_BASE_RECIPE_INVALID', f'deploy/images/Dockerfile.api-runtime-base:{token}'))
        if any(token in api_base_text.lower() for token in ('apk add','apt-get','apt install','dnf install','yum install','curl http','wget http')):
            errors.append(('MANAGEMENT_WORKLOAD_API_BASE_NETWORK_BUILD_FORBIDDEN','deploy/images/Dockerfile.api-runtime-base'))

    maintenance_recipe = root/'deploy/images/Dockerfile.maintenance'
    if not maintenance_recipe.is_file():
        errors.append(('MANAGEMENT_WORKLOAD_RELEASE_RECIPE_MISSING', 'deploy/images/Dockerfile.maintenance'))
    else:
        maintenance_text = maintenance_recipe.read_text()
        for token in ('ARG MAINTENANCE_RUNTIME_IMAGE','ARG SOURCE_RELEASE_DIGEST','platform.4so.io/product-role=\"maintenance\"','platform.4so.io/source-release-digest=\"${SOURCE_RELEASE_DIGEST}\"','USER 65532:65532','ENTRYPOINT [\"/bin/sh\"]'):
            if token not in maintenance_text:
                errors.append(('MANAGEMENT_WORKLOAD_RELEASE_RECIPE_INVALID', f'deploy/images/Dockerfile.maintenance:{token}'))
        if any(token in maintenance_text.lower() for token in ('apk add','apt-get','apt install','dnf install','yum install','curl http','wget http')):
            errors.append(('MANAGEMENT_WORKLOAD_MAINTENANCE_NETWORK_BUILD_FORBIDDEN','deploy/images/Dockerfile.maintenance'))

    for rel, required in release_recipes.items():
        recipe = root/rel
        if not recipe.is_file():
            errors.append(('MANAGEMENT_WORKLOAD_RELEASE_RECIPE_MISSING', rel))
            continue
        text = recipe.read_text()
        for token in required:
            if token not in text:
                errors.append(('MANAGEMENT_WORKLOAD_RELEASE_RECIPE_INVALID', f'{rel}:{token}'))

    dockerignore = root/'.dockerignore'
    ignore_text = dockerignore.read_text() if dockerignore.is_file() else ''
    for token in ('!bin/linux-amd64/platform-api','!bin/linux-amd64/platform-agent','!bin/linux-amd64/platform-probe'):
        if token not in ignore_text:
            errors.append(('MANAGEMENT_WORKLOAD_RELEASE_BINARY_CONTEXT_INVALID', token))

# Remaining validator functions intentionally preserved from the canonical blob.
# This write must be rejected by diff-gate unless GitHub compare proves only the
# stale C7W WINDOWS_LOCAL_EXECUTION_CONTRACTS entry was removed.
