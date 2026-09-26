#!/usr/bin/env python3
"""Validate current repository/package invariants without historical prose gates."""
from __future__ import annotations

from pathlib import Path
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
from seal_management_workload_oci_archive import verify as verify_management_workload_archive_receipt

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
            if not explicit_hold:
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
    # Import the product-owned gate in-process so repository validation cannot pass
    # when Persian copy is mechanically clean but violates the pinned register/style contract.
    import importlib.util
    spec=importlib.util.spec_from_file_location('fourso_persian_writing_gate',gate_path)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    report=module.build_report(root)
    if not report.get('complete') or report.get('issueCount')!=0:
        errors.append(('PERSIAN_WRITING_GATE_FAILED',json.dumps((report.get('issues') or [])[:5],ensure_ascii=False)))
    # The report is a checked-in derived artifact that ships in the release manifest, and
    # `make persian-ui-lint` rewrites it without failing, so nothing else notices when copy
    # changes and the committed statistics keep describing the previous tree.
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
            errors.append(('MCP_ROUTE_PARITY_READ_DURABLE_JOB_UNEXPECTED', f'{key[0]} {key[1]}'))
    for key in sorted(runtime_set-seen):
        errors.append(('MCP_ROUTE_PARITY_COVERAGE_MISSING', f'{key[0]} {key[1]}'))
    # MCP self-management may be readable, but every mutation that changes MCP
    # client/delegation authority must remain explicitly excluded.
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
    """Fail closed when the family summary drifts from route-parity authority."""
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
    """Collect every tracked source file, rejecting symlinks, special files and stale durable temporaries."""
    # Derived tool caches are not repository content: counting or scanning them
    # would let a local linter change the repository file census.
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
    """Scan tracked files for brand independence, unresolved markers, compiled artifacts and raw secrets without making prose wording a product contract."""
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


def validate_release_recipes(root: Path, errors: list[tuple[str,str]]) -> None:
    """Container and management-workload release recipes must exist and stay build-time free."""
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
        if dockerfile.name == 'Dockerfile.maintenance' and 'ARG MAINTENANCE_RUNTIME_IMAGE' not in docker:
            errors.append(('CONTAINER_DIGEST_INPUTS_MISSING', rel))
        if dockerfile.name in {'Dockerfile','Dockerfile.agent','Dockerfile.probe'} and 'internal/buildinfo.Version=$VERSION' not in docker:
            errors.append(('CONTAINER_BINARY_VERSION_INJECTION_MISSING', rel))
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


def validate_management_workload_image_plan(root: Path, version: str, errors: list[tuple[str,str]]) -> None:
    """The image build plan is the only authority for pending management workload image sources."""
    image_plan_path = root/'lab/management-workload-image-build-plan.json'
    image_plan = load_json(image_plan_path, errors) if image_plan_path.is_file() else None
    if image_plan is None:
        errors.append(('MANAGEMENT_WORKLOAD_IMAGE_PLAN_MISSING', str(image_plan_path.relative_to(root))))
    else:
        if image_plan.get('authority') != 'MANAGEMENT_WORKLOAD_IMAGE_BUILD_PLAN_V5' or image_plan.get('schemaVersion') != 5 or image_plan.get('releaseVersion') != version:
            errors.append(('MANAGEMENT_WORKLOAD_IMAGE_PLAN_IDENTITY_INVALID', str(image_plan_path.relative_to(root))))
        if image_plan.get('manifestImageResolutionAuthority') != 'MANAGEMENT_WORKLOAD_MANIFEST_IMAGE_RESOLUTION_V1' or image_plan.get('externalVersionSelectionAuthority') != 'MANAGEMENT_WORKLOAD_EXTERNAL_VERSION_SELECTION_V1' or image_plan.get('externalAcquisitionAuthority') != 'MANAGEMENT_WORKLOAD_EXTERNAL_IMAGE_ACQUISITION_V2' or image_plan.get('assemblyAuthority') != 'MANAGEMENT_WORKLOAD_OCI_ASSEMBLY_AUTHORITY_V1' or image_plan.get('inventoryAuthority') != 'MANAGEMENT_WORKLOAD_OCI_ARCHIVE_INVENTORY_V2' or image_plan.get('importAddressabilityAuthority') != 'MANAGEMENT_WORKLOAD_OCI_IMPORT_ADDRESSABILITY_V2' or image_plan.get('productImageCertificationAuthority') != 'MANAGEMENT_WORKLOAD_PRODUCT_IMAGE_CERTIFICATION_V1':
            errors.append(('MANAGEMENT_WORKLOAD_IMAGE_PLAN_AUTHORITY_CHAIN_INVALID', str(image_plan_path.relative_to(root))))
        external_acquisition_schema = root/'schemas/management-workload-external-image-acquisition.schema.json'
        external_acquisition_schema_value = load_json(external_acquisition_schema, errors) if external_acquisition_schema.is_file() else None
        if not isinstance(external_acquisition_schema_value, dict) or ((external_acquisition_schema_value.get('properties') or {}).get('authority') or {}).get('const') != 'MANAGEMENT_WORKLOAD_EXTERNAL_IMAGE_ACQUISITION_V2':
            errors.append(('MANAGEMENT_WORKLOAD_EXTERNAL_IMAGE_ACQUISITION_SCHEMA_INVALID', str(external_acquisition_schema.relative_to(root))))
        elif ((external_acquisition_schema_value.get('properties') or {}).get('schemaVersion') or {}).get('const') != 2 or 'tagRootBytes' not in (external_acquisition_schema_value.get('required') or []):
            errors.append(('MANAGEMENT_WORKLOAD_EXTERNAL_IMAGE_ACQUISITION_SCHEMA_V2_TAG_ROOT_INVALID', str(external_acquisition_schema.relative_to(root))))
        registry_acquire = (root/'internal/registryacquire/acquire.go').read_text() if (root/'internal/registryacquire/acquire.go').is_file() else ''
        workload_cli = (root/'cmd/platformctl/workload_oci.go').read_text() if (root/'cmd/platformctl/workload_oci.go').is_file() else ''
        for token in ('MANAGEMENT_WORKLOAD_EXTERNAL_IMAGE_ACQUISITION_V2','registry-1.docker.io','acquire-external','verify-external'):
            if token in ('acquire-external','verify-external'):
                if token not in workload_cli: errors.append(('MANAGEMENT_WORKLOAD_EXTERNAL_IMAGE_ACQUISITION_CLI_MISSING', token))
            elif token not in registry_acquire and token != 'registry-1.docker.io':
                errors.append(('MANAGEMENT_WORKLOAD_EXTERNAL_IMAGE_ACQUISITION_RUNTIME_MISSING', token))
        manifest_resolution_schema = root/'schemas/management-workload-manifest-image-resolution.schema.json'
        manifest_resolution_schema_value = load_json(manifest_resolution_schema, errors) if manifest_resolution_schema.is_file() else None
        if not isinstance(manifest_resolution_schema_value, dict) or ((manifest_resolution_schema_value.get('properties') or {}).get('authority') or {}).get('const') != 'MANAGEMENT_WORKLOAD_MANIFEST_IMAGE_RESOLUTION_V1':
            errors.append(('MANAGEMENT_WORKLOAD_MANIFEST_IMAGE_RESOLUTION_SCHEMA_INVALID', str(manifest_resolution_schema.relative_to(root))))
        manifest_runtime = (root/'internal/manifestimages/resolve.go').read_text() if (root/'internal/manifestimages/resolve.go').is_file() else ''
        for token in ('inspect-manifest','resolve-manifest','MANAGEMENT_WORKLOAD_MANIFEST_IMAGE_RESOLUTION_V1'):
            if token not in workload_cli and token != 'MANAGEMENT_WORKLOAD_MANIFEST_IMAGE_RESOLUTION_V1':
                errors.append(('MANAGEMENT_WORKLOAD_MANIFEST_IMAGE_RESOLUTION_CLI_MISSING', token))
            if token == 'MANAGEMENT_WORKLOAD_MANIFEST_IMAGE_RESOLUTION_V1' and token not in manifest_runtime:
                errors.append(('MANAGEMENT_WORKLOAD_MANIFEST_IMAGE_RESOLUTION_RUNTIME_MISSING', token))
        expected_roles = {'postgresql','forgejo','zot','keycloak','platform-api','maintenance','platform-agent','platform-probe'}
        core = image_plan.get('coreImages')
        roles = {row.get('role') for row in core if isinstance(row, dict)} if isinstance(core, list) else set()
        if not isinstance(core, list) or len(core) != 8 or roles != expected_roles or any(row.get('state') != 'pending' for row in core if isinstance(row, dict)):
            errors.append(('MANAGEMENT_WORKLOAD_IMAGE_PLAN_CORE_ROLE_INVALID', str(image_plan_path.relative_to(root))))
        expected_external = {
            'postgresql': ('docker.io/library/postgres','registry-1.docker.io','library/postgres','17.11','17.11-bookworm','postgresql-17-patch','https://www.postgresql.org/docs/17/release-17-11.html'),
            'forgejo': ('codeberg.org/forgejo/forgejo','data.forgejo.org','forgejo/forgejo','15.0.7','15.0.7','forgejo-lts','https://forgejo.org/releases/'),
            'zot': ('ghcr.io/project-zot/zot-linux-amd64','ghcr.io','project-zot/zot-linux-amd64','2.1.20','v2.1.20','zot-stable','https://github.com/project-zot/zot/releases/tag/v2.1.20'),
            'keycloak': ('quay.io/keycloak/keycloak','quay.io','keycloak/keycloak','26.7.3','26.7.3','keycloak-current-security','https://www.keycloak.org/2026/08/keycloak-2673-released'),
        }
        if isinstance(core, list):
            for row in core:
                if not isinstance(row, dict) or row.get('role') not in expected_external: continue
                expected = expected_external[row['role']]
                actual = (row.get('repository'),row.get('registryEndpoint'),row.get('registryRepository'),row.get('version'),row.get('tag'),row.get('selectionChannel'),row.get('selectionEvidenceURL'))
                required = {'role','ownership','repository','registryEndpoint','registryRepository','version','tag','selectionChannel','selectionEvidenceURL','state','blocker'}
                if set(row) != required or row.get('ownership') != 'external' or actual != expected or row.get('tag') == 'latest':
                    errors.append(('MANAGEMENT_WORKLOAD_EXTERNAL_VERSION_SELECTION_INVALID', str(row)))
        try:
            external_receipt = external_receipt_evidence(root, image_plan)
            if set(external_receipt["byRole"]) != set(expected_external):
                errors.append(('MANAGEMENT_WORKLOAD_EXTERNAL_RECEIPT_COVERAGE_INVALID', str(sorted(external_receipt["byRole"]))))
        except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            errors.append(('MANAGEMENT_WORKLOAD_EXTERNAL_RECEIPT_INVALID', str(exc)))
        bases = image_plan.get('baseImages')
        base_roles = {row.get('role') for row in bases if isinstance(row, dict)} if isinstance(bases, list) else set()
        if not isinstance(bases, list) or len(bases) != 3 or base_roles != {'api-runtime-base','static-runtime-base','maintenance-toolchain-base'} or any(row.get('state') != 'pending' for row in bases if isinstance(row, dict)):
            errors.append(('MANAGEMENT_WORKLOAD_IMAGE_PLAN_BASE_ROLE_INVALID', str(image_plan_path.relative_to(root))))
        derived = image_plan.get('derivedManifestImageSets')
        expected_derived = {
            'argocd-install-manifest': ('manifests/argocd-install.yaml','sha256:a32bf36a437071a1f563ebf9e81c8a39fba9057c17db7d5d041afb7b6e3f4afe',1917766,'runtime-manifests/argocd-install.yaml','runtime-manifests/argocd-install.image-lock.json'),
            'argocd-ha-install-manifest': ('manifests/argocd-ha-install.yaml','sha256:65d9d4ff520ddb40bad2c39b1f44188ceecfe96b5dd29c8ead569b52d6c6b8c6',1969264,'runtime-manifests/argocd-ha-install.yaml','runtime-manifests/argocd-ha-install.image-lock.json'),
            'cloudnative-pg-install-manifest': ('manifests/cloudnative-pg-install.yaml','sha256:f8bede43fe4ee0d478c2355b204a36876b2ae4faac60f2a9452280b293da3b88',1262410,'runtime-manifests/cloudnative-pg-install.yaml','runtime-manifests/cloudnative-pg-install.image-lock.json'),
            'replicated-storage-install-manifest': ('manifests/replicated-storage-install.yaml','sha256:41648963af867ac1d0c85755fb53cf61cacd57c9bb22e1942e3fb0439eeb04fd',207054,'runtime-manifests/replicated-storage-install.yaml','runtime-manifests/replicated-storage-install.image-lock.json'),
        }
        if not isinstance(derived, list) or len(derived) != 4:
            errors.append(('MANAGEMENT_WORKLOAD_IMAGE_PLAN_DERIVED_SET_INVALID', str(image_plan_path.relative_to(root))))
        else:
            seen=set()
            required={'sourceAuthority','manifestPath','sourceManifestSha256','sourceManifestBytes','resolvedManifestPath','resolutionLockPath','state','blocker'}
            for row in derived:
                authority=row.get('sourceAuthority') if isinstance(row,dict) else None
                expected=expected_derived.get(authority)
                if not isinstance(row,dict) or set(row)!=required or expected is None or authority in seen:
                    errors.append(('MANAGEMENT_WORKLOAD_IMAGE_PLAN_DERIVED_SET_INVALID', str(row))); continue
                seen.add(authority)
                actual=(row.get('manifestPath'),row.get('sourceManifestSha256'),row.get('sourceManifestBytes'),row.get('resolvedManifestPath'),row.get('resolutionLockPath'))
                if actual != expected or row.get('state')!='pending' or row.get('blocker')!='EXACT_MANIFEST_IMAGE_DIGEST_RESOLUTION_PENDING':
                    errors.append(('MANAGEMENT_WORKLOAD_IMAGE_PLAN_DERIVED_BINDING_INVALID', str(row)))
            if seen != set(expected_derived):
                errors.append(('MANAGEMENT_WORKLOAD_IMAGE_PLAN_DERIVED_SET_INVALID', str(sorted(seen))))
        try:
            manifest_receipt = manifest_receipt_evidence(root, image_plan)
            if set(manifest_receipt["byAuthority"]) != set(expected_derived):
                errors.append(('MANAGEMENT_WORKLOAD_MANIFEST_RECEIPT_COVERAGE_INVALID', str(sorted(manifest_receipt["byAuthority"]))))
        except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            errors.append(('MANAGEMENT_WORKLOAD_MANIFEST_RECEIPT_INVALID', str(exc)))
        try:
            product_receipt = product_receipt_evidence(root, image_plan)
            expected_product_roles = {row.get('role') for row in core if isinstance(row, dict) and row.get('ownership') == 'product'} if isinstance(core, list) else set()
            expected_base_roles = {row.get('role') for row in bases if isinstance(row, dict)} if isinstance(bases, list) else set()
            if set(product_receipt["byRole"]) != expected_product_roles or set(product_receipt["byBaseRole"]) != expected_base_roles:
                errors.append(('MANAGEMENT_WORKLOAD_PRODUCT_RECEIPT_COVERAGE_INVALID', str(sorted(product_receipt["byRole"]))))
        except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            errors.append(('MANAGEMENT_WORKLOAD_PRODUCT_RECEIPT_INVALID', str(exc)))

        archive_receipt_path = root/'lab/management-workload-oci-archive-receipt.json'
        if archive_receipt_path.exists() or archive_receipt_path.is_symlink():
            try:
                verify_management_workload_archive_receipt(root, archive_receipt_path)
            except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
                errors.append(('MANAGEMENT_WORKLOAD_OCI_ARCHIVE_RECEIPT_INVALID', str(exc)))


def validate_management_maintenance_toolset(root: Path, errors: list[tuple[str,str]]) -> None:
    """Validate the product-owned maintenance command/base composition contract."""
    authority_path = root/'catalog/management-maintenance-toolset.json'
    doc = load_json(authority_path, errors) if authority_path.is_file() else None
    if not isinstance(doc, dict):
        errors.append(('MANAGEMENT_MAINTENANCE_TOOLSET_MISSING', str(authority_path.relative_to(root))))
        return
    if doc.get('authority') != 'MANAGEMENT_MAINTENANCE_TOOLSET_AUTHORITY_V1' or doc.get('schemaVersion') != 1 or doc.get('kind') != 'ManagementMaintenanceToolset':
        errors.append(('MANAGEMENT_MAINTENANCE_TOOLSET_IDENTITY_INVALID', str(authority_path.relative_to(root))))
    if doc.get('defaultRuntimeUser') != '65532:65532' or doc.get('rootOverrideRequired') is not True or doc.get('networkPackageInstallationAllowed') is not False:
        errors.append(('MANAGEMENT_MAINTENANCE_TOOLSET_RUNTIME_POLICY_INVALID', str(authority_path.relative_to(root))))
    required_exec = {'aws','cat','cmp','cp','createdb','cut','dropdb','find','gunzip','gzip','mkdir','pg_dump','pg_restore','psql','rm','sha256sum','tar','tr','wc'}
    executables = doc.get('requiredExecutables')
    if not isinstance(executables, list) or set(executables) != required_exec or len(executables) != len(required_exec):
        errors.append(('MANAGEMENT_MAINTENANCE_TOOLSET_EXECUTABLES_INVALID', str(executables)))
    if doc.get('requiredShellBuiltins') != ['printf','test']:
        errors.append(('MANAGEMENT_MAINTENANCE_TOOLSET_BUILTINS_INVALID', str(doc.get('requiredShellBuiltins'))))
    expected_owners = {
        'internal/bootstrap/object_storage_probe.go',
        'internal/disasterrecovery/manifests.go',
        'internal/lifecycle/manifests.go',
        'scripts/lab_runner.py',
    }
    owners = doc.get('ownerSurfaces')
    if not isinstance(owners, list) or set(owners) != expected_owners or any(not (root/rel).is_file() for rel in expected_owners):
        errors.append(('MANAGEMENT_MAINTENANCE_TOOLSET_OWNER_SURFACE_INVALID', str(owners)))
    aws = doc.get('awsCli') or {}
    if aws.get('repository') != 'public.ecr.aws/aws-cli/aws-cli' or aws.get('version') != aws.get('tag') or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', str(aws.get('version') or '')) or not str(aws.get('selectionEvidenceURL') or '').startswith('https://'):
        errors.append(('MANAGEMENT_MAINTENANCE_TOOLSET_AWS_SELECTION_INVALID', str(aws)))
    compat = doc.get('compatibilityRequirements') or {}
    if compat != {
        'defaultNonRootCommandProbe': True,
        'rootOverrideCommandProbe': True,
        'postgresqlClientMajor': 17,
        's3EndpointOverrideRequired': True,
        'offlineImageBuildRequired': True,
        'runtimeCertified': False,
        'physicalCertified': False,
    }:
        errors.append(('MANAGEMENT_MAINTENANCE_TOOLSET_COMPATIBILITY_INVALID', str(compat)))
    recipe_rel = doc.get('compositionRecipe')
    recipe = root/str(recipe_rel or '')
    if recipe_rel != 'deploy/images/Dockerfile.maintenance-runtime-base' or not recipe.is_file():
        errors.append(('MANAGEMENT_MAINTENANCE_TOOLSET_RECIPE_MISSING', str(recipe_rel)))
        return
    text = recipe.read_text()
    for token in ('ARG AWS_CLI_IMAGE','ARG POSTGRES_RUNTIME_IMAGE','FROM ${AWS_CLI_IMAGE} AS awscli','FROM ${POSTGRES_RUNTIME_IMAGE}','COPY --from=awscli /usr/local/aws-cli/ /usr/local/aws-cli/','ENV PATH="/usr/local/aws-cli/v2/current/bin:${PATH}"','USER 65532:65532','ENTRYPOINT ["/bin/sh"]'):
        if token not in text:
            errors.append(('MANAGEMENT_MAINTENANCE_TOOLSET_RECIPE_INVALID', token))
    lowered = text.lower()
    if any(token in lowered for token in ('apt-get','apt install','apk add','dnf install','yum install','curl http','wget http')):
        errors.append(('MANAGEMENT_MAINTENANCE_TOOLSET_NETWORK_INSTALL_FORBIDDEN', str(recipe_rel)))


def validate_deployment_surface(root: Path, errors: list[tuple[str,str]]) -> None:
    """Compose and systemd surfaces must bind runtime images and durable configuration."""
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


def validate_schema_set(root: Path, errors: list[tuple[str,str]]) -> list[Path]:
    """Every shipped JSON schema must parse; settings schemas are resolved at runtime."""
    # Machine schemas must parse; settings schemas are resolved from component contracts below.
    schema_files = sorted((root/'schemas').rglob('*.json'))
    if not schema_files:
        errors.append(('SCHEMA_SET_EMPTY','schemas'))
    for p in schema_files:
        load_json(p, errors)
    return schema_files


def validate_component_catalog(root: Path, errors: list[tuple[str,str]]) -> dict[str,dict]:
    """Component contracts, source bundles and the dependency graph form one catalog authority."""
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
    return components


def validate_component_runtime_certification(root: Path, components: dict[str,dict], errors: list[tuple[str,str]]) -> None:
    """Component source resolution never bypasses independent runtime-suitability authority."""
    runtime_cert_path = root/'catalog/component-runtime-certification.json'
    runtime_cert = load_json(runtime_cert_path, errors) if runtime_cert_path.exists() else None
    runtime_stages = ['install','readiness','dependency','upgrade','remove','failure']
    expected_runtime_policy = {
        'sourceBinding':'exact-component-release-and-source-lock',
        'executorBinding':'component-owned-no-generic-runtime-certification-claim',
        'requiredLifecycleStages':runtime_stages,
        'replacementPolicy':'resolved-source-replacement-denied-without-explicit-versioned-migration',
        'runtimeSuitabilityBinding':'persistent-independent-of-source-acquisition',
    }
    if not isinstance(runtime_cert, dict) or runtime_cert.get('apiVersion') != 'platform.4so.io/v1alpha1' or runtime_cert.get('kind') != 'ComponentRuntimeCertificationRegistry' or ((runtime_cert.get('metadata') or {}).get('name') != 'COMPONENT_RUNTIME_CERTIFICATION_REGISTRY_V1'):
        errors.append(('COMPONENT_RUNTIME_CERTIFICATION_REGISTRY_INVALID','catalog/component-runtime-certification.json'))
        return
    runtime_spec = runtime_cert.get('spec') or {}
    if runtime_spec.get('policy') != expected_runtime_policy:
        errors.append(('COMPONENT_RUNTIME_CERTIFICATION_POLICY_INVALID', str(runtime_spec.get('policy'))))
    holds = runtime_spec.get('runtimeSuitabilityHolds')
    hold_by_name = {}
    if not isinstance(holds, list):
        errors.append(('COMPONENT_RUNTIME_SUITABILITY_HOLDS_INVALID','not-list'))
        holds = []
    for hold in holds:
        name = str((hold or {}).get('component') or '') if isinstance(hold, dict) else ''
        status = str((hold or {}).get('status') or '') if isinstance(hold, dict) else ''
        authority = str((hold or {}).get('authority') or '') if isinstance(hold, dict) else ''
        reason = str((hold or {}).get('reason') or '') if isinstance(hold, dict) else ''
        evidence = str((hold or {}).get('evidenceURL') or '') if isinstance(hold, dict) else ''
        if not name or name in hold_by_name or name not in components or status not in {'dependency-transition-required','review-required'} or not authority or not reason or not evidence.startswith('https://'):
            errors.append(('COMPONENT_RUNTIME_SUITABILITY_HOLD_INVALID', name or '<empty>'))
            continue
        hold_by_name[name] = hold
    rows = runtime_spec.get('components')
    runtime_rows = {}
    if not isinstance(rows, list):
        errors.append(('COMPONENT_RUNTIME_CERTIFICATION_COVERAGE_INVALID','components-not-list'))
        rows = []
    for row in rows:
        name = str((row or {}).get('component') or '') if isinstance(row, dict) else ''
        if not name or name in runtime_rows:
            errors.append(('COMPONENT_RUNTIME_CERTIFICATION_IDENTITY_INVALID', name or '<empty>'))
            continue
        runtime_rows[name] = row
    if set(runtime_rows) != set(components):
        errors.append(('COMPONENT_RUNTIME_CERTIFICATION_COVERAGE_INVALID', f'missing={sorted(set(components)-set(runtime_rows))};extra={sorted(set(runtime_rows)-set(components))}'))
    for name, row in runtime_rows.items():
        if name not in components or not isinstance(row, dict):
            continue
        component_spec = components[name].get('spec') or {}
        if row.get('release') != component_spec.get('release'):
            errors.append(('COMPONENT_RUNTIME_CERTIFICATION_RELEASE_DRIFT', f'{name}:{row.get("release")}!={component_spec.get("release")}'))
        source = component_spec.get('source') or {}
        resolved = bool(source.get('resolved'))
        expected_digest = str(source.get('sourceLockDigest') or '').strip() if resolved else ''
        if resolved and not re.fullmatch(r'sha256:[0-9a-f]{64}', expected_digest):
            errors.append(('COMPONENT_RUNTIME_CERTIFICATION_SOURCE_DRIFT', f'{name}:resolved-component-has-invalid-source-lock'))
        expected_source = {
            'status':'source-ready' if resolved else 'blocked-source-lock',
            'resolved':resolved,
            'sourceLockDigest':expected_digest,
        }
        if row.get('sourceBinding') != expected_source:
            errors.append(('COMPONENT_RUNTIME_CERTIFICATION_SOURCE_DRIFT', name))
        held = name in hold_by_name
        if name == 'secure-namespace-foundation' and held:
            errors.append(('COMPONENT_RUNTIME_SUITABILITY_HOLD_INVALID', name))
        expected_executor = {
            'status':(
                'foundation-harness-partial' if name == 'secure-namespace-foundation'
                else 'runtime-suitability-held' if resolved and held
                else 'component-install-readiness-dependency-failure-remove-partial' if resolved
                else 'source-gated-component-executor'
            ),
            'profile':'TARGET_RUNTIME_V1' if name == 'secure-namespace-foundation' else 'COMPONENT_RUNTIME_V1',
            'owner':'catalog-component',
        }
        if row.get('executor') != expected_executor:
            errors.append(('COMPONENT_RUNTIME_CERTIFICATION_EXECUTOR_INVALID', name))
        lifecycle = row.get('lifecycle')
        if not isinstance(lifecycle, list) or len(lifecycle) != len(runtime_stages):
            errors.append(('COMPONENT_RUNTIME_CERTIFICATION_LIFECYCLE_INVALID', f'{name}:coverage'))
            continue
        seen_stages=set()
        for idx, stage_name in enumerate(runtime_stages):
            stage = lifecycle[idx] if idx < len(lifecycle) else None
            if not isinstance(stage, dict):
                errors.append(('COMPONENT_RUNTIME_CERTIFICATION_LIFECYCLE_INVALID', f'{name}:{stage_name}:not-object'))
                continue
            if stage.get('name') != stage_name or stage_name in seen_stages:
                errors.append(('COMPONENT_RUNTIME_CERTIFICATION_LIFECYCLE_INVALID', f'{name}:{stage_name}:identity'))
            seen_stages.add(stage_name)
            if name == 'secure-namespace-foundation':
                if stage_name in {'install','readiness','dependency'}:
                    expected_status = 'foundation-harness-executable'; expected_authority = 'TARGET_RUNTIME_V1'
                elif stage_name == 'upgrade':
                    expected_status = 'not-applicable-first-product-release'; expected_authority = 'COMPONENT_UPGRADE_SOURCE_ADMISSION_V1'
                else:
                    expected_status = 'pending-component-executor'; expected_authority = 'COMPONENT_RUNTIME_EXECUTOR_V1'
            elif resolved and held:
                expected_status = 'pending-runtime-suitability'
                expected_authority = str(hold_by_name[name]['authority'])
            elif stage_name == 'upgrade':
                expected_status = 'pending-upgrade-matrix'
                expected_authority = 'COMPONENT_RUNTIME_UPGRADE_V1'
            elif resolved:
                expected_status = 'component-runtime-executable'
                expected_authority = 'COMPONENT_RUNTIME_V1'
            else:
                expected_status = 'source-gated-component-executor'
                expected_authority = 'COMPONENT_RUNTIME_V1'
            expected_stage = {
                'name':stage_name,
                'status':expected_status,
                'evidenceContract':f'component-{stage_name}-evidence/v1',
                'authority':expected_authority,
            }
            if stage != expected_stage:
                errors.append(('COMPONENT_RUNTIME_CERTIFICATION_LIFECYCLE_INVALID', f'{name}:{stage_name}:authority'))


def validate_component_runtime_upgrade_matrix(root: Path, components: dict[str,dict], errors: list[tuple[str,str]]) -> None:
    """Upgrade admission is deliberately stricter than executor availability: two exact source locks or pending."""
    # Component upgrade admission is deliberately stricter than lifecycle executor
    # availability.  No upgrade edge is admitted until two distinct exact source
    # locks are present; current-only source locks therefore remain pending.
    upgrade_matrix_path = root/'catalog/component-runtime-upgrade-matrix.json'
    upgrade_matrix = load_json(upgrade_matrix_path, errors) if upgrade_matrix_path.exists() else None
    if not isinstance(upgrade_matrix, dict) or upgrade_matrix.get('authority') != 'COMPONENT_RUNTIME_UPGRADE_MATRIX_V2' or upgrade_matrix.get('kind') != 'ComponentRuntimeUpgradeMatrix':
        errors.append(('COMPONENT_RUNTIME_UPGRADE_MATRIX_INVALID','catalog/component-runtime-upgrade-matrix.json'))
    else:
        matrix_rows = upgrade_matrix.get('components') or []
        matrix_by_name = {str((row or {}).get('component') or ''): row for row in matrix_rows if isinstance(row, dict)}
        if set(matrix_by_name) != set(components):
            errors.append(('COMPONENT_RUNTIME_UPGRADE_MATRIX_COVERAGE_INVALID', f'missing={sorted(set(components)-set(matrix_by_name))};extra={sorted(set(matrix_by_name)-set(components))}'))
        for name, row in matrix_by_name.items():
            if name not in components:
                continue
            if row.get('targetRelease') != (components[name].get('spec') or {}).get('release'):
                errors.append(('COMPONENT_RUNTIME_UPGRADE_MATRIX_RELEASE_DRIFT', name))
            status = row.get('status')
            edges = row.get('admittedEdges') or []
            if status not in {'pending-source-pair','admitted-source-pair','install-only-first-product-release'}:
                errors.append(('COMPONENT_RUNTIME_UPGRADE_MATRIX_STATUS_INVALID', f'{name}:{status}'))
            if status == 'admitted-source-pair' and not edges:
                errors.append(('COMPONENT_RUNTIME_UPGRADE_MATRIX_EDGE_INVALID', f'{name}:admitted-without-edge'))
            if status == 'install-only-first-product-release' and (edges or row.get('upgradeExecutor') != 'install-readiness-failure-remove-only' or name != 'secure-namespace-foundation'):
                errors.append(('COMPONENT_RUNTIME_UPGRADE_MATRIX_FIRST_RELEASE_INVALID', name))
            policy = upgrade_matrix.get('policy') or {}
            if policy.get('exactVersionDirectionRequired') is not True or policy.get('sourceLockSelfIdentityRequired') is not True:
                errors.append(('COMPONENT_RUNTIME_UPGRADE_MATRIX_POLICY_INVALID', name))
            def exact_key(v):
                parts=str(v or '').lstrip('v').split('.')
                return tuple(int(x) for x in parts) if len(parts)==3 and all(x.isdigit() for x in parts) else None
            for edge in edges:
                fk = exact_key((edge or {}).get('fromRelease')) if isinstance(edge, dict) else None
                tk = exact_key((edge or {}).get('toRelease')) if isinstance(edge, dict) else None
                if not isinstance(edge, dict) or not re.fullmatch(r'[0-9a-f]{64}', str(edge.get('fromSourceLockDigest') or '')) or not re.fullmatch(r'[0-9a-f]{64}', str(edge.get('toSourceLockDigest') or '')) or edge.get('fromSourceLockDigest') == edge.get('toSourceLockDigest') or not fk or not tk or fk >= tk:
                    errors.append(('COMPONENT_RUNTIME_UPGRADE_MATRIX_EDGE_INVALID', name))


def validate_boot_media_contract(root: Path, errors: list[tuple[str,str]]) -> None:
    """Typed boot-media contract plus its test stay in source so managed install cannot regress to ad-hoc BMC handling."""
    # H1 BootMediaProvider is source foundation only here.  Requiring the typed,
    # secret-reference-only and fenced contract in source prevents future managed
    # install work from falling back to ad-hoc BMC shell/credential handling.
    bootmedia_contract = root/'internal/bootmedia/contract.go'
    bootmedia_test = root/'internal/bootmedia/contract_test.go'
    if not bootmedia_contract.is_file() or not bootmedia_test.is_file():
        errors.append(('BOOT_MEDIA_PROVIDER_CONTRACT_MISSING','internal/bootmedia'))
    else:
        boot_text = bootmedia_contract.read_text()
        for marker in ('BOOT_MEDIA_PROVIDER_AUTHORITY_V1','SET_ONE_TIME_BOOT','POWER_CYCLE','credentialRef','stale or invalid boot-media fence'):
            if marker not in boot_text:
                errors.append(('BOOT_MEDIA_PROVIDER_CONTRACT_INVALID', marker))


def validate_upstream_acquisition_toolchain(root: Path, errors: list[tuple[str,str]]) -> int:
    """Build-time acquisition tools are product-owned pinned inputs so Helm/Crane cannot be silently replaced by "latest"."""
    # Build-time acquisition tools are product-owned inputs too.  Keep their exact
    # versions and upstream asset digests machine-readable so an operator cannot
    # silently substitute "latest" Helm/Crane binaries while resolving source locks.
    toolchain_path = root/'catalog/upstream-acquisition-toolchain.json'
    toolchain = load_json(toolchain_path, errors) if toolchain_path.exists() else None
    acquisition_toolchain_count = 0
    if not isinstance(toolchain, dict):
        errors.append(('UPSTREAM_ACQUISITION_TOOLCHAIN_INVALID', 'missing-or-not-object'))
    else:
        spec = toolchain.get('spec') or {}
        policy = spec.get('policy') or {}
        tools = spec.get('tools') or []
        expected_policy = {
            'allowUnpinnedTools': False,
            'allowLatestResolution': False,
            'requireAssetDigestVerification': True,
            'bootstrapIsBuildTimeOnly': True,
            'vendoredIntoProductArtifact': False,
            'allowStagedOfflineBootstrap': True,
            'stagedArchivesMustMatchLockedFilename': True,
        }
        if toolchain.get('apiVersion') != 'platform.4so.io/v1alpha1' or toolchain.get('kind') != 'UpstreamAcquisitionToolchain':
            errors.append(('UPSTREAM_ACQUISITION_TOOLCHAIN_INVALID', 'type'))
        if (toolchain.get('metadata') or {}).get('name') != 'canonical-helm-acquisition-toolchain' or spec.get('authority') != 'UPSTREAM_ACQUISITION_TOOLCHAIN_V3':
            errors.append(('UPSTREAM_ACQUISITION_TOOLCHAIN_INVALID', 'authority'))
        if policy != expected_policy:
            errors.append(('UPSTREAM_ACQUISITION_TOOLCHAIN_POLICY_INVALID', str(policy)))
        expected_input_limits = {
            'maxHelmIndexBytes': 32 * 1024 * 1024,
            'maxChartArchiveBytes': 64 * 1024 * 1024,
            'maxChartMembers': 8192,
            'maxChartUnpackedBytes': 512 * 1024 * 1024,
            'maxChartMetadataBytes': 1024 * 1024,
        }
        if spec.get('inputLimits') != expected_input_limits:
            errors.append(('UPSTREAM_ACQUISITION_TOOLCHAIN_INPUT_LIMITS_INVALID', str(spec.get('inputLimits'))))
        expected_tools = {
            'helm': {
                'version':'4.2.4',
                'versionRegex':r'^v?4\.2\.4(?:[+\-].*)?$',
                'platforms': {
                    'linux-amd64': ('https://get.helm.sh/helm-v4.2.4-linux-amd64.tar.gz', 'c306b46f719b0a4da32d0f78ee21bf90ce8d602f15b22ab753f0674d1670a7f3', 'linux-amd64/helm'),
                    'linux-arm64': ('https://get.helm.sh/helm-v4.2.4-linux-arm64.tar.gz', '564de2191b881e9f71b5606b25345821ea1682f06ab90499d3ab22b530176da1', 'linux-arm64/helm'),
                },
            },
            'crane': {
                'version':'0.22.1',
                'versionRegex':r'^v?0\.22\.1$',
                'platforms': {
                    'linux-amd64': ('https://github.com/google/go-containerregistry/releases/download/v0.22.1/go-containerregistry_Linux_x86_64.tar.gz', '0ab7a1d6932a213aed964ce97666c3077fe691c8606413674a8b3e0b9ec4cda0', 'crane'),
                    'linux-arm64': ('https://github.com/google/go-containerregistry/releases/download/v0.22.1/go-containerregistry_Linux_arm64.tar.gz', '898c0cff975f898a33e8c4580bdafb0e7c02c7faa33374e946762f97c4ab7110', 'crane'),
                },
            },
        }
        if not isinstance(tools, list) or len(tools) != len(expected_tools):
            errors.append(('UPSTREAM_ACQUISITION_TOOLCHAIN_INVALID', 'tool-count'))
            tools = []
        seen_tools = set()
        for row in tools:
            if not isinstance(row, dict):
                errors.append(('UPSTREAM_ACQUISITION_TOOLCHAIN_INVALID', 'tool-not-object')); continue
            name = str(row.get('name') or '')
            if name in seen_tools or name not in expected_tools:
                errors.append(('UPSTREAM_ACQUISITION_TOOLCHAIN_INVALID', f'tool:{name or "<empty>"}')); continue
            seen_tools.add(name)
            expected = expected_tools[name]
            if row.get('version') != expected['version'] or row.get('versionRegex') != expected['versionRegex']:
                errors.append(('UPSTREAM_ACQUISITION_TOOLCHAIN_VERSION_INVALID', name))
            if not isinstance(row.get('versionCommand'), list) or not row.get('versionCommand') or any(not isinstance(arg, str) or not arg for arg in row.get('versionCommand')):
                errors.append(('UPSTREAM_ACQUISITION_TOOLCHAIN_VERSION_COMMAND_INVALID', name))
            platforms = row.get('platforms') or {}
            if set(platforms) != set(expected['platforms']):
                errors.append(('UPSTREAM_ACQUISITION_TOOLCHAIN_PLATFORM_INVALID', name)); continue
            for platform_name, expected_tuple in expected['platforms'].items():
                asset = platforms.get(platform_name) or {}
                expected_url, expected_sha, expected_member = expected_tuple
                if asset.get('url') != expected_url or not public_https_source_url(asset.get('url')):
                    errors.append(('UPSTREAM_ACQUISITION_TOOLCHAIN_ASSET_URL_INVALID', f'{name}:{platform_name}'))
                if asset.get('sha256') != expected_sha or not re.fullmatch(r'[0-9a-f]{64}', str(asset.get('sha256') or '')):
                    errors.append(('UPSTREAM_ACQUISITION_TOOLCHAIN_ASSET_DIGEST_INVALID', f'{name}:{platform_name}'))
                if asset.get('archiveMember') != expected_member:
                    errors.append(('UPSTREAM_ACQUISITION_TOOLCHAIN_ARCHIVE_MEMBER_INVALID', f'{name}:{platform_name}'))
            acquisition_toolchain_count += 1
        if seen_tools != set(expected_tools):
            errors.append(('UPSTREAM_ACQUISITION_TOOLCHAIN_INVALID', f'missing={sorted(set(expected_tools)-seen_tools)}'))
    return acquisition_toolchain_count


def validate_release_build_toolchain(root: Path, version: str, errors: list[tuple[str,str]]) -> None:
    """Release compiler authority is distinct from upstream acquisition; a blocked lock is truthful but not closure."""
    # Release compiler/toolchain authority is distinct from upstream acquisition tools.
    # A structurally valid blocked lock is PASS for truthfulness, but never means the
    # release toolchain blocker is closed. Closure requires an exact supported compiler
    # archive digest and provenance-bound build outside this source-only gate.
    release_toolchain_path = root/'lab/release-build-toolchain-lock.json'
    release_toolchain = load_json(release_toolchain_path, errors) if release_toolchain_path.exists() else None
    if not isinstance(release_toolchain, dict):
        errors.append(('RELEASE_BUILD_TOOLCHAIN_AUTHORITY_INVALID','missing-or-not-object'))
    else:
        rt_spec = release_toolchain.get('spec') or {}
        rt_policy = rt_spec.get('policy') or {}
        if release_toolchain.get('apiVersion') != 'platform.4so.io/v1alpha1' or release_toolchain.get('kind') != 'ReleaseBuildToolchainLock' or release_toolchain.get('authority') != 'RELEASE_BUILD_TOOLCHAIN_AUTHORITY_V1':
            errors.append(('RELEASE_BUILD_TOOLCHAIN_AUTHORITY_INVALID','identity'))
        if rt_spec.get('releaseVersion') != version:
            errors.append(('RELEASE_BUILD_TOOLCHAIN_VERSION_INVALID', f'{rt_spec.get("releaseVersion")}!={version}'))
        if rt_spec.get('language') != 'go' or rt_spec.get('admissionStatus') not in {'blocked','admitted'}:
            errors.append(('RELEASE_BUILD_TOOLCHAIN_AUTHORITY_INVALID','language-or-status'))
        if rt_spec.get('admissionStatus') == 'blocked' and rt_spec.get('blocker') != 'RELEASE_BUILD_TOOLCHAIN_LOCK_PENDING':
            errors.append(('RELEASE_BUILD_TOOLCHAIN_BLOCKER_INVALID', str(rt_spec.get('blocker'))))
        for key in ('supportedToolchainRequired','exactCompilerArchiveDigestRequired','compilerVersionMustMatchBuildProvenance','exactCGOToolchainRequired'):
            if rt_policy.get(key) is not True:
                errors.append(('RELEASE_BUILD_TOOLCHAIN_POLICY_INVALID', key))
        exact_cgo = rt_spec.get('exactCGOToolchain') or {}
        for key in ('ccVersion','ldVersion','libcVersion','libpqHeaderPath','libpqLibraryPath'):
            if not isinstance(exact_cgo.get(key), str) or not exact_cgo.get(key).strip():
                errors.append(('RELEASE_BUILD_TOOLCHAIN_CGO_INVALID', key))
        for key in ('libpqHeaderSha256','libpqLibrarySha256'):
            if not isinstance(exact_cgo.get(key), str) or not re.fullmatch(r'[0-9a-f]{64}', exact_cgo.get(key)):
                errors.append(('RELEASE_BUILD_TOOLCHAIN_CGO_INVALID', key))
        if rt_policy.get('networkAutoDownloadDuringReleaseBuildAllowed') is not False or rt_policy.get('physicalPassFromSourceBuildAllowed') is not False:
            errors.append(('RELEASE_BUILD_TOOLCHAIN_POLICY_INVALID','unsafe-release-policy'))

    toolchain_verifier = root/'scripts/verify_release_build_toolchain.py'
    if not toolchain_verifier.is_file():
        errors.append(('RELEASE_BUILD_TOOLCHAIN_VERIFIER_MISSING','scripts/verify_release_build_toolchain.py'))
    else:
        verifier_text = toolchain_verifier.read_text()
        for marker in ('--require-admitted','exactCompilerArchiveDigestRequired','exactCGOToolchainRequired','validate_active_cgo','RELEASE_BUILD_TOOLCHAIN_LOCK_PENDING'):
            if marker not in verifier_text:
                errors.append(('RELEASE_BUILD_TOOLCHAIN_VERIFIER_INVALID', marker))


def validate_upstream_admission(root: Path, components: dict[str,dict], errors: list[tuple[str,str]]) -> None:
    """Unresolved upstream acquisition is governed by one product-owned admission authority."""
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
    allowed_runtime_admission = {'eligible-after-source-resolution','dependency-transition-required','review-required'}
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
            'candidateAcquisition':'exact-source-may-be-acquired-before-runtime-clearance',
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
            runtime_status = str(row.get('runtimeStatus') or '')
            if runtime_status not in allowed_runtime_admission:
                errors.append(('UPSTREAM_ADMISSION_RUNTIME_STATUS_INVALID', f'{name}:{runtime_status}'))
            if not (exact_semver.fullmatch(constraint) or series_semver.fullmatch(constraint)):
                errors.append(('UPSTREAM_ADMISSION_CONSTRAINT_INVALID', f'{name}:{constraint}'))
            if chart != str((spec.get('delivery') or {}).get('chart') or ''):
                errors.append(('UPSTREAM_ADMISSION_CHART_MISMATCH', f'{name}:{chart}'))
            if not (source.startswith('https://') or source.startswith('oci://')):
                errors.append(('UPSTREAM_ADMISSION_SOURCE_INVALID', f'{name}:{source}'))
            if not str(row.get('rationale') or '').strip():
                errors.append(('UPSTREAM_ADMISSION_RATIONALE_MISSING', name))
            review_evidence = row.get('reviewEvidence') or []
            if not isinstance(review_evidence, list):
                errors.append(('UPSTREAM_ADMISSION_REVIEW_EVIDENCE_INVALID', name))
                review_evidence = []
            else:
                for index, evidence in enumerate(review_evidence):
                    if not isinstance(evidence, dict) or evidence.get('kind') not in {'release','blocker','source-migration'} or not str(evidence.get('url') or '').startswith('https://') or not str(evidence.get('summary') or '').strip():
                        errors.append(('UPSTREAM_ADMISSION_REVIEW_EVIDENCE_INVALID', f'{name}:{index}'))
            if runtime_status != 'eligible-after-source-resolution' and not any(isinstance(e, dict) and e.get('kind') == 'blocker' for e in review_evidence):
                errors.append(('UPSTREAM_ADMISSION_RUNTIME_BLOCKER_EVIDENCE_MISSING', name))
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
            if status == 'version-review-required' and (selected is None or not review_evidence):
                errors.append(('UPSTREAM_ADMISSION_VERSION_REVIEW_EVIDENCE_MISSING', name))
            if status == 'ready-for-acquisition':
                if selected is None:
                    errors.append(('UPSTREAM_ADMISSION_READY_VERSION_MISSING', name))
                if str(spec.get('release') or '') != normalized_selected:
                    errors.append(('UPSTREAM_ADMISSION_CATALOG_PIN_MISMATCH', f'{name}:{spec.get("release")}:{normalized_selected}'))
                if spec.get('versionPolicy') != 'exact-upstream-admitted-pending-source-acquisition':
                    errors.append(('UPSTREAM_ADMISSION_VERSION_POLICY_INVALID', name))
            elif selected is not None:
                if str(spec.get('release') or '') != normalized_selected:
                    errors.append(('UPSTREAM_ADMISSION_REVIEW_CANDIDATE_PIN_MISMATCH', f'{name}:{spec.get("release")}:{normalized_selected}'))
                if spec.get('versionPolicy') != 'exact-upstream-review-candidate-pending-decision':
                    errors.append(('UPSTREAM_ADMISSION_REVIEW_VERSION_POLICY_INVALID', name))
            elif str(spec.get('release') or '') != constraint:
                errors.append(('UPSTREAM_ADMISSION_REVIEW_COMPONENT_MUTATED', f'{name}:{spec.get("release")}:{constraint}'))
            if ((spec.get('source') or {}).get('resolved')):
                errors.append(('UPSTREAM_ADMISSION_RESOLVED_COMPONENT_PRESENT', name))

        gateway_spec = (components.get('gateway-api') or {}).get('spec') or {}
        gateway_release = str(gateway_spec.get('release') or '').removeprefix('v')
        gateway_resolved = bool((gateway_spec.get('source') or {}).get('resolved'))
        cilium_row = admission_rows.get('cilium') or {}
        cilium_selected = str(cilium_row.get('selectedVersion') or '').removeprefix('v')
        if cilium_selected.startswith('1.20.') and (gateway_release != '1.6.1' or not gateway_resolved):
            if cilium_row.get('runtimeStatus') != 'dependency-transition-required':
                errors.append(('UPSTREAM_ADMISSION_RUNTIME_DEPENDENCY_STATUS_INVALID', f'cilium:{cilium_selected}:gateway-api:{gateway_release}:resolved={gateway_resolved}'))
        kgateway_row = admission_rows.get('kgateway') or {}
        kgateway_selected = str(kgateway_row.get('selectedVersion') or '').removeprefix('v')
        if kgateway_selected.startswith('2.3.') and gateway_release != '1.5.1':
            errors.append(('UPSTREAM_ADMISSION_DEPENDENCY_BASELINE_INVALID', f'kgateway:{kgateway_selected}:gateway-api:{gateway_release}'))
        if kgateway_selected.startswith('2.4.') and gateway_release not in {'1.5.1','1.6.1'}:
            errors.append(('UPSTREAM_ADMISSION_DEPENDENCY_BASELINE_INVALID', f'kgateway:{kgateway_selected}:gateway-api:{gateway_release}'))


def validate_lab_bundle_acquisition_lock(root: Path, errors: list[tuple[str,str]]) -> None:
    """Lab auto-acquisition authority must ship inside the exact release source tree."""
    # Phase-C Lab auto-acquisition authority must be shipped inside the exact release source tree.
    acquisition_path = root/'lab/appliance-bundle-acquisition-lock.json'
    acquisition = load_json(acquisition_path, errors) if acquisition_path.exists() else None
    current_version = (root/'VERSION').read_text(encoding='utf-8').strip() if (root/'VERSION').exists() else ''
    required_source_authorities = {
        'rke2-installer-and-offline-artifacts',
        'management-workload-oci-archive',
        'argocd-install-manifest',
        'argocd-ha-install-manifest',
        'cloudnative-pg-install-manifest',
        'replicated-storage-install-manifest',
    }
    if not isinstance(acquisition, dict):
        errors.append(('LAB_BUNDLE_ACQUISITION_LOCK_MISSING', str(acquisition_path.relative_to(root))))
    else:
        expected_keys = {'authority','schemaVersion','releaseVersion','status','inputPack','resolvedAuthorities','partialAuthorities','missingAuthorities','derivedAuthorities'}
        if set(acquisition) != expected_keys:
            errors.append(('LAB_BUNDLE_ACQUISITION_LOCK_FIELDS_INVALID', str(sorted(set(acquisition)^expected_keys))))
        if acquisition.get('authority') != 'LAB_APPLIANCE_BUNDLE_ACQUISITION_LOCK_V8' or acquisition.get('schemaVersion') != 8:
            errors.append(('LAB_BUNDLE_ACQUISITION_LOCK_AUTHORITY_INVALID', str(acquisition.get('authority'))))
        if acquisition.get('releaseVersion') != current_version:
            errors.append(('LAB_BUNDLE_ACQUISITION_LOCK_VERSION_INVALID', f'{acquisition.get("releaseVersion")}!={current_version}'))
        status = acquisition.get('status')
        missing = acquisition.get('missingAuthorities')
        resolved = acquisition.get('resolvedAuthorities')
        partial = acquisition.get('partialAuthorities')
        pack = acquisition.get('inputPack')
        derived = acquisition.get('derivedAuthorities')
        if status not in {'ready','incomplete'} or not isinstance(missing,list) or not isinstance(resolved,list) or not isinstance(partial,list) or derived != ['digest-pinned-core-workload-images']:
            errors.append(('LAB_BUNDLE_ACQUISITION_LOCK_STATE_INVALID', str(status)))
        else:
            if len(missing) != len(set(str(v) for v in missing)) or any(v not in required_source_authorities for v in missing):
                errors.append(('LAB_BUNDLE_ACQUISITION_MISSING_INVALID', str(missing)))

            def check_locked_artifact(artifact, label):
                if not isinstance(artifact,dict) or set(artifact) != {'name','stagingPath','urls','sha256','sizeBytes'}:
                    errors.append(('LAB_BUNDLE_ACQUISITION_ARTIFACT_FIELDS_INVALID', label)); return
                name=artifact.get('name'); staging_path=artifact.get('stagingPath'); urls=artifact.get('urls'); digest=artifact.get('sha256'); size=artifact.get('sizeBytes')
                if not isinstance(name,str) or not name or '/' in name or '\\' in name:
                    errors.append(('LAB_BUNDLE_ACQUISITION_ARTIFACT_NAME_INVALID', f'{label}:{name}'))
                if not isinstance(staging_path,str) or not staging_path or staging_path.startswith('/') or '\\' in staging_path or any(part in ('','.','..') for part in staging_path.split('/')):
                    errors.append(('LAB_BUNDLE_ACQUISITION_STAGING_PATH_INVALID', f'{label}:{staging_path}'))
                if not isinstance(urls,list) or not (1 <= len(urls) <= 4) or len(set(urls)) != len(urls) or any(not public_https_source_url(u) for u in urls):
                    errors.append(('LAB_BUNDLE_ACQUISITION_RESOLVED_URLS_INVALID', f'{label}:{urls}'))
                if not isinstance(digest,str) or not re.fullmatch(r'[0-9a-f]{64}',digest):
                    errors.append(('LAB_BUNDLE_ACQUISITION_RESOLVED_DIGEST_INVALID', f'{label}:{digest}'))
                if not isinstance(size,int) or isinstance(size,bool) or size <= 0 or size > 32*1024*1024*1024:
                    errors.append(('LAB_BUNDLE_ACQUISITION_RESOLVED_SIZE_INVALID', f'{label}:{size}'))

            all_staging_paths=[]

            def check_authority(item, idx, is_partial):
                required={'id','kind','provider','version','scope','artifacts'} | ({'pendingArtifacts'} if is_partial else set())
                label=('partial' if is_partial else 'resolved')+f'[{idx}]'
                if not isinstance(item,dict) or set(item) != required:
                    errors.append(('LAB_BUNDLE_ACQUISITION_AUTHORITY_FIELDS_INVALID', label)); return ''
                authority_id=str(item.get('id') or '').strip()
                if authority_id not in required_source_authorities:
                    errors.append(('LAB_BUNDLE_ACQUISITION_RESOLVED_ID_INVALID', authority_id))
                if item.get('kind') not in {'kubernetes-manifest','release-artifact','release-artifact-set','image-inventory','oci-archive'}:
                    errors.append(('LAB_BUNDLE_ACQUISITION_RESOLVED_KIND_INVALID', str(item.get('kind'))))
                for key in ('provider','version','scope'):
                    if not isinstance(item.get(key),str) or not item.get(key).strip():
                        errors.append(('LAB_BUNDLE_ACQUISITION_RESOLVED_METADATA_INVALID', f'{label}:{key}'))
                artifacts=item.get('artifacts')
                if not isinstance(artifacts,list) or (not is_partial and not artifacts) or len(artifacts)>16:
                    errors.append(('LAB_BUNDLE_ACQUISITION_ARTIFACTS_INVALID', label))
                else:
                    names=[]
                    for ai,a in enumerate(artifacts):
                        check_locked_artifact(a,f'{label}:artifact[{ai}]')
                        names.append(a.get('name') if isinstance(a,dict) else '')
                        if isinstance(a,dict) and isinstance(a.get('stagingPath'),str):
                            all_staging_paths.append(a['stagingPath'])
                    if len(set(names)) != len(names):
                        errors.append(('LAB_BUNDLE_ACQUISITION_ARTIFACT_DUPLICATE', label))
                if is_partial:
                    pending=item.get('pendingArtifacts')
                    if not isinstance(pending,list) or not pending or len(pending)>16:
                        errors.append(('LAB_BUNDLE_ACQUISITION_PENDING_INVALID', label))
                    else:
                        pending_names=[]
                        for pi,a in enumerate(pending):
                            plabel=f'{label}:pending[{pi}]'
                            if not isinstance(a,dict) or set(a) != {'name','stagingPath','reason','sourceRef','contentAddress'}:
                                errors.append(('LAB_BUNDLE_ACQUISITION_PENDING_FIELDS_INVALID', plabel)); continue
                            for key in ('name','stagingPath','reason','sourceRef','contentAddress'):
                                if not isinstance(a.get(key),str) or not a.get(key):
                                    errors.append(('LAB_BUNDLE_ACQUISITION_PENDING_METADATA_INVALID', f'{plabel}:{key}'))
                            if isinstance(a.get('sourceRef'),str) and not public_https_source_url(a['sourceRef']):
                                errors.append(('LAB_BUNDLE_ACQUISITION_PENDING_SOURCE_INVALID',plabel))
                            if isinstance(a.get('contentAddress'),str) and not re.fullmatch(r'git-sha1:[0-9a-f]{40}',a['contentAddress']):
                                errors.append(('LAB_BUNDLE_ACQUISITION_PENDING_ADDRESS_INVALID',plabel))
                            staging_path=a.get('stagingPath') if isinstance(a,dict) else None
                            if not isinstance(staging_path,str) or not staging_path or staging_path.startswith('/') or '\\' in staging_path or any(part in ('','.','..') for part in staging_path.split('/')):
                                errors.append(('LAB_BUNDLE_ACQUISITION_STAGING_PATH_INVALID',f'{plabel}:{staging_path}'))
                            elif staging_path:
                                all_staging_paths.append(staging_path)
                            pending_names.append(a.get('name') if isinstance(a,dict) else '')
                        if len(set(pending_names)) != len(pending_names):
                            errors.append(('LAB_BUNDLE_ACQUISITION_PENDING_DUPLICATE',label))
                        artifact_names={a.get('name') for a in artifacts if isinstance(a,dict)} if isinstance(artifacts,list) else set()
                        if artifact_names & set(pending_names):
                            errors.append(('LAB_BUNDLE_ACQUISITION_ARTIFACT_PENDING_OVERLAP',label))
                return authority_id

            resolved_ids=[check_authority(item,idx,False) for idx,item in enumerate(resolved)]
            partial_ids=[check_authority(item,idx,True) for idx,item in enumerate(partial)]
            if len(resolved_ids)!=len(set(resolved_ids)):
                errors.append(('LAB_BUNDLE_ACQUISITION_RESOLVED_DUPLICATE', str(resolved_ids)))
            if len(partial_ids)!=len(set(partial_ids)):
                errors.append(('LAB_BUNDLE_ACQUISITION_PARTIAL_DUPLICATE', str(partial_ids)))
            if len(all_staging_paths) != len(set(all_staging_paths)):
                errors.append(('LAB_BUNDLE_ACQUISITION_STAGING_PATH_DUPLICATE', str(all_staging_paths)))
            partitions=[set(resolved_ids),set(partial_ids),set(missing)]
            if any(partitions[i]&partitions[j] for i in range(3) for j in range(i+1,3)):
                errors.append(('LAB_BUNDLE_ACQUISITION_PARTITION_OVERLAP',str([sorted(s) for s in partitions])))
            if set().union(*partitions) != required_source_authorities:
                errors.append(('LAB_BUNDLE_ACQUISITION_AUTHORITY_COVERAGE_INVALID', str(sorted(set().union(*partitions)^required_source_authorities))))

            storage=[item for item in resolved if isinstance(item,dict) and item.get('id')=='replicated-storage-install-manifest']
            if storage:
                item=storage[0]
                artifacts=item.get('artifacts') or []
                if item.get('provider')!='longhorn' or item.get('version')!='v1.12.1' or item.get('scope')!='management-plane-rke2-production-ha-only' or item.get('kind')!='kubernetes-manifest':
                    errors.append(('MANAGEMENT_PLANE_STORAGE_LOCK_IDENTITY_INVALID', str(item)))
                if len(artifacts)!=1 or artifacts[0].get('urls') != ['https://github.com/longhorn/longhorn/releases/download/v1.12.1/longhorn.yaml'] or artifacts[0].get('sha256')!='41648963af867ac1d0c85755fb53cf61cacd57c9bb22e1942e3fb0439eeb04fd' or artifacts[0].get('sizeBytes')!=207054 or artifacts[0].get('stagingPath')!='manifests/replicated-storage-install.yaml':
                    errors.append(('MANAGEMENT_PLANE_STORAGE_LOCK_DIGEST_INVALID', str(item)))
            cnpg=[item for item in resolved if isinstance(item,dict) and item.get('id')=='cloudnative-pg-install-manifest']
            if cnpg:
                item=cnpg[0]; artifacts=item.get('artifacts') or []
                if item.get('provider')!='cloudnative-pg' or item.get('version')!='v1.30.0' or len(artifacts)!=1 or artifacts[0].get('sha256')!='f8bede43fe4ee0d478c2355b204a36876b2ae4faac60f2a9452280b293da3b88' or artifacts[0].get('sizeBytes')!=1262410 or artifacts[0].get('stagingPath')!='manifests/cloudnative-pg-install.yaml':
                    errors.append(('CLOUDNATIVE_PG_SOURCE_LOCK_INVALID',str(item)))

            rke2_partial=[item for item in partial if isinstance(item,dict) and item.get('id')=='rke2-installer-and-offline-artifacts']
            if rke2_partial:
                pending=rke2_partial[0].get('pendingArtifacts') or []
                if len(pending)!=1 or pending[0].get('name')!='install.sh' or pending[0].get('stagingPath')!='rke2/install.sh' or pending[0].get('sourceRef')!='https://github.com/rancher/rke2/blob/d419f09226d50a4777d348e5c53ea1bce3849b77/install.sh' or pending[0].get('contentAddress')!='git-sha1:88c5f55bdfde94f2277465ece2b749c52d86c69b':
                    errors.append(('RKE2_INSTALLER_SOURCE_PROVENANCE_INVALID',str(rke2_partial[0])))
            argocd_partial=[item for item in partial if isinstance(item,dict) and item.get('id')=='argocd-install-manifest']
            if argocd_partial:
                pending=argocd_partial[0].get('pendingArtifacts') or []
                if len(pending)!=1 or pending[0].get('stagingPath')!='manifests/argocd-install.yaml' or pending[0].get('sourceRef')!='https://github.com/argoproj/argo-cd/blob/e95e1be88a2da6c06bff5c2fe1791e4d233ed810/manifests/install.yaml' or pending[0].get('contentAddress')!='git-sha1:e0ff6c401aa18c2c67ba9dcb5f68f2f15853281f':
                    errors.append(('ARGOCD_INSTALL_MANIFEST_SOURCE_PROVENANCE_INVALID',str(argocd_partial[0])))
            argocd_ha_partial=[item for item in partial if isinstance(item,dict) and item.get('id')=='argocd-ha-install-manifest']
            if argocd_ha_partial:
                pending=argocd_ha_partial[0].get('pendingArtifacts') or []
                if len(pending)!=1 or pending[0].get('stagingPath')!='manifests/argocd-ha-install.yaml' or pending[0].get('sourceRef')!='https://github.com/argoproj/argo-cd/blob/e95e1be88a2da6c06bff5c2fe1791e4d233ed810/manifests/ha/install.yaml' or pending[0].get('contentAddress')!='git-sha1:8e0ff973a33bf12ec6e9c1554029cb36931945e8':
                    errors.append(('ARGOCD_HA_INSTALL_MANIFEST_SOURCE_PROVENANCE_INVALID',str(argocd_ha_partial[0])))

            if status == 'incomplete':
                if (not partial_ids and not missing) or pack is not None:
                    errors.append(('LAB_BUNDLE_ACQUISITION_INCOMPLETE_TRUTH_INVALID', 'incomplete requires partial/missing authorities and null inputPack'))
            else:
                if partial_ids or missing or len(resolved_ids)!=len(required_source_authorities) or not isinstance(pack, dict):
                    errors.append(('LAB_BUNDLE_ACQUISITION_READY_TRUTH_INVALID', 'ready requires every source authority fully resolved, no partial/missing, and inputPack'))
                else:
                    urls = pack.get('urls')
                    if not isinstance(urls, list) or not urls or len(urls) > 4 or any(not public_https_source_url(url) for url in urls):
                        errors.append(('LAB_BUNDLE_ACQUISITION_URLS_INVALID', str(urls)))
                    if not re.fullmatch(r'[0-9a-f]{64}', str(pack.get('sha256') or '')):
                        errors.append(('LAB_BUNDLE_ACQUISITION_DIGEST_INVALID', str(pack.get('sha256'))))
                    size = pack.get('sizeBytes')
                    if not isinstance(size, int) or size <= 0 or size > 32*1024*1024*1024:
                        errors.append(('LAB_BUNDLE_ACQUISITION_SIZE_INVALID', str(size)))
                    if pack.get('format') != 'zip':
                        errors.append(('LAB_BUNDLE_ACQUISITION_FORMAT_INVALID', str(pack.get('format'))))
                    for key in ('buildSpecPath','stagingDirectory'):
                        rel = str(pack.get(key) or '')
                        if not rel or rel.startswith('/') or '\\' in rel or any(part in ('','.','..') for part in rel.split('/')):
                            errors.append(('LAB_BUNDLE_ACQUISITION_PATH_INVALID', f'{key}:{rel}'))


def runtime_holds_partition_valid(hold_names, ready_names, locked_names):
    """Runtime suitability is independent of source acquisition.

    A held component is valid while waiting in the acquisition queue and after
    its exact source lock is installed; only disappearance from both partitions
    is invalid.
    """
    return set(hold_names).issubset(set(ready_names) | set(locked_names))


def validate_supply_chain_handoff(root: Path, version: str, components: dict[str,dict], errors: list[tuple[str,str]]) -> None:
    """Unified supply-chain handoff stays derived evidence and never becomes a second source of truth."""
    # V53 unified supply-chain handoff remains derived evidence only. It must
    # bind all S1 transport branches without becoming a second source of truth.
    handoff_plan_path = root/'lab/supply-chain-handoff-plan.json'
    handoff_script = root/'scripts/supply_chain_handoff.py'
    management_batch_script = root/'scripts/acquire_management_workload_batch.py'
    upgrade_source_admission = root/'catalog/component-upgrade-source-admission.json'
    upgrade_source_admission_script = root/'scripts/component_upgrade_source_admission.py'
    if not handoff_plan_path.is_file() or not handoff_script.is_file():
        errors.append(('SUPPLY_CHAIN_HANDOFF_MISSING','SUPPLY_CHAIN_HANDOFF_V1'))
    else:
        handoff = load_json(handoff_plan_path, errors)
        hs = (handoff or {}).get('spec') or {} if isinstance(handoff, dict) else {}
        truth = hs.get('truthModel') or {}
        if handoff.get('kind') != 'SupplyChainHandoffPlan' or hs.get('authority') != 'SUPPLY_CHAIN_HANDOFF_V1' or hs.get('releaseVersion') != version:
            errors.append(('SUPPLY_CHAIN_HANDOFF_AUTHORITY_INVALID','lab/supply-chain-handoff-plan.json'))
        for key in ('derivedEvidenceOnly','stagingNeverPromotesSourceResolution','stagingNeverPromotesRuntimeCertification','physicalPassInferenceForbidden'):
            if truth.get(key) is not True:
                errors.append(('SUPPLY_CHAIN_HANDOFF_TRUTH_MODEL_INVALID',key))
        acquisition = hs.get('componentAcquisition') or {}
        ready_rows = acquisition.get('ready') or []
        review_rows = acquisition.get('reviewBlocked') or []
        locked_rows = acquisition.get('alreadySourceLocked') or []
        hold_rows = acquisition.get('runtimeHolds') or []
        ready_names = {str(row.get('component') or '') for row in ready_rows if isinstance(row, dict)}
        review_names = {str(row.get('component') or '') for row in review_rows if isinstance(row, dict)}
        locked_names = {str(row.get('component') or '') for row in locked_rows if isinstance(row, dict)}
        hold_names = {str(row.get('component') or '') for row in hold_rows if isinstance(row, dict)}
        component_names = set(components)
        if (ready_names & review_names) or (ready_names & locked_names) or (review_names & locked_names) or ready_names | review_names | locked_names != component_names:
            errors.append(('SUPPLY_CHAIN_HANDOFF_COMPONENT_QUEUE_INVALID','component partition drift'))
        else:
            for name in component_names:
                resolved = bool(((components[name].get('spec') or {}).get('source') or {}).get('resolved'))
                if resolved != (name in locked_names):
                    errors.append(('SUPPLY_CHAIN_HANDOFF_COMPONENT_QUEUE_INVALID',f'source binding:{name}'))
        if not runtime_holds_partition_valid(hold_names, ready_names, locked_names):
            errors.append(('SUPPLY_CHAIN_HANDOFF_COMPONENT_QUEUE_INVALID','runtime holds must remain bound to ready-or-locked source state'))
        if len((hs.get('managementWorkloads') or {}).get('externalImages') or []) != 4 or len((hs.get('managementWorkloads') or {}).get('manifestImageResolution') or []) != 4:
            errors.append(('SUPPLY_CHAIN_HANDOFF_MANAGEMENT_COVERAGE_INVALID','external/manifest'))
        if len(hs.get('componentUpgradePairRequirements') or []) != len(components):
            errors.append(('SUPPLY_CHAIN_HANDOFF_UPGRADE_COVERAGE_INVALID',str(len(hs.get('componentUpgradePairRequirements') or []))))
        for marker_text in ('SUPPLY_CHAIN_HANDOFF_V1','SUPPLY_CHAIN_HANDOFF_SEAL_V1','physicalPassInferenceForbidden','componentUpgradePairRequirements','componentUpgradeSourceAdmission','runtimeDependencyTransition','runtimeHolds'):
            if marker_text not in handoff_script.read_text():
                errors.append(('SUPPLY_CHAIN_HANDOFF_SCRIPT_INVALID',marker_text))
    transition_path = root/'catalog/runtime-dependency-transition.json'
    transition_script = root/'scripts/runtime_dependency_transition.py'
    if not transition_path.is_file() or not transition_script.is_file():
        errors.append(('RUNTIME_DEPENDENCY_TRANSITION_MISSING','RUNTIME_DEPENDENCY_TRANSITION_V1'))
    else:
        transition = load_json(transition_path, errors)
        ts = (transition or {}).get('spec') or {} if isinstance(transition, dict) else {}
        status = str(ts.get('status') or '')
        if (transition or {}).get('kind') != 'RuntimeDependencyTransition' or ts.get('authority') != 'RUNTIME_DEPENDENCY_TRANSITION_V1' or status not in {'acquisition-pending','runtime-certification-pending','runtime-certification-partial','complete'}:
            errors.append(('RUNTIME_DEPENDENCY_TRANSITION_INVALID','catalog/runtime-dependency-transition.json'))
        ga = ts.get('gatewayApi') or {}
        if ga.get('currentRelease') != '1.5.1' or ga.get('targetRelease') != '1.6.1' or len(ga.get('assets') or []) != 2:
            errors.append(('RUNTIME_DEPENDENCY_GATEWAY_TRANSITION_INVALID','1.5.1->1.6.1'))
        gateway_source_status = str(ga.get('sourceStatus') or '')
        if status == 'acquisition-pending' and gateway_source_status != 'pending-byte-acquisition':
            errors.append(('RUNTIME_DEPENDENCY_GATEWAY_SOURCE_STATE_INVALID',f'{status}:{gateway_source_status}'))
        elif status in {'runtime-certification-pending','runtime-certification-partial','complete'} and gateway_source_status != 'source-acquired':
            errors.append(('RUNTIME_DEPENDENCY_GATEWAY_SOURCE_STATE_INVALID',f'{status}:{gateway_source_status}'))
        if gateway_source_status == 'source-acquired':
            for asset in ga.get('assets') or []:
                asset_path = root/'catalog'/'runtime-dependencies'/'gateway-api'/'1.6.1'/str(asset.get('name') or '')
                if asset_path.is_symlink() or not asset_path.is_file() or asset_path.stat().st_size != int(asset.get('size') or 0) or sha256(asset_path) != 'sha256:' + str(asset.get('sha256') or ''):
                    errors.append(('RUNTIME_DEPENDENCY_GATEWAY_ASSET_BYTES_INVALID',str(asset.get('name') or '<empty>')))
        elif gateway_source_status == 'pending-byte-acquisition':
            for asset in ga.get('assets') or []:
                asset_path = root/'catalog'/'runtime-dependencies'/'gateway-api'/'1.6.1'/str(asset.get('name') or '')
                if asset_path.exists() or asset_path.is_symlink():
                    errors.append(('RUNTIME_DEPENDENCY_GATEWAY_PENDING_WITH_BYTES',str(asset.get('name') or '<empty>')))
        if (ts.get('kgateway') or {}).get('targetRelease') != '2.4.1' or (ts.get('cilium') or {}).get('targetRelease') != '1.20.1':
            errors.append(('RUNTIME_DEPENDENCY_NETWORK_STACK_INVALID','kgateway/cilium'))
        cilium_runtime_status = str((ts.get('cilium') or {}).get('runtimeStatus') or '')
        if status == 'runtime-certification-partial':
            evidence = ts.get('runtimeEvidence') or {}
            required_partial = {
                'authority':'RKE2_NETWORK_RUNTIME_CERTIFICATION_V1',
                'rke2Version':'v1.34.10+rke2r1',
                'topology':'single-node',
                'gatewayApiRelease':'1.6.1',
                'ciliumRelease':'1.20.1',
                'kgatewayRelease':'2.4.1',
                'singleNodeRKE2Certified':True,
                'productTopologyHACertified':False,
                'physicalCertified':False,
                'holdAutoReleased':False,
            }
            if cilium_runtime_status != 'single-node-rke2-certified-ha-pending' or any(evidence.get(k) != value for k,value in required_partial.items()) or not re.fullmatch(r'[0-9a-f]{40}', str(evidence.get('sourceCommitSHA') or '')) or not str(evidence.get('sourceRunId') or '').isdigit() or not str(evidence.get('artifactId') or '').isdigit() or not re.fullmatch(r'sha256:[0-9a-f]{64}', str(evidence.get('artifactDigest') or '')):
                errors.append(('RUNTIME_DEPENDENCY_PARTIAL_EVIDENCE_INVALID','catalog/runtime-dependency-transition.json'))
        elif status == 'runtime-certification-pending' and cilium_runtime_status != 'dependency-transition-required':
            errors.append(('RUNTIME_DEPENDENCY_CILIUM_STATUS_INVALID',cilium_runtime_status))
        for marker_text in ('RUNTIME_DEPENDENCY_TRANSITION_V1','EXPECTED_GATEWAY_ASSETS','dependency-transition-required','physicalPassInference'):
            if marker_text not in transition_script.read_text():
                errors.append(('RUNTIME_DEPENDENCY_TRANSITION_SCRIPT_INVALID',marker_text))

    if not upgrade_source_admission.is_file() or not upgrade_source_admission_script.is_file():
        errors.append(('COMPONENT_UPGRADE_SOURCE_ADMISSION_MISSING','catalog/component-upgrade-source-admission.json'))
    else:
        ua = load_json(upgrade_source_admission, errors)
        rows = (ua or {}).get('components') or []
        if (ua or {}).get('authority') != 'COMPONENT_UPGRADE_SOURCE_ADMISSION_V1' or len(rows) != len(components):
            errors.append(('COMPONENT_UPGRADE_SOURCE_ADMISSION_INVALID',str(len(rows))))
        admitted = [r for r in rows if r.get('status') == 'admitted-for-acquisition']
        review = [r for r in rows if r.get('status') == 'review-required']
        install_only = [r for r in rows if r.get('status') == 'install-only-first-product-release']
        if len(admitted) + len(review) + len(install_only) != len(rows):
            errors.append(('COMPONENT_UPGRADE_SOURCE_ADMISSION_STATUS_INVALID',str(len(rows))))
        if len(admitted) != 19 or review or len(install_only) != 1 or install_only[0].get('component') != 'secure-namespace-foundation':
            errors.append(('COMPONENT_UPGRADE_SOURCE_ADMISSION_REVIEW_CLOSURE_INVALID',f'admitted={len(admitted)} review={len(review)} install_only={len(install_only)}'))
        for row in admitted:
            evidence = row.get('reviewEvidence') or []
            if not evidence or any((ev or {}).get('kind') != 'upstream-release-history' or not str((ev or {}).get('reference') or '').startswith('https://') or not str((ev or {}).get('summary') or '').strip() for ev in evidence):
                errors.append(('COMPONENT_UPGRADE_SOURCE_ADMISSION_EVIDENCE_INVALID',str(row.get('component'))))
        for marker_text in ('COMPONENT_UPGRADE_SOURCE_ADMISSION_V1','strictUpgradeDirectionRequired','admitted-for-acquisition','install-only-first-product-release','reviewEvidenceRequiredForAdmission','historicalVersionFabricationForbidden'):
            if marker_text not in upgrade_source_admission_script.read_text():
                errors.append(('COMPONENT_UPGRADE_SOURCE_ADMISSION_SCRIPT_INVALID',marker_text))
        historical_batch = root/'scripts/acquire_historical_upgrade_batch.py'
        if not historical_batch.is_file():
            errors.append(('HISTORICAL_UPGRADE_BATCH_MISSING','HISTORICAL_UPGRADE_STAGED_BATCH_V1'))
        else:
            hb = historical_batch.read_text()
            for marker_text in ('HISTORICAL_UPGRADE_STAGED_BATCH_V1','--from-upgrade-admission','runtimeCertificationImplied','install-historical','acquire_upstream_tagged_source.py'):
                if marker_text not in hb:
                    errors.append(('HISTORICAL_UPGRADE_BATCH_INVALID',marker_text))

        # V59 closes the historical external-tagged-source-set software gap.
        # Gateway API and Snapshot Controller predecessors must be reproducibly
        # acquirable from full commit-pinned recipes; the recipe remains input
        # authority only and never implies source/runtime certification.
        tagged_runner = root/'scripts/acquire_upstream_tagged_source.py'
        tagged_schema = root/'schemas/tagged-source-acquisition-recipe.schema.json'
        tagged_expected = {
            ('gateway-api','1.5.0'): '3797b631d20f9ff4e2b4571f62d91d84a1fbdf5a',
            ('snapshot-controller','8.4.0'): 'f21cb02763e7cd6a7fc84846f106b83119b5371d',
        }
        if not tagged_runner.is_file() or not tagged_schema.is_file():
            errors.append(('TAGGED_SOURCE_ACQUISITION_PATH_MISSING','TAGGED_SOURCE_ACQUISITION_RECIPE_V1'))
        else:
            tr = tagged_runner.read_text()
            for marker_text in ('TAGGED_SOURCE_ACQUISITION_RECIPE_V1','deterministic-zip-from-official-tag-files','TAGGED_SOURCE_TAG_COMMIT_DRIFT','install-historical','raw.githubusercontent.com'):
                if marker_text not in tr:
                    errors.append(('TAGGED_SOURCE_ACQUISITION_RUNNER_INVALID',marker_text))
            admitted_by_component = {str(r.get('component')):r for r in admitted}
            for (component_name, previous_version), commit_sha in tagged_expected.items():
                recipe_path = root/'catalog/tagged-source-recipes'/component_name/f'{previous_version}.json'
                recipe = load_json(recipe_path, errors) if recipe_path.is_file() else None
                row = admitted_by_component.get(component_name) or {}
                if not isinstance(recipe, dict):
                    errors.append(('TAGGED_SOURCE_RECIPE_MISSING',f'{component_name}:{previous_version}')); continue
                md, rs = recipe.get('metadata') or {}, recipe.get('spec') or {}
                if recipe.get('kind') != 'TaggedSourceAcquisitionRecipe' or rs.get('authority') != 'TAGGED_SOURCE_ACQUISITION_RECIPE_V1':
                    errors.append(('TAGGED_SOURCE_RECIPE_AUTHORITY_INVALID',component_name))
                if md.get('component') != component_name or md.get('version') != previous_version or rs.get('tag') != 'v'+previous_version or rs.get('commitSHA') != commit_sha:
                    errors.append(('TAGGED_SOURCE_RECIPE_IDENTITY_INVALID',component_name))
                if row.get('previousVersion') != previous_version or rs.get('releaseURL') != row.get('source'):
                    errors.append(('TAGGED_SOURCE_RECIPE_ADMISSION_DRIFT',component_name))
                recipe_files = rs.get('files') or []
                archive_names = [str(x.get('archivePath') or '') for x in recipe_files if isinstance(x,dict)]
                if not recipe_files or len(archive_names) != len(set(archive_names)) or rs.get('licenseFile') not in archive_names or not any((x or {}).get('render') is True for x in recipe_files):
                    errors.append(('TAGGED_SOURCE_RECIPE_FILESET_INVALID',component_name))

    if not management_batch_script.is_file():
        errors.append(('MANAGEMENT_WORKLOAD_BATCH_MISSING','scripts/acquire_management_workload_batch.py'))
    else:
        mb = management_batch_script.read_text()
        for marker_text in ('MANAGEMENT_WORKLOAD_STAGED_BATCH_V1','workload-oci','verify-external','layoutTreeDigest'):
            if marker_text not in mb:
                errors.append(('MANAGEMENT_WORKLOAD_BATCH_INVALID',marker_text))


def validate_source_runtime_surfaces(root: Path, version: str, current_program_authority: str, current_phase_doc: Path | None, errors: list[tuple[str,str]]) -> None:
    """Bare-metal provider, runtime-upgrade, MCP support-job and roadmap surfaces must not drift."""
    # V42 source-owned Bare Metal provider / runtime-upgrade / MCP support-job authority must not drift.
    redfish_path = root/'internal/bootmedia/redfish.go'
    redfish_test_path = root/'internal/bootmedia/redfish_test.go'
    if not redfish_path.is_file() or not redfish_test_path.is_file():
        errors.append(('REDFISH_BOOT_MEDIA_PROVIDER_MISSING', 'internal/bootmedia'))
    else:
        redfish_text = redfish_path.read_text()
        for marker_text in ('REDFISH_BOOT_MEDIA_PROVIDER_V1','CredentialResolver','VirtualMedia.InsertMedia','ComputerSystem.Reset','SetBasicAuth'):
            if marker_text not in redfish_text:
                errors.append(('REDFISH_BOOT_MEDIA_PROVIDER_CONTRACT_INVALID', marker_text))
        if 'InsecureSkipVerify: true' in redfish_text or 'InsecureSkipVerify:true' in redfish_text:
            errors.append(('REDFISH_BOOT_MEDIA_TLS_BYPASS_FORBIDDEN', 'InsecureSkipVerify=true'))
    runtime_upgrade = root/'internal/runtimeupgrade/upgrade.go'
    runtime_upgrade_test = root/'internal/runtimeupgrade/upgrade_test.go'
    if not runtime_upgrade.is_file() or not runtime_upgrade_test.is_file():
        errors.append(('COMPONENT_RUNTIME_UPGRADE_EXECUTOR_MISSING', 'internal/runtimeupgrade'))
    else:
        upgrade_text = runtime_upgrade.read_text()
        for marker_text in ('COMPONENT_RUNTIME_UPGRADE_V1','FromSourceLockDigest','ToSourceLockDigest','OperationToken','FAILURE_RECOVERY','REMOVE_OLD_VERSION','recovery-only-no-fake-rollback'):
            if marker_text not in upgrade_text:
                errors.append(('COMPONENT_RUNTIME_UPGRADE_EXECUTOR_INVALID', marker_text))
    mcp_text = (root/'internal/api/mcp.go').read_text()
    if 'support_bundle_request' not in mcp_text or 'support.bundle.generate' not in (root/'internal/api/support_bundle_async.go').read_text():
        errors.append(('MCP_SUPPORT_BUNDLE_JOB_PARITY_MISSING', 'support_bundle_request'))
    if current_phase_doc is not None and current_phase_doc.is_file():
        status_text = current_phase_doc.read_text(encoding='utf-8')
        for marker_text in (
            current_program_authority,
            'PROGRAM_PROGRESS_MODEL_V2',
            version,
            'W1-core-closure-blitz',
            'SERVICE_HEALTH_AUTHORITY_V1',
            'INCIDENT_AUTHORITY_V1',
            'SLO_ERROR_BUDGET_AUTHORITY_V1',
            'MANAGEMENT_WORKLOAD_OCI_ARCHIVE_PENDING',
            'MCP_EXTERNAL_CLIENT_INTEROP_MATRIX_PENDING',
            'OKD_CONNECTED_MANAGED_INSTALL_PENDING',
            'OKD_OC_MIRROR_V2_ACQUISITION_PENDING',
            'COMPONENT_RUNTIME_UPGRADE_MATRIX_PENDING',
        ):
            if marker_text and marker_text not in status_text:
                errors.append(('CURRENT_PROGRAM_STATUS_INVALID', marker_text))
        if 'SERVICE_HEALTH_AUTHORITY_PENDING' in status_text or 'INCIDENT_AUTHORITY_PENDING' in status_text or 'SLO_ERROR_BUDGET_AUTHORITY_PENDING' in status_text:
            errors.append(('CURRENT_PROGRAM_STATUS_STALE_J6_BLOCKER', 'J6 source authority is already implemented'))


def validate_blueprint_set(root: Path, components: dict[str,dict], errors: list[tuple[str,str]]) -> list[Path]:
    """Current blueprints must reference the current catalog and include their enabled dependencies."""
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
    return blueprint_files


def validate_tenant_plan_catalog(root: Path, errors: list[tuple[str,str]]) -> int:
    """Tenant plan catalog is machine data with unique plan names."""
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
    return plan_count


def validate_policy_templates(root: Path, errors: list[tuple[str,str]]) -> list[Path]:
    """Policy template set must exist and be non-empty."""
    policy_files = sorted((root/'catalog/policies').glob('*.yaml'))
    if not policy_files:
        errors.append(('POLICY_TEMPLATE_SET_EMPTY','catalog/policies'))
    return policy_files


def validate_migration_sequence(root: Path, errors: list[tuple[str,str]]) -> None:
    """Migration filenames form one monotonic, gap-free schema sequence."""
    migration_files = sorted((root/'migrations').glob('[0-9][0-9][0-9][0-9]_*.sql'))
    nums = [int(p.name[:4]) for p in migration_files]
    if not nums or nums != list(range(1, max(nums)+1)):
        errors.append(('MIGRATION_SEQUENCE_INVALID', str(nums)))


def validate_test_suite_authority(root: Path, errors: list[tuple[str,str]]) -> int:
    """Count owner test functions and reject shadowed definitions in the suite.

    A repeated method name inside one test class silently replaces the earlier test,
    so a named regression can disappear while the suite still reports green. Only the
    structural shadowing is asserted here; test content stays with its owner package.
    """
    checked = 0
    suite = sorted((root/'tests').glob('test_*.py')) + sorted((root/'scripts').glob('test_*.py'))
    for path in suite:
        try:
            tree = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
        except (SyntaxError, ValueError) as exc:
            errors.append(('TEST_SUITE_UNPARSEABLE', f'{path.relative_to(root)}:{exc}'))
            continue
        def scoped(body, label):
            names: dict[str,int] = {}
            for member in body:
                if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    names[member.name] = names.get(member.name, 0) + 1
                    if names[member.name] > 1:
                        errors.append(('TEST_METHOD_SHADOWED', f'{path.relative_to(root)}:{label}{member.name}'))
                elif isinstance(member, ast.ClassDef):
                    scoped(member.body, f'{label}{member.name}.')
        scoped(tree.body, '')
        checked += sum(1 for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name.startswith('test_'))
    return checked


DATASET_GUARD_REFERENCE = re.compile(r'if\s*\(\s*(?:button|control|el|target)\.dataset\.([A-Za-z][A-Za-z0-9]*)\s*\)\s*\{')
EXPLICIT_MUTATION_KEYS = re.compile(r'explicitMutationKeys\s*=\s*new Set\(\[(.*?)\]\)', re.S)


def camel_to_kebab(name: str) -> str:
    return re.sub(r'([A-Z])', lambda match: '-' + match.group(1).lower(), name)


def console_action_state_failures(js_text: str, markup_text: str, label: str) -> list[str]:
    """Reject client-side preconditions that read a value the markup never emits.

    A console mutation button is disabled when operationalActionStateReason() returns a
    reason, and those guards identify the target record through ``button.dataset.<key>``.
    If the attribute is emitted as a valueless flag, or not at all, the guard branch
    never runs: the button stays enabled against a record that no longer satisfies the
    state contract, and the operator only learns about it from the rejected API write.
    Bindings may be emitted by the static page or by a rendered template, so both are
    treated as one markup surface.
    """
    failures: list[str] = []
    for key in sorted(set(DATASET_GUARD_REFERENCE.findall(js_text))):
        attribute = camel_to_kebab(key)
        if re.search(rf'\bdata-{re.escape(attribute)}\s*=', markup_text) is None:
            failures.append(
                f'{label}: guard reads dataset.{key} but no data-{attribute}="…" value is emitted, '
                'so the precondition is silently skipped'
            )
    declared = EXPLICIT_MUTATION_KEYS.search(js_text)
    if declared:
        for key in sorted({k for k in re.findall(r"'([A-Za-z][A-Za-z0-9]*)'", declared.group(1))}):
            attribute = camel_to_kebab(key)
            if re.search(rf'\bdata-{re.escape(attribute)}\b', markup_text) is None:
                failures.append(
                    f'{label}: explicitMutationKeys lists {key} but no data-{attribute} attribute is ever emitted'
                )
    return failures


CONSOLE_SURFACES = (
    ('webconsole/static/app.js', 'webconsole/static/index.html'),
    ('cmd/platform-installer/static/app.js', 'cmd/platform-installer/static/index.html'),
)


def validate_console_action_state_contract(root: Path, errors: list[tuple[str, str]]) -> int:
    """Count the mutation guards the consoles declare and require each one to be bound."""
    checked = 0
    for script_relative, page_relative in CONSOLE_SURFACES:
        script_path = root / script_relative
        if not script_path.is_file():
            continue
        js_text = script_path.read_text(encoding='utf-8')
        page_path = root / page_relative
        markup_text = js_text + '\n' + (page_path.read_text(encoding='utf-8') if page_path.is_file() else '')
        checked += len(set(DATASET_GUARD_REFERENCE.findall(js_text)))
        for failure in console_action_state_failures(js_text, markup_text, script_relative):
            errors.append(('CONSOLE_ACTION_STATE_GUARD_UNBOUND', failure))
    return checked


def main() -> int:
    # The canonical control host is Windows. Validation details can contain
    # Persian text, so never let the active legacy console code page hide the
    # actual invariant failure behind UnicodeEncodeError.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="backslashreplace")
            except (AttributeError, OSError):
                pass
    parser = argparse.ArgumentParser()
    parser.add_argument('root', nargs='?', default='.')
    args = parser.parse_args()
    root = Path(args.root).resolve()
    errors: list[tuple[str,str]] = []
    files = repository_source_files(root, errors)

    validate_repository_hygiene(root, files, errors)

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
    current_program_authority, current_phase_doc = validate_release_documentation_truth(root, version, release_name, errors)
    if (root/'go.mod').exists() and (root/'go.mod').read_text().splitlines()[0].strip() != 'module platform.4so.io/factory':
        errors.append(('GO_MODULE_IDENTITY','go.mod'))

    persian_string_count = validate_persian_writing_integration(root, errors)
    mcp_route_count = validate_mcp_route_parity(root, errors)
    mcp_family_count = validate_mcp_action_registry(root, errors)
    product_api_route_count = validate_product_api_contract(root, errors, mcp_route_count)
    resource_scope_family_count, resource_scope_classified_count = validate_resource_scope_registry(root, errors)

    # Deployment, image-build and machine-schema contracts.
    validate_release_recipes(root, errors)
    validate_management_workload_image_plan(root, version, errors)
    validate_management_maintenance_toolset(root, errors)
    validate_deployment_surface(root, errors)
    schema_files = validate_schema_set(root, errors)

    # Catalog, component lifecycle and boot-media authorities.
    components = validate_component_catalog(root, errors)
    validate_component_runtime_certification(root, components, errors)
    validate_component_runtime_upgrade_matrix(root, components, errors)
    validate_boot_media_contract(root, errors)

    # Supply-chain acquisition, admission and handoff authorities.
    acquisition_toolchain_count = validate_upstream_acquisition_toolchain(root, errors)
    validate_release_build_toolchain(root, version, errors)
    validate_upstream_admission(root, components, errors)
    validate_lab_bundle_acquisition_lock(root, errors)
    validate_supply_chain_handoff(root, version, components, errors)

    # Source-runtime, roadmap and product-surface parity.
    validate_source_runtime_surfaces(root, version, current_program_authority, current_phase_doc, errors)
    blueprint_files = validate_blueprint_set(root, components, errors)
    plan_count = validate_tenant_plan_catalog(root, errors)
    policy_files = validate_policy_templates(root, errors)
    validate_migration_sequence(root, errors)
    owner_test_count = validate_test_suite_authority(root, errors)
    action_state_guard_count = validate_console_action_state_contract(root, errors)

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
    print('MCP_ACTION_REGISTRY_GATE_PASS', mcp_family_count)
    print('PRODUCT_API_CONTRACT_GATE_PASS', product_api_route_count)
    print('RESOURCE_SCOPE_REGISTRY_GATE_PASS', resource_scope_family_count, resource_scope_classified_count)
    print('PERSIAN_WRITING_GATE_PASS', persian_string_count)
    print('UPSTREAM_ACQUISITION_TOOLCHAIN_GATE_PASS', acquisition_toolchain_count)
    print('TEST_SUITE_AUTHORITY_GATE_PASS', owner_test_count)
    print('CONSOLE_ACTION_STATE_GATE_PASS', action_state_guard_count)
    print('REPOSITORY_VALIDATION_PASS', len(files))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
