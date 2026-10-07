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
            if disposition != 'tool-read' or key[0] != 'POST' or row.get('idempotencyRequired') is not True:
                errors.append(('MCP_ROUTE_PARITY_DURABLE_READ_INVALID', f'{key[0]} {key[1]}'))
        elif row.get('idempotencyRequired') is True:
            errors.append(('MCP_ROUTE_PARITY_IDEMPOTENCY_WITHOUT_DURABILITY', f'{key[0]} {key[1]}'))
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
    """Generated Product API contract must cover the same route set and carry owner scope without owning business logic."""
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
    """No scope inference: every family is owner-classified or remains visibly unclassified."""
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
        if dockerfile.name in {'Dockerfile','Dockerfile.agent','Dockerfile.probe'}:
            if 'internal/buildinfo.Version=$VERSION' not in docker:
                errors.append(('CONTAINER_BINARY_VERSION_INJECTION_MISSING', rel))
            source_regex="grep -Eq '^[0-9a-f]{40}$'"
            source_ldflag='internal/buildinfo.SourceCommit=$SOURCE_COMMIT'
            from_rows=[line.strip() for line in docker.splitlines() if line.strip().startswith('FROM ')]
            if (
                'ARG SOURCE_COMMIT' not in docker
                or docker.count(source_regex)!=1
                or docker.count(source_ldflag)!=1
                or len(from_rows)!=2
                or from_rows[0]!='FROM ${GO_BUILD_IMAGE} AS build'
                or from_rows[1]!='FROM ${RUNTIME_IMAGE}'
            ):
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
                verify_management_workload_archive_receipt_structure(archive_receipt_path)
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
    expected_owners = {'internal/bootstrap/object_storage_probe.go','internal/disasterrecovery/manifests.go','internal/lifecycle/manifests.go','scripts/lab_runner.py'}
    owners = doc.get('ownerSurfaces')
    if not isinstance(owners, list) or set(owners) != expected_owners or any(not (root/rel).is_file() for rel in expected_owners):
        errors.append(('MANAGEMENT_MAINTENANCE_TOOLSET_OWNER_SURFACE_INVALID', str(owners)))
    aws = doc.get('awsCli') or {}
    if aws.get('repository') != 'public.ecr.aws/aws-cli/aws-cli' or aws.get('version') != aws.get('tag') or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', str(aws.get('version') or '')) or not str(aws.get('selectionEvidenceURL') or '').startswith('https://'):
        errors.append(('MANAGEMENT_MAINTENANCE_TOOLSET_AWS_SELECTION_INVALID', str(aws)))
    compat = doc.get('compatibilityRequirements') or {}
    if compat != {'defaultNonRootCommandProbe': True,'rootOverrideCommandProbe': True,'postgresqlClientMajor': 17,'s3EndpointOverrideRequired': True,'offlineImageBuildRequired': True,'runtimeCertified': False,'physicalCertified': False}:
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
    schema_files = sorted((root/'schemas').rglob('*.json'))
    if not schema_files:
        errors.append(('SCHEMA_SET_EMPTY','schemas'))
    for p in schema_files:
        load_json(p, errors)
    return schema_files


def validate_component_catalog(root: Path, errors: list[tuple[str,str]]) -> dict[str,dict]:
    """Component contracts, source bundles and the dependency graph form one catalog authority."""
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
    expected_runtime_policy = {'sourceBinding':'exact-component-release-and-source-lock','executorBinding':'component-owned-no-generic-runtime-certification-claim','requiredLifecycleStages':runtime_stages,'replacementPolicy':'resolved-source-replacement-denied-without-explicit-versioned-migration','runtimeSuitabilityBinding':'persistent-independent-of-source-acquisition','coreClosureScope':'mandatory-components-only','optionalRuntimeHoldSemantics':'profile-blocking-not-core-freeze-blocking'}
    if not isinstance(runtime_cert, dict) or runtime_cert.get('apiVersion') != 'platform.4so.io/v1alpha1' or runtime_cert.get('kind') != 'ComponentRuntimeCertificationRegistry' or ((runtime_cert.get('metadata') or {}).get('name') != 'COMPONENT_RUNTIME_CERTIFICATION_REGISTRY_V1'):
        errors.append(('COMPONENT_RUNTIME_CERTIFICATION_REGISTRY_INVALID','catalog/component-runtime-certification.json'))
        return
    runtime_spec = runtime_cert.get('spec') or {}
    if runtime_spec.get('policy') != expected_runtime_policy:
        errors.append(('COMPONENT_RUNTIME_CERTIFICATION_POLICY_INVALID', str(runtime_spec.get('policy'))))
    holds = runtime_spec.get('runtimeSuitabilityHolds')
    hold_by_name = {}
    if not isinstance(holds, list):
        errors.append(('COMPONENT_RUNTIME_SUITABILITY_HOLDS_INVALID','not-list')); holds = []
    for hold in holds:
        name = str((hold or {}).get('component') or '') if isinstance(hold, dict) else ''
        status = str((hold or {}).get('status') or '') if isinstance(hold, dict) else ''
        authority = str((hold or {}).get('authority') or '') if isinstance(hold, dict) else ''
        reason = str((hold or {}).get('reason') or '') if isinstance(hold, dict) else ''
        evidence = str((hold or {}).get('evidenceURL') or '') if isinstance(hold, dict) else ''
        if not name or name in hold_by_name or name not in components or status not in {'dependency-transition-required','review-required'} or not authority or not reason or not evidence.startswith('https://'):
            errors.append(('COMPONENT_RUNTIME_SUITABILITY_HOLD_INVALID', name or '<empty>')); continue
        hold_by_name[name] = hold
    rows = runtime_spec.get('components')
    runtime_rows = {}
    if not isinstance(rows, list):
        errors.append(('COMPONENT_RUNTIME_CERTIFICATION_COVERAGE_INVALID','components-not-list')); rows = []
    for row in rows:
        name = str((row or {}).get('component') or '') if isinstance(row, dict) else ''
        if not name or name in runtime_rows:
            errors.append(('COMPONENT_RUNTIME_CERTIFICATION_IDENTITY_INVALID', name or '<empty>')); continue
        runtime_rows[name] = row
    if set(runtime_rows) != set(components):
        errors.append(('COMPONENT_RUNTIME_CERTIFICATION_COVERAGE_INVALID', f'missing={sorted(set(components)-set(runtime_rows))};extra={sorted(set(runtime_rows)-set(components))}'))
    for name, row in runtime_rows.items():
        if name not in components or not isinstance(row, dict): continue
        component_spec = components[name].get('spec') or {}
        if row.get('release') != component_spec.get('release'):
            errors.append(('COMPONENT_RUNTIME_CERTIFICATION_RELEASE_DRIFT', f'{name}:{row.get("release")}!={component_spec.get("release")}'))
        source = component_spec.get('source') or {}; resolved = bool(source.get('resolved')); expected_digest = str(source.get('sourceLockDigest') or '').strip() if resolved else ''
        if resolved and not re.fullmatch(r'sha256:[0-9a-f]{64}', expected_digest):
            errors.append(('COMPONENT_RUNTIME_CERTIFICATION_SOURCE_DRIFT', f'{name}:resolved-component-has-invalid-source-lock'))
        expected_source = {'status':'source-ready' if resolved else 'blocked-source-lock','resolved':resolved,'sourceLockDigest':expected_digest}
        if row.get('sourceBinding') != expected_source: errors.append(('COMPONENT_RUNTIME_CERTIFICATION_SOURCE_DRIFT', name))


def validate_component_runtime_upgrade_matrix(root: Path, components: dict[str,dict], errors: list[tuple[str,str]]) -> None:
    """Upgrade admission is deliberately stricter than executor availability: two exact source locks or pending."""
    upgrade_matrix_path = root/'catalog/component-runtime-upgrade-matrix.json'
    upgrade_matrix = load_json(upgrade_matrix_path, errors) if upgrade_matrix_path.exists() else None
    if not isinstance(upgrade_matrix, dict) or upgrade_matrix.get('authority') != 'COMPONENT_RUNTIME_UPGRADE_MATRIX_V2' or upgrade_matrix.get('kind') != 'ComponentRuntimeUpgradeMatrix':
        errors.append(('COMPONENT_RUNTIME_UPGRADE_MATRIX_INVALID','catalog/component-runtime-upgrade-matrix.json'))
        return
    matrix_rows = upgrade_matrix.get('components') or []
    matrix_by_name = {str((row or {}).get('component') or ''): row for row in matrix_rows if isinstance(row, dict)}
    if set(matrix_by_name) != set(components):
        errors.append(('COMPONENT_RUNTIME_UPGRADE_MATRIX_COVERAGE_INVALID', f'missing={sorted(set(components)-set(matrix_by_name))};extra={sorted(set(matrix_by_name)-set(components))}'))


def validate_boot_media_contract(root: Path, errors: list[tuple[str,str]]) -> None:
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
    toolchain_path = root/'catalog/upstream-acquisition-toolchain.json'
    toolchain = load_json(toolchain_path, errors) if toolchain_path.exists() else None
    acquisition_toolchain_count = 0
    if not isinstance(toolchain, dict):
        errors.append(('UPSTREAM_ACQUISITION_TOOLCHAIN_INVALID', 'missing-or-not-object'))
    else:
        spec = toolchain.get('spec') or {}; tools = spec.get('tools') or []
        if toolchain.get('apiVersion') != 'platform.4so.io/v1alpha1' or toolchain.get('kind') != 'UpstreamAcquisitionToolchain': errors.append(('UPSTREAM_ACQUISITION_TOOLCHAIN_INVALID','type'))
        acquisition_toolchain_count=len(tools) if isinstance(tools,list) else 0
    return acquisition_toolchain_count


def final_exact_release_environment_contract_errors(source: str) -> list[str]:
    """Validate source-bound C9 release-environment handoff without formatting-sensitive markers."""
    try: tree = ast.parse(source)
    except (SyntaxError, ValueError): return ['SEALER_SOURCE_UNPARSEABLE']
    functions = {node.name: node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
    contract_errors=[]
    def called_name(call): return call.func.id if isinstance(call.func,ast.Name) else None
    def assigned_names(target):
        if isinstance(target,ast.Name): return [target.id]
        if isinstance(target,(ast.Tuple,ast.List)): return [item.id for item in target.elts if isinstance(item,ast.Name)]
        return []
    for function_name,prefix in (('resume_existing_evidence','RESUME'),('execute','EXECUTE')):
        function=functions.get(function_name)
        if function is None: contract_errors.append(f'{prefix}_FUNCTION_MISSING'); continue
        source_bound_names=set()
        for node in ast.walk(function):
            if not isinstance(node,(ast.Assign,ast.AnnAssign)): continue
            value=node.value
            if not isinstance(value,ast.Call) or called_name(value)!='exact_source_toolchain_lock' or len(value.args)<2: continue
            if not (isinstance(value.args[0],ast.Name) and value.args[0].id=='root' and isinstance(value.args[1],ast.Name) and value.args[1].id=='source_sha'): continue
            targets=node.targets if isinstance(node,ast.Assign) else [node.target]
            for target in targets:
                names=assigned_names(target)
                if names: source_bound_names.add(names[0])
        if not source_bound_names: contract_errors.append(f'{prefix}_SOURCE_TOOLCHAIN_LOCK_MISSING'); continue
        environment_bound=False
        for node in ast.walk(function):
            if not isinstance(node,ast.Call) or called_name(node)!='require_exact_release_environment': continue
            for keyword in node.keywords:
                if keyword.arg=='toolchain_lock' and isinstance(keyword.value,ast.Name) and keyword.value.id in source_bound_names: environment_bound=True; break
            if environment_bound: break
        if not environment_bound: contract_errors.append(f'{prefix}_ENVIRONMENT_TOOLCHAIN_LOCK_MISSING')
    return contract_errors


def validate_release_build_toolchain(root: Path, version: str, errors: list[tuple[str,str]]) -> None:
    release_toolchain_path = root/'lab/release-build-toolchain-lock.json'
    release_toolchain = load_json(release_toolchain_path, errors) if release_toolchain_path.exists() else None
    if not isinstance(release_toolchain, dict): errors.append(('RELEASE_BUILD_TOOLCHAIN_AUTHORITY_INVALID','missing-or-not-object'))
    final_sealer=root/'scripts/seal_final_exact_release.py'
    if final_sealer.is_file():
        for contract_error in final_exact_release_environment_contract_errors(final_sealer.read_text(encoding='utf-8',errors='strict')):
            errors.append(('FINAL_EXACT_RELEASE_ENVIRONMENT_PREFLIGHT_INVALID',contract_error))


def validate_upstream_admission(root: Path, components: dict[str,dict], errors: list[tuple[str,str]]) -> None:
    admission_path=root/'catalog/upstream-admission.json'
    if not admission_path.is_file(): errors.append(('UPSTREAM_ADMISSION_INVALID','catalog/upstream-admission.json'))


def validate_lab_bundle_acquisition_lock(root: Path, errors: list[tuple[str,str]]) -> None:
    acquisition_path=root/'lab/appliance-bundle-acquisition-lock.json'
    if not acquisition_path.is_file(): errors.append(('LAB_BUNDLE_ACQUISITION_LOCK_MISSING',str(acquisition_path.relative_to(root))))


def runtime_holds_partition_valid(hold_names, ready_names, locked_names):
    return set(hold_names).issubset(set(ready_names) | set(locked_names))


def validate_supply_chain_handoff(root: Path, version: str, components: dict[str,dict], errors: list[tuple[str,str]]) -> None:
    handoff_plan_path=root/'lab/supply-chain-handoff-plan.json'
    if not handoff_plan_path.is_file(): errors.append(('SUPPLY_CHAIN_HANDOFF_MISSING','SUPPLY_CHAIN_HANDOFF_V1'))


def validate_source_runtime_surfaces(root: Path, version: str, current_program_authority: str, current_phase_doc: Path | None, errors: list[tuple[str,str]]) -> None:
    redfish_path=root/'internal/bootmedia/redfish.go'; redfish_test_path=root/'internal/bootmedia/redfish_test.go'
    if not redfish_path.is_file() or not redfish_test_path.is_file(): errors.append(('REDFISH_BOOT_MEDIA_PROVIDER_MISSING','internal/bootmedia'))
    if current_phase_doc is not None and current_phase_doc.is_file():
        status_text=current_phase_doc.read_text(encoding='utf-8')
        if current_program_authority not in status_text: errors.append(('CURRENT_PROGRAM_STATUS_INVALID',current_program_authority))


def validate_blueprint_set(root: Path, components: dict[str,dict], errors: list[tuple[str,str]]) -> list[Path]:
    blueprint_files=sorted((root/'blueprints').glob('*.json'))
    if not blueprint_files: errors.append(('BLUEPRINT_SET_EMPTY','blueprints'))
    return blueprint_files


def validate_tenant_plan_catalog(root: Path, errors: list[tuple[str,str]]) -> int:
    plans_path=root/'catalog/tenancy/plans.json'; plans=load_json(plans_path,errors) if plans_path.exists() else None
    if not isinstance(plans,dict): errors.append(('TENANT_PLAN_CATALOG_INVALID',str(plans_path.relative_to(root)))); return 0
    plan_rows=(plans.get('spec') or {}).get('plans') or []
    return len(plan_rows)


def validate_policy_templates(root: Path, errors: list[tuple[str,str]]) -> list[Path]:
    policy_files=sorted((root/'catalog/policies').glob('*.yaml'))
    if not policy_files: errors.append(('POLICY_TEMPLATE_SET_EMPTY','catalog/policies'))
    return policy_files


def validate_migration_sequence(root: Path, errors: list[tuple[str,str]]) -> None:
    migration_files=sorted((root/'migrations').glob('[0-9][0-9][0-9][0-9]_*.sql')); nums=[int(p.name[:4]) for p in migration_files]
    if not nums or nums!=list(range(1,max(nums)+1)): errors.append(('MIGRATION_SEQUENCE_INVALID',str(nums)))


def validate_test_suite_authority(root: Path, errors: list[tuple[str,str]]) -> int:
    checked=0; suite=sorted((root/'tests').glob('test_*.py'))+sorted((root/'scripts').glob('test_*.py'))
    for path in suite:
        try: tree=ast.parse(path.read_text(encoding='utf-8'),filename=str(path))
        except (SyntaxError,ValueError) as exc: errors.append(('TEST_SUITE_UNPARSEABLE',f'{path.relative_to(root)}:{exc}')); continue
        def scoped(body,label):
            names={}
            for member in body:
                if isinstance(member,(ast.FunctionDef,ast.AsyncFunctionDef)):
                    names[member.name]=names.get(member.name,0)+1
                    if names[member.name]>1: errors.append(('TEST_METHOD_SHADOWED',f'{path.relative_to(root)}:{label}{member.name}'))
                elif isinstance(member,ast.ClassDef): scoped(member.body,f'{label}{member.name}.')
        scoped(tree.body,''); checked+=sum(1 for n in ast.walk(tree) if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name.startswith('test_'))
    return checked


DATASET_GUARD_REFERENCE = re.compile(r'if\s*\(\s*(?:button|control|el|target)\.dataset\.([A-Za-z][A-Za-z0-9]*)\s*\)\s*\{')
EXPLICIT_MUTATION_KEYS = re.compile(r'explicitMutationKeys\s*=\s*new Set\(\[(.*?)\]\)', re.S)


def camel_to_kebab(name: str) -> str:
    return re.sub(r'([A-Z])', lambda match: '-' + match.group(1).lower(), name)


def console_action_state_failures(js_text: str, markup_text: str, label: str) -> list[str]:
    failures=[]
    for key in sorted(set(DATASET_GUARD_REFERENCE.findall(js_text))):
        attribute=camel_to_kebab(key)
        if re.search(rf'\bdata-{re.escape(attribute)}\s*=',markup_text) is None:
            failures.append(f'{label}: guard reads dataset.{key} but no data-{attribute}="…" value is emitted, so the precondition is silently skipped')
    declared=EXPLICIT_MUTATION_KEYS.search(js_text)
    if declared:
        for key in sorted({k for k in re.findall(r"'([A-Za-z][A-Za-z0-9]*)'",declared.group(1))}):
            attribute=camel_to_kebab(key)
            if re.search(rf'\bdata-{re.escape(attribute)}\b',markup_text) is None: failures.append(f'{label}: explicitMutationKeys lists {key} but no data-{attribute} attribute is ever emitted')
    return failures


CONSOLE_SURFACES=(('webconsole/static/app.js','webconsole/static/index.html'),('cmd/platform-installer/static/app.js','cmd/platform-installer/static/index.html'))


def validate_console_action_state_contract(root: Path, errors: list[tuple[str,str]]) -> int:
    checked=0
    for script_relative,page_relative in CONSOLE_SURFACES:
        script_path=root/script_relative
        if not script_path.is_file(): continue
        js_text=script_path.read_text(encoding='utf-8'); page_path=root/page_relative; markup_text=js_text+'\n'+(page_path.read_text(encoding='utf-8') if page_path.is_file() else '')
        checked+=len(set(DATASET_GUARD_REFERENCE.findall(js_text)))
        for failure in console_action_state_failures(js_text,markup_text,script_relative): errors.append(('CONSOLE_ACTION_STATE_GUARD_UNBOUND',failure))
    return checked


CORE_LOCAL_ONLY_WORKFLOWS=(
    '.github/workflows/mcp-external-interop-campaign.yml',
    '.github/workflows/mcp-external-interop-seal.yml',
    '.github/workflows/mcp-external-receipt-admission.yml',
    '.github/workflows/mcp-external-receipt-recovery.yml',
    '.github/workflows/final-exact-release-seal.yml',
)


def validate_core_local_only_workflows(root: Path, errors: list[tuple[str,str]]) -> None:
    for rel in CORE_LOCAL_ONLY_WORKFLOWS:
        path=root/rel
        if not path.is_file(): errors.append(('CORE_LOCAL_ONLY_WORKFLOW_MISSING',rel)); continue
        text=path.read_text(encoding='utf-8',errors='strict')
        if 'local-only-authority-notice:' not in text or 'contents: read' not in text: errors.append(('CORE_LOCAL_ONLY_WORKFLOW_AUTHORITY_DRIFT',rel))
        for forbidden in ('contents: write','git push','actions/checkout','secrets.','gh run','workflow_run:','\n  push:'):
            if forbidden in text: errors.append(('CORE_LOCAL_ONLY_WORKFLOW_MUTATION_FORBIDDEN',f'{rel}:{forbidden.strip()}'))
        for stale in ('make c7w-','make c9-','/secure/'):
            if stale in text: errors.append(('CORE_LOCAL_ONLY_WORKFLOW_STALE_HANDOFF',f'{rel}:{stale}'))


def validate_no_remote_ci_mutation_authority(root: Path, errors: list[tuple[str,str]]) -> None:
    workflow_root=root/'.github'/'workflows'
    if not workflow_root.is_dir(): return
    forbidden_patterns=(
        ('contents-write',re.compile(r'(?mi)^\s*contents\s*:\s*write\s*(?:#.*)?$')),
        ('inline-contents-write',re.compile(r'(?mi)^\s*permissions\s*:\s*\{[^}\n]*\bcontents\s*:\s*write\b[^}\n]*\}\s*(?:#.*)?$')),
        ('write-all',re.compile(r'(?mi)^\s*permissions\s*:\s*write-all\s*(?:#.*)?$')),
        ('git-push',re.compile(r'(?i)(?<![A-Za-z0-9_-])git\s+push(?=\s|$)')),
    )
    for path in sorted(list(workflow_root.glob('*.yml'))+list(workflow_root.glob('*.yaml'))):
        text=path.read_text(encoding='utf-8',errors='strict'); rel=path.relative_to(root).as_posix()
        for label,pattern in forbidden_patterns:
            if pattern.search(text): errors.append(('REMOTE_CI_MUTATION_AUTHORITY_FORBIDDEN',f'{rel}:{label}'))


WINDOWS_LOCAL_EXECUTION_CONTRACTS = {
    'scripts/project_runtime.py': (
        'if os.name=="nt":',
        'GetProcessTimes',
        'msvcrt.locking',
        'CREATE_NEW_PROCESS_GROUP',
        '"taskkill"',
    ),
    'scripts/admit_mcp_external_receipt.py': (
        'if os.name=="nt":',
        'import msvcrt',
        'import fcntl',
        'msvcrt.LK_LOCK',
        'fcntl.LOCK_EX',
    ),
    'scripts/seal_mcp_external_interop.py': (
        'def _fsync_directory(path:Path)->None:',
        'if os.name!="posix":',
        '_fsync_directory(path.parent)',
    ),
    'scripts/fetch_mcp_external_audit_window.py': (
        'core._fsync_directory(path.parent)',
    ),
    'scripts/run_go_package_shard.py': (
        'CREATE_NEW_PROCESS_GROUP',
        '"taskkill"',
        '"/T"',
        '_terminate_tree(process,force=False)',
        '_terminate_tree(process,force=True)',
    ),
    'scripts/run_smoke_shard.py': (
        'CREATE_NEW_PROCESS_GROUP',
        '"taskkill"',
        '"/T"',
        '_terminate_tree(process,force=False)',
        '_terminate_tree(process,force=True)',
    ),
    'scripts/verify_release.py': (
        'CREATE_NEW_PROCESS_GROUP',
        '"taskkill"',
        '"/T"',
        '_terminate_tree(process,force=False)',
        '_terminate_tree(process,force=True)',
    ),
    'scripts/postgresql_runtime_certify.py': (
        'CREATE_NEW_PROCESS_GROUP',
        '"taskkill"',
        '"/T"',
        'process_group_kwargs()',
    ),
}


def validate_windows_local_execution_contract(root: Path, errors: list[tuple[str, str]]) -> None:
    for rel, required in WINDOWS_LOCAL_EXECUTION_CONTRACTS.items():
        path=root/rel
        if not path.is_file():
            errors.append(('WINDOWS_LOCAL_EXECUTION_CONTRACT_MISSING',rel))
            continue
        source=path.read_text(encoding='utf-8',errors='strict')
        missing=[token for token in required if token not in source]
        if missing:
            errors.append(('WINDOWS_LOCAL_EXECUTION_CONTRACT_DRIFT',f"{rel}:{','.join(missing)}"))
    project=(root/'scripts/project_runtime.py')
    if project.is_file() and 'import argparse, datetime, fcntl' in project.read_text(encoding='utf-8',errors='strict'):
        errors.append(('WINDOWS_LOCAL_EXECUTION_POSIX_IMPORT_FORBIDDEN','scripts/project_runtime.py'))
    pg=(root/'scripts/postgresql_runtime_certify.py')
    if pg.is_file() and 'start_new_session=True' in pg.read_text(encoding='utf-8',errors='strict'):
        errors.append(('WINDOWS_LOCAL_EXECUTION_HARDCODED_POSIX_SPAWN','scripts/postgresql_runtime_certify.py'))

def main() -> int:
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
    validate_core_local_only_workflows(root, errors)
    validate_no_remote_ci_mutation_authority(root, errors)
    validate_windows_local_execution_contract(root, errors)

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
    installer_example = root/'examples'/'installer-host'/'deployment.example.json'
    if installer_example.is_file():
        example_doc = load_json(installer_example, errors)
        example_version = str(((example_doc or {}).get('metadata') or {}).get('version') or '') if isinstance(example_doc, dict) else ''
        if example_version != version:
            errors.append(('INSTALLER_EXAMPLE_VERSION_DRIFT', f'{example_version} != {version}'))
    current_program_authority, current_phase_doc = validate_release_documentation_truth(root, version, release_name, errors)
    if (root/'go.mod').exists() and (root/'go.mod').read_text().splitlines()[0].strip() != 'module platform.4so.io/factory':
        errors.append(('GO_MODULE_IDENTITY','go.mod'))

    persian_string_count = validate_persian_writing_integration(root, errors)
    mcp_route_count = validate_mcp_route_parity(root, errors)
    mcp_family_count = validate_mcp_action_registry(root, errors)
    product_api_route_count = validate_product_api_contract(root, errors, mcp_route_count)
    resource_scope_family_count, resource_scope_classified_count = validate_resource_scope_registry(root, errors)

    validate_release_recipes(root, errors)
    validate_management_workload_image_plan(root, version, errors)
    validate_management_maintenance_toolset(root, errors)
    validate_deployment_surface(root, errors)
    schema_files = validate_schema_set(root, errors)

    components = validate_component_catalog(root, errors)
    validate_component_runtime_certification(root, components, errors)
    validate_component_runtime_upgrade_matrix(root, components, errors)
    try:
        verify_runtime_evidence_registry(root)
    except Exception as exc:
        errors.append(('RUNTIME_EVIDENCE_REGISTRY_INVALID', str(exc)))
    validate_boot_media_contract(root, errors)

    acquisition_toolchain_count = validate_upstream_acquisition_toolchain(root, errors)
    validate_release_build_toolchain(root, version, errors)
    validate_upstream_admission(root, components, errors)
    validate_lab_bundle_acquisition_lock(root, errors)
    validate_supply_chain_handoff(root, version, components, errors)

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
