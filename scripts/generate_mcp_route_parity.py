#!/usr/bin/env python3
import json,re,sys
from pathlib import Path
root=Path(sys.argv[1] if len(sys.argv)>1 else '.').resolve()
server=(root/'internal/api/server.go').read_text()
scope_path=root/'internal/api/resource_scope_registry.json'
scope_registry={}
if scope_path.is_file():
    scope_data=json.loads(scope_path.read_text())
    if scope_data.get('authority')!='RESOURCE_SCOPE_REGISTRY_V1': raise SystemExit('resource scope registry authority mismatch')
    scope_registry={str(row.get('family') or ''):(str(row.get('scope') or 'UNCLASSIFIED'),str(row.get('status') or 'OWNER_REVIEW_REQUIRED')) for row in scope_data.get('families',[]) if isinstance(row,dict)}
routes=re.findall(r's\.mux\.HandleFunc\("(GET|POST|PUT|DELETE|PATCH) (/api/v1/[^\"]+)',server)

EXCLUDED_PREFIXES={
 '/api/v1/mcp/trusted-clients','/api/v1/mcp/delegation-grants','/api/v1/git-credentials',
}
EXCLUDED_EXACT={
 ('POST','/api/v1/service-accounts/{id}/tokens'),
 ('POST','/api/v1/service-accounts/{id}/tokens/{tokenId}/revoke'),
 ('POST','/api/v1/service-accounts/{id}/tokens/{tokenId}/rotate'),
 ('POST','/api/v1/operations'),('POST','/api/v1/operations/{id}/transition'),('POST','/api/v1/operations/{id}/claim'),('POST','/api/v1/operations/{id}/lease/renew'),
 ('POST','/api/v1/operations/{id}/attempt/start'),('POST','/api/v1/operations/{id}/attempt/verify'),('POST','/api/v1/operations/{id}/attempt/failure'),('POST','/api/v1/operations/{id}/attempt/complete'),
 ('POST','/api/v1/operations/{id}/cancel/ack'),('POST','/api/v1/operations/{id}/compensation/plan'),('POST','/api/v1/operations/{id}/compensation/forward/{stepKey}/complete'),('POST','/api/v1/operations/{id}/compensation/start'),('POST','/api/v1/operations/{id}/compensation/claim-next'),('POST','/api/v1/operations/{id}/compensation/{stepKey}/complete'),('POST','/api/v1/operations/{id}/compensation/{stepKey}/failure'),('POST','/api/v1/operations/{id}/steps'),('POST','/api/v1/operations/{id}/steps/{phase}/{stepKey}/trace'),
 ('GET','/api/v1/operations/{id}/evidence/{evidenceId}/payload'),('GET','/api/v1/support-bundle-jobs/{id}/download'),
 ('GET','/api/v1/clusters/{id}/mutation-rbac-manifest'),('POST','/api/v1/clusters/{id}/mutation-rbac-manifest'),('GET','/api/v1/clusters/{id}/revocation-rbac-manifest'),('POST','/api/v1/clusters/{id}/revocation-rbac-acknowledgement'),
 ('POST','/api/v1/finops/usage-measurements'),('POST','/api/v1/finops/capacity-observations'),
 ('POST','/api/v1/ai/control-jobs/{id}/resolve-recovery'),
}
READLIKE_POST={
 '/api/v1/blueprints/authoring-roundtrip','/api/v1/blueprints/validate','/api/v1/compatibility/evaluate','/api/v1/blueprints/resolve','/api/v1/plans','/api/v1/blueprint-releases/compare','/api/v1/installations/plans','/api/v1/notification-routing/preview','/api/v1/external-registry/admission','/api/v1/runtime-closure-reports/verify',
 '/api/v1/edge/boot-attestations/assess','/api/v1/edge/local-ai/profiles/validate','/api/v1/application-platform/resolve',
}
ADMIN_MARKERS=(
 '/finops/rate-cards','/finops/budget-policies', '/identity/saml-brokers','/identity/group-mappings','/identity/admin-jobs/','/compliance/profiles','/compliance/waivers','/catalog-trust-keys','/catalog-releases','/blueprint-releases','/git-providers','/organizations','/service-accounts','/notification-destinations','/notification-routes','/recovery-checkpoints','/backup-policies','/restore-runs/{id}/approve','/upgrade-campaigns/{id}/approve','/upgrade-campaigns/{id}/cancel','/clusters/{id}/revoke','/clusters/{id}/agent-certificates','/cluster-imports/{id}/approve','/cluster-imports/{id}/revoke','/baseline-deployments/{id}/approve','/baseline-deployments/{id}/rollback','/runtime-certifications/{id}/revoke','/tenants/{id}/approve','/tenants/{id}/delete','/provider-profiles','/provider-clusters/{id}/approve','/provider-clusters/{id}/delete','/marketplace/installations/{id}/approve','/marketplace/installations/{id}/uninstall',
)
CONFIRM={
 ('POST','/api/v1/organizations/{id}/memberships/{subject}/revoke'):('X-Confirm-Revoke','revoke-organization-membership'),
 ('POST','/api/v1/service-accounts/{id}/revoke'):('X-Confirm-Revoke','revoke-service-account'),
 ('POST','/api/v1/cluster-imports/{id}/revoke'):('X-Confirm-Revoke','revoke-cluster-import'),
 ('POST','/api/v1/clusters/{id}/revoke'):('X-Confirm-Revoke','revoke-cluster-agent'),
 ('POST','/api/v1/clusters/{id}/agent-certificates/{certId}/revoke'):('X-Confirm-Revoke','revoke-agent-certificate'),
 ('POST','/api/v1/notification-destinations/{id}/disable'):('X-Confirm-Disable','disable-notification-destination'),
 ('POST','/api/v1/tenants/{id}/delete'):('X-Confirm-Delete','delete-tenant-namespace'),
 ('POST','/api/v1/provider-clusters/{id}/delete'):('X-Confirm-Delete','delete-provider-cluster'),
 ('POST','/api/v1/workspaces/{id}/virtual-clusters/{virtualClusterId}/delete'):('X-Confirm-Delete','delete-virtual-cluster'),
 ('POST','/api/v1/marketplace/installations/{id}/uninstall'):('X-Confirm-Uninstall','remove-marketplace-installation'),
}

def family(path):
    seg=path[len('/api/v1/'):].split('/')[0]
    return seg or 'root'
def tool_name(method,path):
    pieces=['api',method.lower()]
    for seg in path[len('/api/v1/'):].split('/'):
        if seg.startswith('{'):
            pieces += ['by', re.sub(r'[^a-z0-9]+','_',seg[1:-1].lower()).strip('_')]
        else:
            pieces.append(re.sub(r'[^a-z0-9]+','_',seg.lower()).strip('_'))
    return '_'.join(filter(None,pieces))[:180]
def action(path):
    seg=[x for x in path[len('/api/v1/'):].split('/') if not x.startswith('{')]
    return '_'.join(seg[1:] or seg[:1])
def disposition(method,path):
    if any(path.startswith(p) for p in EXCLUDED_PREFIXES) or (method,path) in EXCLUDED_EXACT:
        return 'security-excluded'
    if method=='GET' or (method=='POST' and path in READLIKE_POST): return 'tool-read'
    if path.endswith('/approve') or any(marker in path for marker in ADMIN_MARKERS): return 'tool-admin'
    return 'tool-operate'
def exclusion_reason(method,path):
    if path.startswith('/api/v1/mcp/trusted-clients') or path.startswith('/api/v1/mcp/delegation-grants'):
        return 'MCP client/delegation authority is managed by human/admin product workflows; an MCP client cannot modify its own trust or delegation.'
    if path.startswith('/api/v1/git-credentials'):
        return 'Credential lifecycle may expose or rotate secret material and is intentionally not model-callable.'
    if path.startswith('/api/v1/service-accounts') and '/tokens' in path:
        return 'Service-account token lifecycle can issue or rotate bearer secrets and is intentionally not model-callable.'
    if path.startswith('/api/v1/operations') and method == 'POST':
        return 'Low-level worker/state-machine mutation is executor-internal; AI must request the owning product workflow instead of driving operation internals.'
    if '/evidence/' in path and path.endswith('/payload'):
        return 'Raw evidence payload retrieval is excluded; AI consumes bounded redacted evidence projections.'
    if path.endswith('/download'):
        return 'Raw/binary support payload download is excluded; AI consumes metadata and sealed evidence references.'
    if 'rbac-manifest' in path or 'rbac-acknowledgement' in path:
        return 'Raw target RBAC bootstrap/revocation material is excluded from model payloads.'
    if (method,path) in {('POST','/api/v1/finops/usage-measurements'),('POST','/api/v1/finops/capacity-observations')}:
        return 'Measured FinOps telemetry is a trusted collector and financial-evidence boundary; AI clients may read/showback but cannot fabricate ingestion evidence.'
    if (method,path) == ('POST','/api/v1/ai/control-jobs/{id}/resolve-recovery'):
        return 'Indeterminate MCP mutation recovery is a human operator readback/evidence decision; the initiating MCP client cannot resolve its own ambiguous outcome.'
    return 'Sensitive/raw/internal authority is intentionally excluded from MCP; use the higher-level product workflow.'

def risk(d,path):
    if d=='tool-read': return 'low'
    if d=='tool-admin': return 'high'
    if any(x in path for x in ('restore','upgrade','rollback','revoke','delete','uninstall','maintenance-runs','node-lifecycle-actions')): return 'high'
    return 'medium'
entries=[]
for method,path in routes:
    d=disposition(method,path); params=re.findall(r'\{([^}]+)\}',path); conf=CONFIRM.get((method,path))
    route_family=family(path); route_scope,route_scope_status=scope_registry.get(route_family,('UNCLASSIFIED','OWNER_REVIEW_REQUIRED'))
    entries.append({'method':method,'path':path,'family':route_family,'action':action(path),'disposition':d,'toolName':tool_name(method,path) if d!='security-excluded' else '', 'risk':risk(d,path),'pathParams':params,'resourceScope':route_scope,'resourceScopeStatus':route_scope_status,'confirmationHeader':conf[0] if conf else '', 'confirmationValue':conf[1] if conf else '', 'exclusionReason':exclusion_reason(method,path) if d=='security-excluded' else '', 'durableJob':d in ('tool-operate','tool-admin'),'idempotencyRequired':d in ('tool-operate','tool-admin')})
from collections import Counter
counts=Counter(e['disposition'] for e in entries)
out={'authority':'MCP_ROUTE_PARITY_AUTHORITY_V1','source':'internal/api/server.go','routeCount':len(entries),'counts':dict(sorted(counts.items())),'routes':entries}
path=root/'internal/api/mcp_route_parity_registry.json'; path.write_text(json.dumps(out,indent=2,sort_keys=True)+'\n')
print(json.dumps({'routeCount':len(entries),'counts':dict(counts)},sort_keys=True))
