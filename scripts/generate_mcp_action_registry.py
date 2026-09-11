#!/usr/bin/env python3
"""Generate family-level MCP action registry from the canonical route-parity registry.

The route registry is generated from internal/api/server.go and remains the source
of truth for every stable API route. This family registry is only a summarized,
human/agent-readable view; it must never reclassify a route independently.
"""
from __future__ import annotations
import json, sys
from collections import defaultdict
from pathlib import Path

root=Path(sys.argv[1] if len(sys.argv)>1 else '.').resolve()
route_path=root/'internal/api/mcp_route_parity_registry.json'
out_path=root/'internal/api/mcp_action_registry.json'
routes=json.loads(route_path.read_text())
if routes.get('authority')!='MCP_ROUTE_PARITY_AUTHORITY_V1':
    raise SystemExit('route parity authority mismatch')
by_family=defaultdict(list)
for row in routes.get('routes',[]):
    by_family[row['family']].append(row)

families=[]
for family, rows in sorted(by_family.items()):
    callable_rows=[r for r in rows if r['disposition']!='security-excluded']
    excluded=[r for r in rows if r['disposition']=='security-excluded']
    mutation_count=sum(1 for r in rows if r['method']!='GET')
    if callable_rows:
        disposition='typed-tool-complete'
        tools=[r['toolName'] for r in callable_rows]
        rationale=(
            f"All {len(callable_rows)} AI-callable stable route(s) in this family are represented by fixed-route MCP tools generated from "
            "MCP_ROUTE_PARITY_AUTHORITY_V1 and reuse the canonical REST handler. "
            f"{len(excluded)} route(s) remain explicitly security-excluded." if excluded else
            f"All {len(callable_rows)} stable route(s) in this family are represented by fixed-route MCP tools generated from MCP_ROUTE_PARITY_AUTHORITY_V1 and reuse the canonical REST handler."
        )
    else:
        disposition='security-excluded'
        tools=[]
        rationale=f"All {len(excluded)} stable route(s) in this family are security-excluded by MCP_ROUTE_PARITY_AUTHORITY_V1; no raw/generic authority is exposed."
    families.append({
        'family':family,
        'routeCount':len(rows),
        'mutationCount':mutation_count,
        'callableRouteCount':len(callable_rows),
        'securityExcludedRouteCount':len(excluded),
        'disposition':disposition,
        'toolNames':tools,
        'rationale':rationale,
    })

out={
  'apiVersion':'platform.4so.io/v1alpha1',
  'kind':'MCPProductActionRegistry',
  'authority':'MCP_PRODUCT_ACTION_REGISTRY_V1',
  'spec':{
    'policy':{
      'genericMutationToolAllowed':False,
      'rawShellSSHSQLSecretsAllowed':False,
      'selfDelegationMutationAllowed':False,
      'pendingParityFailsC7W':True,
      'securityExclusionRequiresRationale':True,
      'routeParityAuthority':'MCP_ROUTE_PARITY_AUTHORITY_V1',
      'durableMutationAuthority':'MCP_DURABLE_CONTROL_JOB_AUTHORITY_V1',
      'fixedRouteCanonicalHandlerReuse':True,
    },
    'families':families,
  }
}
out_path.write_text(json.dumps(out,indent=2,sort_keys=False)+'\n')
print(json.dumps({'familyCount':len(families),'typedToolComplete':sum(f['disposition']=='typed-tool-complete' for f in families),'securityExcluded':sum(f['disposition']=='security-excluded' for f in families)},sort_keys=True))
