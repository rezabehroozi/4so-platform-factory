#!/usr/bin/env python3
"""Headless console smoke over intentionally empty, mocked authority responses.

This proves navigation, responsive layout, RTL/LTR switching and client-side
rendering only. It does not represent external Appliance or cluster runtime
certification.
"""
from __future__ import annotations

from pathlib import Path
import argparse
import json
import shutil
import os
import re
import subprocess
import sys
import tempfile

from playwright.sync_api import sync_playwright


PROFILE = {
    "id": "evaluation-single-node",
    "displayName": "Evaluation single node",
    "description": "Local evaluation profile",
    "minNodes": 1,
    "recommendedNodes": 1,
    "production": False,
    "default": True,
    "supportedConnectivity": ["connected", "restricted-egress"],
}

def smoke_evidence_dir(root: Path) -> Path:
    configured = os.environ.get("PLATFORM_FACTORY_SMOKE_EVIDENCE_DIR", "").strip()
    target = Path(configured).resolve() if configured else Path(tempfile.mkdtemp(prefix="4so-ui-smoke-"))
    target.mkdir(parents=True, exist_ok=True)
    return target


def inline_document(static_dir: Path, *, installer: bool = False) -> str:
    html = (static_dir / "index.html").read_text(encoding="utf-8")
    css = (static_dir / "styles.css").read_text(encoding="utf-8")
    js = (static_dir / "app.js").read_text(encoding="utf-8")
    if installer:
        js = js.replace(
            "token: sessionStorage.getItem('platformInstallerToken') || ''",
            "token: 'test-value'",
        )
    html, css_count = re.subn(
        r'<link\b(?=[^>]*\brel=["\']stylesheet["\'])(?=[^>]*\bhref=["\']/styles\.css["\'])[^>]*?/?>',
        lambda _: f"<style>{css}</style>",
        html,
        count=1,
        flags=re.IGNORECASE,
    )
    if css_count != 1:
        raise RuntimeError("UI smoke could not inline /styles.css")
    html, js_count = re.subn(
        r'<script\b(?=[^>]*\bsrc=["\']/app\.js["\'])[^>]*?>\s*</script>',
        lambda _: "<script>" + js.replace("</script>", "<\\/script>") + "</script>",
        html,
        count=1,
        flags=re.IGNORECASE,
    )
    if js_count != 1:
        raise RuntimeError("UI smoke could not inline /app.js")
    return html


def prepare_page(page, document: str, *, installer: bool) -> None:
    page.evaluate(
        """() => {
          const makeStore = () => {
            const values = new Map();
            return {
              getItem: key => values.has(key) ? values.get(key) : null,
              setItem: (key, value) => values.set(key, String(value)),
              removeItem: key => values.delete(key),
              clear: () => values.clear()
            };
          };
          Object.defineProperty(window, 'localStorage', {value: makeStore(), configurable: true});
          Object.defineProperty(window, 'sessionStorage', {value: makeStore(), configurable: true});
          window.setInterval = () => 0;
          window.scrollTo = () => {};
        }"""
    )
    if installer:
        mock = """async (input, init={}) => {
          const path = String(input).replace(/^https?:\\/\\/[^/]+/, '').split('?')[0];
          let body = {};
          if (path === '/healthz') body = {status: 'ok', version: 'test-version'};
          else if (path === '/api/v1/status') body = {executionEnabled: false, run: null};
          else if (path === '/api/v1/access/status') body = {transport: {mode: 'http-loopback', listen: '127.0.0.1:9080', transportProtected: false, loopbackOnly: true, insecureOverride: false}, token: {authentication: 'bearer-token', source: 'generated-file', fingerprint: 'sha256:1234567890abcdef', tokenFile: 'bootstrap-token', rotatedAt: '2026-08-06T20:00:00Z'}};
          else if (path === '/api/v1/ssh/trust/status') body = {privateKeyStored: false, knownHostsStored: false, knownHostsRef: 'trust://installer/ssh-known-hosts', entries: []};
          else if (path === '/api/v1/bundle/status') body = {state: 'BLOCKED', verified: false, error: 'No live Bundle in UI smoke'};
          else if (path === '/api/v1/preflight') body = {state: 'NOT_RUN', checks: []};
          else if (path === '/api/v1/field-evidence/report' || path === '/api/v1/diagnostics/report') return new Response(JSON.stringify({error: 'No installation run available in UI smoke'}), {status: 409, headers: {'content-type': 'application/json'}});
          else if (path === '/api/v1/profiles') body = [__PROFILE__];
          else if (path === '/api/v1/integrations') body = {};
          else if (['/api/v1/gitops/status','/api/v1/ha/status','/api/v1/airgap/status'].includes(path)) body = {state: 'NOT_STARTED'};
          else if (path === '/api/v1/disaster-recovery/runs' || path === '/api/v1/lifecycle/runs' || path.startsWith('/api/v1/lifecycle/backups/')) body = [];
          return new Response(JSON.stringify(body), {status: 200, headers: {'content-type': 'application/json'}});
        }""".replace("__PROFILE__", json.dumps(PROFILE, separators=(",", ":")))
    else:
        mock = """async (input, init={}) => {
          const path = String(input).replace(/^https?:\\/\\/[^/]+/, '').split('?')[0];
          let body = [];
          if (path === '/auth/session') body = {name: 'Local operator', sub: 'local-development'};
          else if (path === '/api/v1/version') body = {version: 'test-version'};
          else if (path === '/api/v1/installations/profiles') body = [__PROFILE__];
          else if (path === '/api/v1/installations/integrations') body = {};
          else if (path === '/api/v1/git-authority') body = {method:'GIT_PROVIDER_CREDENTIAL_REFERENCE_V1', secretMaterialPersisted:false, providers:[{id:'gitp_ui',name:'internal-forgejo',kind:'FORGEJO',baseUrl:'https://git.internal',credentialId:'gitcred_ui',default:true,state:'ACTIVE'}], credentials:[{id:'gitcred_ui',revision:1,name:'internal-forgejo',username:'platform-admin',secretRef:'env://FORGEJO_TOKEN',state:'ACTIVE'}]};
          else if (path === '/api/v1/catalog/summary') body = {componentCount: 1, digest: 'sha256:' + '0'.repeat(64), certification: {}, risk: {}};
          else if (path === '/api/v1/catalog/components') body = [{metadata:{name:'ui-component'},spec:{displayName:'UI Component',category:'platform',release:'1.0.0',mandatory:true,compatibility:{distributionProfiles:['rke2']}}}];
          else if (path === '/api/v1/tenancy/plans') body = {small:{name:'small'}};
          else if (path === '/api/v1/blueprints/authoring-contract') body = {method:'BLUEPRINT_VISUAL_API_AUTHORING_PARITY_V1',schemaVersion:1,strictUnknownFields:true,fieldCount:27,fields:[{path:'apiVersion',uiControlId:'blueprint-api-version'},{path:'kind',uiControlId:'blueprint-kind'},{path:'metadata.name',uiControlId:'blueprint-name'},{path:'metadata.version',uiControlId:'blueprint-version'},{path:'spec.description',uiControlId:'blueprint-description'},{path:'spec.compatibility.kubernetes.minVersion',uiControlId:'blueprint-k8s-min',options:['1.34','1.35']},{path:'spec.compatibility.kubernetes.maxVersion',uiControlId:'blueprint-k8s-max',options:['1.34','1.35']},{path:'spec.compatibility.architectures',uiControlId:'blueprint-architectures'},{path:'spec.compatibility.distributionProfiles',uiControlId:'blueprint-distribution-list'},{path:'spec.delivery.mode',uiControlId:'blueprint-delivery-mode'},{path:'spec.delivery.repository',uiControlId:'blueprint-repository'},{path:'spec.delivery.revision',uiControlId:'blueprint-revision'},{path:'spec.delivery.revisionType',uiControlId:'blueprint-revision-type'},{path:'spec.delivery.ociRegistry',uiControlId:'blueprint-registry'},{path:'spec.components[].name',uiControlId:'blueprint-component-list'},{path:'spec.components[].enabled',uiControlId:'blueprint-component-list'},{path:'spec.components[].settings',uiControlId:'blueprint-component-list'},{path:'spec.tenancy.mode',uiControlId:'blueprint-tenancy-mode'},{path:'spec.tenancy.plans',uiControlId:'blueprint-tenant-plans'},{path:'spec.tenancy.deletionPolicy',uiControlId:'blueprint-deletion-policy'},{path:'spec.governance.approvalRequiredFor',uiControlId:'blueprint-approval-risks'},{path:'spec.governance.enforceDigestImages',uiControlId:'blueprint-enforce-digest-images'},{path:'spec.governance.allowPlaintextSecrets',uiControlId:'blueprint-allow-plaintext-secrets'},{path:'spec.certification.requiredLevel',uiControlId:'blueprint-certification'},{path:'spec.certification.evidenceRetentionDays',uiControlId:'blueprint-evidence-days'},{path:'spec.fieldOwnership[].path',uiControlId:'blueprint-field-ownership'},{path:'spec.fieldOwnership[].policy',uiControlId:'blueprint-field-ownership'}]};
          else if (path === '/api/v1/blueprints/authoring-roundtrip') { const bp = JSON.parse(init.body || '{}'); body={method:'BLUEPRINT_VISUAL_API_AUTHORING_PARITY_V1',fieldCount:27,blueprint:bp,canonicalJson:JSON.stringify(bp),digest:'sha256:'+'a'.repeat(64),validation:{valid:true,findings:[]}}; }
          else if (path === '/api/v1/compatibility/evaluate') { const request = JSON.parse(init.body || '{}'); body={authority:'PLATFORM_COMPATIBILITY_MATRIX_V1',constraintCount:1,providerDimension:true,serverReconstructed:true,decision:{method:'PLATFORM_COMPATIBILITY_MATRIX_V1',status:'PASS',target:request.target,checks:[{constraint:'blueprint/ui-parity',dimension:'kubernetes',status:'PASS',target:request.target?.kubernetesVersion||'',allowed:['1.34..1.35'],authority:'PLATFORM_COMPATIBILITY_MATRIX_V1',message:'Kubernetes minor is admitted'},{constraint:'blueprint/ui-parity',dimension:'architecture',status:'PASS',target:request.target?.architecture||'',allowed:['amd64'],authority:'PLATFORM_COMPATIBILITY_MATRIX_V1',message:'target is admitted'},{constraint:'blueprint/ui-parity',dimension:'distribution',status:'PASS',target:request.target?.distribution||'',allowed:['rke2'],authority:'PLATFORM_COMPATIBILITY_MATRIX_V1',message:'target is admitted'},{constraint:'blueprint/ui-parity',dimension:'provider',status:'PASS',target:request.target?.provider||'',allowed:['*'],authority:'PLATFORM_COMPATIBILITY_MATRIX_V1',message:'target is admitted'}],digest:'sha256:'+'c'.repeat(64)}}; }
          else if (path === '/api/v1/blueprint-releases') body = [];
          else if (path === '/api/v1/control-plane/summary') body = {organizations: 0, projects: 0, operations: 0, outboxPending: 0};
          else if (path === '/api/v1/ai/policy') body = {runtimeAuthority:'UNIFIED_AI_RUNTIME_V1',enabled:true,provider:'openai-responses',model:'ui-smoke-model',maxInputBytes:16384,maxOutputTokens:800,redactionRequired:true,structuredOutputRequired:true,rawPromptPersisted:false,advisoryOnly:true,canDecidePass:false,canDecidePhysicalPass:false};
          else if (path === '/api/v1/ai/runs') body = [{id:'air_ui',projectId:'project-ui',revision:1,purpose:'operator-diagnosis',provider:'openai-responses',model:'ui-smoke-model',promptId:'operator.failure-diagnosis.v1',promptDigest:'sha256:'+'1'.repeat(64),contextDigest:'sha256:'+'2'.repeat(64),outputDigest:'sha256:'+'3'.repeat(64),requestDigest:'sha256:'+'4'.repeat(64),redactionCount:2,inputTokens:120,cachedTokens:40,outputTokens:80,output:{classification:'environment',confidence:91,owner:'runtime',summary:'Synthetic secret-safe UI smoke advisory',recommendedChecks:['Verify deterministic evidence'],recommendedFix:'Use normal product workflow after evidence review'},linkedResourceType:'operation',linkedResourceId:'op-ui',advisoryOnly:true,createdAt:'2026-08-28T08:00:00Z',updatedAt:'2026-08-28T08:00:00Z'}];
          else if (path === '/api/v1/lab/guide') body = {authority:'LAB_CERTIFICATION_MATRIX_V1',serverTiers:[{id:'current-import-minimum',displayName:'Current import minimum',physicalServers:4,roles:['management-1','okd-control-1','okd-control-2','okd-control-3'],purpose:'Import certification'}],matrix:[{id:'M00',group:'artifact',name:'Exact SHA',serverTier:'current-import-minimum',phase:'C-ai-native-operator-experience-lab-mcp-foundation',destructive:false,aiEligible:false,actions:['verify exact SHA'],automationStatus:'IMPLEMENTED',automationDetail:'Artifact integrity'}],aiPolicy:{defaultMode:'failure-only',maxFailurePacketBytes:16384,maxOutputTokens:1200},mcp:{protocol:'2026-07-28',transport:'streamable-http',path:'/mcp',defaultAccess:'read-only',permission:'mcp.read',authorization:'capability + project authorization',tools:['lab_guide','target_architecture_model','ai_runtime_policy','cluster_summary','operation_status','ai_run'],mutatingTools:[]}};
          else if (path === '/api/v1/target-architecture-model') body = {authority:'TARGET_ARCHITECTURE_MODEL_V1',distributions:[{id:'kubernetes',status:'SUPPORTED'},{id:'okd',status:'RECOGNIZED_NOT_YET_ADMITTED'}],capabilityResolver:{authority:'TARGET_CAPABILITY_RESOLVER_V1'},programRoadmap:{authority:'PROGRAM_PHASE_MODEL_V3',currentPhase:'C-ai-native-operator-experience-lab-mcp-foundation',goalReady:false,globalGuardrails:['physical pass exact sha'],tracks:[{id:'operator-experience',title:'Operator Experience / UI / UX',objective:'Complete truthful operator workflows',requirements:['responsive RTL accessibility']},{id:'ai-native',title:'AI-Native Control Plane',objective:'Explain and diagnose authority',requirements:['redaction and durable audit']},{id:'mcp-agent-surface',title:'MCP / External Agent Surface',objective:'Scoped external reads',requirements:['mcp.read project authorization']}],phases:[{id:'C-ai-native-operator-experience-lab-mcp-foundation',status:'blocked'}]}};
          else if (!path.startsWith('/api/v1/')) body = {};
          return new Response(JSON.stringify(body), {status: 200, headers: {'content-type': 'application/json'}});
        }""".replace("__PROFILE__", json.dumps(PROFILE, separators=(",", ":")))
    page.evaluate(f"window.fetch = {mock}")
    page.set_content(document, wait_until="load")
    page.wait_for_timeout(250)


def browser_errors(page) -> list[str]:
    errors: list[str] = []
    page.on("pageerror", lambda exc: errors.append(f"pageerror: {exc}"))
    page.on("console", lambda msg: errors.append(f"console-{msg.type}: {msg.text}") if msg.type == "error" else None)
    return errors


def check_console(browser, root: Path, viewport: dict[str, int]) -> dict[str, object]:
    context = browser.new_context(viewport=viewport)
    page = context.new_page()
    errors = browser_errors(page)
    prepare_page(page, inline_document(root / "webconsole/static"), installer=False)
    live_contract = page.evaluate("() => ({marketplace: livePages.has('marketplace'), tenants: livePages.has('tenants'), ai: livePages.has('ai')})")
    if not live_contract.get('marketplace') or not live_contract.get('tenants') or not live_contract.get('ai'):
        errors.append('async-marketplace-tenant-ai-live-refresh-missing')
    session_contract = page.evaluate(r"""async () => {
      const originalFetch = window.fetch;
      const originalRedirectPending = state.sessionRedirectPending;
      state.sessionRedirectPending = true;
      window.fetch = async (input, init={}) => {
        const path = String(input).replace(/^https?:\/\/[^/]+/, '').split('?')[0];
        if (path === '/api/v1/session-expired-smoke') return new Response(JSON.stringify({error:{message:'expired'}}), {status:401, headers:{'content-type':'application/json'}});
        return originalFetch(input, init);
      };
      try {
        await softApi('/api/v1/session-expired-smoke', [], 'session-expired-smoke');
        return {propagated:false};
      } catch (error) {
        return {propagated:true, status:error.status, sessionExpired:error.sessionExpired===true};
      } finally {
        window.fetch = originalFetch;
        state.sessionRedirectPending = originalRedirectPending;
      }
    }""")
    if not session_contract.get('propagated') or session_contract.get('status') != 401 or not session_contract.get('sessionExpired'):
        errors.append('soft-api-session-expiry-not-propagated')
    abort_contract = page.evaluate(r"""async () => {
      const originalFetch = window.fetch;
      const originalController = state.pageLoadController;
      state.degradedRequests = [];
      const controller = new AbortController();
      state.pageLoadController = controller;
      window.fetch = (input, init={}) => new Promise((resolve, reject) => {
        const signal = init.signal;
        if (signal?.aborted) { reject(new DOMException('Aborted', 'AbortError')); return; }
        signal?.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')), {once:true});
      });
      const pending = softApi('/api/v1/abort-smoke', [], 'abort-smoke');
      controller.abort();
      let propagated = false;
      try { await pending; } catch (error) { propagated = error?.name === 'AbortError'; }
      const degraded = [...state.degradedRequests];
      window.fetch = originalFetch;
      state.pageLoadController = originalController;
      return {propagated, degradedCount: degraded.length};
    }""")
    if not abort_contract.get('propagated') or abort_contract.get('degradedCount') != 0:
        errors.append('soft-api-abort-leaks-as-partial-authority')
    permission_transition = page.evaluate(r"""async () => {
      const originalFetch=window.fetch, originalSession=state.session, originalPending=state.sessionRedirectPending, originalAccessContext=state.accessContext, originalPermissionContextReady=state.permissionContextReady;
      state.sessionRedirectPending=false;
      try {
        state.session={sub:'permission-smoke',roles:['platform-viewer']};applyAccessMode();
        window.fetch=async (input, init={}) => {
          const path=String(input).replace(/^https?:\/\/[^/]+/, '').split('?')[0];
          if(path==='/auth/session')return new Response(JSON.stringify({sub:'permission-smoke',roles:['platform-operator']}),{status:200,headers:{'content-type':'application/json'}});
          if(path==='/api/v1/access/context')return new Response(JSON.stringify({subject:'permission-smoke',globalRole:'platform-operator',allOrganizations:false,effectiveOrganizationRoles:{'org-view':'organization-viewer','org-op':'organization-operator'},effectiveProjectRoles:{'project-view':'project-viewer','project-op':'project-operator'}}),{status:200,headers:{'content-type':'application/json'}});
          if(path==='/api/v1/permission-promote-smoke')return new Response(JSON.stringify({ok:true}),{status:200,headers:{'content-type':'application/json'}});
          return originalFetch(input,init);
        };
        const mutationButton=document.querySelector('#cluster-import-form button[type="submit"]');
        const disabledAsViewer=mutationButton?.disabled===true;
        const installationPlanButton=document.querySelector('#installation-form button[type="submit"]');
        const installationPlanEnabledForViewer=installationPlanButton?.disabled===false;
        const marketplaceRecommendMutationClassified=isMutationButton(document.querySelector('#marketplace-recommend'));
        const gitCredentialRevokeMutationClassified=isMutationButton(document.querySelector('#git-credential-revoke'));
        const blueprintCompareReadOnlyClassified=!isMutationButton(document.querySelector('#blueprint-compare'));
        const viewerSafeActionProbe=document.createElement('button');
        viewerSafeActionProbe.type='button';viewerSafeActionProbe.dataset.closureAction='verify';viewerSafeActionProbe.dataset.viewerSafe='true';document.body.append(viewerSafeActionProbe);
        applyAccessMode(viewerSafeActionProbe.parentElement);
        const viewerSafeActionEnabled=viewerSafeActionProbe.disabled===false;
        viewerSafeActionProbe.remove();
        const promoted=await api('/api/v1/permission-promote-smoke',{method:'POST',body:{}});
        const promotedRole=state.session?.roles?.[0]||'';
        const enabledAfterPromotion=mutationButton?.disabled===false;
        const scopedViewerProbe=document.createElement('button');
        scopedViewerProbe.type='button';scopedViewerProbe.dataset.syntheticAction='create';scopedViewerProbe.dataset.projectScope='project-view';document.body.append(scopedViewerProbe);
        const scopedOperatorProbe=document.createElement('button');
        scopedOperatorProbe.type='button';scopedOperatorProbe.dataset.syntheticAction='create';scopedOperatorProbe.dataset.projectScope='project-op';document.body.append(scopedOperatorProbe);
        const scopedAdminProbe=document.createElement('button');
        scopedAdminProbe.type='button';scopedAdminProbe.dataset.syntheticAction='create';scopedAdminProbe.dataset.organizationScope='org-op';scopedAdminProbe.dataset.scopeAccess='admin';document.body.append(scopedAdminProbe);
        applyAccessMode();
        const scopedViewerDenied=scopedViewerProbe.disabled===true;
        const scopedOperatorAllowed=scopedOperatorProbe.disabled===false;
        const scopedAdminDenied=scopedAdminProbe.disabled===true;
        scopedViewerProbe.remove();scopedOperatorProbe.remove();scopedAdminProbe.remove();
        const intrinsicProbe=document.createElement('button');
        intrinsicProbe.type='button';intrinsicProbe.dataset.syntheticAction='create';document.body.append(intrinsicProbe);
        state.session={sub:'permission-smoke',roles:['platform-viewer']};applyAccessMode(intrinsicProbe.parentElement);
        setIntrinsicDisabled(intrinsicProbe,true);
        state.session={sub:'permission-smoke',roles:['platform-operator']};applyAccessMode(intrinsicProbe.parentElement);
        const intrinsicDisabledPreserved=intrinsicProbe.disabled===true;
        intrinsicProbe.remove();
        state.session={sub:'permission-smoke',roles:['platform-operator']};applyAccessMode();
        const confirmDialog=document.querySelector('#confirm-dialog');
        confirmDialog.showModal();
        window.fetch=async (input, init={}) => {
          const path=String(input).replace(/^https?:\/\/[^/]+/, '').split('?')[0];
          if(path==='/auth/session')return new Response(JSON.stringify({sub:'permission-smoke',roles:['platform-viewer']}),{status:200,headers:{'content-type':'application/json'}});
          if(path==='/api/v1/access/context')return new Response(JSON.stringify({subject:'permission-smoke',globalRole:'platform-viewer',allOrganizations:false,effectiveOrganizationRoles:{'org-view':'organization-viewer'},effectiveProjectRoles:{'project-view':'project-viewer'}}),{status:200,headers:{'content-type':'application/json'}});
          if(path==='/api/v1/permission-demote-smoke')return new Response(JSON.stringify({error:{message:'forbidden'}}),{status:403,headers:{'content-type':'application/json'}});
          return originalFetch(input,init);
        };
        let denied=false;try{await api('/api/v1/permission-demote-smoke',{method:'POST',body:{}});}catch(error){denied=error.status===403;}
        return {promoted:promoted?.ok===true,promotedRole,disabledAsViewer,installationPlanEnabledForViewer,marketplaceRecommendMutationClassified,gitCredentialRevokeMutationClassified,blueprintCompareReadOnlyClassified,viewerSafeActionEnabled,enabledAfterPromotion,scopedViewerDenied,scopedOperatorAllowed,scopedAdminDenied,intrinsicDisabledPreserved,denied,demotedRole:state.session?.roles?.[0]||'',readOnly:document.body.classList.contains('read-only-session'),confirmClosedAfterDemotion:!confirmDialog.open};
      } finally { window.fetch=originalFetch;state.session=originalSession;state.sessionRedirectPending=originalPending;state.accessContext=originalAccessContext;state.permissionContextReady=originalPermissionContextReady;applyAccessMode(); }
    }""")
    if not permission_transition.get('promoted') or permission_transition.get('promotedRole') != 'platform-operator' or not permission_transition.get('disabledAsViewer') or not permission_transition.get('installationPlanEnabledForViewer') or not permission_transition.get('marketplaceRecommendMutationClassified') or not permission_transition.get('gitCredentialRevokeMutationClassified') or not permission_transition.get('blueprintCompareReadOnlyClassified') or not permission_transition.get('viewerSafeActionEnabled') or not permission_transition.get('enabledAfterPromotion') or not permission_transition.get('scopedViewerDenied') or not permission_transition.get('scopedOperatorAllowed') or not permission_transition.get('scopedAdminDenied') or not permission_transition.get('intrinsicDisabledPreserved') or not permission_transition.get('denied') or permission_transition.get('demotedRole') != 'platform-viewer' or not permission_transition.get('readOnly') or not permission_transition.get('confirmClosedAfterDemotion'):
        errors.append(f"permission-transition-authority:{permission_transition}")
    navigation_abort_contract = page.evaluate(r"""async () => {
      clearDirtyForms();
      const originalOverview = loaders.overview;
      const originalServices = loaders.services;
      const announcer = document.querySelector('#route-announcer');
      const events = [];
      const observer = new MutationObserver(() => events.push({text:announcer.textContent, page:state.currentPage}));
      observer.observe(announcer, {childList:true, subtree:true, characterData:true});
      loaders.overview = async () => {
        const signal = state.pageLoadController?.signal;
        await new Promise((resolve, reject) => {
          const timer = setTimeout(resolve, 80);
          signal?.addEventListener('abort', () => { clearTimeout(timer); reject(new DOMException('Aborted','AbortError')); }, {once:true});
        });
      };
      loaders.services = async () => { await new Promise(resolve => setTimeout(resolve, 30)); };
      try {
        await navigate('workspace');
        events.length = 0;
        const first = navigate('overview');
        await new Promise(resolve => setTimeout(resolve, 5));
        const second = navigate('services');
        await Promise.all([first, second]);
        return {events, currentPage:state.currentPage, finalText:announcer.textContent};
      } finally {
        observer.disconnect();
        loaders.overview = originalOverview;
        loaders.services = originalServices;
      }
    }""")
    stale_announcements = [item for item in navigation_abort_contract.get('events', []) if 'Overview page loaded' in item.get('text', '') and item.get('page') == 'services']
    if stale_announcements or navigation_abort_contract.get('currentPage') != 'services' or 'Integrations & services page loaded' not in navigation_abort_contract.get('finalText', ''):
        errors.append('superseded-navigation-completes-after-new-route')
    overview_partial_contract = page.evaluate(r"""async () => {
      const originalFetch = window.fetch;
      window.fetch = async (input, init={}) => {
        const path = String(input).replace(/^https?:\/\/[^/]+/, '').split('?')[0];
        if (path === '/api/v1/clusters') return new Response(JSON.stringify({error:{message:'cluster authority down'}}), {status:503, headers:{'content-type':'application/json'}});
        return originalFetch(input, init);
      };
      try {
        await navigate('overview');
        const metrics = document.querySelector('#overview-metrics').innerText;
        const clusterCheck = [...document.querySelectorAll('#journey-checklist .check-item')].find(item => item.innerText.includes('Connect a Kubernetes cluster'));
        return {
          metrics,
          clusterCheck: clusterCheck?.innerText || '',
          clusterHasContinue: !!clusterCheck?.querySelector('[data-navigate]'),
          degraded: document.querySelector('#page-degraded-banner').innerText,
          attention: document.querySelector('#attention-list').innerText
        };
      } finally { window.fetch = originalFetch; }
    }""")
    if 'Cluster authority unavailable' not in overview_partial_contract.get('metrics', '') or 'Authority unavailable; retry before acting.' not in overview_partial_contract.get('clusterCheck', '') or overview_partial_contract.get('clusterHasContinue') or 'Partial data' not in overview_partial_contract.get('degraded', '') or 'Attention data unavailable' not in overview_partial_contract.get('attention', ''):
        errors.append('overview-partial-authority-masquerades-as-zero-or-actionable')
    overview_hard_failure_contract = page.evaluate(r"""async () => {
      const originalFetch = window.fetch;
      await navigate('overview');
      window.fetch = async (input, init={}) => {
        const path = String(input).replace(/^https?:\/\/[^/]+/, '').split('?')[0];
        if (path === '/api/v1/version') return new Response(JSON.stringify({error:{message:'version authority down'}}), {status:503, headers:{'content-type':'application/json'}});
        return originalFetch(input, init);
      };
      try {
        await loadPage('overview', true);
        return {
          metrics: document.querySelector('#overview-metrics').innerText,
          checklist: document.querySelector('#journey-checklist').innerText,
          attention: document.querySelector('#attention-list').innerText,
          activity: document.querySelector('#overview-activity').innerText,
          next: document.querySelector('#overview-next-action').textContent,
          nextDisabled: document.querySelector('#overview-next-action').disabled
        };
      } finally { window.fetch = originalFetch; }
    }""")
    if any('version authority down' not in overview_hard_failure_contract.get(key, '') for key in ('metrics','checklist','attention','activity')) or overview_hard_failure_contract.get('next') != 'Overview unavailable' or not overview_hard_failure_contract.get('nextDisabled'):
        errors.append('overview-hard-failure-leaves-stale-authoritative-surface')
    page.evaluate("async () => { await navigate('workspace'); }")
    page.locator('#workspace details.action-console').first.evaluate("el => el.open = true")
    page.locator('#organization-name').fill('unsaved-organization')
    # Blur the edited field without depending on a presentation element being
    # visible at every responsive breakpoint. Dirty-form semantics, not the
    # page-title layout, are the release invariant.
    page.locator('#organization-name').evaluate("el => el.blur()")
    dirty_contract = page.evaluate("() => ({dirty:hasUnsavedChanges(), editing:userIsEditing()})")
    if not dirty_contract.get('dirty') or not dirty_contract.get('editing'):
        errors.append('dirty-form-does-not-pause-refresh-after-focus-loss')
    page.evaluate("clearDirtyForms()")
    interaction_contract = page.evaluate(r"""() => {
      const active = document.querySelector('.page.active');
      const details = document.createElement('details');
      details.open = true;
      details.innerHTML = '<summary>interaction smoke</summary><p>read-only details</p>';
      active.appendChild(details);
      const expanded = userIsEditing();
      details.remove();
      state.interactionHoldUntil = Date.now() + 1000;
      const recent = userIsEditing();
      state.interactionHoldUntil = 0;
      return {expanded, recent};
    }""")
    if not interaction_contract.get('expanded') or not interaction_contract.get('recent'):
        errors.append('expanded-or-recent-interaction-does-not-pause-live-refresh')
    pages = [
        "overview", "workspace", "installation", "clusters", "providers", "blueprints", "marketplace", "baselines",
        "verification", "fleet", "tenants", "operations", "ai", "lab", "notifications", "services", "catalog", "validator",
    ]
    activated: list[str] = []
    for name in pages:
        page.evaluate("name => navigate(name)", name)
        page.wait_for_timeout(80)
        if page.locator(f"#{name}.page.active").count() != 1:
            errors.append(f"page-not-active:{name}")
        if page.evaluate("document.documentElement.scrollWidth > window.innerWidth + 2"):
            errors.append(f"horizontal-overflow:{name}")
        activated.append(name)
    page.evaluate("() => navigate('ai')")
    page.wait_for_timeout(120)
    ai_surface = page.evaluate(r"""() => ({
      authority: document.querySelector('#ai-runtime-details')?.innerText || '',
      access: document.querySelector('#ai-mcp-access')?.innerText || '',
      usage: document.querySelector('#ai-usage-summary')?.innerText || '',
      inspect: !!document.querySelector('[data-ai-run-inspect="air_ui"]'),
      disabled: document.querySelector('#ai-diagnosis-form button[type="submit"]')?.disabled === true
    })""")
    if 'UNIFIED_AI_RUNTIME_V1' not in ai_surface.get('authority','') or 'mcp.read' not in ai_surface.get('access','') or 'ai.diagnose' not in ai_surface.get('access','') or '200' not in ai_surface.get('usage','') or not ai_surface.get('inspect') or ai_surface.get('disabled'):
        errors.append(f"ai-native-operator-surface:{ai_surface}")
    page.locator('[data-ai-run-inspect="air_ui"]').click()
    page.wait_for_timeout(40)
    if 'Structured advisory output' not in page.locator('#detail-content').inner_text():
        errors.append('ai-run-inspect-evidence-missing')
    page.locator('#detail-dialog').evaluate("el => el.close()")

    data_workspace = page.evaluate(r"""() => {
      const host = document.querySelector('#operation-grid');
      const attempts=[7,2,11,3,9,1,8,5,10,0,6,4];
      const rows = attempts.map((attempt,index) => tableRow([
        tableCell(`<span class="cell-title">operation-${index}</span>`),
        tableCell(badge(index === 3 ? 'FAILED' : 'SUCCEEDED'), 'status-cell'),
        tableCell(`<span class="technical">target-${index}</span>`),
        tableCell(String(attempt), 'numeric')
      ]));
      host.innerHTML = dataTable('Data workspace smoke', [{label:'Operation'},{label:'State'},{label:'Target'},{label:'Attempt',className:'numeric'}], rows, 'No operations', 'None', {source:'operations'});
      ensureCollectionToolbar(host);
      const toolbar = host.previousElementSibling;
      const input = toolbar?.querySelector('input[type=search]');
      if (input) { input.value = 'operation-3'; input.dispatchEvent(new Event('input', {bubbles:true})); }
      const visible = [...host.querySelectorAll('tbody tr[data-record-row]')].filter(row => !row.hidden).length;
      const headerScopes = [...host.querySelectorAll('thead th')].every(th => th.getAttribute('scope') === 'col');
      if(input){input.value='';input.dispatchEvent(new Event('input',{bubbles:true}));}
      const sort=host.querySelector('[data-table-sort-index="3"]');
      sort?.click();
      const ascending=host.querySelector('tbody tr td.numeric')?.textContent.trim();
      const ariaAscending=sort?.closest('th')?.getAttribute('aria-sort');
      sort?.click();
      const descending=host.querySelector('tbody tr td.numeric')?.textContent.trim();
      const ariaDescending=sort?.closest('th')?.getAttribute('aria-sort');
      const reversedRows=[...rows].reverse();
      host.innerHTML=dataTable('Data workspace smoke', [{label:'Operation'},{label:'State'},{label:'Target'},{label:'Attempt',className:'numeric'}], reversedRows, 'No operations', 'None', {source:'operations'});
      restoreDataTableSortPreferences(host);
      const persistedDescending=host.querySelector('tbody tr td.numeric')?.textContent.trim();
      const persistedAria=host.querySelector('[data-table-sort-index="3"]')?.closest('th')?.getAttribute('aria-sort');
      ensureCollectionToolbar(host);
      const persistedInput=host.previousElementSibling?.querySelector('input[type=search]');
      if(persistedInput){persistedInput.value='operation-3';persistedInput.dispatchEvent(new Event('input',{bubbles:true}));}
      const saved=state.degradedRequests;
      state.degradedRequests=[{label:'operations',path:'/api/v1/operations',message:'authority unavailable',status:503}];
      host.innerHTML=dataTable('Data workspace smoke', [{label:'Operation'}], [], 'No durable operations', 'None', {source:'operations'});
      ensureCollectionToolbar(host);
      const filterDuringUnavailable=persistedInput?.value||'';
      const unavailable=host.innerHTML;
      state.degradedRequests=saved;
      host.innerHTML=dataTable('Data workspace smoke', [{label:'Operation'},{label:'State'},{label:'Target'},{label:'Attempt',className:'numeric'}], rows, 'No operations', 'None', {source:'operations'});
      restoreDataTableSortPreferences(host);
      ensureCollectionToolbar(host);
      const visibleAfterRecovery=[...host.querySelectorAll('tbody tr[data-record-row]')].filter(row=>!row.hidden).length;
      return {table:!!host.querySelector('table.data-table'), rows:host.querySelectorAll('tbody tr[data-record-row]').length, visible, toolbarVisible:toolbar ? !toolbar.hidden : false, headerScopes, ascending, descending, ariaAscending, ariaDescending, persistedDescending, persistedAria, filterDuringUnavailable, visibleAfterRecovery, unavailable:unavailable.includes('data-retry-current') && !unavailable.includes('No durable operations')};
    }""")
    if not data_workspace.get('table') or data_workspace.get('rows') != 12 or data_workspace.get('visible') != 1 or not data_workspace.get('toolbarVisible') or not data_workspace.get('headerScopes') or data_workspace.get('ascending') != '0' or data_workspace.get('descending') != '11' or data_workspace.get('ariaAscending') != 'ascending' or data_workspace.get('ariaDescending') != 'descending' or data_workspace.get('persistedDescending') != '11' or data_workspace.get('persistedAria') != 'descending' or data_workspace.get('filterDuringUnavailable') != 'operation-3' or data_workspace.get('visibleAfterRecovery') != 1 or not data_workspace.get('unavailable'):
        errors.append(f"data-workspace-contract:{data_workspace}")
    read_only = page.evaluate(r"""() => {
      const original = state.session;
      state.session = {sub:'viewer-smoke', roles:['platform-viewer']};
      const host = document.querySelector('#operation-grid');
      host.innerHTML = '<button type="button" data-operation-cancel="op-smoke">Cancel</button><button type="button" data-operation-id="op-smoke">Inspect</button>';
      applyAccessMode(host);
      showDetails('Read-only mutation smoke','<button type="button" data-notification-retry-dead-letter>Requeue dead letter</button>');
      const deadLetter=document.querySelector('[data-notification-retry-dead-letter]')?.disabled===true;
      document.querySelector('#detail-dialog')?.close();
      const result = {cancel:host.querySelector('[data-operation-cancel]').disabled, inspect:host.querySelector('[data-operation-id]').disabled, deadLetter};
      state.session = original;
      applyAccessMode();
      return result;
    }""")
    if not read_only.get('cancel') or read_only.get('inspect') or not read_only.get('deadLetter'):
        errors.append(f"read-only-mutation-intent:{read_only}")
    page.evaluate("() => navigate('blueprints')")
    page.wait_for_timeout(120)
    page.locator('#blueprint-expert-tools').evaluate("el => el.open = true")
    parity_text = page.locator('#blueprint-parity-summary').inner_text()
    parity_badge = page.locator('#blueprint-parity-badge').inner_text()
    if 'BLUEPRINT_VISUAL_API_AUTHORING_PARITY_V1' not in parity_text or '27/27' not in parity_text or 'API PARITY' not in parity_badge:
        errors.append('blueprint-visual-api-parity-ui-missing')
    parity_blueprint = {'apiVersion':'platform.4so.io/v1alpha1','kind':'PlatformBlueprint','metadata':{'name':'ui-parity','version':'1.0.0'},'spec':{'description':'UI parity','compatibility':{'kubernetes':{'minVersion':'1.34','maxVersion':'1.35'},'architectures':['amd64'],'distributionProfiles':['rke2']},'delivery':{'mode':'gitops','repository':'https://git.example.test/platform.git','revision':'main','revisionType':'branch','ociRegistry':'registry.example.test/platform'},'components':[{'name':'ui-component','enabled':True,'settings':{'feature':{'enabled':True}}}],'tenancy':{'mode':'namespace','plans':['small'],'deletionPolicy':'approval-and-backup-required'},'governance':{'approvalRequiredFor':['high','critical'],'enforceDigestImages':True,'allowPlaintextSecrets':False},'certification':{'requiredLevel':'render','evidenceRetentionDays':365},'fieldOwnership':[]}}
    page.evaluate('(bp)=>applyBlueprintToVisualEditor(bp)', parity_blueprint)
    page.locator('#blueprint-export-json').click(); page.wait_for_timeout(40)
    exported = json.loads(page.locator('#blueprint-authoring-json').input_value())
    if exported != parity_blueprint: errors.append('blueprint-visual-export-not-api-equal')
    imported_blueprint = json.loads(json.dumps(parity_blueprint))
    imported_blueprint['metadata']['name'] = 'ui-import-dirty'
    page.locator('#blueprint-authoring-json').fill(json.dumps(imported_blueprint, separators=(',', ':')))
    page.locator('#blueprint-import-json').click(); page.wait_for_timeout(40)
    import_dirty = page.evaluate("() => ({form:dirtyWithin(document.querySelector('#blueprint-release-form')), editor:blueprintEditorHasUnsavedChanges()})")
    if not import_dirty.get('form') or not import_dirty.get('editor'):
        errors.append('blueprint-json-import-does-not-mark-visual-editor-dirty')
    page.evaluate("clearBlueprintEditorDirty()")
    page.locator('#blueprint-verify-parity').click(); page.wait_for_timeout(80)
    if 'Exact round-trip PASS' not in page.locator('#blueprint-parity-result').inner_text(): errors.append('blueprint-api-roundtrip-ui-failed')
    page.evaluate("async () => { clearDirtyForms(); await navigate('validator'); }")
    page.locator('#blueprint-input').fill(json.dumps(parity_blueprint, separators=(',', ':')))
    page.locator('#blueprint-input').evaluate("el => el.blur()")
    standalone_dirty = page.evaluate("() => ({dirty:hasUnsavedChanges(), editing:userIsEditing()})")
    if not standalone_dirty.get('dirty') or not standalone_dirty.get('editing'):
        errors.append('standalone-blueprint-dirty-guard-missing')
    page.evaluate("clearDirtyForms()")
    page.locator('#compatibility-form button[type=submit]').click(); page.wait_for_timeout(80)
    compatibility_text = page.locator('#compatibility-result').inner_text()
    if 'Compatible' not in compatibility_text or 'PLATFORM_COMPATIBILITY_MATRIX_V1' not in compatibility_text or '4/4 checks PASS' not in compatibility_text:
        errors.append('compatibility-authority-ui-missing')
    viewer_safe = page.evaluate("() => { const original=state.session; state.session={sub:'viewer-smoke',roles:['platform-viewer']}; applyAccessMode(document.querySelector('#validator')); const disabled=document.querySelector('#compatibility-form button[type=submit]').disabled; state.session=original; applyAccessMode(document.querySelector('#validator')); return !disabled; }")
    if not viewer_safe: errors.append('compatibility-viewer-safe-action-disabled')
    maintenance_contract = page.evaluate(r"""async () => {
      const originalFetch = window.fetch;
      const profileForm = document.querySelector('#maintenance-profile-form');
      const windowForm = document.querySelector('#maintenance-window-form');
      window.fetch = async (input, init={}) => {
        const path = String(input).replace(/^https?:\/\/[^/]+/, '').split('?')[0];
        if (path === '/api/v1/clusters/cluster-a/maintenance-profile') return new Response(JSON.stringify({profile:{environment:'PRODUCTION',defaultDrainTimeoutSeconds:900,revision:1}}), {status:200,headers:{'content-type':'application/json'}});
        if (path === '/api/v1/clusters/cluster-b/maintenance-profile') return new Response(JSON.stringify({error:{message:'not found'}}), {status:404,headers:{'content-type':'application/json'}});
        if (path === '/api/v1/clusters/race-a/maintenance-profile') { await new Promise(resolve=>setTimeout(resolve,35)); return new Response(JSON.stringify({profile:{environment:'PRODUCTION',defaultDrainTimeoutSeconds:1200,revision:1}}), {status:200,headers:{'content-type':'application/json'}}); }
        if (path === '/api/v1/clusters/race-b/maintenance-profile') return new Response(JSON.stringify({error:{message:'not found'}}), {status:404,headers:{'content-type':'application/json'}});
        if (path.endsWith('/maintenance-windows')) return new Response(JSON.stringify({windows:[]}), {status:200,headers:{'content-type':'application/json'}});
        if (path.endsWith('/maintenance-runs')) return new Response(JSON.stringify({runs:[]}), {status:200,headers:{'content-type':'application/json'}});
        return originalFetch(input, init);
      };
      try {
        clearDirtyForms(profileForm); clearDirtyForms(windowForm);
        await loadClusterMaintenanceAuthority('cluster-a');
        const first = {environment:document.querySelector('#maintenance-environment').value, profileTimeout:document.querySelector('#maintenance-default-timeout').value, windowTimeout:document.querySelector('#maintenance-window-timeout').value};
        document.querySelector('#maintenance-window-timeout').value='777';
        windowForm.dataset.dirty='true';
        await loadClusterMaintenanceAuthority('cluster-a');
        const preserved = document.querySelector('#maintenance-window-timeout').value;
        clearDirtyForms(windowForm);
        await loadClusterMaintenanceAuthority('cluster-b');
        const second = {environment:document.querySelector('#maintenance-environment').value, profileTimeout:document.querySelector('#maintenance-default-timeout').value, windowTimeout:document.querySelector('#maintenance-window-timeout').value};
        const stale = loadClusterMaintenanceAuthority('race-a');
        await new Promise(resolve=>setTimeout(resolve,5));
        const current = loadClusterMaintenanceAuthority('race-b');
        await Promise.all([stale,current]);
        const race = {clusterId:state.currentMaintenanceClusterId, environment:document.querySelector('#maintenance-environment').value, profileTimeout:document.querySelector('#maintenance-default-timeout').value};
        return {first,preserved,second,race};
      } finally {
        window.fetch = originalFetch;
        clearDirtyForms(profileForm); clearDirtyForms(windowForm);
      }
    }""")
    if maintenance_contract.get('first') != {'environment':'PRODUCTION','profileTimeout':'900','windowTimeout':'900'}:
        errors.append('maintenance-profile-authority-not-applied')
    if maintenance_contract.get('preserved') != '777':
        errors.append('maintenance-refresh-overwrites-dirty-window-form')
    if maintenance_contract.get('second') != {'environment':'DEVELOPMENT','profileTimeout':'300','windowTimeout':'300'}:
        errors.append('maintenance-cross-cluster-stale-state-not-reset')
    if maintenance_contract.get('race') != {'clusterId':'race-b','environment':'DEVELOPMENT','profileTimeout':'300'}:
        errors.append('maintenance-stale-response-overwrites-current-cluster')
    page.evaluate("() => navigate('services')")
    page.wait_for_timeout(120)
    git_authority_text = page.locator('#git-authority-summary').inner_text()
    if 'GIT_PROVIDER_CREDENTIAL_REFERENCE_V1' not in git_authority_text or 'env://FORGEJO_TOKEN' not in git_authority_text:
        errors.append('git-credential-authority-ui-missing')
    error_states = page.locator(".error-state").count()
    overflow = page.evaluate("document.documentElement.scrollWidth > window.innerWidth + 2")
    mobile_menu_opened = True
    if viewport["width"] < 800:
        if not page.evaluate("document.querySelector('.sidebar').inert === true"):
            errors.append('closed-mobile-drawer-not-inert')
        page.locator("#mobile-nav-toggle").click()
        page.wait_for_timeout(50)
        mobile_menu_opened = "open" in (page.locator(".sidebar").get_attribute("class") or "")
        page.keyboard.press('Shift+Tab')
        wrapped_to_last = page.evaluate("document.activeElement && document.activeElement.id === 'logout'")
        page.keyboard.press('Tab')
        wrapped_to_first = page.evaluate("document.activeElement && document.activeElement.dataset && document.activeElement.dataset.section === 'home'")
        if not wrapped_to_last or not wrapped_to_first:
            errors.append('mobile-drawer-focus-trap-failed')
    language_toggle_visible = page.locator("#language-toggle").is_visible()
    if not language_toggle_visible:
        errors.append("language-toggle-not-visible-after-navigation-access")
    page.evaluate("document.querySelector('#language-toggle').click()")
    page.wait_for_timeout(100)
    rtl_direction = page.locator("html").get_attribute("dir")
    rtl_title = page.locator("#page-title").text_content()
    screenshot = smoke_evidence_dir(root) / f'console-{viewport["width"]}x{viewport["height"]}.png'
    page.screenshot(path=str(screenshot), full_page=True)
    page.evaluate("document.querySelector('#language-toggle').click()")
    page.wait_for_timeout(80)
    ltr_direction = page.locator("html").get_attribute("dir")
    result = {
        "viewport": viewport,
        "pages": activated,
        "errorStates": error_states,
        "horizontalOverflow": overflow,
        "languageToggleVisible": language_toggle_visible,
        "rtlDirection": rtl_direction,
        "ltrDirectionAfterRestore": ltr_direction,
        "rtlTitle": rtl_title,
        "mobileMenuOpened": mobile_menu_opened,
        "errors": errors,
        "screenshot": str(screenshot),
    }
    context.close()
    return result


def check_installer(browser, root: Path, viewport: dict[str, int]) -> dict[str, object]:
    context = browser.new_context(viewport=viewport)
    page = context.new_page()
    errors = browser_errors(page)
    prepare_page(page, inline_document(root / "cmd/platform-installer/static", installer=True), installer=True)
    pages = ["overview", "installation", "progress", "health", "recovery", "lifecycle"]
    activated: list[str] = []
    for name in pages:
        page.evaluate("name => document.querySelector(`#nav [data-page='${name}']`).click()", name)
        page.wait_for_timeout(100)
        if page.locator(f"#{name}.page.active").count() != 1:
            errors.append(f"page-not-active:{name}")
        if page.evaluate("document.documentElement.scrollWidth > window.innerWidth + 2"):
            errors.append(f"horizontal-overflow:{name}")
        activated.append(name)
    overflow = page.evaluate("document.documentElement.scrollWidth > window.innerWidth + 2")
    if viewport["width"] < 800 and not page.evaluate("document.querySelector('#sidebar').inert === true"):
        errors.append('closed-mobile-drawer-not-inert')
    language_toggle_visible = page.locator("#language-toggle").is_visible()
    if not language_toggle_visible:
        errors.append("language-toggle-not-visible")
    page.evaluate("document.querySelector('#language-toggle').click()")
    page.wait_for_timeout(100)
    rtl_direction = page.locator("html").get_attribute("dir")
    rtl_title = page.locator("#page-title").text_content()
    rtl_alert = page.locator("#global-alert").text_content()
    screenshot = smoke_evidence_dir(root) / f'installer-{viewport["width"]}x{viewport["height"]}.png'
    page.screenshot(path=str(screenshot), full_page=True)
    page.evaluate("document.querySelector('#language-toggle').click()")
    page.wait_for_timeout(80)
    ltr_direction = page.locator("html").get_attribute("dir")
    result = {
        "viewport": viewport,
        "pages": activated,
        "horizontalOverflow": overflow,
        "languageToggleVisible": language_toggle_visible,
        "rtlDirection": rtl_direction,
        "ltrDirectionAfterRestore": ltr_direction,
        "rtlTitle": rtl_title,
        "rtlExecutionAlert": rtl_alert,
        "serviceCards": page.locator("[data-service]").count(),
        "errors": errors,
        "screenshot": str(screenshot),
    }
    context.close()
    return result


def assert_compatibility_ui_contract(root: Path) -> None:
    html=(root/'webconsole/static/index.html').read_text(encoding='utf-8')
    js=(root/'webconsole/static/app.js').read_text(encoding='utf-8')
    for token in ('provider-architectures','provider-distributions','provider-cluster-architecture','provider-cluster-distribution'):
        if token not in html: raise AssertionError(f'compatibility UI control missing: {token}')
    for token in ('PLATFORM_COMPATIBILITY_MATRIX_V1','Compatibility matrix','compatibility.status'):
        if token not in js: raise AssertionError(f'compatibility UI renderer missing: {token}')

def run_single_viewport(root: Path, kind: str, width: int) -> dict[str, object]:
    system_chromium = shutil.which("chromium") or shutil.which("chromium-browser") or shutil.which("google-chrome")
    playwright = sync_playwright().start()
    browser = None
    try:
        chromium = system_chromium or playwright.chromium.executable_path
        if not chromium or not Path(chromium).is_file():
            raise RuntimeError("UI_SMOKE_BROWSER_MISSING: install Chromium with `python3 -m playwright install chromium` or provide a system chromium/chrome")
        browser = playwright.chromium.launch(headless=True, executable_path=chromium, args=["--no-sandbox"])
        viewport = {"width": width, "height": 900 if width != 390 else 844}
        checker = check_console if kind == "console" else check_installer
        return checker(browser, root, viewport)
    finally:
        if browser is not None:
            try:
                browser.close()
            except Exception:
                pass
        playwright.stop()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--single-kind", choices=("console", "installer"), help=argparse.SUPPRESS)
    parser.add_argument("--single-width", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--single-result", help=argparse.SUPPRESS)
    args = parser.parse_args()
    root = Path(args.root).resolve()
    assert_compatibility_ui_contract(root)

    if args.single_kind:
        if args.single_width not in (320, 390, 768, 1024, 1440) or not args.single_result:
            raise SystemExit("single viewport mode requires a supported --single-width and --single-result")
        result = run_single_viewport(root, args.single_kind, args.single_width)
        Path(args.single_result).write_text(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
        return 0

    evidence_dir = smoke_evidence_dir(root)

    def run_matrix(kind: str) -> list[dict[str, object]]:
        runs: list[dict[str, object]] = []
        for width in (320, 390, 768, 1024, 1440):
            # Isolate the full Python + Playwright driver + Chromium lifecycle per
            # viewport. Browser-only restarts still shared the Node driver pipe and
            # could turn a completed viewport into a later EPIPE in long matrices.
            result_file = evidence_dir / f".{kind}-{width}-result.json"
            command = [sys.executable, str(Path(__file__).resolve()), str(root), "--single-kind", kind, "--single-width", str(width), "--single-result", str(result_file)]
            completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=120, env={**os.environ, "PLATFORM_FACTORY_SMOKE_EVIDENCE_DIR": str(evidence_dir)})
            if completed.returncode != 0:
                raise RuntimeError(f"UI viewport process failed kind={kind} width={width} rc={completed.returncode}: {completed.stderr.strip() or completed.stdout.strip()}")
            runs.append(json.loads(result_file.read_text(encoding="utf-8")))
            result_file.unlink(missing_ok=True)
        return runs

    product_console = run_matrix("console")
    bootstrap_installer = run_matrix("installer")
    results: dict[str, object] = {
        "schemaVersion": 1,
        "release": "test-release",
        "mode": "local-static-headless-with-mocked-empty-authority-responses",
        "runtimeCertified": False,
        "productConsole": product_console,
        "bootstrapInstaller": bootstrap_installer,
    }

    failures: list[dict[str, object]] = []
    for group in ("productConsole", "bootstrapInstaller"):
        for run in results[group]:  # type: ignore[index]
            if run["errors"] or run.get("horizontalOverflow") or run.get("errorStates", 0):
                failures.append({"group": group, "run": run})
            if run.get("rtlDirection") != "rtl" or run.get("ltrDirectionAfterRestore") != "ltr":
                failures.append({"group": group, "issue": "locale direction toggle failed", "run": run})
            if not str(run.get("rtlTitle", "")).strip():
                failures.append({"group": group, "issue": "translated title missing", "run": run})
    results["status"] = "PASS" if not failures else "FAIL"
    results["failures"] = failures
    output = evidence_dir / "product-console-headless-smoke.json"
    output.write_text(json.dumps(results, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    print("UI_HEADLESS_SMOKE_" + results["status"], output)
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
