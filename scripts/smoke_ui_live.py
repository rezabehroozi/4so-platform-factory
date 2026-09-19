#!/usr/bin/env python3
"""Live-loopback browser smoke against the real platform-api authority.

Unlike smoke_ui.py, this test does not replace the Authority with synthetic/mock data and therefore
proves the Catalog console actions are wired to the real API/state machine.
It is still local acceptance, not external cluster/runtime certification.
"""
from __future__ import annotations
import argparse, base64, json, os, re, shutil, socket, subprocess, tempfile, time, urllib.request, urllib.error
from pathlib import Path

EXPECTED_VERSION = (Path(__file__).resolve().parents[1] / 'VERSION').read_text().strip()
from playwright.sync_api import sync_playwright
from smoke_plan_safety import planning_impact, activate_mutation_rbac

def smoke_evidence_dir(root: Path) -> Path:
    configured=os.environ.get("PLATFORM_FACTORY_SMOKE_EVIDENCE_DIR","").strip()
    target=Path(configured).resolve() if configured else Path(tempfile.mkdtemp(prefix="4so-ui-live-smoke-"))
    target.mkdir(parents=True,exist_ok=True)
    return target


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0)); return sock.getsockname()[1]


def api_req(base: str, path: str, method: str = "GET", body=None, headers=None):
    data=None if body is None else json.dumps(body).encode(); h=dict(headers or {})
    if data is not None: h["Content-Type"]="application/json"
    request=urllib.request.Request(base+path,data=data,method=method,headers=h)
    try:
        with urllib.request.urlopen(request,timeout=5) as response:
            raw=response.read(); return response.status,json.loads(raw or b"null")
    except urllib.error.HTTPError as exc:
        raw=exc.read()
        try: parsed=json.loads(raw or b"null")
        except Exception: parsed={"raw":raw.decode(errors="replace")}
        return exc.code,parsed

def certification_inventory():
    import datetime as dt
    now=dt.datetime.now(dt.timezone.utc)
    iso=lambda value:value.isoformat().replace("+00:00","Z")
    api=[
      {"apiVersion":"v1","group":"","version":"v1","kind":"ResourceQuota","resource":"resourcequotas","namespaced":True,"verbs":["get","list","patch"]},
      {"apiVersion":"v1","group":"","version":"v1","kind":"LimitRange","resource":"limitranges","namespaced":True,"verbs":["get","list","patch"]},
      {"apiVersion":"v1","group":"","version":"v1","kind":"ServiceAccount","resource":"serviceaccounts","namespaced":True,"verbs":["get","list","patch"]},
      {"apiVersion":"v1","group":"","version":"v1","kind":"ConfigMap","resource":"configmaps","namespaced":True,"verbs":["get","list","patch"]},
      {"apiVersion":"networking.k8s.io/v1","group":"networking.k8s.io","version":"v1","kind":"NetworkPolicy","resource":"networkpolicies","namespaced":True,"verbs":["get","list","patch"]},
    ]
    return {"observedAt":iso(now),"externalUid":"ui-cert-smoke-cluster","distribution":"rke2","kubernetesVersion":"v1.34.9+rke2r1","nodes":[{"name":"node-1","uid":"node-1","roles":["control-plane"],"os":"Ubuntu 24.04","architecture":"amd64","kubeletVersion":"v1.34.9","ready":True}],"storageClasses":[],"capacity":{"cpuCapacityMilli":4000,"cpuAllocatableMilli":3500,"memoryCapacityBytes":8589934592,"memoryAllocatableBytes":7516192768,"podsCapacity":110,"podsAllocatable":100},"networking":{"cni":"cilium","gatewayApi":True},"certificates":[{"name":"kubernetes-api","subject":"CN=kubernetes","issuer":"CN=kubernetes-ca","serialNumber":"1","fingerprint":"sha256:"+"a"*64,"notBefore":iso(now-dt.timedelta(days=1)),"notAfter":iso(now+dt.timedelta(days=180))}],"capabilities":["read-only-inventory","controlled-baseline-deployment","cni-inventory","runtime-probe-image-digest-pinned","certificate-inventory","api-surface-inventory","crd-inventory","openapi-schema-authority","strict-schema-dry-run","target-enrollment-principal-isolated","target-mutation-rbac-active"],"apiResources":api,"crds":[],"apiDiscoveryComplete":True,"crdDiscoveryComplete":True,"schemaDiscoveryVersion":"OPENAPI_V3","schemaDiscoveryDigest":"sha256:"+"9"*64,"schemaDiscoveryComplete":True}

def seed_certification_cluster(api_base: str):
    status,org=api_req(api_base,"/api/v1/organizations","POST",{"name":"ui-cert-smoke","displayName":"UI Certification Smoke"}); assert status==201,(status,org)
    status,project=api_req(api_base,"/api/v1/projects","POST",{"organizationId":org["id"],"name":"prod","displayName":"Production"}); assert status==201,(status,project)
    status,created=api_req(api_base,"/api/v1/cluster-imports","POST",{"projectId":project["id"],"name":"ui-cert-cluster","displayName":"UI Certification Cluster"}); assert status==201,(status,created)
    imp=created["import"]; enrollment=created["enrollmentToken"]
    status,_=api_req(api_base,f"/api/v1/cluster-imports/{imp['id']}/approve","POST",{}, {"If-Match":f'"{imp["revision"]}"'}); assert status==200,status
    status,claimed=api_req(api_base,f"/agent/v1/cluster-imports/{imp['id']}/claim","POST",{"token":enrollment,"externalUid":"ui-cert-smoke-cluster","agentVersion":EXPECTED_VERSION}); assert status==200,(status,claimed)
    activate_mutation_rbac(api_base,claimed['cluster']['id'],claimed['agentToken'],certification_inventory())
    return project,claimed["cluster"],claimed["agentToken"]

def seed_operation_trace(api_base: str, project: dict):
    actor={"X-Actor-ID":"ui-trace-operator"}
    status,op=api_req(api_base,"/api/v1/operations","POST",{"projectId":project["id"],"kind":"ui.trace.demo","targetRef":"cluster:ui-trace","desiredRevision":"sha256:"+"7"*64,"risk":"medium","class":"MUTATING"},{**actor,"Idempotency-Key":"ui-step-trace"}); assert status==201,(status,op)
    for target in ("PLANNING","QUEUED"):
        status,op=api_req(api_base,f"/api/v1/operations/{op['id']}/transition","POST",{"state":target},{**actor,"If-Match":f'"{op["revision"]}"'}); assert status==200,(status,op)
    status,lease=api_req(api_base,f"/api/v1/operations/{op['id']}/claim","POST",{"workerId":"ui-trace-worker","leaseSeconds":60},actor); assert status==200,(status,lease)
    status,view=api_req(api_base,f"/api/v1/operations/{op['id']}"); assert status==200,(status,view); op=view["operation"]
    status,op=api_req(api_base,f"/api/v1/operations/{op['id']}/attempt/start","POST",{"workerId":"ui-trace-worker","fenceToken":lease["fenceToken"]},{**actor,"If-Match":f'"{op["revision"]}"'}); assert status==200,(status,op)
    status,step=api_req(api_base,f"/api/v1/operations/{op['id']}/steps","POST",{"workerId":"ui-trace-worker","fenceToken":lease["fenceToken"],"stepKey":"apply-resources","state":"RUNNING"},actor); assert status==201,(status,step)
    payload=json.dumps({"objects":5,"result":"read-back verified"},sort_keys=True,separators=(",",":")).encode()
    status,sealed=api_req(api_base,f"/api/v1/operations/{op['id']}/steps/forward/apply-resources/trace","POST",{"workerId":"ui-trace-worker","fenceToken":lease["fenceToken"],"traceKey":"ui-readback","level":"INFO","eventType":"kubernetes.apply.readback","message":"five resources applied and read back","evidenceKind":"kubernetes-readback","mediaType":"application/json","payloadBase64":base64.b64encode(payload).decode()},actor); assert status==201 and sealed["method"]=="OPERATION_STEP_TRACE_EVIDENCE_V1",(status,sealed)
    return op["id"],sealed["evidence"]["id"]

def start(binary: Path, root: Path, state: Path):
    port=free_port(); env=os.environ.copy(); env["PLATFORM_FACTORY_LISTEN"]=f"127.0.0.1:{port}"; env["PLATFORM_FACTORY_STATE_FILE"]=str(state); env["PLATFORM_FACTORY_DEVELOPMENT_MODE"]="true"
    env["PLATFORM_FACTORY_AGENT_MTLS_REQUIRED"]="false"
    env["PLATFORM_FACTORY_PUBLIC_URL"]="https://platform.example.test"
    env["PLATFORM_FACTORY_FLEET_AGENT_IMAGE"]="registry.local/platform-agent@sha256:"+"a"*64
    env["PLATFORM_FACTORY_RUNTIME_PROBE_IMAGE"]="registry.local/platform-probe@sha256:"+"b"*64
    process=subprocess.Popen([str(binary)],cwd=root,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
    health_base=f"http://127.0.0.1:{port}"
    browser_base=health_base
    for _ in range(120):
        try:
            with urllib.request.urlopen(health_base+"/readyz",timeout=1) as response:
                if response.status==200: return process,browser_base,health_base
        except Exception: pass
        time.sleep(.1)
    process.terminate(); raise RuntimeError("platform-api not ready")


def stop(process):
    process.terminate()
    try: process.wait(timeout=5)
    except subprocess.TimeoutExpired: process.kill(); process.wait()


def confirm(page):
    page.locator("#confirm-dialog[open] #confirm-accept").click()
    page.wait_for_timeout(120)


def card(page, channel: str, state: str):
    # Match the authoritative channel/state badges exactly. Filtering the whole card text is
    # unsafe because action labels such as "Sign & review" can make a DRAFT card look like REVIEW.
    channel_badge=page.locator(".badge").filter(has_text=re.compile(rf"^\s*{re.escape(channel)}\s*$"))
    state_badge=page.locator(".badge").filter(has_text=re.compile(rf"^\s*{re.escape(state)}\s*$"))
    return page.locator("#catalog-release-grid .resource-card, #catalog-release-grid tr[data-record-row]").filter(has=channel_badge).filter(has=state_badge).last


def wait_card(page, channel: str, state: str, timeout: int = 5000):
    item=card(page,channel,state)
    item.wait_for(state="visible",timeout=timeout)
    return item


def inline_console(root: Path) -> str:
    static=root/"webconsole/static"
    html=(static/"index.html").read_text(encoding="utf-8")
    css=(static/"styles.css").read_text(encoding="utf-8")
    js=(static/"app.js").read_text(encoding="utf-8")
    html=html.replace('<link rel="stylesheet" href="/styles.css">',f"<style>{css}</style>")
    return html.replace('<script src="/app.js"></script>',"<script>"+js.replace("</script>","<\\/script>")+"</script>")


def install_real_api_bridge(page, api_base: str) -> None:
    def real_api_fetch(url, options=None):
        options=options or {}
        target=str(url)
        if target.startswith("/"): target=api_base+target
        elif not target.startswith("http://") and not target.startswith("https://"): target=api_base+"/"+target.lstrip("/")
        method=str(options.get("method") or "GET").upper()
        headers={str(k):str(v) for k,v in (options.get("headers") or {}).items()}
        body=options.get("body")
        data=None if body is None else str(body).encode()
        request=urllib.request.Request(target,data=data,headers=headers,method=method)
        try:
            response=urllib.request.urlopen(request,timeout=5)
            raw=response.read().decode()
            return {"status":response.status,"body":raw,"headers":dict(response.headers.items())}
        except urllib.error.HTTPError as exc:
            return {"status":exc.code,"body":exc.read().decode(),"headers":dict(exc.headers.items())}
    page.expose_function("__realApiFetch",real_api_fetch)
    page.evaluate("""() => {
      const makeStore = () => { const values = new Map(); return {getItem:k => values.has(k) ? values.get(k) : null, setItem:(k,v) => values.set(k,String(v)), removeItem:k => values.delete(k), clear:() => values.clear()}; };
      Object.defineProperty(window, 'localStorage', {value:makeStore(), configurable:true});
      Object.defineProperty(window, 'sessionStorage', {value:makeStore(), configurable:true});
      window.fetch = async (input, init = {}) => {
        const headers = {};
        if (init.headers instanceof Headers) init.headers.forEach((v,k) => headers[k]=v);
        else Object.assign(headers, init.headers || {});
        const out = await window.__realApiFetch(String(input), {method:init.method || 'GET', headers, body:init.body ?? null});
        return new Response(out.body, {status:out.status, headers:out.headers});
      };
    }""")

def main() -> int:
    parser=argparse.ArgumentParser(); parser.add_argument("binary"); parser.add_argument("root",nargs="?",default="."); args=parser.parse_args()
    binary=Path(args.binary).resolve(); root=Path(args.root).resolve()
    system_chromium=os.environ.get("PLATFORM_FACTORY_UI_BROWSER_EXECUTABLE","").strip() or shutil.which("chromium") or shutil.which("chromium-browser") or shutil.which("google-chrome")
    with tempfile.TemporaryDirectory() as temp:
        process,base,api_base=start(binary,root,Path(temp)/"state.json")
        status,identity_mapping=api_req(api_base,"/api/v1/identity/group-mappings","POST",{"group":"ui-live-platform-admins","productRole":"platform-admin"}); assert status==201,(status,identity_mapping)
        project,cert_cluster,cert_agent_token=seed_certification_cluster(api_base)
        # Seed real cluster-level environment/window authority for the Connected Clusters console.
        status,maintenance_profile=api_req(api_base,f"/api/v1/clusters/{cert_cluster['id']}/maintenance-profile","PUT",{"environment":"PRODUCTION","defaultDrainTimeoutSeconds":120},{"X-Actor-ID":"ui-maint-requester"}); assert status==200,(status,maintenance_profile)
        import datetime as dt
        now=dt.datetime.now(dt.timezone.utc); iso=lambda value:value.isoformat().replace("+00:00","Z")
        status,maintenance_window=api_req(api_base,f"/api/v1/clusters/{cert_cluster['id']}/maintenance-windows","POST",{"name":"ui-live-maintenance","startsAt":iso(now-dt.timedelta(minutes=1)),"endsAt":iso(now+dt.timedelta(hours=1)),"maxUnavailable":1,"drainTimeoutSeconds":120},{"X-Actor-ID":"ui-maint-requester"}); assert status==201,(status,maintenance_window)
        status,maintenance_created=api_req(api_base,f"/api/v1/clusters/{cert_cluster['id']}/maintenance-runs","POST",{"windowId":maintenance_window['id'],"nodeNames":["node-1"]},{"X-Actor-ID":"ui-maint-requester","Idempotency-Key":"ui-live-maintenance-run"}); assert status==201,(status,maintenance_created)
        maintenance_run_id=maintenance_created["run"]["id"]
        trace_operation_id,trace_evidence_id=seed_operation_trace(api_base,project)
        # Seed a real impact-aware plan before opening the Console. The fixture describes the Agent result,
        # while platform-api independently recomputes and verifies API/disruption semantics against Authority inventory.
        status,created_plan=api_req(api_base,"/api/v1/baseline-deployments","POST",{"projectId":project["id"],"clusterId":cert_cluster["id"],"baselineId":"secure-namespace-foundation","baselineVersion":"1.0.0"},{"X-Actor-ID":"ui-operator","Idempotency-Key":"ui-live-planning-impact"}); assert status==201,(status,created_plan)
        ui_plan_id=created_plan["deployment"]["id"]
        status,plan_task=api_req(api_base,f"/agent/v1/clusters/{cert_cluster['id']}/baseline-tasks/next",headers={"Authorization":"Bearer "+cert_agent_token}); assert status==200 and plan_task["action"]=="PLAN",(status,plan_task)
        plan_changes=[{"resource":f"{r['kind']}/{r['name']}","action":"ADD","desiredDigest":plan_task["desiredDigest"]} for r in plan_task.get("resources",[])]
        plan_result={"taskFenceToken":plan_task["taskFenceToken"],"action":"PLAN","success":True,"changes":plan_changes,"impact":planning_impact(plan_task,plan_changes)}
        status,planned=api_req(api_base,f"/agent/v1/clusters/{cert_cluster['id']}/baseline-tasks/{ui_plan_id}/result","POST",plan_result,{"Authorization":"Bearer "+cert_agent_token,"If-Match":f'"{plan_task["deploymentRevision"]}"'}); assert status==200 and planned["state"]=="AWAITING_APPROVAL",(status,planned)
        playwright=sync_playwright().start()
        try:
            chromium=system_chromium or playwright.chromium.executable_path
            if not chromium or not Path(chromium).is_file():
                raise SystemExit("UI_LIVE_SMOKE_BROWSER_MISSING: install Chromium with `python3 -m playwright install chromium` or provide a system chromium/chrome")
            browser=playwright.chromium.launch(headless=True,executable_path=chromium,args=["--no-sandbox"])
            context=browser.new_context(viewport={"width":1440,"height":1000})
            page=context.new_page(); page.set_default_timeout(7000); errors=[]; failed=[]; transport="browser-http-direct"
            page.on("pageerror",lambda exc: errors.append(f"pageerror:{exc}"))
            page.on("console",lambda msg: errors.append(f"console:{msg.text}") if msg.type=="error" else None)
            page.on("response",lambda response: failed.append(f"{response.status} {response.url}") if response.status>=500 else None)
            try:
                page.goto(base+"/",wait_until="networkidle")
            except Exception as exc:
                if "ERR_BLOCKED_BY_ADMINISTRATOR" not in str(exc): raise
                page.close(); page=context.new_page(); page.set_default_timeout(7000); errors=[]; failed=[]; transport="playwright-python-real-api-bridge"
                page.on("pageerror",lambda exc: errors.append(f"pageerror:{exc}"))
                page.on("console",lambda msg: errors.append(f"console:{msg.text}") if msg.type=="error" else None)
                install_real_api_bridge(page,api_base)
                page.set_content(inline_console(root),wait_until="load")
                page.wait_for_timeout(300)
            # Workspace exposes the real OIDC group mapping authority, not realm-role decoration.
            page.evaluate("() => navigate('workspace')"); page.wait_for_timeout(300)
            assert page.locator("#workspace.page.active").count()==1
            identity_text=page.locator("#oidc-group-mapping-panel").inner_text()
            assert "OIDC_GROUP_MAPPING_AUTHORITY_V1" in identity_text and "ui-live-platform-admins" in identity_text and "realm roles ignored" in identity_text,identity_text

            # Connected Clusters exposes the real cluster maintenance authority and pending approval state.
            page.evaluate("() => navigate('clusters')"); page.wait_for_timeout(350)
            assert page.locator("#clusters.page.active").count()==1
            page.locator("#clusters details[data-operator-action='maintenance']").evaluate("el => el.open = true")
            maintenance_text=page.locator("#cluster-maintenance-panel").inner_text()
            assert "KUBERNETES_NODE_MAINTENANCE_V1" in maintenance_text and "PRODUCTION" in maintenance_text,maintenance_text
            window_card=page.locator("#maintenance-window-grid .resource-card").first
            run_card=page.locator("#maintenance-run-grid .resource-card").first
            window_card.scroll_into_view_if_needed(); run_card.scroll_into_view_if_needed()
            window_text=window_card.inner_text(); run_text=run_card.inner_text()
            assert "ui-live-maintenance" in window_text,window_text
            assert "AWAITING_APPROVAL" in run_text,run_text
            assert page.locator(f'#maintenance-run-grid [data-maintenance-run-action="inspect"][data-id="{maintenance_run_id}"]').count()==1,run_text

            page.evaluate("() => navigate('catalog')"); page.wait_for_timeout(250)
            assert page.locator("#catalog.page.active").count()==1
            admission=json.loads((root/'catalog/upstream-admission.json').read_text())['spec']['components']
            admission_text=page.locator("#catalog-upstream-admission").inner_text()
            expected_review=[row['component'] for row in admission if row.get('status')!='ready-for-acquisition']
            expected_ready=sum(1 for row in admission if row.get('status')=='ready-for-acquisition')
            assert f"{expected_ready}" in page.locator("#catalog-summary").inner_text()
            for component_name in expected_review: assert component_name in admission_text
            page.locator("#catalog details.action-console").first.evaluate("el => el.open = true")
            assert page.locator("#catalog-signer").inner_text().find("Signer ready")>=0
            page.locator("#catalog-trust-form button[type='submit']").click()
            trust_card=page.locator("#catalog-trust-grid .resource-card")
            trust_card.first.wait_for(state="visible")
            assert trust_card.count()==1

            page.locator("#catalog-release-visibility").select_option("PLATFORM")
            page.locator("#catalog-release-version").fill("1.0.0")
            checks=page.locator("[data-catalog-component-select]")
            assert checks.count()>=1
            checked=[]
            for i in range(checks.count()):
                if checks.nth(i).is_checked(): checked.append(checks.nth(i).get_attribute("value"))
            assert checked==["secure-namespace-foundation"],checked
            page.locator("#catalog-release-form button[type='submit']").click(); page.wait_for_timeout(300)
            c=wait_card(page,"CANDIDATE","DRAFT")
            c.locator("[data-catalog-action='review']").click(); confirm(page)
            c=wait_card(page,"CANDIDATE","REVIEW")
            c.locator("[data-catalog-action='publish']").click(); confirm(page)
            c=wait_card(page,"CANDIDATE","PUBLISHED")
            c.locator("[data-catalog-action='promote']").click(); page.wait_for_timeout(300)
            r=wait_card(page,"RENDER","DRAFT")
            r.locator("[data-catalog-action='review']").click(); confirm(page)
            r=wait_card(page,"RENDER","REVIEW")
            r.locator("[data-catalog-action='publish']").click(); confirm(page)
            r=wait_card(page,"RENDER","PUBLISHED")
            page.locator("#catalog-render-namespace").fill("ui-live-smoke")
            r.locator("[data-catalog-action='render']").click(); page.wait_for_timeout(300)
            dialog=page.locator("#detail-dialog[open]")
            assert dialog.count()==1
            text=dialog.inner_text()
            assert "Deterministic render complete" in text and "6 Kubernetes resources" in text,text
            technical=dialog.locator("pre").first.inner_text()
            assert "ui-live-smoke" in technical and "${" not in technical and "example.invalid" not in technical
            page.locator('#detail-dialog button[value="close"]').click(); page.wait_for_timeout(100)

            # Prove Planning Impact review is wired to the real Authority and approval gating.
            page.evaluate("() => navigate('baselines')"); page.wait_for_timeout(350)
            assert page.locator("#baselines.page.active").count()==1
            plan_card=page.locator("#baseline-deployment-grid .resource-card").filter(has_text="secure-namespace-foundation").filter(has_text="IMPACT READY")
            plan_card.wait_for(state="visible",timeout=4000)
            plan_text=plan_card.inner_text()
            assert "MEDIUM" in plan_text and "RECOMMENDED" in plan_text,plan_text
            assert plan_card.locator("[data-baseline-action='approve']").count()==1,plan_text
            impact_summary=plan_card.locator("details > summary").filter(has_text="Impact, capacity & maintenance")
            impact_summary.click(); impact_details=impact_summary.locator("xpath=.."); impact_details.scroll_into_view_if_needed()
            impact_text=impact_details.inner_text()
            assert "PLATFORM_COMPATIBILITY_MATRIX_V1" in impact_text and "Compatibility matrix" in impact_text and "amd64" in impact_text and "rke2" in impact_text and "imported" in impact_text and "API / CRD compatibility" in impact_text and "Strict schema dry-run" in impact_text and "Rollback feasibility" in impact_text and "Evidence collection" in impact_text and "Current usage" in impact_text and "UNKNOWN" in impact_text and "free headroom" in impact_text,impact_text
            evidence_summary=plan_card.locator("details > summary").filter(has_text="Evidence collection plan (6)")
            evidence_summary.click(); evidence_details=evidence_summary.locator("xpath=.."); evidence_details.scroll_into_view_if_needed()
            evidence_text=evidence_details.inner_text()
            assert "BASELINE_EVIDENCE_COLLECTION_V1" in impact_text,impact_text
            assert "KUBE_RESOURCE_READBACK" in evidence_text and "90 days" in evidence_text,evidence_text
            rollback_summary=plan_card.locator("details > summary").filter(has_text="Rollback feasibility (5)")
            rollback_summary.click(); rollback_details=rollback_summary.locator("xpath=.."); rollback_details.scroll_into_view_if_needed()
            rollback_text=rollback_details.inner_text()
            assert "DELETE_CREATED_RESOURCE" in rollback_text and "Authorization: PASS" in rollback_text,rollback_text
            plan_card.locator("[data-baseline-action='approve']").click(); confirm(page); page.wait_for_timeout(300)
            status,approved_plan=api_req(api_base,f"/api/v1/baseline-deployments/{ui_plan_id}")
            assert status==200 and approved_plan["state"]=="QUEUED" and approved_plan["planImpact"]["approvalReady"] is True,(status,approved_plan)

            # Prove the new Certification Console action is backed by the real Authority, not decorative UI.
            page.evaluate("() => navigate('verification')"); page.wait_for_timeout(350)
            assert page.locator("#verification.page.active").count()==1
            page.locator("#verification details.action-console").first.evaluate("el => el.open = true")
            assert page.locator("#runtime-certification-project").input_value()==project["id"]
            assert page.locator("#runtime-certification-cluster").input_value()==cert_cluster["id"]
            assert page.locator("#runtime-certification-catalog option").count()>=1
            page.locator("#runtime-certification-namespace").fill("ui-cert-foundation")
            page.locator("#runtime-certification-form button[type='submit']").click(); page.wait_for_timeout(350)
            cert_card=page.locator("#runtime-certification-grid .resource-card").filter(has_text="FOUNDATION_V1").filter(has_text="QUEUED")
            assert cert_card.count()==1, page.locator("#runtime-certification-grid").inner_text()
            cert_card.locator("[data-certification-action='inspect']").click(); page.wait_for_timeout(100)
            cert_detail=page.locator("#detail-dialog[open]").inner_text()
            assert "External Live Certified: false" in cert_detail and "Production Ready: false" in cert_detail,cert_detail
            page.locator('#detail-dialog button[value="close"]').click(); page.wait_for_timeout(80)

            # Operations Console exposes the real per-step trace/evidence authority, not a decorative log.
            page.evaluate("() => navigate('operations')"); page.wait_for_timeout(300)
            assert page.locator("#operations.page.active").count()==1
            security_text=page.locator("#security-audit-panel").inner_text()
            assert "IMMUTABLE_AUTHN_AUTHZ_AUDIT_V1" in security_text and "hash-chain linked" in security_text and "AUTHENTICATION" in security_text and "AUTHORIZATION" in security_text,security_text
            trace_row=page.locator("#operation-grid tr[data-record-row]").filter(has_text="ui.trace.demo").locator("[data-operation-id]")
            trace_row.wait_for(state="visible",timeout=4000); assert trace_row.count()==1,page.locator("#operation-grid").inner_text()
            trace_row.click(); page.wait_for_timeout(120)
            trace_dialog=page.locator("#detail-dialog[open]"); trace_text=trace_dialog.inner_text()
            assert "Step trace / logs & evidence" in trace_text and "OPERATION_STEP_TRACE_EVIDENCE_V1" in trace_text and "FORWARD · apply-resources · attempt 1 · #1" in trace_text,trace_text
            assert "kubernetes.apply.readback" in trace_text and "five resources applied and read back" in trace_text and "payload available" in trace_text and "Inspect payload" in trace_text,trace_text
            status,trace_view=api_req(api_base,f"/api/v1/operations/{trace_operation_id}"); assert status==200 and trace_view["traces"][0]["evidenceId"]==trace_evidence_id,(status,trace_view)
            trace_dialog.locator(f'[data-operation-evidence-payload="{trace_evidence_id}"]').click(); page.wait_for_timeout(100)
            payload_text=page.locator("#detail-dialog[open]").inner_text(); assert "Step evidence payload" in payload_text and "read-back verified" in payload_text,payload_text
            page.locator('#detail-dialog button[value="close"]').click(); page.wait_for_timeout(80)

            # Notification Console actions use the real Authority. Delivery transport is covered by smoke_notification_routing.py.
            page.evaluate("() => navigate('notifications')"); page.wait_for_timeout(300)
            assert page.locator("#notifications.page.active").count()==1
            page.locator("#notifications details.action-console").first.evaluate("el => el.open = true")
            page.wait_for_function("() => document.querySelector('#notification-destination-organization')?.options.length > 0")
            page.locator("#notification-destination-organization").select_option(project["organizationId"])
            page.locator("#notification-route-organization").select_option(project["organizationId"])
            page.locator("#notification-destination-name").fill("ui-console-alerts")
            page.locator("#notification-destination-kind").select_option("CONSOLE")
            page.locator("#notification-destination-form button[type='submit']").click()
            dest_card=page.locator("#notification-destination-grid tr[data-record-row]").filter(has_text="ui-console-alerts").filter(has_text="ACTIVE")
            try: dest_card.wait_for(state="visible",timeout=4000)
            except Exception: pass
            if dest_card.count()!=1:
                status,debug_destinations=api_req(api_base,"/api/v1/notification-destinations")
                raise AssertionError({"grid":page.locator("#notification-destination-grid").inner_text(),"apiStatus":status,"destinations":debug_destinations,"toast":page.locator("#toast").inner_text() if page.locator("#toast").count() else ""})
            page.locator("#notification-route-name").fill("ui-runtime-failures")
            event_box=page.locator("#notification-event-type-list input[value='certification.failed']")
            assert event_box.count()==1; event_box.check()
            options=page.locator("#notification-route-destinations option")
            assert options.count()>=1
            page.locator("#notification-route-destinations").select_option([options.first.get_attribute("value")])
            page.locator("#notification-route-form button[type='submit']").click()
            route_card=page.locator("#notification-route-grid tr[data-record-row]").filter(has_text="ui-runtime-failures").filter(has_text="ACTIVE")
            route_card.wait_for(state="visible",timeout=4000)
            assert route_card.count()==1,page.locator("#notification-route-grid").inner_text()
            page.locator("#notification-preview-organization").select_option(project["organizationId"])
            page.locator("#notification-preview-event-type").select_option("certification.failed")
            page.locator("#notification-preview-severity").select_option("CRITICAL")
            page.locator("#notification-preview-form button[type='submit']").click()
            page.wait_for_function("() => document.querySelector('#notification-preview-result')?.textContent?.includes('ui-runtime-failures')")
            preview_text=page.locator("#notification-preview-result").inner_text()
            assert "ui-runtime-failures" in preview_text and "Side effects" in preview_text and "NONE" in preview_text,preview_text
            status,preview_api=api_req(api_base,"/api/v1/notification-routing/preview",method="POST",body={"organizationId":project["organizationId"],"eventType":"certification.failed","severity":"CRITICAL"})
            assert status==200 and preview_api["authority"]=="NOTIFICATION_ROUTING_PREVIEW_AUTHORITY_V1" and preview_api["sideEffects"] is False and preview_api["deliveryCreated"] is False,(status,preview_api)

            # Blueprint Overlay Console creates a real immutable Authority resource.
            page.evaluate("() => navigate('blueprints')"); page.wait_for_timeout(300)
            assert page.locator("#blueprints.page.active").count()==1
            page.locator("#blueprint-expert-tools").evaluate("el => el.open = true")
            page.wait_for_function("() => document.querySelector('#blueprint-parity-summary')?.textContent?.includes('27/27')")
            parity_summary=page.locator("#blueprint-parity-summary").inner_text()
            assert "BLUEPRINT_VISUAL_API_AUTHORING_PARITY_V1" in parity_summary and "27/27" in parity_summary,parity_summary
            page.locator("#blueprint-verify-parity").click(); page.wait_for_timeout(250)
            parity_result=page.locator("#blueprint-parity-result").inner_text()
            assert "Exact round-trip PASS" in parity_result and "BLUEPRINT_VISUAL_API_AUTHORING_PARITY_V1" in parity_result,parity_result
            page.locator("#blueprint-overlay-project").select_option(project["id"])
            page.locator("#blueprint-overlay-scope").select_option("PROVIDER")
            page.locator("#blueprint-overlay-name").fill("ui-provider-overlay")
            page.locator("#blueprint-overlay-version").fill("1.0.0")
            page.locator("#blueprint-overlay-key").fill("vsphere")
            page.locator("#blueprint-overlay-changes").fill('/spec/description = "UI provider overlay"')
            page.locator("#blueprint-overlay-form button[type='submit']").click()
            overlay_card=page.locator("#blueprint-overlay-grid .resource-card").filter(has_text="ui-provider-overlay").filter(has_text="PROVIDER")
            overlay_card.wait_for(state="visible",timeout=4000)
            assert overlay_card.count()==1,page.locator("#blueprint-overlay-grid").inner_text()
            status,debug_overlays=api_req(api_base,f'/api/v1/blueprint-overlays?projectId={project["id"]}')
            assert status==200 and any(row.get("name")=="ui-provider-overlay" for row in debug_overlays),(status,debug_overlays)

            page.locator("#language-toggle").click(); page.wait_for_timeout(100)
            assert page.locator("html").get_attribute("dir")=="rtl"
            screenshot=smoke_evidence_dir(root)/"catalog-live-authority-1440x1000.png"
            page.screenshot(path=str(screenshot),full_page=True)
            context.close(); browser.close()
            if errors or failed: raise AssertionError({"errors":errors,"failedResponses":failed})
            report={"schemaVersion":1,"mode":"live-loopback-real-platform-api","authorityMocked":False,"browserTransport":transport,"browserHTTPDirect":transport=="browser-http-direct","fetchTransportBridge":transport!="browser-http-direct","catalogLifecycle":"CANDIDATE->RENDER PUBLISHED","renderResourceCount":6,"planningImpactConsoleAuthorityMocked":False,"planningImpactReviewVisible":True,"planningImpactApprovedFromConsole":True,"operationStepTraceConsoleAuthorityMocked":False,"operationStepTraceVisible":True,"runtimeCertificationConsoleQueued":True,"runtimeCertificationAuthorityMocked":False,"notificationConsoleAuthorityMocked":False,"notificationDestinationCreated":True,"notificationRouteCreated":True,"notificationRoutingPreviewVerified":True,"blueprintOverlayConsoleAuthorityMocked":False,"blueprintOverlayCreated":True,"blueprintAuthoringParityAuthorityMocked":False,"blueprintAuthoringParityVisible":True,"blueprintAuthoringRoundTripPASS":True,"rtlVerified":True,"externalRuntimeCertified":False,"screenshot":str(screenshot),"status":"PASS"}
            (smoke_evidence_dir(root)/"catalog-live-authority-smoke.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
            print("UI_LIVE_AUTHORITY_SMOKE_PASS",screenshot)
        finally:
            try:
                playwright.stop()
            finally:
                stop(process)
    return 0


if __name__=="__main__":
    raise SystemExit(main())
