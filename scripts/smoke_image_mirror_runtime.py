#!/usr/bin/env python3
from __future__ import annotations
import datetime as dt, hashlib, json, os, socket, subprocess, sys, tempfile, threading, time, urllib.error, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

SNAPSHOT_IMAGE='registry.k8s.io/sig-storage/snapshot-controller@sha256:74ca61ab13e978f03cf0f336a607281d15f04cda0a38a881306365473b28a3d8'

def sha(raw:bytes)->str: return 'sha256:'+hashlib.sha256(raw).hexdigest()
def free_port():
    with socket.socket() as s: s.bind(('127.0.0.1',0)); return s.getsockname()[1]

def write_blob(root:Path, raw:bytes)->dict:
    dg=sha(raw); p=root/'blobs'/'sha256'/dg.split(':',1)[1]; p.parent.mkdir(parents=True,exist_ok=True); p.write_bytes(raw)
    return {'digest':dg,'size':len(raw)}

def make_oci_layout(root:Path):
    root.mkdir(parents=True,exist_ok=True); (root/'oci-layout').write_text('{"imageLayoutVersion":"1.0.0"}')
    config=json.dumps({'architecture':'amd64','os':'linux'},separators=(',',':')).encode(); cd=write_blob(root,config); cd['mediaType']='application/vnd.oci.image.config.v1+json'
    layer=b'4so-test-only-oci-layer'; ld=write_blob(root,layer); ld['mediaType']='application/vnd.oci.image.layer.v1.tar'
    manifest={'schemaVersion':2,'mediaType':'application/vnd.oci.image.manifest.v1+json','config':cd,'layers':[ld]}
    mraw=json.dumps(manifest,separators=(',',':'),sort_keys=True).encode(); md=write_blob(root,mraw); md['mediaType']='application/vnd.oci.image.manifest.v1+json'
    (root/'index.json').write_text(json.dumps({'schemaVersion':2,'manifests':[md]},separators=(',',':')))
    return 'registry.test.invalid/team/test-image@'+md['digest']

class RegistryState:
    def __init__(self): self.blobs={}; self.manifests={}; self.uploads={}; self.lock=threading.Lock()

class Handler(BaseHTTPRequestHandler):
    state:RegistryState=None
    def log_message(self,*_): pass
    def do_POST(self):
        if '/blobs/uploads/' in self.path:
            loc=self.path.rstrip('/')+'/upload-1'; self.send_response(202); self.send_header('Location',loc); self.end_headers(); return
        self.send_error(404)
    def do_PUT(self):
        raw=self.rfile.read(int(self.headers.get('Content-Length','0') or 0))
        if '/blobs/uploads/' in self.path:
            from urllib.parse import urlparse,parse_qs
            dg=parse_qs(urlparse(self.path).query).get('digest',[''])[0]
            if sha(raw)!=dg: self.send_error(400); return
            with self.state.lock: self.state.blobs[dg]=raw
            self.send_response(201); self.end_headers(); return
        if '/manifests/' in self.path:
            dg=self.path.rsplit('/',1)[-1]
            if sha(raw)!=dg: self.send_error(400); return
            with self.state.lock: self.state.manifests[dg]=raw
            self.send_response(201); self.send_header('Docker-Content-Digest',dg); self.end_headers(); return
        self.send_error(404)
    def do_HEAD(self):
        dg=self.path.rsplit('/',1)[-1]
        with self.state.lock:
            exists=(dg in self.state.manifests) if '/manifests/' in self.path else (dg in self.state.blobs)
        if not exists: self.send_response(404); self.end_headers(); return
        self.send_response(200)
        if '/manifests/' in self.path: self.send_header('Docker-Content-Digest',dg)
        self.end_headers()

def iso(t): return t.isoformat().replace('+00:00','Z')

def target_inventory():
    now=dt.datetime.now(dt.timezone.utc)
    return {'observedAt':iso(now),'externalUid':'image-mirror-smoke-cluster','distribution':'rke2','kubernetesVersion':'v1.34.9+rke2r1','nodes':[{'name':'node-1','uid':'node-1','roles':['control-plane'],'os':'Ubuntu 24.04','architecture':'amd64','kubeletVersion':'v1.34.9','ready':True}], 'storageClasses':[{'name':'replicated','provisioner':'openebs.io/local','reclaimPolicy':'Delete','volumeBindingMode':'WaitForFirstConsumer','allowVolumeExpansion':True,'default':True}], 'capacity':{'cpuCapacityMilli':4000,'cpuAllocatableMilli':3500,'memoryCapacityBytes':8589934592,'memoryAllocatableBytes':7516192768,'podsCapacity':110,'podsAllocatable':100}, 'networking':{'cni':'cilium','ingressControllers':['rke2-ingress-nginx'],'gatewayApi':True}, 'certificates':[{'name':'kubernetes-api','subject':'CN=kubernetes','issuer':'CN=kubernetes-ca','serialNumber':'1','fingerprint':'sha256:'+'a'*64,'notBefore':iso(now-dt.timedelta(days=1)),'notAfter':iso(now+dt.timedelta(days=180))}], 'addOns':[{'name':'cilium','namespace':'kube-system','version':'1.18','healthy':True}], 'capabilities':['read-only-inventory','storage-inventory','capacity-inventory','certificate-inventory','cert.metrics','cert.logs','cert.alerts','cert.dns','cert.tls','cert.network','cert.tenant-isolation','cert.pvc','cert.snapshot','cert.backup','cert.restore','target-enrollment-principal-isolated','target-mutation-rbac-active']}

def activate_mutation_rbac(base,cluster_id,token,desired):
    initial=json.loads(json.dumps(desired)); initial['capabilities']=[c for c in initial.get('capabilities',[]) if c not in ('target-mutation-rbac-active','target-mutation-rbac-activation-issued')]
    if 'target-enrollment-principal-isolated' not in initial['capabilities']: initial['capabilities'].append('target-enrollment-principal-isolated')
    st,out=req(base,f"/agent/v1/clusters/{cluster_id}/inventory",'POST',initial,{'Authorization':'Bearer '+token}); assert st==200,(st,out)
    st,activation=req(base,f"/api/v1/clusters/{cluster_id}/mutation-rbac-manifest",'POST',{},headers={'X-Actor-ID':'operator'}); assert st==200 and activation.get('activationIssued') is True,(st,activation)
    active=json.loads(json.dumps(desired)); caps=[c for c in active.get('capabilities',[]) if c!='target-mutation-rbac-activation-issued']
    if 'target-enrollment-principal-isolated' not in caps: caps.append('target-enrollment-principal-isolated')
    if 'target-mutation-rbac-active' not in caps: caps.append('target-mutation-rbac-active')
    active['capabilities']=caps
    st,out=req(base,f"/agent/v1/clusters/{cluster_id}/inventory",'POST',active,{'Authorization':'Bearer '+token}); assert st==200,(st,out)
    return out

def complete_target_certification(base,project_id,cluster_id,token,release_id):
    st,created=req(base,'/api/v1/runtime-certifications','POST',{'projectId':project_id,'clusterId':cluster_id,'catalogReleaseId':release_id,'profile':'TARGET_RUNTIME_V1','namespace':'4so-image-mirror-cert'},{'Idempotency-Key':'image-mirror-target-runtime-1'}); assert st==201 and created['run']['state']=='QUEUED',(st,created)
    st,install=req(base,f'/agent/v1/clusters/{cluster_id}/runtime-certification-tasks/next',headers={'Authorization':'Bearer '+token}); assert st==200 and install['phase']=='INSTALL',(st,install)
    n=len(install['resources']); assert n>0,install
    checks=[{'key':'fresh-install-target','status':'PASS'}]+[{'key':f'apply/{i}','status':'PASS'} for i in range(1,n+1)]
    st,cp=req(base,f"/agent/v1/clusters/{cluster_id}/runtime-certification-tasks/{install['runId']}/result",'POST',{'taskFenceToken':install['taskFenceToken'],'phase':'INSTALL','success':True,'inventoryDigest':install['inventoryDigest'],'renderedDigest':install['renderedDigest'],'checks':checks},{'Authorization':'Bearer '+token,'If-Match':f'"{install["runRevision"]}"'}); assert st==200 and cp['state']=='VERIFYING',(st,cp)
    st,verify=req(base,f'/agent/v1/clusters/{cluster_id}/runtime-certification-tasks/next',headers={'Authorization':'Bearer '+token}); assert st==200 and verify['phase']=='VERIFY',(st,verify)
    required=['nodes-ready','cluster-dns-service','kubernetes-api-tls','target-runtime/metrics-query','target-runtime/logs-push','target-runtime/logs-query','target-runtime/alert-fire','target-runtime/alert-query','target-runtime/network-namespaces','target-runtime/network-default-deny','target-runtime/network-dns-tenant-a','target-runtime/network-dns-tenant-b','target-runtime/network-intra-tenant-allow','target-runtime/network-cross-tenant-deny','target-runtime/network-cross-tenant-explicit-allow','target-runtime/pvc-bind','target-runtime/pvc-io','target-runtime/snapshot-create','target-runtime/snapshot-restore-pvc','target-runtime/snapshot-restore-io','target-runtime/backup-create','target-runtime/restore-validate']
    checks=[{'key':'durable-install-checkpoint','status':'PASS'}]+[{'key':f'verify/{i}','status':'PASS'} for i in range(1,n+1)]+[{'key':k,'status':'PASS'} for k in required]
    st,done=req(base,f"/agent/v1/clusters/{cluster_id}/runtime-certification-tasks/{verify['runId']}/result",'POST',{'taskFenceToken':verify['taskFenceToken'],'phase':'VERIFY','success':True,'inventoryDigest':verify['inventoryDigest'],'renderedDigest':verify['renderedDigest'],'checks':checks},{'Authorization':'Bearer '+token,'If-Match':f'"{verify["runRevision"]}"'}); assert st==200 and done['state']=='SUCCEEDED' and done['evidenceDigest'].startswith('sha256:'),(st,done)
    return done['evidenceDigest']

def run_json(cmd,cwd):
    p=subprocess.run([str(x) for x in cmd],cwd=cwd,text=True,capture_output=True,timeout=120)
    if p.returncode!=0: raise RuntimeError(f"command failed {cmd}: {p.returncode}\nstdout={p.stdout}\nstderr={p.stderr}")
    return json.loads(p.stdout)

def req(base,path,method='GET',body=None,headers=None):
    data=None if body is None else json.dumps(body).encode(); h=dict(headers or {})
    if data is not None: h['Content-Type']='application/json'
    r=urllib.request.Request(base+path,data=data,method=method,headers=h)
    try:
        with urllib.request.urlopen(r,timeout=8) as resp: return resp.status,json.loads(resp.read() or b'null')
    except urllib.error.HTTPError as e:
        raw=e.read()
        try: out=json.loads(raw or b'null')
        except Exception: out={'raw':raw.decode(errors='replace')}
        return e.code,out

def start_api(binary,root,state,zot):
    port=free_port(); env=os.environ.copy(); env['PLATFORM_FACTORY_LISTEN']=f'127.0.0.1:{port}'; env['PLATFORM_FACTORY_STATE_FILE']=str(state); env['PLATFORM_FACTORY_INTERNAL_REGISTRY_URL']=zot
    env['PLATFORM_FACTORY_AGENT_MTLS_REQUIRED']='false'; env['PLATFORM_FACTORY_PUBLIC_URL']='https://platform.example.test'; env['PLATFORM_FACTORY_FLEET_AGENT_IMAGE']='registry.local/platform-agent@sha256:'+'a'*64; env['PLATFORM_FACTORY_RUNTIME_PROBE_IMAGE']='registry.local/platform-probe@sha256:'+'b'*64
    p=subprocess.Popen([str(binary)],cwd=root,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True); base=f'http://127.0.0.1:{port}'
    for _ in range(120):
        try:
            if req(base,'/readyz')[0]==200: return p,base
        except Exception: pass
        time.sleep(.1)
    p.terminate(); raise RuntimeError('platform-api not ready')

def stop(p):
    p.terminate()
    try:p.wait(timeout=5)
    except subprocess.TimeoutExpired:p.kill();p.wait()

def lifecycle(base,rel):
    st,r=req(base,f"/api/v1/catalog-releases/{rel['id']}/review",'POST',{}, {'If-Match':f'"{rel["revision"]}"'}); assert st==200,(st,r)
    st,r=req(base,f"/api/v1/catalog-releases/{rel['id']}/publish",'POST',{}, {'If-Match':f'"{r["revision"]}"'}); assert st==200,(st,r)
    return r

def main():
    if len(sys.argv)!=3: raise SystemExit('usage: smoke_image_mirror_runtime.py platform-api platformctl')
    api=Path(sys.argv[1]).resolve(); ctl=Path(sys.argv[2]).resolve(); root=Path(__file__).resolve().parents[1]
    state=RegistryState(); Handler.state=state; srv=ThreadingHTTPServer(('127.0.0.1',0),Handler); thread=threading.Thread(target=srv.serve_forever,daemon=True); thread.start(); registry=f'http://127.0.0.1:{srv.server_address[1]}'
    try:
        with tempfile.TemporaryDirectory() as td:
            td=Path(td); layout=td/'oci'; ref=make_oci_layout(layout); bundle=td/'image-bundle.zip'
            assembled=run_json([ctl,'image-bundle','assemble','--oci-layout',layout,'--reference',ref,'--out',bundle],root); assert assembled['assembled'] is True and assembled['networkFetchRequired'] is False,assembled
            verified=run_json([ctl,'image-bundle','verify','-f',bundle],root); assert verified['valid'] is True and verified['sourceReference']==ref,verified
            pushed=run_json([ctl,'image-bundle','push','-f',bundle,'--registry-url',registry,'--confirmation','MIRROR'],root); assert pushed['registryVerified'] is True and pushed['mirrorReference'].startswith(f'127.0.0.1:{srv.server_address[1]}/mirror/'),pushed
            root_digest=ref.rsplit('@',1)[1]
            with state.lock: assert root_digest in state.manifests and len(state.blobs)==2,(state.manifests.keys(),state.blobs.keys())

            p,base=start_api(api,root,td/'state.json',registry)
            try:
                st,org=req(base,'/api/v1/organizations','POST',{'name':'image-mirror-smoke','displayName':'Image Mirror Smoke'}); assert st==201,(st,org)
                st,project=req(base,'/api/v1/projects','POST',{'organizationId':org['id'],'name':'mirror-cert','displayName':'Mirror Certification'}); assert st==201,(st,project)
                st,version=req(base,'/api/v1/version'); assert st==200,(st,version)
                st,created_import=req(base,'/api/v1/cluster-imports','POST',{'projectId':project['id'],'name':'mirror-edge','displayName':'Mirror Edge'}); assert st==201,(st,created_import)
                imp=created_import['import']; enrollment=created_import['enrollmentToken']
                st,_=req(base,f"/api/v1/cluster-imports/{imp['id']}/approve",'POST',{}, {'If-Match':'1'}); assert st==200,st
                st,claimed=req(base,f"/agent/v1/cluster-imports/{imp['id']}/claim",'POST',{'token':enrollment,'externalUid':'image-mirror-smoke-cluster','agentVersion':version['version']}); assert st==200,(st,claimed)
                cluster=claimed['cluster']; token=claimed['agentToken']
                activate_mutation_rbac(base,cluster['id'],token,target_inventory())
                st,signer=req(base,'/api/v1/catalog-governance/signing-identity'); assert st==200 and signer.get('available') is True,(st,signer)
                st,key=req(base,'/api/v1/catalog-trust-keys','POST',{'organizationId':org['id'],'name':'mirror-signer','publicKey':signer['publicKey']}); assert st==201,(st,key)
                st,components=req(base,'/api/v1/catalog/components'); assert st==200,(st,components)
                selected=[c for c in components if c.get('metadata',{}).get('name') in ('secure-namespace-foundation','snapshot-controller')]; assert len(selected)==2,selected
                st,created=req(base,'/api/v1/catalog-releases','POST',{'organizationId':org['id'],'catalogName':'image-mirror-smoke','catalogVersion':'1.0.0','visibility':'PRIVATE','channel':'CANDIDATE','components':selected}); assert st==201,(st,created)
                cand=lifecycle(base,created['release'])
                st,prom=req(base,f"/api/v1/catalog-releases/{cand['id']}/promote",'POST',{'channel':'RENDER'}); assert st==201,(st,prom)
                rend=lifecycle(base,prom['release'])
                evidence=complete_target_certification(base,project['id'],cluster['id'],token,rend['id'])
                st,prom=req(base,f"/api/v1/catalog-releases/{rend['id']}/promote",'POST',{'channel':'RUNTIME'}); assert st==201,(st,prom)
                rel=prom['release']
                for component in selected:
                    component['spec']['certification']={'status':'target-runtime-certified','profiles':['TARGET_RUNTIME_V1'],'evidenceDigest':evidence}
                st,detail=req(base,f"/api/v1/catalog-releases/{rel['id']}/draft",'PUT',{'components':selected},{'If-Match':f'"{rel["revision"]}"'}); assert st==200,(st,detail)
                rel=detail['release']
                st,review=req(base,f"/api/v1/catalog-releases/{rel['id']}/review",'POST',{}, {'If-Match':f'"{rel["revision"]}"'}); assert st==200,(st,review)
                st,blocked=req(base,f"/api/v1/catalog-releases/{rel['id']}/publish",'POST',{}, {'If-Match':f'"{review["revision"]}"'}); assert st==422 and 'mirror' in json.dumps(blocked).lower(),(st,blocked)
                snapshot_digest=SNAPSHOT_IMAGE.rsplit('@',1)[1]
                with state.lock: state.manifests[snapshot_digest]=b'TEST-HARNESS-HEAD-PRESENCE-ONLY'
                st,still_blocked=req(base,f"/api/v1/catalog-releases/{rel['id']}/publish",'POST',{}, {'If-Match':f'"{review["revision"]}"'})
                assert st==422 and 'component-specific runtime certification authority is required' in json.dumps(still_blocked),(st,still_blocked)
                # A valid managed mirror is necessary for RUNTIME, but it is not
                # sufficient: TARGET_RUNTIME_V1 proves the target capability
                # harness and must not certify snapshot-controller (or any other
                # component that was not installed from its immutable source).
                with state.lock: assert snapshot_digest in state.manifests,state.manifests.keys()
                assert pushed['registryVerified'] is True,pushed
                print('OCI_IMAGE_MIRROR_AIRGAP_AUTHORITY_SMOKE_PASS',assembled['bundleDigest'],pushed['mirrorReference'],snapshot_digest)
            finally: stop(p)
    finally:
        srv.shutdown(); srv.server_close(); thread.join(timeout=2)
    return 0
if __name__=='__main__': raise SystemExit(main())
