#!/usr/bin/env python3
"""Run the standalone bootstrap installer through its HTTP API in simulation mode."""
from __future__ import annotations
import base64, hashlib, json, os, socket, subprocess, sys, tempfile, time
from pathlib import Path

from oci_smoke_fixture import workload_repositories, write_workload_oci_archive

EXPECTED_VERSION = (Path(__file__).resolve().parents[1] / 'VERSION').read_text().strip()
from urllib.request import Request, urlopen
from urllib.error import HTTPError

def sha(data: bytes) -> str: return 'sha256:'+hashlib.sha256(data).hexdigest()
def free_port() -> int:
    with socket.socket() as s: s.bind(('127.0.0.1',0)); return s.getsockname()[1]
def request(url: str, token: str, method='GET', payload=None, headers=None):
    body=None if payload is None else json.dumps(payload).encode()
    request_headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'}
    request_headers.update(headers or {})
    req=Request(url,data=body,method=method,headers=request_headers)
    try:
        with urlopen(req,timeout=10) as response: return response.status,json.load(response)
    except HTTPError as exc: return exc.code,json.load(exc)
def main() -> int:
    binary=Path(sys.argv[1]).resolve()
    platformctl=Path(sys.argv[2]).resolve() if len(sys.argv)>2 else None
    with tempfile.TemporaryDirectory() as tmp:
        root=Path(tmp)
        cli_state=root/'cli-contract-state'
        cli_env=os.environ.copy(); cli_env['PLATFORM_INSTALLER_STATE_DIR']=str(cli_state)
        completed=subprocess.run([str(binary),'--help'],env=cli_env,capture_output=True,text=True,timeout=5)
        assert completed.returncode==0 and 'Usage: platform-installer' in completed.stdout,(completed.returncode,completed.stdout,completed.stderr)
        assert not cli_state.exists(),'--help must not initialize installer state'
        completed=subprocess.run([str(binary),'--definitely-unknown'],env=cli_env,capture_output=True,text=True,timeout=5)
        assert completed.returncode==2 and 'unknown platform-installer argument' in completed.stderr,(completed.returncode,completed.stdout,completed.stderr)
        assert not cli_state.exists(),'unknown arguments must fail before installer state initialization'
        bundle=root/'bundle'; artifacts=bundle/'artifacts'; artifacts.mkdir(parents=True)
        refs=write_workload_oci_archive(artifacts/'workloads.oci.tar', workload_repositories())
        def workload_manifest(name: str, ref: str) -> bytes:
            return ('apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n        - name: '+name+'\n          image: '+ref+'\n').encode()
        files={'install.sh':b'#!/bin/sh\nexit 0\n','rke2.tar.gz':b'rke2','rke2-images.tar.zst':b'rke2-images','workloads.oci.tar':(artifacts/'workloads.oci.tar').read_bytes(),'argocd-install.yaml':workload_manifest('argocd',refs['registry.local/argocd']),'cnpg-install.yaml':workload_manifest('cnpg',refs['registry.local/cnpg']),'storage-install.yaml':workload_manifest('storage',refs['registry.local/storage'])}
        for name,data in files.items(): (artifacts/name).write_bytes(data)
        images=sorted(refs.values())
        index_artifacts=['artifacts/'+name for name in files]; index={'version':EXPECTED_VERSION,'images':images,'artifacts':index_artifacts,'artifactDigests':{'artifacts/'+name:sha(data) for name,data in files.items()}}; (bundle/'artifacts'/'airgap-index.json').write_text(json.dumps(index,sort_keys=True)+'\n'); files['airgap-index.json']=(bundle/'artifacts'/'airgap-index.json').read_bytes()
        release_digest='sha256:'+'7'*64
        manifest={'apiVersion':'platform.4so.io/v1alpha1','kind':'ApplianceBundle','metadata':{'version':EXPECTED_VERSION,'sourceReleaseDigest':release_digest},'spec':{'rke2':{'version':'test','installer':{'path':'artifacts/install.sh','sha256':sha(files['install.sh'])},'installArtifacts':[{'path':'artifacts/rke2.tar.gz','sha256':sha(files['rke2.tar.gz'])}],'imageArchives':[{'path':'artifacts/rke2-images.tar.zst','sha256':sha(files['rke2-images.tar.zst'])}]},'airgap':{'complete':True,'index':{'path':'artifacts/airgap-index.json','sha256':sha(files['airgap-index.json'])},'requiredImages':images},'workloads':{'imageArchives':[{'path':'artifacts/workloads.oci.tar','sha256':sha(files['workloads.oci.tar'])}],'postgresqlImage':refs['registry.local/postgres'],'platformApiImage':refs['registry.local/platform-api'],'forgejoImage':refs['registry.local/forgejo'],'zotImage':refs['registry.local/zot'],'keycloakImage':refs['registry.local/keycloak'],'maintenanceImage':refs['registry.local/maintenance'],'gitOpsManifest':{'path':'artifacts/argocd-install.yaml','sha256':sha(files['argocd-install.yaml'])},'cloudNativePGManifest':{'path':'artifacts/cnpg-install.yaml','sha256':sha(files['cnpg-install.yaml'])},'storageManifest':{'path':'artifacts/storage-install.yaml','sha256':sha(files['storage-install.yaml'])},'fleetAgentImage':refs['registry.local/platform-agent'],'runtimeProbeImage':refs['registry.local/platform-probe']}}}
        manifest_raw=(json.dumps(manifest,indent=2,sort_keys=True)+'\n').encode(); (bundle/'bundle.json').write_bytes(manifest_raw)
        all_artifacts=[]
        for rel in sorted(['artifacts/'+name for name in files]):
            raw=(bundle/rel).read_bytes(); all_artifacts.append({'path':rel,'sha256':sha(raw),'size':len(raw)})
        lock={'apiVersion':'platform.4so.io/v1alpha1','kind':'ApplianceBundleLock','metadata':{'bundleVersion':EXPECTED_VERSION,'sourceReleaseDigest':release_digest},'manifestDigest':sha(manifest_raw),'artifacts':all_artifacts,'requiredImages':sorted(images)}
        (bundle/'bundle.lock.json').write_text(json.dumps(lock,indent=2,sort_keys=True)+'\n')
        port=free_port(); token='test-'+'bootstrap-token-'+'abcdefghijklmnopqrstuvwxyz'
        env=os.environ.copy(); env.update({'PLATFORM_INSTALLER_LISTEN':f'127.0.0.1:{port}','PLATFORM_INSTALLER_BUNDLE_DIR':str(bundle),'PLATFORM_INSTALLER_STATE_DIR':str(root/'state'),'PLATFORM_INSTALLER_SIMULATION':'true','PLATFORM_INSTALLER_SIMULATION_ROOT':str(root/'host'),'PLATFORM_INSTALLER_ALLOW_EXECUTION':'true','PLATFORM_INSTALLER_BOOTSTRAP_TOKEN':token})
        process=subprocess.Popen([str(binary)],env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
        base=f'http://127.0.0.1:{port}'
        try:
            for _ in range(80):
                try:
                    with urlopen(base+'/healthz',timeout=1): break
                except Exception: time.sleep(.1)
            else: raise RuntimeError('installer did not start')
            status,access_status=request(base+'/api/v1/access/status',token); assert status==200 and access_status['transport']['mode']=='http-loopback' and access_status['token']['fingerprint'].startswith('sha256:'),access_status
            old_token=token
            if platformctl:
                token_file=root/'bootstrap-token'; token_file.write_text(token+'\n'); token_file.chmod(0o600)
                completed=subprocess.run([str(platformctl),'installer-access','status','--installer-url',base,'--token-file',str(token_file)],capture_output=True,text=True,timeout=20)
                assert completed.returncode==0 and 'http-loopback' in completed.stdout,(completed.returncode,completed.stdout,completed.stderr)
                completed=subprocess.run([str(platformctl),'installer-access','rotate-token','--installer-url',base,'--token-file',str(token_file),'--out-token-file',str(token_file),'--confirmation','ROTATE'],capture_output=True,text=True,timeout=20)
                assert completed.returncode==0 and 'rotated' in completed.stdout,(completed.returncode,completed.stdout,completed.stderr)
                token=token_file.read_text().strip(); assert len(token)>=32 and token!=old_token
            else:
                token='rotated-'+'bootstrap-token-'+'abcdefghijklmnopqrstuvwxyz'
                status,rotated=request(base+'/api/v1/access/token/rotate',old_token,'POST',{'confirmation':'ROTATE','newToken':token}); assert status==200 and rotated['rotated'] is True and token not in json.dumps(rotated),rotated
            status,_=request(base+'/api/v1/access/status',old_token); assert status==401
            status,access_status=request(base+'/api/v1/access/status',token); assert status==200 and access_status['token']['source']=='existing-file',access_status
            installation={'profileId':'evaluation-single-node','connectivity':'connected','infrastructure':{'provider':'existing-hosts','existingCluster':False,'nodeAddresses':['127.0.0.1'],'credentialRef':'secret://local/root'},'network':{'publicEndpoint':'https://platform.example.test','dnsZone':'example.test','tlsMode':'bootstrap-self-signed'},'services':{'git':{'mode':'managed-internal'},'registry':{'mode':'managed-internal'},'database':{'mode':'managed-internal'},'objectStorage':{'mode':'managed-internal'},'identity':{'mode':'managed-internal','adminEmail':'admin@example.test'}},'acceptRisk':True}
            status,bundle_status=request(base+'/api/v1/bundle/status',token); assert status==200 and bundle_status['verified'] is True and bundle_status['lockDigest'].startswith('sha256:'),bundle_status
            status,plan=request(base+'/api/v1/plan',token,'POST',{'installation':installation})
            assert status==200 and plan['plan']['executable'] is True and plan['plan']['authorityGate']=='bootstrap-local-journal',plan
            status,preflight=request(base+'/api/v1/preflight',token,'POST',{'installation':installation}); assert status==200 and preflight['state']=='PASSED' and preflight['simulation'] is True and preflight['digest'].startswith('sha256:'),preflight
            status,preflight_status=request(base+'/api/v1/preflight',token); assert status==200 and preflight_status['id']==preflight['id'],preflight_status
            status,_=request(base+'/api/v1/start',token,'POST',{'installation':installation}); assert status==202
            final=None
            for _ in range(100):
                status,body=request(base+'/api/v1/status',token); assert status==200
                final=body.get('run')
                if final and final['state'] in ('SUCCEEDED','FAILED'): break
                time.sleep(.1)
            assert final and final['state']=='SUCCEEDED',final
            assert all(s['state']=='SUCCEEDED' for s in final['steps']) and any(s['key']=='revoke-bootstrap-credential' for s in final['steps'])
            status,gitops=request(base+'/api/v1/gitops/status',token); assert status==200 and gitops['state']=='RECONCILED' and gitops['revisionDigest']==gitops['observedDigest'],gitops
            status,run=request(base+'/api/v1/lifecycle/backup',token,'POST',{'service':'forgejo'}); assert status==202,run
            lifecycle=None
            for _ in range(100):
                status,runs=request(base+'/api/v1/lifecycle/runs',token); assert status==200
                lifecycle=next((item for item in runs if item['id']==run['id']),None)
                if lifecycle and lifecycle['state'] in ('SUCCEEDED','FAILED'): break
                time.sleep(.05)
            assert lifecycle and lifecycle['state']=='SUCCEEDED' and lifecycle.get('backupId'),lifecycle
            status,backups=request(base+'/api/v1/lifecycle/backups/forgejo',token); assert status==200 and backups,backups
            status,key_result=request(base+'/api/v1/secrets/ssh-private-key',token,'POST',{'privateKey':'-----BEGIN OPENSSH PRIVATE KEY-----\nsimulated\n-----END OPENSSH PRIVATE KEY-----'}); assert status==201,key_result
            host_key=base64.b64encode(bytes([7])*32).decode()
            raw_known_hosts='\n'.join([f'10.0.0.12 ssh-ed25519 {host_key}',f'10.0.0.13 ssh-ed25519 {host_key}'])
            status,trust_result=request(base+'/api/v1/secrets/ssh-known-hosts',token,'POST',{'knownHosts':raw_known_hosts}); assert status==201 and trust_result['privateKeyStored'] is True and trust_result['knownHostsStored'] is True and len(trust_result['entries'])==2,trust_result
            assert host_key not in json.dumps(trust_result),trust_result
            status,trust_status=request(base+'/api/v1/ssh/trust/status',token); assert status==200 and trust_status['knownHostsStored'] is True and all(item['fingerprint'].startswith('SHA256:') for item in trust_status['entries']),trust_status
            assert host_key not in json.dumps(trust_status),trust_status
            ha_installation={'profileId':'production-standard-ha','connectivity':'disconnected','infrastructure':{'provider':'existing-hosts','existingCluster':False,'nodeAddresses':['10.0.0.11','10.0.0.12','10.0.0.13'],'credentialRef':'secret://installer/ssh-private-key','sshUser':'root','storageClass':'replicated-rwx'},'network':{'publicEndpoint':'https://platform.example.test','dnsZone':'example.test','tlsMode':'managed-private-ca'},'services':{'git':{'mode':'managed-internal'},'registry':{'mode':'managed-internal'},'database':{'mode':'managed-internal'},'objectStorage':{'mode':'external','provider':'s3-compatible','url':'https://s3.example.test','credentialRef':'external-secret://platform-system/s3-credentials','bucket':'platform-backups','prefix':'factory'},'identity':{'mode':'managed-internal','adminEmail':'admin@example.test'}},'acceptRisk':True}
            status,ha_plan=request(base+'/api/v1/plan',token,'POST',{'installation':ha_installation}); assert status==200 and ha_plan['plan']['executable'] is True and ha_plan['plan']['authorityGate']=='bootstrap-ha-local-journal',ha_plan
            status,ha_preflight=request(base+'/api/v1/preflight',token,'POST',{'installation':ha_installation}); assert status==200 and ha_preflight['state']=='PASSED',ha_preflight
            status,_=request(base+'/api/v1/start',token,'POST',{'installation':ha_installation}); assert status==202
            ha_final=None
            previous_run_id=final['id']
            for _ in range(140):
                status,body=request(base+'/api/v1/status',token); assert status==200
                candidate=body.get('run')
                if candidate and candidate.get('id') != previous_run_id and candidate.get('request',{}).get('profileId') == 'production-standard-ha':
                    ha_final=candidate
                    if ha_final['state'] in ('SUCCEEDED','FAILED'): break
                time.sleep(.1)
            assert ha_final and ha_final['state']=='SUCCEEDED',ha_final
            step_states={item['key']:item['state'] for item in ha_final['steps']}
            assert step_states and all(state=='SUCCEEDED' for state in step_states.values()),step_states
            for required_step in ('deploy-replicated-storage','verify-off-node-backup','revoke-bootstrap-credential'):
                assert step_states.get(required_step)=='SUCCEEDED',(required_step,step_states)
            status,ha_status=request(base+'/api/v1/ha/status',token); assert status==200 and ha_status['selected'] is True,ha_status
            status,airgap_status=request(base+'/api/v1/airgap/status',token); assert status==200 and airgap_status['complete'] is True and airgap_status['verified'] is True,airgap_status
            status,dr_run=request(base+'/api/v1/disaster-recovery/backup',token,'POST',{}); assert status==202,dr_run
            dr=None
            for _ in range(100):
                status,runs=request(base+'/api/v1/disaster-recovery/runs',token); assert status==200
                dr=next((item for item in runs if item['id']==dr_run['id']),None)
                if dr and dr['state'] in ('SUCCEEDED','FAILED'): break
                time.sleep(.05)
            assert dr and dr['state']=='SUCCEEDED' and dr.get('backupId'),dr
            status,field_report=request(base+'/api/v1/field-evidence/report',token); assert status==200 and field_report['claims']['simulation'] is True and field_report['claims']['runtimeCertified'] is False and field_report['metadata']['evidenceDigest'].startswith('sha256:'),field_report
            status,field_verify=request(base+'/api/v1/field-evidence/verify',token,'POST',field_report); assert status==200 and field_verify['valid'] is True and field_verify['runId']==ha_final['id'] and field_verify['installerBinaryDigest']==sha(binary.read_bytes()),field_verify
            tampered=json.loads(json.dumps(field_report)); tampered['claims']['runtimeCertified']=True
            status,tamper_result=request(base+'/api/v1/field-evidence/verify',token,'POST',tampered); assert status==422,tamper_result
            status,diagnostic=request(base+'/api/v1/diagnostics/report',token); assert status==200 and diagnostic['claims']['diagnosticOnly'] is True and diagnostic['claims']['automaticRetry'] is False and diagnostic['metadata']['digest'].startswith('sha256:'),diagnostic
            status,diagnostic_verify=request(base+'/api/v1/diagnostics/verify',token,'POST',diagnostic); assert status==200 and diagnostic_verify['valid'] is True and diagnostic_verify['runId']==ha_final['id'],diagnostic_verify
            diagnostic_tampered=json.loads(json.dumps(diagnostic)); diagnostic_tampered['analysis']['owningLayer']='forged-owner'
            status,diagnostic_tamper=request(base+'/api/v1/diagnostics/verify',token,'POST',diagnostic_tampered); assert status==422,diagnostic_tamper

            # C5 reset/reinstall authority: reset the exact HA installation, wait for
            # durable completion, prove the same installer access token remains valid,
            # then execute a clean installation again from a fresh bootstrap journal.
            status,_=request(base+'/api/v1/reset/start',token,'POST',{}, {'X-Confirm-Reset':'reset:'+ha_final['id']}); assert status==202
            reset_final=None
            for _ in range(140):
                status,body=request(base+'/api/v1/status',token); assert status==200
                reset_runs=body.get('resetRuns') or []
                reset_final=reset_runs[-1] if reset_runs else None
                if reset_final and reset_final['state'] in ('SUCCEEDED','FAILED'): break
                time.sleep(.05)
            assert reset_final and reset_final['state']=='SUCCEEDED',reset_final
            assert all(step['state']=='SUCCEEDED' for step in reset_final['steps']),reset_final
            status,post_reset_status=request(base+'/api/v1/status',token); assert status==200 and post_reset_status.get('run') is None,post_reset_status
            status,replan=request(base+'/api/v1/plan',token,'POST',{'installation':installation}); assert status==200 and replan['plan']['executable'] is True,replan
            status,repreflight=request(base+'/api/v1/preflight',token,'POST',{'installation':installation}); assert status==200 and repreflight['state']=='PASSED',repreflight
            status,_=request(base+'/api/v1/start',token,'POST',{'installation':installation}); assert status==202
            reinstall=None
            for _ in range(120):
                status,body=request(base+'/api/v1/status',token); assert status==200
                reinstall=body.get('run')
                if reinstall and reinstall['state'] in ('SUCCEEDED','FAILED'): break
                time.sleep(.05)
            assert reinstall and reinstall['state']=='SUCCEEDED',reinstall
            assert all(step['state']=='SUCCEEDED' for step in reinstall['steps']),reinstall
            print('INSTALLER_HTTP_SIMULATION_SMOKE_PASS',final['id'],ha_final['id'],lifecycle['id'],dr['id'],reset_final['id'],reinstall['id'],field_verify['evidenceDigest'],diagnostic_verify['digest'])
            return 0
        finally:
            process.terminate()
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired: process.kill()
            output = process.stdout.read() if process.stdout else ''
            assert 'test-bootstrap-token-abcdefghijklmnopqrstuvwxyz' not in output
            assert 'rotated-bootstrap-token-abcdefghijklmnopqrstuvwxyz' not in output
if __name__=='__main__': raise SystemExit(main())
