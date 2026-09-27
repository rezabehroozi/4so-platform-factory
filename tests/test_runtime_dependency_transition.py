import copy, hashlib, importlib.util, json, shutil, tempfile, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('rdt',ROOT/'scripts/runtime_dependency_transition.py'); mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
class RuntimeDependencyTransitionTests(unittest.TestCase):
    def test_canonical_transition(self):
        out=mod.validate(ROOT)
        doc=json.loads((ROOT/'catalog/runtime-dependency-transition.json').read_text())
        source_status=doc['spec']['gatewayApi']['sourceStatus']
        expected='runtime-certification-partial' if source_status=='source-acquired' else 'acquisition-pending'
        self.assertEqual(expected,out['status'])
        self.assertEqual('2.4.1',out['kgatewayTarget'])
        for asset in doc['spec']['gatewayApi']['assets']:
            path=mod.gateway_asset_path(ROOT,'1.6.1',asset['name'])
            if source_status=='source-acquired':
                self.assertTrue(path.is_file() and not path.is_symlink())
                raw=path.read_bytes()
                self.assertEqual(asset['size'],len(raw))
                self.assertEqual(asset['sha256'],hashlib.sha256(raw).hexdigest())
            else:
                self.assertFalse(path.exists())
    def copy_repo(self):
        td=tempfile.TemporaryDirectory(); dst=Path(td.name)
        (dst/'catalog/components').mkdir(parents=True)
        for name in ('gateway-api','kgateway','cilium'):
            (dst/f'catalog/components/{name}.json').write_text((ROOT/f'catalog/components/{name}.json').read_text())
        for name in ('upstream-admission.json','runtime-dependency-transition.json','component-runtime-certification.json'):
            (dst/f'catalog/{name}').write_text((ROOT/f'catalog/{name}').read_text())
        deps=ROOT/'catalog/runtime-dependencies'
        if deps.is_dir():
            shutil.copytree(deps,dst/'catalog/runtime-dependencies')
        return td,dst
    def restore_cilium_hold(self,dst):
        p=dst/'catalog/component-runtime-certification.json'
        d=json.loads(p.read_text())
        d['spec']['runtimeSuitabilityHolds']=[r for r in d['spec']['runtimeSuitabilityHolds'] if r['component']!='cilium']
        d['spec']['runtimeSuitabilityHolds'].append({
            'component':'cilium',
            'status':'dependency-transition-required',
            'authority':'RUNTIME_DEPENDENCY_TRANSITION_V1',
            'reason':'fixture pre-transition hold',
            'evidenceURL':'https://docs.cilium.io/en/stable/network/servicemesh/gateway-api/gateway-api/'
        })
        p.write_text(json.dumps(d))
    def test_partial_runtime_evidence_scope_inflation_fails_closed(self):
        td,dst=self.copy_repo()
        try:
            p=dst/'catalog/runtime-dependency-transition.json'
            d=json.loads(p.read_text())
            d['spec']['runtimeEvidence']['productTopologyHACertified']=True
            p.write_text(json.dumps(d))
            with self.assertRaisesRegex(RuntimeError,'PARTIAL_EVIDENCE_INVALID'): mod.validate(dst)
        finally: td.cleanup()
    def test_source_acquired_gateway_without_exact_bytes_fails_closed(self):
        td,dst=self.copy_repo()
        try:
            shutil.rmtree(dst/'catalog/runtime-dependencies',ignore_errors=True)
            p=dst/'catalog/runtime-dependency-transition.json'
            d=json.loads(p.read_text())
            d['spec']['gatewayApi']['sourceStatus']='source-acquired'
            d['spec']['status']='runtime-certification-pending'
            d['spec']['cilium']['runtimeStatus']='dependency-transition-required'
            d['spec'].pop('runtimeEvidence',None)
            p.write_text(json.dumps(d))
            self.restore_cilium_hold(dst)
            with self.assertRaisesRegex(RuntimeError,'ASSET_BYTES_MISSING'): mod.validate(dst)
        finally: td.cleanup()
    def test_pending_gateway_cannot_hide_canonical_bytes(self):
        td,dst=self.copy_repo()
        try:
            p=dst/'catalog/runtime-dependency-transition.json'
            d=json.loads(p.read_text())
            d['spec']['gatewayApi']['sourceStatus']='pending-byte-acquisition'
            d['spec']['status']='acquisition-pending'
            d['spec']['cilium']['runtimeStatus']='dependency-transition-required'
            d['spec'].pop('runtimeEvidence',None)
            p.write_text(json.dumps(d))
            self.restore_cilium_hold(dst)
            asset=d['spec']['gatewayApi']['assets'][0]
            out=mod.gateway_asset_path(dst,'1.6.1',asset['name'])
            out.parent.mkdir(parents=True,exist_ok=True); out.write_text('forged')
            with self.assertRaisesRegex(RuntimeError,'PENDING_WITH_CANONICAL_BYTES'): mod.validate(dst)
        finally: td.cleanup()
    def test_asset_digest_tamper_fails_closed(self):
        td,dst=self.copy_repo()
        try:
            p=dst/'catalog/runtime-dependency-transition.json'; d=json.loads(p.read_text()); d['spec']['gatewayApi']['assets'][0]['sha256']='0'*64; p.write_text(json.dumps(d))
            with self.assertRaisesRegex(RuntimeError,'ASSET_INVALID'): mod.validate(dst)
        finally: td.cleanup()
    def test_post_transition_cilium_hold_reintroduction_fails_closed(self):
        td,dst=self.copy_repo()
        try:
            self.restore_cilium_hold(dst)
            with self.assertRaisesRegex(RuntimeError,'CILIUM_RELEASE_HOLD_NOT_RETIRED'): mod.validate(dst)
        finally: td.cleanup()
    def test_kgateway_target_drift_fails_closed(self):
        td,dst=self.copy_repo()
        try:
            p=dst/'catalog/runtime-dependency-transition.json'; d=json.loads(p.read_text()); d['spec']['kgateway']['targetRelease']='2.4.0'; p.write_text(json.dumps(d))
            with self.assertRaisesRegex(RuntimeError,'KGATEWAY_DRIFT'): mod.validate(dst)
        finally: td.cleanup()
    def test_post_transition_cilium_release_is_canonical(self):
        out=mod.validate(ROOT)
        registry=json.loads((ROOT/'catalog/component-runtime-certification.json').read_text())
        self.assertNotIn('cilium',{r['component'] for r in registry['spec']['runtimeSuitabilityHolds']})
        transition=json.loads((ROOT/'catalog/runtime-dependency-transition.json').read_text())
        self.assertEqual('single-node-rke2-certified-ha-pending',transition['spec']['cilium']['runtimeStatus'])
        self.assertEqual('1.20.1',out['ciliumTarget'])

    def test_post_transition_cilium_runtime_status_regression_fails_closed(self):
        td,dst=self.copy_repo()
        try:
            p=dst/'catalog/runtime-dependency-transition.json'
            d=json.loads(p.read_text())
            d['spec']['cilium']['runtimeStatus']='dependency-transition-required'
            p.write_text(json.dumps(d))
            with self.assertRaisesRegex(RuntimeError,'CILIUM_DRIFT'): mod.validate(dst)
        finally: td.cleanup()
if __name__=='__main__': unittest.main()
