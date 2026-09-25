import copy, importlib.util, json, tempfile, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('rdt',ROOT/'scripts/runtime_dependency_transition.py'); mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
class RuntimeDependencyTransitionTests(unittest.TestCase):
    def test_canonical_transition(self):
        out=mod.validate(ROOT); self.assertEqual('acquisition-pending',out['status']); self.assertEqual('2.4.1',out['kgatewayTarget'])
    def copy_repo(self):
        td=tempfile.TemporaryDirectory(); dst=Path(td.name)
        (dst/'catalog/components').mkdir(parents=True)
        for name in ('gateway-api','kgateway','cilium'):
            (dst/f'catalog/components/{name}.json').write_text((ROOT/f'catalog/components/{name}.json').read_text())
        for name in ('upstream-admission.json','runtime-dependency-transition.json','component-runtime-certification.json'):
            (dst/f'catalog/{name}').write_text((ROOT/f'catalog/{name}').read_text())
        return td,dst
    def test_asset_digest_tamper_fails_closed(self):
        td,dst=self.copy_repo()
        try:
            p=dst/'catalog/runtime-dependency-transition.json'; d=json.loads(p.read_text()); d['spec']['gatewayApi']['assets'][0]['sha256']='0'*64; p.write_text(json.dumps(d))
            with self.assertRaisesRegex(RuntimeError,'ASSET_INVALID'): mod.validate(dst)
        finally: td.cleanup()
    def test_cilium_runtime_status_drift_fails_closed(self):
        td,dst=self.copy_repo()
        try:
            p=dst/'catalog/component-runtime-certification.json'
            d=json.loads(p.read_text())
            next(r for r in d['spec']['runtimeSuitabilityHolds'] if r['component']=='cilium')['status']='review-required'
            p.write_text(json.dumps(d))
            with self.assertRaisesRegex(RuntimeError,'CILIUM_RUNTIME_STATUS_INVALID'): mod.validate(dst)
        finally: td.cleanup()
    def test_kgateway_target_drift_fails_closed(self):
        td,dst=self.copy_repo()
        try:
            p=dst/'catalog/runtime-dependency-transition.json'; d=json.loads(p.read_text()); d['spec']['kgateway']['targetRelease']='2.4.0'; p.write_text(json.dumps(d))
            with self.assertRaisesRegex(RuntimeError,'KGATEWAY_DRIFT'): mod.validate(dst)
        finally: td.cleanup()
    def test_source_acquired_cilium_retires_admission_but_keeps_runtime_hold(self):
        td,dst=self.copy_repo()
        try:
            cp=dst/'catalog/components/cilium.json'; component=json.loads(cp.read_text()); component['spec']['source']['resolved']=True; cp.write_text(json.dumps(component))
            ap=dst/'catalog/upstream-admission.json'; admission=json.loads(ap.read_text()); admission['spec']['components']=[r for r in admission['spec']['components'] if r['component']!='cilium']; ap.write_text(json.dumps(admission))
            tp=dst/'catalog/runtime-dependency-transition.json'; transition=json.loads(tp.read_text()); transition['spec']['cilium']['sourceStatus']='source-acquired'; tp.write_text(json.dumps(transition))
            out=mod.validate(dst)
            self.assertEqual('1.20.1',out['ciliumTarget'])
        finally: td.cleanup()
    def test_cilium_persistent_runtime_hold_removal_fails_closed(self):
        td,dst=self.copy_repo()
        try:
            p=dst/'catalog/component-runtime-certification.json'; d=json.loads(p.read_text()); d['spec']['runtimeSuitabilityHolds']=[r for r in d['spec']['runtimeSuitabilityHolds'] if r['component']!='cilium']; p.write_text(json.dumps(d))
            with self.assertRaisesRegex(RuntimeError,'CILIUM_RUNTIME_STATUS_INVALID'): mod.validate(dst)
        finally: td.cleanup()
if __name__=='__main__': unittest.main()
