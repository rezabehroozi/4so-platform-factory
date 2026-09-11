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
        for name in ('upstream-admission.json','runtime-dependency-transition.json'):
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
            p=dst/'catalog/upstream-admission.json'; d=json.loads(p.read_text()); next(r for r in d['spec']['components'] if r['component']=='cilium')['runtimeStatus']='eligible-after-source-resolution'; p.write_text(json.dumps(d))
            with self.assertRaisesRegex(RuntimeError,'CILIUM_RUNTIME_STATUS_INVALID'): mod.validate(dst)
        finally: td.cleanup()
    def test_kgateway_target_drift_fails_closed(self):
        td,dst=self.copy_repo()
        try:
            p=dst/'catalog/runtime-dependency-transition.json'; d=json.loads(p.read_text()); d['spec']['kgateway']['targetRelease']='2.4.0'; p.write_text(json.dumps(d))
            with self.assertRaisesRegex(RuntimeError,'KGATEWAY_DRIFT'): mod.validate(dst)
        finally: td.cleanup()
if __name__=='__main__': unittest.main()
