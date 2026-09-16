import hashlib, importlib.util, tempfile, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('hist',ROOT/'scripts/acquire_historical_upgrade_batch.py')
mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
class HistoricalUpgradeBatchTests(unittest.TestCase):
    def test_committed_queue_has_no_selection_review_bottleneck(self):
        helm,tagged,install_only,review,already,waiting_current=mod.classify(ROOT)
        self.assertEqual(19,len(helm)+len(tagged)+len(already)+len(waiting_current))
        self.assertEqual(17,len(waiting_current))
        self.assertEqual([],helm)
        self.assertEqual({'gateway-api','snapshot-controller'},{r['component'] for r in tagged})
        self.assertEqual(['secure-namespace-foundation'],[r['component'] for r in install_only])
        self.assertEqual([],review)
    def test_manifest_truth_never_implies_runtime_certification(self):
        doc=mod.manifest([])
        self.assertFalse(doc['spec']['runtimeCertificationImplied'])
        self.assertEqual('catalog/component-upgrade-source-admission.json',doc['spec']['canonicalAuthority'])
    def test_stage_entry_uses_upgrade_admission_context_not_bundle_boolean(self):
        row={'component':'gateway-api','previousVersion':'1.5.0','targetRelease':'1.5.1','source':'https://example.test/gateway-api'}
        verified={'valid':True,'component':'gateway-api','version':'1.5.0','upstreamUrl':row['source']}
        with tempfile.TemporaryDirectory() as td:
            bundle=Path(td)/'gateway-api-1.5.0.zip'; bundle.write_bytes(b'bundle')
            verified['bundleDigest']='sha256:'+hashlib.sha256(b'bundle').hexdigest()
            entry=mod.entry(row,bundle,verified)
        self.assertTrue(entry['historical'])

    def test_install_staged_does_not_require_non_authoritative_historical_verify_flag(self):
        source=Path(mod.__file__).read_text()
        self.assertNotIn("verified.get('historical') is not True", source)

    def test_stage_out_reuses_existing_verified_orphan_bundle(self):
        source=Path(mod.__file__).read_text()
        self.assertIn("if out.exists():", source)
        self.assertIn("catalog-bundle','verify','-f',str(out)", source)

    def test_tagged_predecessors_use_commit_pinned_runner(self):
        cmd=mod.acquisition_cmd('gateway-api','tagged',out=ROOT/'x.zip')
        self.assertIn('scripts/acquire_upstream_tagged_source.py',cmd)
        self.assertIn('--from-upgrade-admission',cmd)
        self.assertIn('--historical',cmd)
        helm=mod.acquisition_cmd('alloy','helm')
        self.assertIn('scripts/acquire_upstream_helm.py',helm)
if __name__=='__main__': unittest.main()
