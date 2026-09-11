import importlib.util, json, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('upgrade_adm',ROOT/'scripts/component_upgrade_source_admission.py')
mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
class UpgradeSourceAdmissionTests(unittest.TestCase):
    def test_committed_authority_closes_selection_review_without_fabricating_first_release(self):
        doc=json.loads((ROOT/'catalog/component-upgrade-source-admission.json').read_text())
        self.assertEqual([],mod.validate(doc,ROOT))
        self.assertEqual(20,len(doc['components']))
        self.assertEqual(19,sum(r['status']=='admitted-for-acquisition' for r in doc['components']))
        self.assertEqual(0,sum(r['status']=='review-required' for r in doc['components']))
        self.assertEqual(1,sum(r['status']=='install-only-first-product-release' for r in doc['components']))
    def test_admitted_edge_must_be_strictly_older_and_exact(self):
        doc=mod.seed(ROOT); row=doc['components'][0]; row['status']='admitted-for-acquisition'; row['previousVersion']=row['targetRelease']; row['source']='https://example.invalid/chart'; row['reviewEvidence']=[{'kind':'upstream-release-history','reference':'https://example.invalid/release','summary':'review'}]
        self.assertTrue(any('previous version' in e for e in mod.validate(doc,ROOT)))
    def test_admitted_edge_requires_machine_readable_upstream_review_evidence(self):
        doc=json.loads((ROOT/'catalog/component-upgrade-source-admission.json').read_text()); row=next(r for r in doc['components'] if r['status']=='admitted-for-acquisition'); row['reviewEvidence']=[]
        self.assertTrue(any('upstream review evidence required' in e for e in mod.validate(doc,ROOT)))
    def test_review_row_cannot_pre_authorize_source(self):
        doc=mod.seed(ROOT); doc['components'][0]['previousVersion']='1.0.0'; doc['components'][0]['source']='https://example.invalid/chart'
        self.assertTrue(any('must not pre-authorize' in e for e in mod.validate(doc,ROOT)))
    def test_first_product_release_cannot_fabricate_history(self):
        doc=json.loads((ROOT/'catalog/component-upgrade-source-admission.json').read_text()); row=next(r for r in doc['components'] if r['component']=='secure-namespace-foundation'); row['previousVersion']='0.9.0'; row['source']='https://example.invalid/fake'
        self.assertTrue(any('must not fabricate' in e for e in mod.validate(doc,ROOT)))
    def test_install_only_is_restricted_to_embedded_first_release(self):
        doc=json.loads((ROOT/'catalog/component-upgrade-source-admission.json').read_text()); row=next(r for r in doc['components'] if r['component']=='alloy'); row.update(status='install-only-first-product-release',previousVersion='',source='',reviewEvidence=[{'kind':'product-release-history','reference':'repo://catalog/components/alloy.json','summary':'fake first release'}])
        self.assertTrue(any('not eligible' in e for e in mod.validate(doc,ROOT)))
if __name__=='__main__': unittest.main()
