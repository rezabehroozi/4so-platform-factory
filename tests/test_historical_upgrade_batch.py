import hashlib, importlib.util, json, tempfile, unittest
from unittest import mock
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('hist',ROOT/'scripts/acquire_historical_upgrade_batch.py')
mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
class HistoricalUpgradeBatchTests(unittest.TestCase):
    def test_committed_queue_partitions_all_reviewed_edges_without_selection_review(self):
        helm,tagged,install_only,review,already,waiting_current=mod.classify(ROOT)
        authority=json.loads((ROOT/'catalog/component-upgrade-source-admission.json').read_text())
        admitted=[r for r in authority['components'] if r['status']=='admitted-for-acquisition']
        self.assertEqual(len(admitted),len(helm)+len(tagged)+len(already)+len(waiting_current))
        self.assertEqual(['secure-namespace-foundation'],[r['component'] for r in install_only])
        self.assertEqual([],review)
        names=[]
        for rows in (helm,tagged,already,waiting_current):
            names.extend(r['component'] for r in rows)
        self.assertEqual(sorted(r['component'] for r in admitted),sorted(names))
        self.assertEqual(len(names),len(set(names)))
        for row in tagged:
            recipe=ROOT/'catalog/tagged-source-recipes'/row['component']/f"{row['previousVersion']}.json"
            self.assertTrue(recipe.is_file(),recipe)
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

    def test_install_staged_rejects_symlink_historical_source_lock(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/'repo'
            lock_dir=root/'catalog/runtime/demo/1.0.0'
            lock_dir.mkdir(parents=True)
            real=root/'real-source-lock.json'
            real.write_text('{"component":"demo","version":"1.0.0"}')
            lock=lock_dir/'source-lock.json'
            try:
                lock.symlink_to(real)
            except OSError as exc:
                self.skipTest(f'symlink unavailable: {exc}')
            stage=Path(td)/'stage'; stage.mkdir()
            (stage/mod.MANIFEST).write_text('{}')
            entry={'component':'demo','targetRelease':'1.1.0','previousVersion':'1.0.0','source':'https://example.test/demo','bundleFile':'demo-1.0.0.zip','bundleDigest':'sha256:'+'a'*64,'historical':True}
            with mock.patch.object(mod,'ROOT',root), \
                 mock.patch.object(mod,'validate_manifest',return_value=[entry]), \
                 mock.patch.object(mod,'platformctl',return_value=['platformctl']):
                with self.assertRaisesRegex(RuntimeError,'HISTORICAL_SOURCE_LOCK_NOT_REAL_FILE'):
                    mod.install_staged(stage,None)

    def test_tagged_predecessors_use_commit_pinned_runner(self):
        cmd=mod.acquisition_cmd('gateway-api','tagged',out=ROOT/'x.zip')
        self.assertIn('scripts/acquire_upstream_tagged_source.py',cmd)
        self.assertIn('--from-upgrade-admission',cmd)
        self.assertIn('--historical',cmd)
        helm=mod.acquisition_cmd('alloy','helm')
        self.assertIn('scripts/acquire_upstream_helm.py',helm)

    def test_historical_stage_and_platformctl_reject_direct_symlinks(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            real_stage=root/'stage'; real_stage.mkdir()
            stage_link=root/'stage-link'
            real_ctl=root/'platformctl'; real_ctl.write_text('#!/bin/sh\\nexit 0\\n'); real_ctl.chmod(0o755)
            ctl_link=root/'platformctl-link'
            try:
                stage_link.symlink_to(real_stage,target_is_directory=True)
                ctl_link.symlink_to(real_ctl)
            except OSError as exc:
                self.skipTest(f'symlink unavailable: {exc}')
            with self.assertRaisesRegex(RuntimeError,'PLATFORMCTL_NOT_REAL_FILE'):
                mod.platformctl(str(ctl_link))
            with self.assertRaisesRegex(RuntimeError,'HISTORICAL_STAGE_DIRECTORY_NOT_REAL_DIRECTORY'):
                mod.stage_out(0,stage_link,None)
if __name__=='__main__': unittest.main()
