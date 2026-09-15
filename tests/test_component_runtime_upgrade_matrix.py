import importlib.util
import json
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('component_runtime_upgrade_matrix', ROOT / 'scripts' / 'component_runtime_upgrade_matrix.py')
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


class ComponentRuntimeUpgradeMatrixTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        (self.root / 'catalog' / 'components').mkdir(parents=True)
        self.old_root = mod.ROOT
        mod.ROOT = self.root

    def tearDown(self):
        mod.ROOT = self.old_root
        self.tmp.cleanup()

    def component(self, name='demo', release='2.0.0'):
        doc = {'metadata': {'name': name}, 'spec': {'release': release}}
        (self.root / 'catalog' / 'components' / f'{name}.json').write_text(json.dumps(doc))

    def lock(self, name, release, *, component=None, version=None, marker='x'):
        p = self.root / 'catalog' / 'runtime' / name / release
        p.mkdir(parents=True, exist_ok=True)
        doc = {'component': component or name, 'version': version or release, 'marker': marker}
        (p / 'source-lock.json').write_text(json.dumps(doc))

    def test_wrong_component_or_release_identity_never_admitted(self):
        self.component()
        self.lock('demo', '2.0.0', marker='current')
        self.lock('demo', '1.0.0', component='foreign', marker='previous')
        row = mod.build()['components'][0]
        self.assertEqual(row['status'], 'pending-source-pair')
        self.assertEqual(row['admittedEdges'], [])

    def test_newer_sibling_is_not_reversed_into_upgrade_edge(self):
        self.component(release='2.0.0')
        self.lock('demo', '2.0.0', marker='current')
        self.lock('demo', '3.0.0', marker='future')
        row = mod.build()['components'][0]
        self.assertEqual(row['status'], 'pending-source-pair')
        self.assertEqual(row['admittedEdges'], [])

    def test_exact_older_release_is_admitted_directionally(self):
        self.component(release='2.0.0')
        self.lock('demo', '2.0.0', marker='current')
        self.lock('demo', '1.9.9', marker='previous')
        row = mod.build()['components'][0]
        self.assertEqual(row['status'], 'admitted-source-pair')
        self.assertEqual([(e['fromRelease'], e['toRelease']) for e in row['admittedEdges']], [('1.9.9', '2.0.0')])

    def test_wildcard_target_release_stays_fail_closed(self):
        self.component(release='2.0.x')
        self.lock('demo', '2.0.x', marker='current')
        self.lock('demo', '1.9.9', marker='previous')
        row = mod.build()['components'][0]
        self.assertEqual(row['status'], 'pending-source-pair')
        self.assertEqual(row['admittedEdges'], [])

    def test_first_product_release_is_install_only_not_fake_upgrade_pending(self):
        self.component(name='secure-namespace-foundation', release='1.0.0')
        self.lock('secure-namespace-foundation', '1.0.0', marker='current')
        adm_dir=self.root/'catalog'
        adm={
            'components':[{'component':'secure-namespace-foundation','status':'install-only-first-product-release'}]
        }
        (adm_dir/'component-upgrade-source-admission.json').write_text(json.dumps(adm))
        row=mod.build()['components'][0]
        self.assertEqual('install-only-first-product-release',row['status'])
        self.assertEqual([],row['admittedEdges'])
        self.assertEqual('install-readiness-failure-remove-only',row['upgradeExecutor'])

    def matrix(self, rows):
        return {
            'authority': mod.AUTHORITY,
            'policy': {'exactVersionDirectionRequired': True, 'sourceLockSelfIdentityRequired': True},
            'components': rows,
        }

    def edge(self, frm='0.9.0', to='1.0.0'):
        return {'fromRelease': frm, 'toRelease': to, 'fromSourceLockDigest': 'b' * 64, 'toSourceLockDigest': 'a' * 64}

    def install_only_row(self, name='demo', release='1.0.0', *, edges=None):
        return {
            'component': name, 'targetRelease': release, 'targetSourceLockDigest': 'a' * 64,
            'status': mod.FIRST_RELEASE_STATUS, 'admittedEdges': edges if edges is not None else [],
            'upgradeExecutor': 'install-readiness-failure-remove-only',
        }

    def pending_row(self, name='other', release='2.0.0'):
        return {
            'component': name, 'targetRelease': release, 'targetSourceLockDigest': 'c' * 64,
            'status': 'pending-source-pair', 'admittedEdges': [], 'upgradeExecutor': 'COMPONENT_RUNTIME_UPGRADE_V1',
        }

    def test_validator_accepts_install_only_row_as_first_component(self):
        self.component()
        self.lock('demo', '1.0.0')
        errs = mod.validate(self.matrix([self.install_only_row()]))
        self.assertEqual([], errs)

    def test_validator_rejects_fabricated_edge_on_install_only_component_after_a_bare_row(self):
        # A forged upgrade edge on an install-only component must be rejected from the
        # component under inspection, never inherited from the previous row.
        self.component()
        self.component(name='other', release='2.0.0')
        rows = [self.pending_row(), self.install_only_row(edges=[self.edge()])]
        errs = mod.validate(self.matrix(rows))
        self.assertIn('demo: first release must be install-only without upgrade edge', errs)

    def test_validator_rejects_wrong_executor_on_install_only_component(self):
        self.component()
        row = self.install_only_row()
        row['upgradeExecutor'] = 'COMPONENT_RUNTIME_UPGRADE_V1'
        errs = mod.validate(self.matrix([row]))
        self.assertIn('demo: first release must be install-only without upgrade edge', errs)

    def test_validator_rejects_reverse_edge_even_if_digests_differ(self):
        doc = {
            'authority': mod.AUTHORITY,
            'policy': {'exactVersionDirectionRequired': True, 'sourceLockSelfIdentityRequired': True},
            'components': [{
                'component': 'demo', 'status': 'admitted-source-pair',
                'admittedEdges': [{
                    'fromRelease': '3.0.0', 'toRelease': '2.0.0',
                    'fromSourceLockDigest': 'a'*64, 'toSourceLockDigest': 'b'*64,
                }],
            }],
        }
        self.component()
        errs = mod.validate(doc)
        self.assertTrue(any('strict exact-version upgrade' in e for e in errs), errs)


if __name__ == '__main__':
    unittest.main()
