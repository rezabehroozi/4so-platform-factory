import importlib.util
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('management_batch',ROOT/'scripts'/'acquire_management_workload_batch.py')
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

class ManagementBatchVerifySchemaTests(unittest.TestCase):
    def test_current_top_level_and_legacy_nested_exact_reference_are_supported(self):
        exact='docker.io/library/postgres@sha256:'+'a'*64
        self.assertEqual(exact,mod.verified_exact_reference({'verified':True,'exactReference':exact}))
        self.assertEqual(exact,mod.verified_exact_reference({'verified':True,'result':{'exactReference':exact}}))
        self.assertEqual('',mod.verified_exact_reference({'verified':False,'exactReference':exact}))

if __name__=='__main__':
    unittest.main()
