import copy, importlib.util, json, tempfile, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("mokd_lock",ROOT/"scripts"/"verify_managed_okd_upstream_lock.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)

class ManagedOKDUpstreamLockTests(unittest.TestCase):
    def test_shipped_lock_is_exact_and_claim_scoped(self):
        doc=mod.verify(ROOT/"lab"/"managed-okd-upstream-toolchain-lock.json")
        self.assertEqual("4.19.0-okd-scos.19",doc["exactRelease"])
        self.assertTrue(doc["connectedToolchainReady"])
        self.assertFalse(doc["managedInstallContentReady"])
        self.assertFalse(doc["disconnectedToolchainReady"])
        self.assertFalse(doc["runtimeCertified"])
        self.assertFalse(doc["physicalCertified"])
    def test_mutable_url_and_scope_inflation_are_rejected(self):
        original=json.loads((ROOT/"lab"/"managed-okd-upstream-toolchain-lock.json").read_text())
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/"lock.json"; bad=copy.deepcopy(original)
            bad["artifacts"][0]["url"]="https://github.com/okd-project/okd/releases/latest/download/"+bad["artifacts"][0]["name"]
            p.write_text(json.dumps(bad))
            with self.assertRaisesRegex(RuntimeError,"RELEASE_BINDING"):
                mod.verify(p)
            bad=copy.deepcopy(original); bad["runtimeCertified"]=True; p.write_text(json.dumps(bad))
            with self.assertRaisesRegex(RuntimeError,"CLAIM_SCOPE_INFLATED"):
                mod.verify(p)

if __name__=="__main__": unittest.main()
