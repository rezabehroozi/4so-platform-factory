import copy,importlib.util,json,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("cmcrd",ROOT/"scripts"/"verify_cert_manager_crd_dependency.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)
class CertManagerCRDDependencyTests(unittest.TestCase):
    def test_lock_is_exact_and_noninflated(self):
        d=mod.verify(ROOT,False)
        self.assertEqual(["1.21.0","1.21.1"],[x["release"] for x in d["assets"]])
        self.assertFalse(d["runtimeCertified"]); self.assertFalse(d["physicalCertified"])
    def test_mutable_url_or_scope_inflation_rejected(self):
        src=json.loads((ROOT/"catalog/runtime-dependencies/cert-manager/crd-runtime-dependency-lock.json").read_text())
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); p=root/"catalog/runtime-dependencies/cert-manager/crd-runtime-dependency-lock.json"; p.parent.mkdir(parents=True)
            bad=copy.deepcopy(src); bad["assets"][0]["url"]="https://github.com/cert-manager/cert-manager/releases/latest/download/cert-manager.crds.yaml"; p.write_text(json.dumps(bad))
            with self.assertRaisesRegex(RuntimeError,"URL_INVALID"): mod.verify(root,False)
            bad=copy.deepcopy(src); bad["runtimeCertified"]=True; p.write_text(json.dumps(bad))
            with self.assertRaisesRegex(RuntimeError,"SCOPE_INFLATED"): mod.verify(root,False)
if __name__=="__main__": unittest.main()
