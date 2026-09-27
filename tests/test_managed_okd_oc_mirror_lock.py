import copy,importlib.util,json,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("oclock",ROOT/"scripts"/"verify_managed_okd_oc_mirror_lock.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)
class OcMirrorLockTests(unittest.TestCase):
    def test_shipped_lock_is_exact_and_noninflated(self):
        d=mod.verify(ROOT/"lab"/"managed-okd-oc-mirror-source-lock.json")
        self.assertEqual("release-4.19",d["upstreamBranch"]); self.assertTrue(d["sourcePinned"])
        self.assertFalse(d["binaryEvidenceReady"]); self.assertFalse(d["disconnectedToolchainReady"]); self.assertFalse(d["physicalCertified"])
    def test_mutable_or_inflated_lock_rejects(self):
        src=json.loads((ROOT/"lab"/"managed-okd-oc-mirror-source-lock.json").read_text())
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/"x.json"; bad=copy.deepcopy(src); bad["upstreamCommitSHA"]="main"; p.write_text(json.dumps(bad))
            with self.assertRaisesRegex(RuntimeError,"COMMIT"): mod.verify(p)
            bad=copy.deepcopy(src); bad["disconnectedToolchainReady"]=True; p.write_text(json.dumps(bad))
            with self.assertRaisesRegex(RuntimeError,"SCOPE_INFLATED"): mod.verify(p)
if __name__=="__main__": unittest.main()
