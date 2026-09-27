import importlib.util,json,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("hist",ROOT/"scripts"/"render_exact_helm_runtime.py")
mod=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(mod)
class ExactHelmRenderContractTests(unittest.TestCase):
    def test_kyverno_source_pair_has_exact_distinct_authority(self):
        rows=[]
        for v in ("3.8.1","3.8.2"):
            p=ROOT/"catalog"/"runtime"/"kyverno"/v
            lock=json.loads((p/"source-lock.json").read_text())
            self.assertEqual(v,lock["version"]);self.assertEqual("kyverno",lock["component"])
            self.assertFalse(lock["networkFetchRequired"]);self.assertEqual("sha256-pinned-offline",lock["upstreamVerification"])
            self.assertIn("1.34.0",lock["generation"]["kubernetesRenderDigests"])
            rows.append((lock["upstreamArtifactDigest"],lock["generation"]["kubernetesRenderDigests"]["1.34.0"]))
        self.assertNotEqual(rows[0][0],rows[1][0]);self.assertNotEqual(rows[0][1],rows[1][1])
if __name__=="__main__":unittest.main()
