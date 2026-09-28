import importlib.util,json,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("renderer",ROOT/"scripts"/"render_exact_helm_runtime.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)

class ExactHelmRuntimeProfileTests(unittest.TestCase):
    def test_victoria_profile_is_exact_and_noninflated(self):
        p=ROOT/"catalog/runtime-profiles/victoria-metrics.json"
        d=json.loads(p.read_text())
        self.assertEqual("VICTORIA_METRICS_RUNTIME_PROFILE_V1",d["authority"])
        self.assertEqual(["0.90.1","0.90.2"],d["releases"])
        values=ROOT/d["valuesPath"]
        self.assertEqual(d["valuesSha256"],mod.sha(values))
        self.assertEqual("vmstack",d["fullnameOverride"])
        self.assertIn("fullnameOverride: vmstack",(values).read_text())
        self.assertFalse(d["embeddedGrafanaEnabled"])
        self.assertFalse(d["operatorAdmissionWebhooksEnabled"])
        self.assertFalse(d["runtimeCertified"]); self.assertFalse(d["physicalCertified"])
    def test_cilium_profile_uses_runtime_certificate_generation(self):
        p=ROOT/"catalog/runtime-profiles/cilium.json"
        d=json.loads(p.read_text())
        self.assertEqual("CILIUM_RUNTIME_PROFILE_V1",d["authority"])
        self.assertEqual(["1.20.0","1.20.1"],d["releases"])
        values=ROOT/d["valuesPath"]
        self.assertEqual(d["valuesSha256"],mod.sha(values))
        self.assertEqual("cronJob",d["hubbleTLSAutoMethod"])
        self.assertIn("method: cronJob",values.read_text())
        self.assertFalse(d["runtimeCertified"]); self.assertFalse(d["physicalCertified"])
        profile,paths=mod.runtime_profile("cilium","1.20.1",[])
        self.assertEqual("CILIUM_RUNTIME_PROFILE_V1",profile["authority"])
        self.assertEqual([values],paths)

    def test_runtime_profile_rejects_source_values_conflict_and_escape(self):
        with self.assertRaisesRegex(RuntimeError,"SOURCE_VALUE_CONFLICT"):
            mod.runtime_profile("victoria-metrics","0.90.2",[ROOT/"VERSION"])
        with self.assertRaisesRegex(RuntimeError,"PATH_"):
            mod.repo_file("../escape.yaml","HELM_RUNTIME_PROFILE_VALUES")

if __name__=="__main__": unittest.main()
