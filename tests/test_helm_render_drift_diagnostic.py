import importlib.util,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("hdrift",ROOT/"scripts"/"diagnose_exact_helm_render_drift.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)
class HelmRenderDriftDiagnosticTests(unittest.TestCase):
    def test_diff_reports_paths_without_values(self):
        a={"metadata":{"name":"x"},"spec":{"token":"one","stable":1}}
        b={"metadata":{"name":"x"},"spec":{"token":"two","stable":1}}
        out=mod.diff(a,b)
        self.assertEqual([{"path":"$.spec.token","kind":"value"}],out)
        self.assertNotIn("one",str(out)); self.assertNotIn("two",str(out))
if __name__=="__main__": unittest.main()
