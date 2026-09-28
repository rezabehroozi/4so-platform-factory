import importlib.util,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
S=importlib.util.spec_from_file_location("p",ROOT/"scripts"/"persist_evidence_if_inputs_unchanged.py");m=importlib.util.module_from_spec(S);S.loader.exec_module(m)
class T(unittest.TestCase):
 def test_safe_rel_rejects_escape(self):
  for v in ("/tmp/x","../x","a/../../b"):
   with self.assertRaises(RuntimeError):m.safe_rel(v)
 def test_safe_rel_accepts_repo_paths(self):
  self.assertEqual(Path("lab/evidence.json"),m.safe_rel("lab/evidence.json"))
if __name__=="__main__":unittest.main()
