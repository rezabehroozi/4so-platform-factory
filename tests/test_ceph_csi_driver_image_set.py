import copy,importlib.util,json,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
S=importlib.util.spec_from_file_location("m",ROOT/"scripts"/"ceph_csi_driver_image_set.py");m=importlib.util.module_from_spec(S);S.loader.exec_module(m)
class T(unittest.TestCase):
 def test_input(self):
  d=m.load_input(ROOT/"catalog/runtime-dependencies/ceph-csi/1.0.4/driver-image-set-input.json");self.assertEqual(8,len(d["images"]))
 def test_evidence_if_present(self):
  p=ROOT/"lab/ceph-csi-driver-image-set-evidence.json"
  if not p.is_file(): self.skipTest("workflow evidence pending")
  d=m.verify(ROOT/"catalog/runtime-dependencies/ceph-csi/1.0.4/driver-image-set-input.json",p);self.assertTrue(d["allImagesDigestPinned"]);self.assertFalse(d["physicalCertified"])
 def test_mutation_rejected(self):
  p=ROOT/"lab/ceph-csi-driver-image-set-evidence.json"
  if not p.is_file(): self.skipTest("workflow evidence pending")
  d=json.loads(p.read_text())
  with tempfile.TemporaryDirectory() as td:
   q=Path(td)/"e.json";bad=copy.deepcopy(d);bad["images"][0]["exactReference"]=bad["images"][0]["sourceReference"];q.write_text(json.dumps(bad))
   with self.assertRaisesRegex(RuntimeError,"BINDING"):m.verify(ROOT/"catalog/runtime-dependencies/ceph-csi/1.0.4/driver-image-set-input.json",q)
if __name__=="__main__":unittest.main()
