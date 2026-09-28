import hashlib,importlib.util,json,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("pack",ROOT/"scripts"/"build_appliance_input_pack.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)
class InputPackTests(unittest.TestCase):
  def test_shipped_authorities_generate_complete_production_spec(self):
    s=mod.build_spec(ROOT)
    self.assertEqual("0.0.363",s["metadata"]["version"]); self.assertEqual(mod.ZERO,s["metadata"]["sourceReleaseDigest"])
    paths={x["path"] for x in s["spec"]["sourceArtifacts"]}
    self.assertEqual({"rke2/install.sh","rke2/rke2.linux-amd64.tar.gz","rke2/sha256sum-amd64.txt","rke2/rke2-images.linux-amd64.tar.zst","workloads/platform-workloads.oci.tar","manifests/argocd-install.yaml","manifests/argocd-ha-install.yaml","manifests/cloudnative-pg-install.yaml","manifests/replicated-storage-install.yaml"},paths)
    w=s["spec"]["workloads"]; self.assertIn("@sha256:",w["platformApiImage"]); self.assertIn("@sha256:",w["postgresqlImage"]); self.assertEqual("manifests/argocd-ha-install.yaml",w["gitOpsHAManifest"])
  def test_ready_lock_remains_valid_build_input(self):
    lock,archive,_,_=mod.authorities(ROOT)
    self.assertEqual("ready",lock["status"])
    self.assertEqual(archive["archiveSha256"].removeprefix("sha256:"),next(x for x in lock["resolvedAuthorities"] if x["id"]=="management-workload-oci-archive")["artifacts"][0]["sha256"])
  def test_deterministic_zip_and_tamper_rejection(self):
    with tempfile.TemporaryDirectory() as td:
      root=Path(td); staging=root/"staging"; staging.mkdir()
      data=b"exact"; p=staging/"a.bin"; p.write_bytes(data)
      spec={"metadata":{"version":"x"},"spec":{"sourceArtifacts":[{"path":"a.bin","sha256":"sha256:"+hashlib.sha256(data).hexdigest(),"sizeBytes":len(data)}]}}
      r1=mod.write_pack(staging,spec,root/"a.zip"); r2=mod.write_pack(staging,spec,root/"b.zip")
      self.assertEqual(r1["inputPackSha256"],r2["inputPackSha256"])
      p.write_bytes(b"tamper")
      with self.assertRaisesRegex(RuntimeError,"DRIFT"): mod.write_pack(staging,spec,root/"c.zip")
if __name__=="__main__": unittest.main()
