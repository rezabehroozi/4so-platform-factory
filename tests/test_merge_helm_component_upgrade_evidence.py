import importlib.util,json,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("merge",ROOT/"scripts"/"merge_helm_component_upgrade_evidence.py")
mod=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(mod)
class MergeHelmUpgradeEvidenceTests(unittest.TestCase):
    def row(self,c,v,run="1"):
        f,t=mod.PROFILES[c]
        return {"authority":mod.ROW_AUTH,"component":c,"fromRelease":f,"toRelease":t,"kubernetesVersion":v,"sourceRunId":run,"sourceCommitSHA":"a"*40,"historicalReady":True,"upgradeApplyPass":True,"targetReady":True,"workloadIdentityPreserved":True,"targetImagesVerified":True,"targetReapplyConverged":True,"reverseEdgeRejected":True,"genericKubernetesRuntimeEvidenceOnly":True,"rke2Certified":False,"productTopologyHACertified":False,"physicalCertified":False}
    def test_partial_new_run_preserves_existing_component(self):
        with tempfile.TemporaryDirectory() as td:
            d=Path(td); existing=d/"old.json"; arts=d/"arts"; arts.mkdir(); out=d/"out.json"
            cap=mod.component_from_rows("capsule",[self.row("capsule","1.34.11"),self.row("capsule","1.35.8")])
            existing.write_text(json.dumps({"authority":mod.AUTH,"mergeAuthority":"component-scoped-incremental","components":[cap]}))
            (arts/"victoria-metrics-upgrade-1.34.11.json").write_text(json.dumps(self.row("victoria-metrics","1.34.11","2")))
            merged=mod.merge(existing,arts,out)
            self.assertEqual(["capsule"],[x["component"] for x in merged["components"]])
    def test_complete_component_is_promoted(self):
        with tempfile.TemporaryDirectory() as td:
            d=Path(td); arts=d/"arts"; arts.mkdir(); out=d/"out.json"; existing=d/"missing.json"
            for v in ("1.34.11","1.35.8"):(arts/f"victoria-metrics-upgrade-{v}.json").write_text(json.dumps(self.row("victoria-metrics",v,"9")))
            merged=mod.merge(existing,arts,out)
            self.assertEqual("9",merged["components"][0]["sourceRunId"])
            self.assertEqual("victoria-metrics",merged["components"][0]["component"])
if __name__=="__main__":unittest.main()
