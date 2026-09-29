import importlib.util,json,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
SPEC=importlib.util.spec_from_file_location("prodseal",ROOT/"scripts"/"seal_openchoreo_production_authority.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)

class OpenChoreoProductionSealTests(unittest.TestCase):
    def runtime(self,registry="zot.platform.internal:5000"):
        acq=json.loads((ROOT/"lab/openchoreo-runtime-acquisition-receipt.json").read_text())
        images=[]
        for idx,row in enumerate(acq["images"],1):
            images.append({"sourceReference":row["sourceReference"],"digest":row["digest"],"mirrorReference":f"{registry}/4so/openchoreo/image-{idx}@{row['digest']}"})
        ed="sha256:"+"e"*64
        return {"authority":"OPENCHOREO_RUNTIME_SOURCE_AUTHORITY_V1","version":acq["version"],"upstreamRepository":acq["upstreamRepository"],"upstreamCommit":acq["upstreamCommit"],"sourceArchiveSha256":acq["sourceArchiveSha256"],"planes":acq["planes"],"images":images,"executorImageReference":f"{registry}/4so/openchoreo/openchoreo-runtime@{ed}","executorImageDigest":ed,"resolved":True,"mirrorReady":True,"backstageEnabled":False,"workflowPlaneEnabled":False,"observabilityPlaneEnabled":False,"openChoreoMcpEnabled":False,"externalOidcRequired":True,"buildAuthority":"buildkit","registryAuthority":"zot","registryIdentity":registry}

    def readback(self,runtime_path,out_path):
        data=json.loads(runtime_path.read_text())
        refs=[{"reference":row["mirrorReference"],"digest":row["digest"]} for row in data["images"]]
        refs.append({"reference":data["executorImageReference"],"digest":data["executorImageDigest"]})
        evidence={"apiVersion":"platform.4so.io/v1alpha1","kind":"OpenChoreoProductionZotReadbackEvidence","authority":"OPENCHOREO_PRODUCTION_ZOT_READBACK_EVIDENCE_V1","runtimeSourceAuthority":"OPENCHOREO_RUNTIME_SOURCE_AUTHORITY_V1","runtimeSourceSha256":mod.sha256(runtime_path),"version":data["version"],"upstreamCommit":data["upstreamCommit"],"registryAuthority":"zot","registryIdentity":data["registryIdentity"],"imageCount":6,"readbackCount":7,"readbackTool":"test-reader","liveRegistryReadbackPass":True,"references":refs,"runtimeCertified":False,"physicalCertified":False}
        out_path.write_text(json.dumps(evidence))
        return out_path

    def test_promotes_exact_non_ephemeral_zot_without_runtime_claim(self):
        with tempfile.TemporaryDirectory() as td:
            d=Path(td); runtime=d/"runtime.json"; runtime.write_text(json.dumps(self.runtime()))
            selection=d/"selection.json"; selection.write_text((ROOT/"runtime/openchoreo/source-selection.json").read_text())
            out=d/"promoted.json"; evidence=d/"evidence.json"; readback=self.readback(runtime,d/"readback.json")
            e=mod.promote(runtime,ROOT/"lab/openchoreo-runtime-acquisition-receipt.json",selection,"zot.platform.internal:5000",out,evidence,readback)
            promoted=json.loads(out.read_text())["spec"]
            self.assertTrue(promoted["resolved"]); self.assertTrue(promoted["mirrorReady"]); self.assertEqual(6,len(promoted["images"]))
            self.assertTrue(e["productionSourceSealed"]); self.assertTrue(e["liveRegistryReadbackPass"]); self.assertEqual(7,e["liveRegistryReadbackCount"]); self.assertFalse(e["runtimeCertified"]); self.assertFalse(e["physicalCertified"])

    def test_loopback_registry_and_inventory_drift_reject(self):
        with self.assertRaisesRegex(RuntimeError,"EPHEMERAL_FORBIDDEN"):
            mod.production_registry("127.0.0.1:5000")
        with tempfile.TemporaryDirectory() as td:
            d=Path(td); data=self.runtime(); data["images"]=data["images"][:-1]
            runtime=d/"runtime.json"; runtime.write_text(json.dumps(data))
            selection=d/"selection.json"; selection.write_text((ROOT/"runtime/openchoreo/source-selection.json").read_text())
            with self.assertRaisesRegex(RuntimeError,"COVERAGE"):
                mod.promote(runtime,ROOT/"lab/openchoreo-runtime-acquisition-receipt.json",selection,"zot.platform.internal:5000",d/"out.json",d/"evidence.json",d/"unused-readback.json")

    def test_readback_reference_tamper_rejects_before_promotion(self):
        with tempfile.TemporaryDirectory() as td:
            d=Path(td); runtime=d/"runtime.json"; runtime.write_text(json.dumps(self.runtime()))
            selection=d/"selection.json"; selection.write_text((ROOT/"runtime/openchoreo/source-selection.json").read_text())
            readback=self.readback(runtime,d/"readback.json")
            data=json.loads(readback.read_text()); data["references"][0]["digest"]="sha256:"+"0"*64; readback.write_text(json.dumps(data))
            with self.assertRaisesRegex(RuntimeError,"READBACK_REFERENCE_MISMATCH"):
                mod.promote(runtime,ROOT/"lab/openchoreo-runtime-acquisition-receipt.json",selection,"zot.platform.internal:5000",d/"out.json",d/"evidence.json",readback)
            self.assertFalse((d/"out.json").exists())

    def test_registry_expectation_prevents_wrong_zot_promotion(self):
        with tempfile.TemporaryDirectory() as td:
            d=Path(td); runtime=d/"runtime.json"; runtime.write_text(json.dumps(self.runtime()))
            selection=d/"selection.json"; selection.write_text((ROOT/"runtime/openchoreo/source-selection.json").read_text())
            with self.assertRaisesRegex(RuntimeError,"EXPECTATION_MISMATCH"):
                mod.promote(runtime,ROOT/"lab/openchoreo-runtime-acquisition-receipt.json",selection,"other-zot.internal:5000",d/"out.json",d/"evidence.json",d/"unused-readback.json")

if __name__=="__main__":
    unittest.main()
