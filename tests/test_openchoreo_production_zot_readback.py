import importlib.util,json,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
SPEC=importlib.util.spec_from_file_location("zotreadback",ROOT/"scripts"/"verify_openchoreo_production_zot_readback.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)

class OpenChoreoProductionZotReadbackTests(unittest.TestCase):
    def runtime(self,registry="zot.platform.internal:5000"):
        acq=json.loads((ROOT/"lab/openchoreo-runtime-acquisition-receipt.json").read_text())
        images=[]
        for idx,row in enumerate(acq["images"],1):
            images.append({"sourceReference":row["sourceReference"],"digest":row["digest"],"mirrorReference":f"{registry}/4so/openchoreo/image-{idx}@{row['digest']}"})
        ed="sha256:"+"e"*64
        return {"authority":"OPENCHOREO_RUNTIME_SOURCE_AUTHORITY_V1","version":acq["version"],"upstreamRepository":acq["upstreamRepository"],"upstreamCommit":acq["upstreamCommit"],"sourceArchiveSha256":acq["sourceArchiveSha256"],"planes":acq["planes"],"images":images,"executorImageReference":f"{registry}/4so/openchoreo/openchoreo-runtime@{ed}","executorImageDigest":ed,"resolved":True,"mirrorReady":True,"backstageEnabled":False,"workflowPlaneEnabled":False,"observabilityPlaneEnabled":False,"openChoreoMcpEnabled":False,"externalOidcRequired":True,"buildAuthority":"buildkit","registryAuthority":"zot","registryIdentity":registry}

    def test_seven_exact_references_require_live_digest_equality(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/"runtime.json"; p.write_text(json.dumps(self.runtime()))
            out=mod.verify(p,lambda ref:ref.rsplit("@",1)[1],"test-reader")
            self.assertTrue(out["liveRegistryReadbackPass"]); self.assertEqual(7,out["readbackCount"]); self.assertEqual(6,out["imageCount"])
            self.assertFalse(out["runtimeCertified"]); self.assertFalse(out["physicalCertified"])

    def test_one_registry_digest_mismatch_rejects_whole_readback(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/"runtime.json"; p.write_text(json.dumps(self.runtime()))
            count={"n":0}
            def reader(ref):
                count["n"]+=1
                return "sha256:"+"0"*64 if count["n"]==2 else ref.rsplit("@",1)[1]
            with self.assertRaisesRegex(RuntimeError,"DIGEST_MISMATCH"):
                mod.verify(p,reader,"test-reader")

    def test_ephemeral_or_cross_registry_runtime_rejects_before_network(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/"runtime.json"; p.write_text(json.dumps(self.runtime("127.0.0.1:5000")))
            with self.assertRaisesRegex(RuntimeError,"EPHEMERAL"):
                mod.verify(p,lambda ref:ref.rsplit("@",1)[1],"test-reader")
            data=self.runtime(); data["images"][0]["mirrorReference"]="other-zot.internal:5000/x@"+data["images"][0]["digest"]; p.write_text(json.dumps(data))
            with self.assertRaisesRegex(RuntimeError,"REGISTRY_MISMATCH"):
                mod.verify(p,lambda ref:ref.rsplit("@",1)[1],"test-reader")

if __name__=="__main__":
    unittest.main()
