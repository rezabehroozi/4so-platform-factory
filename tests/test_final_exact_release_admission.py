import hashlib,importlib.util,json,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("final_adm",ROOT/"scripts"/"final_exact_release_admission.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)

class FinalExactReleaseAdmissionTests(unittest.TestCase):
    def fixture(self,root:Path):
        (root/"lab").mkdir()
        pack="a"*64; archive="b"*64
        lock={"authority":mod.S1_AUTHORITY,"schemaVersion":8,"status":"ready","missingAuthorities":[],"partialAuthorities":[],"inputPack":{"format":"zip","buildSpecPath":"build-spec.json","stagingDirectory":"staging","sha256":pack,"sizeBytes":123,"urls":[f"https://dist.example.test/sha256/{pack}/appliance.zip"]},"resolvedAuthorities":[{"id":"management-workload-oci-archive","artifacts":[{"sha256":archive,"sizeBytes":456,"urls":[f"https://dist.example.test/sha256/{archive}/archive.tar"]}]}]}
        (root/"lab/appliance-bundle-acquisition-lock.json").write_text(json.dumps(lock))
        clients=[]
        for c in mod.CLIENTS:
            clients.append({"clientId":c,"challengeSha256":"sha256:"+hashlib.sha256((c+"-challenge").encode()).hexdigest(),"evidenceDigest":"sha256:"+hashlib.sha256((c+"-evidence").encode()).hexdigest(),"receiptSha256":"sha256:"+hashlib.sha256((c+"-receipt").encode()).hexdigest(),"checks":{"a":True,"b":True,"c":True,"d":True,"e":True,"f":True,"g":True}})
        mcp={"authority":mod.MCP_AUTHORITY,"externalCertificationPass":True,"allRequiredChecksPass":True,"certifiedClientCount":4,"campaignAuthority":"MCP_EXTERNAL_CLIENT_INTEROP_CAMPAIGN_V1","campaignSha256":"sha256:"+hashlib.sha256(b"campaign").hexdigest(),"clients":clients,"runtimeCertified":False,"physicalCertified":False}
        (root/"lab/mcp-external-client-interoperability-evidence.json").write_text(json.dumps(mcp))
        return lock,mcp
    def test_two_external_authorities_admit_final_release_without_physical_claim(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.fixture(root); out=mod.verify(root)
            self.assertTrue(out["admitted"]); self.assertFalse(out["physicalCertified"])
            self.assertTrue(out["applianceDistributionSha256"].startswith("sha256:"))
    def test_missing_mcp_evidence_is_pending(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.fixture(root); (root/"lab/mcp-external-client-interoperability-evidence.json").unlink()
            with self.assertRaisesRegex(mod.Pending,"MCP_EXTERNAL_INTEROP_PENDING"): mod.verify(root)
    def test_mutable_distribution_url_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.fixture(root)
            p=root/"lab/appliance-bundle-acquisition-lock.json"; d=json.loads(p.read_text()); d["inputPack"]["urls"]=["https://dist.example.test/latest/appliance.zip"]; p.write_text(json.dumps(d))
            with self.assertRaisesRegex(RuntimeError,"CONTENT_ADDRESS"): mod.verify(root)
if __name__=="__main__": unittest.main()
