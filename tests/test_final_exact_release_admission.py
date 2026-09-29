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
            clients.append({"clientId":c,"clientSurface":mod.CLIENT_SURFACES[c],"challengeSha256":"sha256:"+hashlib.sha256((c+"-challenge").encode()).hexdigest(),"evidenceDigest":"sha256:"+hashlib.sha256((c+"-evidence").encode()).hexdigest(),"externalReceiptSha256":"sha256:"+hashlib.sha256((c+"-receipt").encode()).hexdigest(),"checks":{"a":True,"b":True,"c":True,"d":True,"e":True,"f":True,"g":True},"serverAuditWitness":{"authority":"MCP_EXTERNAL_SERVER_AUDIT_WITNESS_V1","serverAuditWitnessPass":True,"witnessedCheckCount":6,"auditHeadDigest":"sha256:"+hashlib.sha256((c+"-audit-head").encode()).hexdigest(),"auditExportSha256":"sha256:"+hashlib.sha256((c+"-audit-export").encode()).hexdigest()}})
        mcp={"authority":mod.MCP_AUTHORITY,"externalCertificationPass":True,"allRequiredChecksPass":True,"serverAuditWitnessPass":True,"serverAuditWitnessedCheckCount":24,"certifiedClientCount":4,"campaignAuthority":"MCP_EXTERNAL_CLIENT_INTEROP_CAMPAIGN_V1","campaignSha256":"sha256:"+hashlib.sha256(b"campaign").hexdigest(),"clients":clients,"runtimeCertified":False,"physicalCertified":False}
        (root/"lab/mcp-external-client-interoperability-evidence.json").write_text(json.dumps(mcp))
        return lock,mcp
    def test_two_external_authorities_admit_final_release_without_physical_claim(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.fixture(root); out=mod.verify(root)
            self.assertTrue(out["admitted"]); self.assertFalse(out["physicalCertified"])
            self.assertTrue(out["applianceDistributionSha256"].startswith("sha256:"))
    def test_multipart_distribution_is_admitted_with_same_full_digest(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); lock,_=self.fixture(root)
            p=root/"lab/appliance-bundle-acquisition-lock.json"; d=json.loads(p.read_text())
            pack=d["inputPack"]; pd=pack.pop("urls")
            pack["parts"]=[{"index":0,"urls":[pd[0].replace("appliance.zip","part0")],"sha256":pack["sha256"],"sizeBytes":pack["sizeBytes"]}]
            ar=d["resolvedAuthorities"][0]["artifacts"][0]; au=ar.pop("urls")
            ar["parts"]=[{"index":0,"urls":[au[0].replace("archive.tar","part0")],"sha256":ar["sha256"],"sizeBytes":ar["sizeBytes"]}]
            p.write_text(json.dumps(d))
            out=mod.verify(root); self.assertTrue(out["admitted"])

    def test_multipart_distribution_rejects_part_sum_drift(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.fixture(root)
            p=root/"lab/appliance-bundle-acquisition-lock.json"; d=json.loads(p.read_text())
            pack=d["inputPack"]; url=pack.pop("urls")[0]
            pack["parts"]=[{"index":0,"urls":[url.replace("appliance.zip","part0")],"sha256":pack["sha256"],"sizeBytes":pack["sizeBytes"]-1}]
            p.write_text(json.dumps(d))
            with self.assertRaisesRegex(RuntimeError,"SIZE_SUM"): mod.verify(root)

    def test_missing_mcp_evidence_is_pending(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.fixture(root); (root/"lab/mcp-external-client-interoperability-evidence.json").unlink()
            with self.assertRaisesRegex(mod.Pending,"MCP_EXTERNAL_INTEROP_PENDING"): mod.verify(root)
    def test_pending_status_is_structured_for_ci_summary(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.fixture(root); (root/"lab/mcp-external-client-interoperability-evidence.json").unlink()
            try:
                mod.verify(root)
            except mod.Pending as exc:
                pending=str(exc)
                status={"authority":mod.AUTHORITY,"admitted":False,"pending":pending,"blockers":[{"code":pending,"detail":"required external closure evidence is not sealed on canonical main"}],"physicalCertified":False}
                self.assertEqual("MCP_EXTERNAL_INTEROP_PENDING",status["blockers"][0]["code"])
                self.assertFalse(status["admitted"])
            else:
                self.fail("pending evidence unexpectedly admitted")

    def test_external_progress_reports_missing_clients_without_inventing_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.fixture(root)
            (root/"lab/mcp-external-client-interoperability-evidence.json").unlink()
            p=root/"lab/mcp-external-client-interop-progress.json"
            p.write_text(json.dumps({"authority":"MCP_EXTERNAL_CLIENT_INTEROP_PROGRESS_V1","kind":"MCPExternalClientInteropProgress","clients":[{"clientId":"chatgpt","clientSurface":mod.CLIENT_SURFACES["chatgpt"]},{"clientId":"gemini","clientSurface":mod.CLIENT_SURFACES["gemini"]}],"certifiedClientCount":2,"complete":False,"runtimeCertified":False,"physicalCertified":False}))
            progress=mod.external_client_progress(root)
            self.assertEqual(["chatgpt","gemini"],progress["certifiedClients"])
            self.assertEqual(["claude","grok"],progress["missingClients"])
            self.assertEqual("claude",progress["nextClient"])
            self.assertFalse(progress["evidenceSealPending"])

    def test_complete_progress_without_evidence_reports_seal_pending(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.fixture(root)
            (root/"lab/mcp-external-client-interoperability-evidence.json").unlink()
            rows=[{"clientId":c,"clientSurface":mod.CLIENT_SURFACES[c]} for c in mod.CLIENTS]
            (root/"lab/mcp-external-client-interop-progress.json").write_text(json.dumps({"authority":"MCP_EXTERNAL_CLIENT_INTEROP_PROGRESS_V1","kind":"MCPExternalClientInteropProgress","clients":rows,"certifiedClientCount":4,"complete":True,"runtimeCertified":False,"physicalCertified":False}))
            progress=mod.external_client_progress(root)
            self.assertEqual([],progress["missingClients"])
            self.assertIsNone(progress["nextClient"])
            self.assertTrue(progress["evidenceSealPending"])

    def test_unwitnessed_external_evidence_remains_pending(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.fixture(root)
            p=root/"lab/mcp-external-client-interoperability-evidence.json"
            evidence=json.loads(p.read_text()); evidence["serverAuditWitnessPass"]=False; evidence["serverAuditWitnessedCheckCount"]=0; p.write_text(json.dumps(evidence))
            with self.assertRaisesRegex(mod.Pending,"MCP_EXTERNAL_SERVER_AUDIT_WITNESS_PENDING"):
                mod.verify(root)

    def test_wrong_client_surface_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.fixture(root)
            p=root/"lab/mcp-external-client-interoperability-evidence.json"
            evidence=json.loads(p.read_text()); evidence["clients"][0]["clientSurface"]="Generic MCP"; p.write_text(json.dumps(evidence))
            with self.assertRaisesRegex(RuntimeError,"CLIENT_SURFACE"):
                mod.verify(root)

    def test_mutable_distribution_url_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.fixture(root)
            p=root/"lab/appliance-bundle-acquisition-lock.json"; d=json.loads(p.read_text()); d["inputPack"]["urls"]=["https://dist.example.test/latest/appliance.zip"]; p.write_text(json.dumps(d))
            with self.assertRaisesRegex(RuntimeError,"CONTENT_ADDRESS"): mod.verify(root)
if __name__=="__main__": unittest.main()
