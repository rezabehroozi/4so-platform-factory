import hashlib,importlib.util,json,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("mcpseal",ROOT/"scripts"/"seal_mcp_external_interop.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)

class MCPExternalSealTests(unittest.TestCase):
    def receipt(self,client,checks,endpoint="https://mcp.example.test/mcp"):
        return {"authority":mod.RECEIPT_AUTHORITY,"clientId":client,"protocol":"2026-07-28","transport":"streamable-http","endpoint":endpoint,"executionId":"run-"+client,"externalExecution":True,"credentialedExecution":True,"checks":{x:True for x in checks},"scopeLeakObserved":False,"revokedGrantAccepted":False,"selfApprovalAccepted":False,"evidenceDigest":"sha256:"+hashlib.sha256(client.encode()).hexdigest()}
    def test_four_named_clients_are_required_and_sealed(self):
        matrix=json.loads((ROOT/"lab"/"mcp-external-client-interop-matrix.json").read_text()); checks=matrix["spec"]["sharedRequiredChecks"]
        with tempfile.TemporaryDirectory() as td:
            d=Path(td)
            for c in mod.CLIENTS:(d/(c+".json")).write_text(json.dumps(self.receipt(c,checks)))
            out=mod.seal(ROOT/"lab"/"mcp-external-client-interop-matrix.json",d)
            self.assertEqual(4,out["certifiedClientCount"]); self.assertTrue(out["externalCertificationPass"]); self.assertFalse(out["runtimeCertified"]); self.assertFalse(out["physicalCertified"])
    def test_missing_negative_control_or_endpoint_drift_rejects(self):
        matrix=json.loads((ROOT/"lab"/"mcp-external-client-interop-matrix.json").read_text()); checks=matrix["spec"]["sharedRequiredChecks"]
        with tempfile.TemporaryDirectory() as td:
            d=Path(td)
            for c in mod.CLIENTS:(d/(c+".json")).write_text(json.dumps(self.receipt(c,checks)))
            bad=json.loads((d/"chatgpt.json").read_text()); bad["revokedGrantAccepted"]=True; (d/"chatgpt.json").write_text(json.dumps(bad))
            with self.assertRaisesRegex(RuntimeError,"NEGATIVE_CONTROL"):mod.seal(ROOT/"lab"/"mcp-external-client-interop-matrix.json",d)
            (d/"chatgpt.json").write_text(json.dumps(self.receipt("chatgpt",checks,"https://other.example.test/mcp")))
            with self.assertRaisesRegex(RuntimeError,"ENDPOINT_DRIFT"):mod.seal(ROOT/"lab"/"mcp-external-client-interop-matrix.json",d)

if __name__=="__main__": unittest.main()
